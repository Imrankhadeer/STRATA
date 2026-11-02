"""
Incident Correlator & Aggregator for Ternline Phase 2.

Aggregates isolated SecurityFinding records into unified, multi-service Incident cases.
Deduplicates correlated attack traces, tracks involved microservice boundaries,
dynamically escalates composite severity, and emits live operational bus updates.
"""

import datetime
import logging
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.models import (
    IncidentFindingModel,
    IncidentModel,
    SecurityFinding,
)
from backend.ops.bus import ops_bus
from backend.schemas.incidents import IncidentSeverity, IncidentStatus

logger = logging.getLogger("cyber_engine.incidents.correlator")

SEVERITY_WEIGHTS: Dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}

DETECTOR_MITRE_MAP: Dict[str, Dict[str, List[str]]] = {
    "detector.auth.brute_force": {
        "tactics": ["TA0006"],
        "techniques": ["T1110", "T1078"],
    },
    "detector.exfiltration.cross_service": {
        "tactics": ["TA0010"],
        "techniques": ["T1048", "T1020"],
    },
    "investigator.deep_search": {
        "tactics": ["TA0009"],
        "techniques": ["T1005", "T1530"],
    },
    "detector.sql.injection": {
        "tactics": ["TA0001"],
        "techniques": ["T1190"],
    },
}


class IncidentCorrelator:
    """
    Evaluates SecurityFindings and correlates them into active Incident cases.
    """

    def __init__(self, db: Session):
        self.db = db

    def correlate_finding(self, finding: SecurityFinding) -> IncidentModel:
        """
        Correlates a newly detected SecurityFinding into an existing open Incident,
        or provisions a new Incident case.
        """
        tenant_id = finding.tenant_id
        evidence = finding.evidence or {}

        # 1. Extract correlation anchors
        trace_id = evidence.get("trace_id")
        client_ip = evidence.get("source_ip") or evidence.get("client_ip") or evidence.get("ip")
        user_id = evidence.get("user_id") or evidence.get("username")
        service_id = evidence.get("service_id") or evidence.get("target_service")

        # 2. Search for existing active incident within active correlation window (last 6 hours)
        now = datetime.datetime.now(datetime.timezone.utc)
        window_start = now - datetime.timedelta(hours=6)

        query = (
            self.db.query(IncidentModel)
            .filter(
                IncidentModel.tenant_id == tenant_id,
                IncidentModel.status.in_([IncidentStatus.OPEN.value, IncidentStatus.INVESTIGATING.value]),
                IncidentModel.created_at >= window_start,
            )
        )

        open_incidents = query.all()
        matched_incident: Optional[IncidentModel] = None

        # Matching priority:
        # A. Direct trace_id match
        if trace_id:
            for inc in open_incidents:
                if trace_id in (inc.trace_ids or []):
                    matched_incident = inc
                    break

        # B. Matching primary entity (e.g. same client_ip)
        if not matched_incident and client_ip:
            for inc in open_incidents:
                if inc.primary_entity_id == client_ip:
                    matched_incident = inc
                    break

        # 3. Associate finding to matched incident or create new incident
        if matched_incident:
            incident = self._merge_finding_into_incident(matched_incident, finding, trace_id, client_ip, service_id)
        else:
            incident = self._create_new_incident(finding, trace_id, client_ip, user_id, service_id)

        return incident

    def aggregate_unassigned_findings(self, tenant_id: str) -> List[IncidentModel]:
        """
        Scans for SecurityFinding records not yet associated with any incident
        and correlates them into incident cases.
        """
        # Subquery finding IDs already associated
        assigned_stmt = select(IncidentFindingModel.finding_id).filter(
            IncidentFindingModel.tenant_id == tenant_id
        )

        unassigned_findings = (
            self.db.query(SecurityFinding)
            .filter(
                SecurityFinding.tenant_id == tenant_id,
                ~SecurityFinding.finding_id.in_(assigned_stmt),
            )
            .order_by(SecurityFinding.created_at.asc())
            .all()
        )

        correlated_incidents: List[IncidentModel] = []
        for finding in unassigned_findings:
            inc = self.correlate_finding(finding)
            if inc not in correlated_incidents:
                correlated_incidents.append(inc)

        return correlated_incidents

    def _merge_finding_into_incident(
        self,
        incident: IncidentModel,
        finding: SecurityFinding,
        trace_id: Optional[str],
        client_ip: Optional[str],
        service_id: Optional[str],
    ) -> IncidentModel:
        now = datetime.datetime.now(datetime.timezone.utc)

        # Link junction table if not already linked
        existing_link = (
            self.db.query(IncidentFindingModel)
            .filter(
                IncidentFindingModel.incident_id == incident.incident_id,
                IncidentFindingModel.finding_id == finding.finding_id,
            )
            .first()
        )
        if not existing_link:
            self.db.add(
                IncidentFindingModel(
                    incident_id=incident.incident_id,
                    finding_id=finding.finding_id,
                    tenant_id=incident.tenant_id,
                    added_at=now,
                )
            )
            incident.finding_count += 1

        # Update trace IDs
        traces: Set[str] = set(incident.trace_ids or [])
        if trace_id:
            traces.add(trace_id)
        incident.trace_ids = sorted(list(traces))

        # Update affected services
        services: Set[str] = set(incident.affected_services or [])
        if service_id:
            services.add(service_id)
        if hasattr(finding, "services") and finding.services:
            services.update(finding.services)
        incident.affected_services = sorted(list(services))

        # Update MITRE mappings
        mitre_info = DETECTOR_MITRE_MAP.get(finding.detector_id, {})
        tactics: Set[str] = set(incident.mitre_tactics or [])
        techniques: Set[str] = set(incident.mitre_techniques or [])
        tactics.update(mitre_info.get("tactics", []))
        techniques.update(mitre_info.get("techniques", []))
        incident.mitre_tactics = sorted(list(tactics))
        incident.mitre_techniques = sorted(list(techniques))

        # Recalculate composite severity
        f_weight = SEVERITY_WEIGHTS.get(finding.severity.lower(), 2)
        curr_weight = SEVERITY_WEIGHTS.get(incident.severity.lower(), 2)
        if f_weight > curr_weight:
            incident.severity = finding.severity.lower()
            logger.info(
                "IncidentCorrelator: Escalated incident '%s' severity to '%s'",
                incident.incident_id,
                incident.severity,
            )

        incident.updated_at = now
        self.db.commit()
        self.db.refresh(incident)

        # Publish SSE notification
        ops_bus.publish(
            component="incidents",
            event_type="incident.updated",
            level="warning" if incident.severity in ("critical", "high") else "info",
            message=f"Incident '{incident.incident_id}' updated: correlated finding '{finding.title}'",
            tenant_id=incident.tenant_id,
            finding_id=finding.finding_id,
            metadata={
                "incident_id": incident.incident_id,
                "severity": incident.severity,
                "finding_count": incident.finding_count,
                "affected_services": incident.affected_services,
            },
        )

        return incident

    def _create_new_incident(
        self,
        finding: SecurityFinding,
        trace_id: Optional[str],
        client_ip: Optional[str],
        user_id: Optional[str],
        service_id: Optional[str],
    ) -> IncidentModel:
        now = datetime.datetime.now(datetime.timezone.utc)
        date_str = now.strftime("%Y%m%d")
        inc_id = f"INC-{date_str}-{uuid.uuid4().hex[:6].upper()}"

        # Determine primary entity
        primary_type = None
        primary_id = None
        if client_ip:
            primary_type = "ip"
            primary_id = client_ip
        elif user_id:
            primary_type = "user"
            primary_id = user_id
        elif service_id:
            primary_type = "service"
            primary_id = service_id

        services: Set[str] = set()
        if service_id:
            services.add(service_id)
        if hasattr(finding, "services") and finding.services:
            services.update(finding.services)

        traces: Set[str] = set()
        if trace_id:
            traces.add(trace_id)

        mitre_info = DETECTOR_MITRE_MAP.get(finding.detector_id, {})
        tactics = mitre_info.get("tactics", [])
        techniques = mitre_info.get("techniques", [])

        incident = IncidentModel(
            incident_id=inc_id,
            tenant_id=finding.tenant_id,
            title=finding.title,
            summary=f"Incident automatically initialized from finding '{finding.title}' ({finding.detector_id}).",
            severity=finding.severity.lower(),
            status=IncidentStatus.OPEN.value,
            lead_detector_id=finding.detector_id,
            primary_entity_type=primary_type,
            primary_entity_id=primary_id,
            trace_ids=sorted(list(traces)),
            affected_services=sorted(list(services)),
            mitre_tactics=tactics,
            mitre_techniques=techniques,
            finding_count=1,
            created_at=now,
            updated_at=now,
        )
        self.db.add(incident)
        self.db.commit()

        # Link junction table
        self.db.add(
            IncidentFindingModel(
                incident_id=inc_id,
                finding_id=finding.finding_id,
                tenant_id=finding.tenant_id,
                added_at=now,
            )
        )
        self.db.commit()
        self.db.refresh(incident)

        logger.info(
            "IncidentCorrelator: Provisioned new incident '%s' for tenant '%s' (severity: %s)",
            inc_id,
            finding.tenant_id,
            incident.severity,
        )

        ops_bus.publish(
            component="incidents",
            event_type="incident.created",
            level="error" if incident.severity == "critical" else "warning",
            message=f"New incident initialized: '{incident.title}' [{inc_id}]",
            tenant_id=incident.tenant_id,
            finding_id=finding.finding_id,
            metadata={
                "incident_id": inc_id,
                "severity": incident.severity,
                "primary_entity": f"{primary_type}:{primary_id}" if primary_type else None,
                "services": incident.affected_services,
            },
        )

        return incident

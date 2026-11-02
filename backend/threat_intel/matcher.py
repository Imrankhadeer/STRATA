"""
Threat Intelligence Matcher & MITRE ATT&CK Engine for Ternline Phase 2.

Cross-references Indicators of Compromise (IOCs) against stored telemetry events,
computes affected service footprints, and calculates real-time MITRE ATT&CK matrix coverage.
"""

import datetime
import logging
from typing import Any, Dict, List, Set

from sqlalchemy import cast, func, or_, String
from sqlalchemy.orm import Session

from backend.models import (
    DeclarativeRuleModel,
    EventModel,
    SecurityFinding,
    ThreatIntelIocModel,
)
from backend.schemas.threat_intel import (
    MitreCoverageResponse,
    MitreTechniqueSummary,
    ThreatIntelIocResponse,
    ThreatIntelMatchResult,
)

logger = logging.getLogger("cyber_engine.threat_intel.matcher")

BASELINE_MITRE_MATRIX: List[Dict[str, Any]] = [
    {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts / Credential Abuse",
        "tactic": "Initial Access / Persistence",
        "detectors": ["detector.auth.brute_force", "rule.auth.credential_abuse"],
        "mitigation_strategy": "Immediate API key revocation and session containment.",
    },
    {
        "technique_id": "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "detectors": ["detector.exfiltration.cross_service"],
        "mitigation_strategy": "Multi-stage cross-service network egress blocking.",
    },
    {
        "technique_id": "T1005",
        "technique_name": "Data from Local System / DB Harvest",
        "tactic": "Collection",
        "detectors": ["investigator.deep_search"],
        "mitigation_strategy": "Database connection pool throttling and query plan auditing.",
    },
    {
        "technique_id": "T1110",
        "technique_name": "Brute Force & Password Spraying",
        "tactic": "Credential Access",
        "detectors": ["detector.auth.brute_force"],
        "mitigation_strategy": "Temporary IP block and perimeter token-bucket rate limiting.",
    },
    {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application / SQLi",
        "tactic": "Initial Access",
        "detectors": ["detector.sql.injection"],
        "mitigation_strategy": "Perimeter WAF pattern filtering and database statement containment.",
    },
]


class ThreatIntelMatcher:
    """
    Evaluates telemetry against active threat intelligence indicators and maps MITRE matrix coverage.
    """

    def __init__(self, db: Session):
        self.db = db

    def match_telemetry(
        self,
        tenant_id: str,
        query: str,
        time_window_hours: int = 24,
        limit: int = 50,
    ) -> ThreatIntelMatchResult:
        q_clean = query.strip()
        now = datetime.datetime.now(datetime.timezone.utc)
        start_time = now - datetime.timedelta(hours=time_window_hours)

        # 1. Match against registered IOCs
        matched_ioc_models = (
            self.db.query(ThreatIntelIocModel)
            .filter(
                ThreatIntelIocModel.tenant_id == tenant_id,
                ThreatIntelIocModel.is_active == True,
                or_(
                    ThreatIntelIocModel.value.ilike(f"%{q_clean}%"),
                    ThreatIntelIocModel.threat_actor.ilike(f"%{q_clean}%"),
                    ThreatIntelIocModel.description.ilike(f"%{q_clean}%"),
                ),
            )
            .all()
        )

        matched_iocs = [ThreatIntelIocResponse.model_validate(m) for m in matched_ioc_models]

        mitre_techs: Set[str] = set()
        for ioc in matched_iocs:
            if ioc.mitre_techniques:
                mitre_techs.update(ioc.mitre_techniques)

        # 2. Match against telemetry events in PostgreSQL
        # Searches event_type, service_id, source/target resource, or attributes JSON
        event_query = (
            self.db.query(EventModel)
            .filter(
                EventModel.tenant_id == tenant_id,
                EventModel.timestamp >= start_time,
                or_(
                    EventModel.event_type.ilike(f"%{q_clean}%"),
                    EventModel.service_id.ilike(f"%{q_clean}%"),
                    EventModel.source_resource.ilike(f"%{q_clean}%"),
                    EventModel.target_resource.ilike(f"%{q_clean}%"),
                    cast(EventModel.attributes, String).ilike(f"%{q_clean}%"),
                ),
            )
            .order_by(EventModel.timestamp.desc())
        )

        matched_events_count = event_query.count()
        events = event_query.limit(limit).all()

        services: Set[str] = set()
        formatted_events: List[Dict[str, Any]] = []

        for ev in events:
            if ev.service_id:
                services.add(ev.service_id)
            formatted_events.append({
                "event_id": ev.event_id,
                "trace_id": ev.trace_id,
                "service_id": ev.service_id,
                "event_type": ev.event_type,
                "severity": ev.severity,
                "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
                "attributes": ev.attributes or {},
            })

        logger.info(
            "ThreatIntelMatcher: Query '%s' matched %d IOC(s) and %d event(s) across %d service(s)",
            q_clean,
            len(matched_iocs),
            matched_events_count,
            len(services),
        )

        return ThreatIntelMatchResult(
            query=q_clean,
            matched_iocs=matched_iocs,
            matched_events_count=matched_events_count,
            matched_events=formatted_events,
            affected_services=sorted(list(services)),
            mitre_techniques=sorted(list(mitre_techs)),
        )

    def get_mitre_coverage(self, tenant_id: str) -> MitreCoverageResponse:
        now = datetime.datetime.now(datetime.timezone.utc)

        # Fetch active findings grouped by detector_id
        finding_counts_rows = (
            self.db.query(SecurityFinding.detector_id, func.count(SecurityFinding.finding_id))
            .filter(
                SecurityFinding.tenant_id == tenant_id,
                SecurityFinding.status == "open",
            )
            .group_by(SecurityFinding.detector_id)
            .all()
        )
        detector_finding_map = {row[0]: row[1] for row in finding_counts_rows}

        # Fetch IOCs for tenant to count per technique
        iocs = (
            self.db.query(ThreatIntelIocModel)
            .filter(
                ThreatIntelIocModel.tenant_id == tenant_id,
                ThreatIntelIocModel.is_active == True,
            )
            .all()
        )
        technique_ioc_map: Dict[str, int] = {}
        for ioc in iocs:
            for tech in (ioc.mitre_techniques or []):
                technique_ioc_map[tech] = technique_ioc_map.get(tech, 0) + 1

        techniques_summaries: List[MitreTechniqueSummary] = []

        for item in BASELINE_MITRE_MATRIX:
            tech_id = item["technique_id"]
            # Sum findings for all associated detectors
            active_f_count = sum(detector_finding_map.get(d, 0) for d in item["detectors"])
            ioc_cnt = technique_ioc_map.get(tech_id, 0)

            techniques_summaries.append(
                MitreTechniqueSummary(
                    technique_id=tech_id,
                    technique_name=item["technique_name"],
                    tactic=item["tactic"],
                    detectors=item["detectors"],
                    ioc_count=ioc_cnt,
                    active_findings_count=active_f_count,
                    mitigation_strategy=item["mitigation_strategy"],
                )
            )

        return MitreCoverageResponse(
            total_techniques_covered=len(techniques_summaries),
            techniques=techniques_summaries,
            last_evaluated_at=now,
        )


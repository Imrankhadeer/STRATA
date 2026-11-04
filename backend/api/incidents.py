"""
REST API for Phase 2: Incident Management & Aggregation.

Provides endpoints for:
1. Listing and querying correlated incidents.
2. Viewing detailed incident records with linked findings and multi-service event timelines.
3. Updating incident lifecycle status (open -> investigating -> contained -> resolved).
4. Coordinated multi-entity containment delegating to Phase 1 ResponseExecutor.
5. Automated background aggregation of unassigned findings.
"""

import datetime
import logging
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.core.auth import AuthContext, Permission, require_permission
from backend.db.session import get_db
from backend.models import (
    EventModel,
    IncidentFindingModel,
    IncidentModel,
    SecurityFinding,
)
from backend.ops.bus import ops_bus
from backend.schemas.incidents import (
    IncidentContainmentRequest,
    IncidentContainmentResponse,
    IncidentCreateRequest,
    IncidentDetailResponse,
    IncidentFindingSummary,
    IncidentResponse,
    IncidentSeverity,
    IncidentStatus,
    IncidentUpdateRequest,
)
from backend.incidents.correlator import IncidentCorrelator

logger = logging.getLogger("cyber_engine.api.incidents")

router = APIRouter(prefix="/api/v1/incidents", tags=["Incidents"])


@router.get("", response_model=List[IncidentResponse])
async def list_incidents(
    status_filter: Optional[IncidentStatus] = Query(None, alias="status"),
    severity: Optional[IncidentSeverity] = None,
    service: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    auth: AuthContext = Depends(require_permission(Permission.INCIDENTS_READ)),
    db: Session = Depends(get_db),
):
    """
    Lists aggregated incident cases for the authenticated tenant.
    Requires permission: incidents:read
    """
    query = db.query(IncidentModel).filter(IncidentModel.tenant_id == auth.tenant_id)

    if status_filter:
        query = query.filter(IncidentModel.status == status_filter.value)
    if severity:
        query = query.filter(IncidentModel.severity == severity.value)

    incidents = (
        query.order_by(IncidentModel.updated_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    if service:
        incidents = [inc for inc in incidents if service in (inc.affected_services or [])]

    return incidents


@router.get("/{incident_id}", response_model=IncidentDetailResponse)
async def get_incident_detail(
    incident_id: str,
    auth: AuthContext = Depends(require_permission(Permission.INCIDENTS_READ)),
    db: Session = Depends(get_db),
):
    """
    Retrieves full incident details, constituent SecurityFindings, and the chronological microservice event timeline.
    Requires permission: incidents:read
    """
    incident = (
        db.query(IncidentModel)
        .filter(
            IncidentModel.incident_id == incident_id,
            IncidentModel.tenant_id == auth.tenant_id,
        )
        .first()
    )
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    # 1. Fetch linked findings
    finding_rows = (
        db.query(SecurityFinding)
        .join(
            IncidentFindingModel,
            IncidentFindingModel.finding_id == SecurityFinding.finding_id,
        )
        .filter(
            IncidentFindingModel.incident_id == incident_id,
            IncidentFindingModel.tenant_id == auth.tenant_id,
        )
        .order_by(SecurityFinding.created_at.asc())
        .all()
    )

    findings_summary: List[IncidentFindingSummary] = [
        IncidentFindingSummary(
            finding_id=f.finding_id,
            detector_id=f.detector_id,
            title=f.title,
            severity=f.severity,
            confidence=f.confidence,
            created_at=f.created_at,
            evidence=f.evidence or {},
        )
        for f in finding_rows
    ]

    # 2. Fetch event timeline across all incident traces
    timeline: List[Dict[str, Any]] = []
    if incident.trace_ids:
        events = (
            db.query(EventModel)
            .filter(
                EventModel.tenant_id == auth.tenant_id,
                EventModel.trace_id.in_(incident.trace_ids),
            )
            .order_by(EventModel.timestamp.asc())
            .limit(100)
            .all()
        )
        for ev in events:
            timeline.append({
                "event_id": ev.event_id,
                "trace_id": ev.trace_id,
                "service_id": ev.service_id,
                "event_type": ev.event_type,
                "severity": ev.severity,
                "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
                "attributes": ev.attributes or {},
            })

    return IncidentDetailResponse(
        incident_id=incident.incident_id,
        tenant_id=incident.tenant_id,
        title=incident.title,
        summary=incident.summary,
        severity=IncidentSeverity(incident.severity),
        status=IncidentStatus(incident.status),
        lead_detector_id=incident.lead_detector_id,
        primary_entity_type=incident.primary_entity_type,
        primary_entity_id=incident.primary_entity_id,
        trace_ids=incident.trace_ids or [],
        affected_services=incident.affected_services or [],
        mitre_tactics=incident.mitre_tactics or [],
        mitre_techniques=incident.mitre_techniques or [],
        finding_count=incident.finding_count,
        assigned_to=incident.assigned_to,
        resolved_at=incident.resolved_at,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        findings=findings_summary,
        events_timeline=timeline,
    )


@router.post("", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
async def create_incident(
    payload: IncidentCreateRequest,
    auth: AuthContext = Depends(require_permission(Permission.INCIDENTS_WRITE)),
    db: Session = Depends(get_db),
):
    """
    Manually creates an incident or manually groups findings into a new incident case.
    Requires permission: incidents:write
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    inc_id = f"INC-{now.strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

    services = set()
    traces = set()

    if payload.finding_ids:
        findings = (
            db.query(SecurityFinding)
            .filter(
                SecurityFinding.finding_id.in_(payload.finding_ids),
                SecurityFinding.tenant_id == auth.tenant_id,
            )
            .all()
        )
        found_ids = {finding.finding_id for finding in findings}
        missing_ids = sorted(set(payload.finding_ids) - found_ids)
        if missing_ids:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="One or more finding IDs do not exist in this tenant.",
            )
        for f in findings:
            ev = f.evidence or {}
            if ev.get("service_id"):
                services.add(ev.get("service_id"))
            if ev.get("trace_id"):
                traces.add(ev.get("trace_id"))

    incident = IncidentModel(
        incident_id=inc_id,
        tenant_id=auth.tenant_id,
        title=payload.title,
        summary=payload.summary or f"Manual incident created by {auth.operator_principal or auth.app_id}",
        severity=payload.severity.value,
        status=IncidentStatus.OPEN.value,
        lead_detector_id="manual.soc.triage",
        primary_entity_type=payload.primary_entity_type,
        primary_entity_id=payload.primary_entity_id,
        trace_ids=sorted(list(traces)),
        affected_services=sorted(list(services)),
        mitre_tactics=[],
        mitre_techniques=[],
        finding_count=len(payload.finding_ids),
        assigned_to=payload.assigned_to,
        created_at=now,
        updated_at=now,
    )
    db.add(incident)
    db.commit()

    # Link findings
    for fid in payload.finding_ids:
        db.add(
            IncidentFindingModel(
                incident_id=inc_id,
                finding_id=fid,
                tenant_id=auth.tenant_id,
                added_at=now,
            )
        )
    db.commit()
    db.refresh(incident)

    ops_bus.publish(
        component="incidents",
        event_type="incident.created",
        level="info",
        message=f"Manual incident case initialized: '{incident.title}' [{inc_id}]",
        tenant_id=auth.tenant_id,
        metadata={"incident_id": inc_id, "severity": incident.severity},
    )

    return incident


@router.patch("/{incident_id}", response_model=IncidentResponse)
async def update_incident(
    incident_id: str,
    payload: IncidentUpdateRequest,
    auth: AuthContext = Depends(require_permission(Permission.INCIDENTS_WRITE)),
    db: Session = Depends(get_db),
):
    """
    Updates incident status, severity, assignment, or notes.
    Requires permission: incidents:write
    """
    incident = (
        db.query(IncidentModel)
        .filter(
            IncidentModel.incident_id == incident_id,
            IncidentModel.tenant_id == auth.tenant_id,
        )
        .first()
    )
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    now = datetime.datetime.now(datetime.timezone.utc)
    if payload.title is not None:
        incident.title = payload.title
    if payload.summary is not None:
        incident.summary = payload.summary
    if payload.severity is not None:
        incident.severity = payload.severity.value
    if payload.assigned_to is not None:
        incident.assigned_to = payload.assigned_to
    if payload.status is not None:
        incident.status = payload.status.value
        if payload.status == IncidentStatus.RESOLVED:
            incident.resolved_at = now

    incident.updated_at = now
    db.commit()
    db.refresh(incident)

    ops_bus.publish(
        component="incidents",
        event_type="incident.updated",
        level="info",
        message=f"Incident '{incident_id}' updated (Status: {incident.status}, Severity: {incident.severity})",
        tenant_id=auth.tenant_id,
        metadata={"incident_id": incident_id, "status": incident.status},
    )

    return incident


@router.post("/{incident_id}/contain", response_model=IncidentContainmentResponse)
async def contain_incident(
    incident_id: str,
    payload: IncidentContainmentRequest,
    auth: AuthContext = Depends(require_permission(Permission.INCIDENTS_CONTAIN)),
    db: Session = Depends(get_db),
):
    """
    Orchestrates coordinated active defense containment across all attacker IPs and compromised credentials
    associated with this incident, leveraging Phase 1 ResponseExecutor.
    Requires permission: incidents:contain
    """
    incident = (
        db.query(IncidentModel)
        .filter(
            IncidentModel.incident_id == incident_id,
            IncidentModel.tenant_id == auth.tenant_id,
        )
        .first()
    )
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    # 1. Gather all findings for this incident
    finding_rows = (
        db.query(SecurityFinding)
        .join(
            IncidentFindingModel,
            IncidentFindingModel.finding_id == SecurityFinding.finding_id,
        )
        .filter(
            IncidentFindingModel.incident_id == incident_id,
            IncidentFindingModel.tenant_id == auth.tenant_id,
        )
        .all()
    )

    contained_ips: set = set()
    contained_keys: set = set()

    if incident.primary_entity_type == "ip" and incident.primary_entity_id:
        contained_ips.add(incident.primary_entity_id)

    for f in finding_rows:
        ev = f.evidence or {}
        ip = ev.get("source_ip") or ev.get("client_ip") or ev.get("ip")
        if ip:
            contained_ips.add(ip.strip())
        key = ev.get("key_id") or ev.get("api_key")
        if key:
            contained_keys.add(key.strip())

    now = datetime.datetime.now(datetime.timezone.utc)
    actions_triggered: List[Dict[str, Any]] = []

    # 2. Delegate to Phase 1 DefensePlanner & ResponseExecutor
    from backend.defense.planner import compute_action_fingerprint
    from backend.models import DefenseActionModel
    from backend.schemas.defense import (
        ActionScope,
        ActionStatus,
        ActionType,
        CredentialAuthority,
        ProtectionMode,
        TargetEntityType,
    )

    # Contain IPs
    if payload.contain_ips:
        for ip in contained_ips:
            try:
                fp = compute_action_fingerprint(
                    tenant_id=auth.tenant_id,
                    action_type=ActionType.TEMPORARY_IP_BLOCK.value,
                    target_entity_type=TargetEntityType.IP_ADDRESS.value,
                    target_entity_id=ip,
                    parameters={"block_duration_minutes": 60},
                )
                existing = (
                    db.query(DefenseActionModel)
                    .filter(
                        DefenseActionModel.tenant_id == auth.tenant_id,
                        DefenseActionModel.deduplication_fingerprint == fp,
                        DefenseActionModel.status.in_([
                            ActionStatus.PROPOSED.value,
                            ActionStatus.AWAITING_APPROVAL.value,
                            ActionStatus.APPROVED.value,
                            ActionStatus.EXECUTING.value,
                            ActionStatus.VERIFIED_ACTIVE.value,
                        ]),
                    )
                    .first()
                )
                if existing:
                    action_to_exec = existing
                else:
                    act_id = f"act-{uuid.uuid4().hex[:8]}"
                    action_to_exec = DefenseActionModel(
                        action_id=act_id,
                        tenant_id=auth.tenant_id,
                        finding_id=finding_rows[0].finding_id if finding_rows else None,
                        action_type=ActionType.TEMPORARY_IP_BLOCK.value,
                        scope=ActionScope.TERNLINE_INGEST.value,
                        target_entity_type=TargetEntityType.IP_ADDRESS.value,
                        target_entity_id=ip,
                        status=ActionStatus.PROPOSED.value,
                        protection_mode=ProtectionMode.ASSISTED.value,
                        deduplication_fingerprint=fp,
                        parameters={"block_duration_minutes": 60},
                        ttl_seconds=3600,
                        requested_by=auth.operator_principal or f"key:{auth.app_id}",
                        created_at=now,
                    )
                    db.add(action_to_exec)
                    db.commit()

                actions_triggered.append({
                    "action_id": action_to_exec.action_id,
                    "type": "temporary_ip_block",
                    "target": ip,
                    "status": action_to_exec.status,
                })
            except Exception as ex:
                logger.warning("Containment execution error for IP %s: %s", ip, ex)

    # Contain API keys
    if payload.contain_credentials:
        for key in contained_keys:
            try:
                fp = compute_action_fingerprint(
                    tenant_id=auth.tenant_id,
                    action_type=ActionType.API_KEY_REVOCATION.value,
                    target_entity_type=TargetEntityType.API_KEY.value,
                    target_entity_id=key,
                    parameters={},
                )
                existing = (
                    db.query(DefenseActionModel)
                    .filter(
                        DefenseActionModel.tenant_id == auth.tenant_id,
                        DefenseActionModel.deduplication_fingerprint == fp,
                        DefenseActionModel.status.in_([
                            ActionStatus.PROPOSED.value,
                            ActionStatus.AWAITING_APPROVAL.value,
                            ActionStatus.APPROVED.value,
                            ActionStatus.EXECUTING.value,
                            ActionStatus.VERIFIED_ACTIVE.value,
                        ]),
                    )
                    .first()
                )
                if existing:
                    action_to_exec = existing
                else:
                    act_id = f"act-{uuid.uuid4().hex[:8]}"
                    action_to_exec = DefenseActionModel(
                        action_id=act_id,
                        tenant_id=auth.tenant_id,
                        finding_id=finding_rows[0].finding_id if finding_rows else None,
                        action_type=ActionType.API_KEY_REVOCATION.value,
                        scope=ActionScope.TERNLINE_INGEST.value,
                        credential_authority=CredentialAuthority.TERNLINE_MANAGED.value,
                        target_entity_type=TargetEntityType.API_KEY.value,
                        target_entity_id=key,
                        status=ActionStatus.PROPOSED.value,
                        protection_mode=ProtectionMode.ASSISTED.value,
                        deduplication_fingerprint=fp,
                        parameters={},
                        ttl_seconds=3600,
                        requested_by=auth.operator_principal or f"key:{auth.app_id}",
                        created_at=now,
                    )
                    db.add(action_to_exec)
                    db.commit()

                actions_triggered.append({
                    "action_id": action_to_exec.action_id,
                    "type": "api_key_revocation",
                    "target": key,
                    "status": action_to_exec.status,
                })
            except Exception as ex:
                logger.warning("Containment execution error for key %s: %s", key, ex)

    # Proposed actions require the separate dual-custody approval workflow.
    incident.status = IncidentStatus.INVESTIGATING.value
    incident.updated_at = now
    db.commit()

    ops_bus.publish(
        component="incidents",
        event_type="incident.containment_requested",
        level="warning",
        message=f"Incident '{incident_id}' has {len(actions_triggered)} containment action(s) awaiting approval",
        tenant_id=auth.tenant_id,
        metadata={
            "incident_id": incident_id,
            "actions_count": len(actions_triggered),
            "rationale": payload.rationale,
        },
    )

    return IncidentContainmentResponse(
        incident_id=incident_id,
        status=incident.status,
        contained_entities_count=len(actions_triggered),
        actions_triggered=actions_triggered,
        timestamp=now,
    )


@router.post("/aggregate", response_model=List[IncidentResponse])
async def aggregate_unassigned_findings(
    auth: AuthContext = Depends(require_permission(Permission.INCIDENTS_WRITE)),
    db: Session = Depends(get_db),
):
    """
    Scans for unassigned SecurityFindings and groups them into correlated Incident cases.
    Requires permission: incidents:write
    """
    correlator = IncidentCorrelator(db)
    aggregated = correlator.aggregate_unassigned_findings(tenant_id=auth.tenant_id)
    return aggregated

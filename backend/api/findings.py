"""
FastAPI router for querying and managing Security Findings.

Provides:
- GET /api/v1/findings — List findings for authenticated tenant with filtering & pagination
- GET /api/v1/findings/{finding_id} — Retrieve detailed finding and investigation links
- POST /api/v1/findings/{finding_id}/feedback — Human analyst feedback (resolve, mark false positive)
"""

from typing import List, Optional, Dict, Any, Literal
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
import datetime

from backend.db.session import get_db
from backend.core.auth import get_current_auth, AuthContext
from backend.models import SecurityFinding, InvestigationReport

router = APIRouter(prefix="/api/v1/findings", tags=["Security Findings"])


class SecurityFindingSchema(BaseModel):
    finding_id: str
    tenant_id: str
    detector_id: str
    detector_version: str
    title: str
    severity: str
    confidence: str
    description: str
    event_id: Optional[str] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime.datetime
    status: str
    investigation_ids: List[str] = Field(default_factory=list)


class FindingFeedbackRequest(BaseModel):
    status: Literal["open", "resolved", "false_positive"]
    reason: str = Field(min_length=3, max_length=1000)


@router.get("", response_model=List[SecurityFindingSchema])
async def list_findings(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (open, resolved, false_positive)"),
    severity_filter: Optional[str] = Query(None, alias="severity", description="Filter by severity (critical, high, medium, low)"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_current_auth),
):
    """
    Lists security findings for the authenticated tenant.
    Enforces strict tenant isolation and chronological descending order.
    """
    query = db.query(SecurityFinding).filter(SecurityFinding.tenant_id == auth.tenant_id)

    if status_filter:
        query = query.filter(SecurityFinding.status == status_filter.lower())
    if severity_filter:
        query = query.filter(SecurityFinding.severity == severity_filter.lower())

    findings = query.order_by(SecurityFinding.created_at.desc()).offset(offset).limit(limit).all()

    results = []
    for f in findings:
        inv_ids = [inv.investigation_id for inv in f.investigations] if f.investigations else []
        results.append(
            SecurityFindingSchema(
                finding_id=f.finding_id,
                tenant_id=f.tenant_id,
                detector_id=f.detector_id,
                detector_version=f.detector_version,
                title=f.title,
                severity=f.severity,
                confidence=f.confidence,
                description=f.description,
                event_id=f.event_id,
                evidence=f.evidence or {},
                created_at=f.created_at,
                status=f.status,
                investigation_ids=inv_ids,
            )
        )
    return results


@router.get("/{finding_id}", response_model=SecurityFindingSchema)
async def get_finding(
    finding_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_current_auth),
):
    """
    Retrieves full details and evidence for a specific finding.
    """
    # Scope lookup by tenant_id in the query so cross-tenant UUIDs return 404
    # rather than 403 — preventing existence oracle / enumeration attacks.
    finding = db.query(SecurityFinding).filter(
        SecurityFinding.finding_id == finding_id,
        SecurityFinding.tenant_id == auth.tenant_id,
    ).first()

    if not finding:
        # Check if finding_id corresponds to a Deep Track query report
        inv = db.query(InvestigationReport).filter(
            (InvestigationReport.finding_id == finding_id) | (InvestigationReport.investigation_id == finding_id),
            InvestigationReport.tenant_id == auth.tenant_id
        ).first()
        if inv:
            if payload.status == "false_positive":
                inv.verdict = "likely_benign"
            elif payload.status == "resolved":
                inv.verdict = "resolved"
            else:
                inv.verdict = "confirmed_threat"
            db.commit()
            return SecurityFindingSchema(
                finding_id=finding_id,
                tenant_id=auth.tenant_id,
                detector_id="deep_investigator.query",
                detector_version="1.0",
                title=f"Query Investigation: {inv.summary[:40]}",
                severity="medium",
                confidence="high",
                description=inv.summary,
                evidence={"feedback_history": [{"status": payload.status, "reason": payload.reason}]},
                created_at=inv.created_at,
                status=payload.status,
                investigation_ids=[inv.investigation_id],
            )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security finding '{finding_id}' not found.",
        )

    inv_ids = [inv.investigation_id for inv in finding.investigations] if finding.investigations else []

    return SecurityFindingSchema(
        finding_id=finding.finding_id,
        tenant_id=finding.tenant_id,
        detector_id=finding.detector_id,
        detector_version=finding.detector_version,
        title=finding.title,
        severity=finding.severity,
        confidence=finding.confidence,
        description=finding.description,
        event_id=finding.event_id,
        evidence=finding.evidence or {},
        created_at=finding.created_at,
        status=finding.status,
        investigation_ids=inv_ids,
    )


@router.post("/{finding_id}/feedback", response_model=SecurityFindingSchema)
async def submit_finding_feedback(
    finding_id: str,
    payload: FindingFeedbackRequest,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_current_auth),
):
    """
    Records human-in-the-loop analyst feedback on a finding (resolved, false positive, reopened).
    Preserves audit history directly within evidence metadata.
    """
    # Same tenant-scoped query: always 404 for findings the caller cannot own.
    finding = db.query(SecurityFinding).filter(
        SecurityFinding.finding_id == finding_id,
        SecurityFinding.tenant_id == auth.tenant_id,
    ).first()

    if not finding:
        # Check if finding_id corresponds to a Deep Track query report
        inv = db.query(InvestigationReport).filter(
            (InvestigationReport.finding_id == finding_id) | (InvestigationReport.investigation_id == finding_id),
            InvestigationReport.tenant_id == auth.tenant_id
        ).first()
        if inv:
            if payload.status == "false_positive":
                inv.verdict = "likely_benign"
            elif payload.status == "resolved":
                inv.verdict = "resolved"
            else:
                inv.verdict = "confirmed_threat"
            db.commit()
            return SecurityFindingSchema(
                finding_id=finding_id,
                tenant_id=auth.tenant_id,
                detector_id="deep_investigator.query",
                detector_version="1.0",
                title=f"Query Investigation: {inv.summary[:40]}",
                severity="medium",
                confidence="high",
                description=inv.summary,
                evidence={"feedback_history": [{"status": payload.status, "reason": payload.reason}]},
                created_at=inv.created_at,
                status=payload.status,
                investigation_ids=[inv.investigation_id],
            )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security finding '{finding_id}' not found.",
        )

    finding.status = payload.status

    # Record feedback audit trail
    evidence = dict(finding.evidence or {})
    feedback_history = list(evidence.get("feedback_history", []))
    feedback_history.append({
        "status": payload.status,
        "reason": payload.reason,
        "recorded_by": auth.tenant_id,
        "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    })
    evidence["feedback_history"] = feedback_history
    finding.evidence = evidence

    db.commit()
    db.refresh(finding)

    inv_ids = [inv.investigation_id for inv in finding.investigations] if finding.investigations else []

    return SecurityFindingSchema(
        finding_id=finding.finding_id,
        tenant_id=finding.tenant_id,
        detector_id=finding.detector_id,
        detector_version=finding.detector_version,
        title=finding.title,
        severity=finding.severity,
        confidence=finding.confidence,
        description=finding.description,
        event_id=finding.event_id,
        evidence=finding.evidence or {},
        created_at=finding.created_at,
        status=finding.status,
        investigation_ids=inv_ids,
    )


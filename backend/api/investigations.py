"""
FastAPI endpoints for CYBER ENGINE Deep-Investigation Path.
Allows triggering selective investigations and retrieving investigation reports.
"""

import asyncio
from typing import List, Optional, Set
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.core.auth import get_current_auth, AuthContext
from backend.models import Tenant, SecurityFinding, InvestigationReport
from backend.investigation.collector import EvidenceCollector
from backend.investigation.factory import get_investigator
from backend.investigation.quality import InvestigationQualityAuditor
from backend.schemas.investigation import (
    InvestigationFinding,
    Hypothesis,
    CandidateDetectorRule,
)
from backend.ops.bus import ops_bus

router = APIRouter(prefix="/api/v1/investigations", tags=["Investigations"])

# In-flight lock tracking to prevent concurrent duplicate model calls
_in_flight_investigations: Set[str] = set()
_in_flight_lock = asyncio.Lock()


@router.post("/{finding_id}", response_model=InvestigationFinding, status_code=status.HTTP_200_OK)
async def investigate_finding(
    finding_id: str,
    force_refresh: bool = Query(
        False, description="Explicitly request a fresh investigation, bypassing cached reports"
    ),
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_current_auth),
):
    """
    Selectively activates the Deep-Investigation Path for a security finding.
    Enforces cost controls & idempotency: Reuses completed reports unless force_refresh=True.
    Locks in-flight requests to prevent concurrent duplicate model calls.
    Deterministically audits evidence grounding via InvestigationQualityAuditor before persistence.
    """
    finding = db.query(SecurityFinding).filter(
        SecurityFinding.finding_id == finding_id
    ).first()

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security finding '{finding_id}' not found.",
        )

    # Tenant boundary enforcement
    if finding.tenant_id != auth.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Cannot investigate finding across tenant boundaries.",
        )

    # Idempotency & Cost Control: Reuse completed report if available
    if not force_refresh:
        existing_report = (
            db.query(InvestigationReport)
            .filter(
                InvestigationReport.finding_id == finding_id,
                InvestigationReport.tenant_id == auth.tenant_id,
            )
            .order_by(InvestigationReport.created_at.desc())
            .first()
        )
        if existing_report:
            ops_bus.publish(
                component="deep-track",
                event_type="investigation.cached_reuse",
                level="info",
                message=f"Reused cached investigation report '{existing_report.investigation_id}' (0 LLM cost)",
                tenant_id=auth.tenant_id,
                finding_id=finding_id,
                investigation_id=existing_report.investigation_id,
            )
            return InvestigationFinding(
                investigation_id=existing_report.investigation_id,
                finding_id=existing_report.finding_id,
                tenant_id=existing_report.tenant_id,
                verdict=existing_report.verdict,
                summary=existing_report.summary,
                hypotheses=[Hypothesis(**h) for h in (existing_report.hypotheses or [])],
                candidate_rules=[CandidateDetectorRule(**r) for r in (existing_report.candidate_rules or [])],
                recommended_mitigations=existing_report.recommended_mitigations or [],
                investigator_provider=existing_report.investigator_provider,
                investigator_model=existing_report.investigator_model,
                completed_at=existing_report.created_at,
            )

    # Concurrency guard: Prevent concurrent duplicate requests from firing redundant model calls
    flight_key = f"{auth.tenant_id}:{finding_id}"
    async with _in_flight_lock:
        if flight_key in _in_flight_investigations:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An investigation is already in progress for this finding. Please wait for completion.",
            )
        _in_flight_investigations.add(flight_key)

    try:
        collector = EvidenceCollector(db)
        context = collector.assemble_context(finding_id)
        if not context:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Could not assemble investigation context for finding '{finding_id}'.",
            )

        ops_bus.publish(
            component="deep-track",
            event_type="investigation.started",
            level="info",
            message=f"Initiated Deep Track investigation for finding {finding_id} ({len(context.timeline_events)} timeline events)",
            tenant_id=auth.tenant_id,
            finding_id=finding_id,
            trace_id=context.trace_id,
            metadata={"services": context.services, "events_count": len(context.timeline_events)},
        )

        investigator = get_investigator()
        report = await investigator.investigate(context)

        # Wire InvestigationQualityAuditor before persistence
        auditor = InvestigationQualityAuditor()
        audit_report = auditor.audit(context, report)

        # Invariant: Invalid investigation citations CANNOT be persisted as trustworthy evidence
        if audit_report.hallucinated_event_ids or audit_report.citation_fidelity_errors:
            ops_bus.publish(
                component="deep-track",
                event_type="investigation.quality_audit_failed",
                level="error",
                message=f"Investigation quality audit rejected report: {len(audit_report.hallucinated_event_ids)} ungrounded citations",
                tenant_id=auth.tenant_id,
                finding_id=finding_id,
                investigation_id=report.investigation_id,
                metadata={"hallucinated_ids": audit_report.hallucinated_event_ids},
            )
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error": "Investigation report failed evidence grounding audit",
                    "hallucinated_event_ids": audit_report.hallucinated_event_ids,
                    "fidelity_errors": audit_report.citation_fidelity_errors,
                },
            )

        ops_bus.publish(
            component="deep-track",
            event_type="investigation.quality_audit_passed",
            level="success",
            message=f"Investigation report passed citation grounding audit (all citations verified)",
            tenant_id=auth.tenant_id,
            finding_id=finding_id,
            investigation_id=report.investigation_id,
        )

        # Persist the validated investigation report in the database
        db_report = InvestigationReport(
            investigation_id=report.investigation_id,
            finding_id=report.finding_id,
            tenant_id=report.tenant_id,
            verdict=report.verdict,
            summary=report.summary,
            hypotheses=[h.model_dump() for h in report.hypotheses],
            candidate_rules=[r.model_dump() for r in report.candidate_rules],
            recommended_mitigations=report.recommended_mitigations,
            investigator_provider=report.investigator_provider,
            investigator_model=report.investigator_model,
        )
        db.add(db_report)
        db.commit()

        ops_bus.publish(
            component="deep-track",
            event_type="investigation.completed",
            level="success",
            message=f"Deep Track completed for finding {finding_id}: verdict='{report.verdict}' ({len(report.candidate_rules)} candidate rules proposed)",
            tenant_id=auth.tenant_id,
            finding_id=finding_id,
            investigation_id=report.investigation_id,
            metadata={
                "verdict": report.verdict,
                "provider": report.investigator_provider,
                "model": report.investigator_model,
                "hypotheses_count": len(report.hypotheses),
                "candidate_rules_count": len(report.candidate_rules),
            },
        )

        return report
    finally:
        async with _in_flight_lock:
            _in_flight_investigations.discard(flight_key)


@router.get("/{investigation_id}", response_model=InvestigationFinding)
async def get_investigation_report(
    investigation_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_current_auth),
):
    """
    Retrieves an existing investigation report by its ID.
    """
    db_report = db.query(InvestigationReport).filter(
        InvestigationReport.investigation_id == investigation_id
    ).first()

    if not db_report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation report '{investigation_id}' not found.",
        )

    if db_report.tenant_id != auth.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Access to another tenant's investigation report is denied.",
        )

    return InvestigationFinding(
        investigation_id=db_report.investigation_id,
        finding_id=db_report.finding_id,
        tenant_id=db_report.tenant_id,
        verdict=db_report.verdict,
        summary=db_report.summary,
        hypotheses=[Hypothesis(**h) for h in (db_report.hypotheses or [])],
        candidate_rules=[CandidateDetectorRule(**r) for r in (db_report.candidate_rules or [])],
        recommended_mitigations=db_report.recommended_mitigations or [],
        investigator_provider=db_report.investigator_provider,
        investigator_model=db_report.investigator_model,
        completed_at=db_report.created_at,
    )


@router.get("/finding/{finding_id}", response_model=List[InvestigationFinding])
async def list_investigations_for_finding(
    finding_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_current_auth),
):
    """
    Lists all investigation reports created for a given security finding.
    """
    finding = db.query(SecurityFinding).filter(
        SecurityFinding.finding_id == finding_id
    ).first()

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found.",
        )

    if finding.tenant_id != auth.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Access denied across tenant boundaries.",
        )

    reports = db.query(InvestigationReport).filter(
        InvestigationReport.finding_id == finding_id
    ).order_by(InvestigationReport.created_at.desc()).all()

    return [
        InvestigationFinding(
            investigation_id=r.investigation_id,
            finding_id=r.finding_id,
            tenant_id=r.tenant_id,
            verdict=r.verdict,
            summary=r.summary,
            hypotheses=[Hypothesis(**h) for h in (r.hypotheses or [])],
            candidate_rules=[CandidateDetectorRule(**cr) for cr in (r.candidate_rules or [])],
            recommended_mitigations=r.recommended_mitigations or [],
            investigator_provider=r.investigator_provider,
            investigator_model=r.investigator_model,
            completed_at=r.created_at,
        )
        for r in reports
    ]

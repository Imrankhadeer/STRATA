import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from backend.db.session import get_db
from backend.models import EventModel, SecurityFinding
from backend.schemas.events import CanonicalEvent, IngestBatchRequest, IngestResponse
from backend.core.auth import get_current_auth, AuthContext
from backend.detection.baseline import BaseDetector, BruteForceLoginDetector, Finding
from backend.detection.correlation import CrossServiceExfiltrationDetector

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["telemetry"])

# Initialize fast-path detector instances.
# All detectors are evaluated for every ingested event.
fast_detectors: List[BaseDetector] = [
    BruteForceLoginDetector(failure_threshold=3),
    CrossServiceExfiltrationDetector(time_window_seconds=300),
]


@router.post("/events", response_model=IngestResponse, status_code=status.HTTP_202_ACCEPTED)
async def ingest_event(
    event: CanonicalEvent,
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db)
):
    """
    Ingest a single canonical telemetry event.
    Enforces tenant isolation and application scoping.
    """
    # Enforce tenant isolation server-side
    event.tenant_id = auth.tenant_id

    # Verify that the event's app_id matches the authenticated API key scope
    if event.app_id != auth.app_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"API key is scoped to application '{auth.app_id}', not '{event.app_id}'"
        )

    # Check for existing event (idempotency / duplicate check)
    existing = db.query(EventModel.event_id).filter(EventModel.event_id == event.event_id).first()
    if existing:
        return IngestResponse(
            accepted=0,
            rejected=0,
            duplicates=1,
            event_ids=[event.event_id],
            errors=[]
        )

    db_event = EventModel(
        event_id=event.event_id,
        schema_version=event.schema_version,
        timestamp=event.timestamp.replace(tzinfo=None),  # store standard UTC
        tenant_id=auth.tenant_id,
        app_id=event.app_id,
        service_id=event.service_id,
        event_type=event.event_type,
        severity=event.severity.value,
        source_resource=event.source_resource,
        target_resource=event.target_resource,
        trace_id=event.trace_id,
        request_id=event.request_id,
        attributes=event.attributes,
        provenance=event.provenance,
    )

    try:
        db.add(db_event)
        db.commit()
    except IntegrityError:
        db.rollback()
        # Duplicate occurred concurrently
        return IngestResponse(
            accepted=0,
            rejected=0,
            duplicates=1,
            event_ids=[event.event_id],
            errors=[]
        )
    except Exception as e:
        db.rollback()
        logger.error("Failed to persist event safely", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal database persistence failure"
        )

    # Fast-path continuous evaluation — run all registered detectors.
    for detector in fast_detectors:
        finding = detector.evaluate(event)
        if finding:
            db_finding = SecurityFinding(
                finding_id=finding.finding_id,
                tenant_id=finding.tenant_id,
                detector_id=finding.detector_id,
                detector_version=finding.detector_version,
                title=finding.title,
                severity=finding.severity,
                confidence=finding.confidence,
                description=finding.description,
                event_id=finding.event_id,
                evidence=finding.evidence,
            )
            db.add(db_finding)
            db.commit()

    return IngestResponse(
        accepted=1,
        rejected=0,
        duplicates=0,
        event_ids=[event.event_id],
        errors=[]
    )


@router.post("/events/batch", response_model=IngestResponse, status_code=status.HTTP_202_ACCEPTED)
async def ingest_events_batch(
    payload: IngestBatchRequest,
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db)
):
    """
    Ingest a batch of canonical telemetry events.
    Atomic or best-effort safe persistence with duplicate detection.
    """
    accepted = 0
    duplicates = 0
    event_ids = []
    errors = []

    for event in payload.events:
        event.tenant_id = auth.tenant_id
        if event.app_id != auth.app_id:
            errors.append({
                "event_id": event.event_id,
                "error": f"Mismatched app_id scope: expected {auth.app_id}, got {event.app_id}"
            })
            continue

        existing = db.query(EventModel.event_id).filter(EventModel.event_id == event.event_id).first()
        if existing:
            duplicates += 1
            event_ids.append(event.event_id)
            continue

        db_event = EventModel(
            event_id=event.event_id,
            schema_version=event.schema_version,
            timestamp=event.timestamp.replace(tzinfo=None),
            tenant_id=auth.tenant_id,
            app_id=event.app_id,
            service_id=event.service_id,
            event_type=event.event_type,
            severity=event.severity.value,
            source_resource=event.source_resource,
            target_resource=event.target_resource,
            trace_id=event.trace_id,
            request_id=event.request_id,
            attributes=event.attributes,
            provenance=event.provenance,
        )

        try:
            db.add(db_event)
            db.commit()
            accepted += 1
            event_ids.append(event.event_id)

            # Evaluate fast-path detectors
            for detector in fast_detectors:
                finding = detector.evaluate(event)
                if finding:
                    db_finding = SecurityFinding(
                        finding_id=finding.finding_id,
                        tenant_id=finding.tenant_id,
                        detector_id=finding.detector_id,
                        detector_version=finding.detector_version,
                        title=finding.title,
                        severity=finding.severity,
                        confidence=finding.confidence,
                        description=finding.description,
                        event_id=finding.event_id,
                        evidence=finding.evidence,
                    )
                    db.add(db_finding)
                    db.commit()

        except IntegrityError:
            db.rollback()
            duplicates += 1
            event_ids.append(event.event_id)
        except Exception as e:
            db.rollback()
            errors.append({"event_id": event.event_id, "error": "Database error"})

    return IngestResponse(
        accepted=accepted,
        rejected=len(errors),
        duplicates=duplicates,
        event_ids=event_ids,
        errors=errors
    )

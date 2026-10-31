import logging
import time
from collections import defaultdict
from typing import List, Optional, Dict, Tuple
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from backend.config import settings
from backend.db.session import get_db
from backend.models import EventModel, SecurityFinding
from backend.schemas.events import CanonicalEvent, IngestBatchRequest, IngestResponse
from backend.core.auth import get_current_auth, AuthContext
from backend.detection.baseline import BaseDetector, BruteForceLoginDetector, Finding
from backend.detection.correlation import CrossServiceExfiltrationDetector
from backend.detection.registry import runtime_rule_registry
from backend.ops.bus import ops_bus

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["telemetry"])

# In-memory Token Bucket Rate Limiter per Tenant
# (tokens_available, last_refreshed_timestamp)
_rate_limit_state: Dict[str, Tuple[float, float]] = defaultdict(lambda: (float(settings.INGESTION_RATE_LIMIT_PER_MINUTE), time.time()))

def _check_rate_limit(tenant_id: str, count: int = 1) -> bool:
    """
    Enforces token-bucket rate limiting based on settings.INGESTION_RATE_LIMIT_PER_MINUTE.
    Fails closed with HTTP 429 when budget is exhausted to protect database IOPS.
    """
    max_rate = float(settings.INGESTION_RATE_LIMIT_PER_MINUTE)
    fill_rate_per_sec = max_rate / 60.0
    now = time.time()

    tokens, last_time = _rate_limit_state[tenant_id]
    # Refill tokens
    elapsed = max(0.0, now - last_time)
    tokens = min(max_rate, tokens + elapsed * fill_rate_per_sec)

    if tokens < count:
        _rate_limit_state[tenant_id] = (tokens, now)
        return False

    _rate_limit_state[tenant_id] = (tokens - count, now)
    return True

# Baseline native detector instances as safety net
fast_detectors: List[BaseDetector] = [
    BruteForceLoginDetector(failure_threshold=3),
    CrossServiceExfiltrationDetector(time_window_seconds=300),
]


def evaluate_and_persist_findings(
    event: CanonicalEvent, auth_tenant_id: str, db: Session
) -> Tuple[str, Optional[str]]:
    """
    Evaluates an ingested event against:
    1. Active declarative rules loaded dynamically for this tenant (recording rule_id & version).
    2. Native baseline detectors as continuous safety net (preventing duplicate alerts if a declarative rule fired).
    Returns:
        Tuple[str, Optional[str]]: (correlation_status ["ok" | "degraded"], degraded_reason)
    """
    # 1. Dynamic active declarative rules for authenticated tenant
    rule_findings, covered_families, corr_status, corr_error = runtime_rule_registry.evaluate_active_rules(event, db)

    if corr_status == "degraded":
        ops_bus.publish(
            component="correlation",
            event_type="correlation.degraded",
            level="error",
            message=f"Distributed correlation degraded for tenant '{auth_tenant_id}': {corr_error}",
            tenant_id=auth_tenant_id,
            trace_id=event.trace_id,
            service_id=event.service_id,
            metadata={"error": corr_error},
        )

    for finding in rule_findings:
        db_finding = SecurityFinding(
            finding_id=finding.finding_id,
            tenant_id=auth_tenant_id,
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
        try:
            db.commit()
            ops_bus.publish(
                component="fast-track",
                event_type="fast_track.rule_triggered",
                level="warn",
                message=f"Declarative rule '{finding.detector_id}' v{finding.detector_version} triggered: {finding.title}",
                tenant_id=auth_tenant_id,
                finding_id=finding.finding_id,
                rule_id=finding.detector_id,
                rule_version=int(finding.detector_version) if str(finding.detector_version).isdigit() else 1,
                trace_id=event.trace_id,
                service_id=event.service_id,
                metadata={"severity": finding.severity, "confidence": finding.confidence},
            )
        except IntegrityError:
            db.rollback()
        except Exception as e:
            db.rollback()
            logger.error("Failed persisting declarative rule finding: %s", e)

    # 2. Native baseline detectors (act as fallback if declarative rules failed or don't cover the family)
    for detector in fast_detectors:
        family = getattr(detector, "detector_id", "")
        # Suppress duplicate alerts only if active declarative rule evaluated successfully for this family
        if family in covered_families:
            ops_bus.publish(
                component="fast-track",
                event_type="finding.suppressed_duplicate",
                level="info",
                message=f"Suppressed native baseline alert for family '{family}' (covered by active rule)",
                tenant_id=auth_tenant_id,
                trace_id=event.trace_id,
            )
            continue
        finding = detector.evaluate(event)
        if finding:
            db_finding = SecurityFinding(
                finding_id=finding.finding_id,
                tenant_id=auth_tenant_id,
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
            try:
                db.commit()
                ops_bus.publish(
                    component="fast-track",
                    event_type="finding.created",
                    level="warn",
                    message=f"Fast Track native detector '{finding.detector_id}' triggered: {finding.title}",
                    tenant_id=auth_tenant_id,
                    finding_id=finding.finding_id,
                    trace_id=event.trace_id,
                    service_id=event.service_id,
                    metadata={"severity": finding.severity, "confidence": finding.confidence},
                )
            except IntegrityError:
                db.rollback()
            except Exception as e:
                db.rollback()
                logger.error("Failed persisting native finding: %s", e)

    return corr_status, corr_error


@router.post("/events", response_model=IngestResponse, status_code=status.HTTP_202_ACCEPTED)
async def ingest_event(
    event: CanonicalEvent,
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db)
):
    """
    Ingest a single canonical telemetry event.
    Enforces tenant isolation, application scoping, and token-bucket rate limits.
    """
    # Rate limit check per tenant
    if not _check_rate_limit(auth.tenant_id, count=1):
        ops_bus.publish(
            component="ingest",
            event_type="ingest.rate_limited",
            level="warn",
            message=f"Rate limit exceeded for tenant '{auth.tenant_id}' (budget: {settings.INGESTION_RATE_LIMIT_PER_MINUTE}/min)",
            tenant_id=auth.tenant_id,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded: maximum {settings.INGESTION_RATE_LIMIT_PER_MINUTE} events per minute.",
            headers={"Retry-After": "10"}
        )

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
        ops_bus.publish(
            component="ingest",
            event_type="ingest.duplicate_filtered",
            level="info",
            message=f"Duplicate event '{event.event_id}' filtered",
            tenant_id=auth.tenant_id,
            service_id=event.service_id,
            trace_id=event.trace_id,
        )
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
        ops_bus.publish(
            component="ingest",
            event_type="ingest.event_received",
            level="info",
            message=f"Ingested {event.event_type} from {event.service_id} (trace: {event.trace_id or 'none'})",
            tenant_id=auth.tenant_id,
            service_id=event.service_id,
            trace_id=event.trace_id,
            metadata={"event_id": event.event_id, "severity": event.severity.value, "target": event.target_resource},
        )
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

    # Continuous evaluation across active declarative rules and native safety net
    corr_status, corr_reason = evaluate_and_persist_findings(event, auth.tenant_id, db)

    return IngestResponse(
        accepted=1,
        rejected=0,
        duplicates=0,
        event_ids=[event.event_id],
        errors=[],
        correlation_status=corr_status,
        correlation_degraded_reason=corr_reason,
    )


@router.post("/events/batch", response_model=IngestResponse, status_code=status.HTTP_202_ACCEPTED)
async def ingest_events_batch(
    payload: IngestBatchRequest,
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db)
):
    """
    Ingest a batch of canonical telemetry events.
    Atomic or best-effort safe persistence with duplicate detection and rate limiting.
    """
    batch_count = len(payload.events)
    if not _check_rate_limit(auth.tenant_id, count=batch_count):
        ops_bus.publish(
            component="ingest",
            event_type="ingest.rate_limited",
            level="warn",
            message=f"Rate limit exceeded for batch of {batch_count} events (tenant: '{auth.tenant_id}')",
            tenant_id=auth.tenant_id,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded for batch: maximum {settings.INGESTION_RATE_LIMIT_PER_MINUTE} events per minute.",
            headers={"Retry-After": "10"}
        )

    accepted = 0
    duplicates = 0
    event_ids = []
    errors = []
    batch_corr_status = "ok"
    batch_corr_reason = None

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

            # Continuous evaluation across active declarative rules and native safety net
            corr_status, corr_reason = evaluate_and_persist_findings(event, auth.tenant_id, db)
            if corr_status == "degraded":
                batch_corr_status = "degraded"
                batch_corr_reason = corr_reason

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
        errors=errors,
        correlation_status=batch_corr_status,
        correlation_degraded_reason=batch_corr_reason,
    )

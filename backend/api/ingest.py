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
from backend.core.auth import get_current_auth, AuthContext, Permission, require_permission
from backend.detection.baseline import BaseDetector, BruteForceLoginDetector, Finding
from backend.detection.correlation import CrossServiceExfiltrationDetector
from backend.detection.registry import runtime_rule_registry
from backend.ops.bus import ops_bus
from backend.ops.metrics import metrics_registry

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["telemetry"])

# In-memory Token Bucket Rate Limiter per Tenant
# (tokens_available, last_refreshed_timestamp)
_rate_limit_state: Dict[str, Tuple[float, float]] = defaultdict(lambda: (float(settings.INGESTION_RATE_LIMIT_PER_MINUTE), time.time()))
_rate_limit_redis_client = None
_TOKEN_BUCKET_SCRIPT = """
local values = redis.call('HMGET', KEYS[1], 'tokens', 'updated_ms')
local now = redis.call('TIME')
local now_ms = now[1] * 1000 + math.floor(now[2] / 1000)
local capacity = tonumber(ARGV[1])
local refill_per_ms = tonumber(ARGV[2])
local requested = tonumber(ARGV[3])
local tokens = tonumber(values[1]) or capacity
local updated_ms = tonumber(values[2]) or now_ms
tokens = math.min(capacity, tokens + math.max(0, now_ms - updated_ms) * refill_per_ms)
if tokens < requested then
  redis.call('HMSET', KEYS[1], 'tokens', tokens, 'updated_ms', now_ms)
  redis.call('EXPIRE', KEYS[1], 120)
  return 0
end
redis.call('HMSET', KEYS[1], 'tokens', tokens - requested, 'updated_ms', now_ms)
redis.call('EXPIRE', KEYS[1], 120)
return 1
"""

def _check_rate_limit(tenant_id: str, count: int = 1) -> bool:
    """
    Enforces token-bucket rate limiting based on settings.INGESTION_RATE_LIMIT_PER_MINUTE.
    Fails closed with HTTP 429 when budget is exhausted to protect database IOPS.
    """
    max_rate = float(settings.INGESTION_RATE_LIMIT_PER_MINUTE)
    fill_rate_per_sec = max_rate / 60.0
    global _rate_limit_redis_client
    if settings.REDIS_URL:
        try:
            if _rate_limit_redis_client is None:
                import redis
                _rate_limit_redis_client = redis.Redis.from_url(
                    settings.REDIS_URL,
                    socket_timeout=0.1,
                    socket_connect_timeout=0.1,
                )
            return bool(
                _rate_limit_redis_client.eval(
                    _TOKEN_BUCKET_SCRIPT,
                    1,
                    f"cyber_engine:ingest_rate:{tenant_id}",
                    max_rate,
                    fill_rate_per_sec / 1000.0,
                    count,
                )
            )
        except Exception as exc:
            if settings.ENVIRONMENT.lower() in ("production", "staging") or settings.REDIS_REQUIRED:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Distributed ingestion rate limiting is unavailable.",
                ) from exc
            logger.warning("Redis rate limiting unavailable; using process-local limiter: %s", exc)

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


def _enqueue_async_event(event: CanonicalEvent, tenant_id: str) -> bool:
    if not getattr(settings, "ASYNC_INGESTION_ENABLED", False) or not settings.REDIS_URL:
        return False
    try:
        import redis
        from backend.detection.worker import TelemetryWorker

        client = redis.Redis.from_url(
            settings.REDIS_URL,
            socket_timeout=0.2,
            socket_connect_timeout=0.2,
        )
        return TelemetryWorker(
            redis_client=client,
            queue_key=settings.ASYNC_QUEUE_KEY,
        ).enqueue(event.model_dump(mode="json"), tenant_id)
    except Exception as exc:
        logger.warning("Could not enqueue event asynchronously; falling back to synchronous detection: %s", exc)
        return False

def evaluate_event_containment(event: CanonicalEvent, tenant_id: str) -> None:
    """
    Evaluates incoming event against Active Defense perimeter containment policy.
    Shared across single event and batch ingestion endpoints.
    Raises HTTP 403 Forbidden if source IP is actively blocklisted.
    Raises HTTP 429 Too Many Requests if entity rate limit quota is exhausted.
    Fails open safely if Redis or infrastructure is degraded.
    """
    from backend.defense.filter import ingest_containment_filter
    client_ip = None
    if event.attributes and isinstance(event.attributes, dict):
        raw_ip = event.attributes.get("client_ip") or event.attributes.get("source_ip") or event.attributes.get("ip")
        if raw_ip:
            client_ip = str(raw_ip).strip()
    if not client_ip and event.source_resource:
        import ipaddress
        raw_res = event.source_resource.strip()
        try:
            ipaddress.ip_address(raw_res)
            client_ip = raw_res
        except ValueError:
            client_ip = None

    entity_id = event.source_resource or event.app_id
    ingest_containment_filter.check_containment(
        tenant_id=tenant_id,
        client_ip=client_ip,
        entity_id=entity_id,
    )


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
            metrics_registry.record_finding(
                tenant_id=auth_tenant_id,
                detector_id=finding.detector_id,
                severity=finding.severity,
            )
            try:
                from backend.incidents.correlator import IncidentCorrelator
                IncidentCorrelator(db).correlate_finding(db_finding)
            except Exception as inc_err:
                logger.warning("Incident auto-correlation error: %s", inc_err)
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
                metrics_registry.record_finding(
                    tenant_id=auth_tenant_id,
                    detector_id=finding.detector_id,
                    severity=finding.severity,
                )
                try:
                    from backend.incidents.correlator import IncidentCorrelator
                    IncidentCorrelator(db).correlate_finding(db_finding)
                except Exception as inc_err:
                    logger.warning("Incident auto-correlation error: %s", inc_err)
            except IntegrityError:
                db.rollback()
            except Exception as e:
                db.rollback()
                logger.error("Failed persisting native finding: %s", e)

    return corr_status, corr_error


@router.post("/events", response_model=IngestResponse, status_code=status.HTTP_202_ACCEPTED)
async def ingest_event(
    event: CanonicalEvent,
    auth: AuthContext = Depends(require_permission(Permission.EVENTS_INGEST)),
    db: Session = Depends(get_db)
):
    """
    Ingest a single canonical telemetry event.
    Enforces tenant isolation, application scoping, and token-bucket rate limits.
    """
    # Rate limit check per tenant
    t_start = time.time()
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

    # Verify that the event's app_id matches the authenticated API key scope.
    # Operator JWTs (auth_type='jwt') are tenant-scoped and may ingest for any registered
    # app within their tenant (e.g. console self-test, SDK validation). Machine API keys
    # must match their provisioned app_id exactly.
    if auth.auth_type != 'jwt' and event.app_id != auth.app_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"API key is scoped to application '{auth.app_id}', not '{event.app_id}'"
        )

    # Active Defense containment check (IP block -> 403, entity rate limit -> 429)
    evaluate_event_containment(event, auth.tenant_id)

    # Check for existing event (idempotency / duplicate check)
    existing = db.query(EventModel.event_id).filter(
        EventModel.event_id == event.event_id,
        EventModel.tenant_id == auth.tenant_id,
    ).first()
    if existing:
        metrics_registry.record_event(tenant_id=auth.tenant_id, service_id=event.service_id, status="duplicate")
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
        metrics_registry.record_event(tenant_id=auth.tenant_id, service_id=event.service_id, status="duplicate")
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

    # Optional Asynchronous Queue Decoupling
    if _enqueue_async_event(event, auth.tenant_id):
        metrics_registry.record_event(tenant_id=auth.tenant_id, service_id=event.service_id, status="accepted")
        metrics_registry.record_latency(time.time() - t_start)
        return IngestResponse(
            accepted=1,
            rejected=0,
            duplicates=0,
            event_ids=[event.event_id],
            errors=[],
            correlation_status="queued",
            correlation_degraded_reason=None,
        )

    # Continuous evaluation across active declarative rules and native safety net
    corr_status, corr_reason = evaluate_and_persist_findings(event, auth.tenant_id, db)
    metrics_registry.record_event(tenant_id=auth.tenant_id, service_id=event.service_id, status="accepted")
    metrics_registry.record_latency(time.time() - t_start)

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
    auth: AuthContext = Depends(require_permission(Permission.EVENTS_INGEST)),
    db: Session = Depends(get_db)
):
    """
    Ingest a batch of canonical telemetry events.
    Atomic or best-effort safe persistence with duplicate detection and rate limiting.
    """
    t_batch_start = time.time()
    errors = []
    scoped_events = []
    for event in payload.events:
        # Reject app-scope mismatches before rate limiting and containment checks.
        if auth.auth_type != "jwt" and event.app_id != auth.app_id:
            errors.append({
                "event_id": event.event_id,
                "error": f"Mismatched app_id scope: expected {auth.app_id}, got {event.app_id}",
            })
            continue
        event.tenant_id = auth.tenant_id
        scoped_events.append(event)

    batch_count = len(scoped_events)
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
    queued_any = False

    # Preflight all valid events before committing any of them so a blocked event
    # rejects the batch without partial persistence.
    for event in scoped_events:
        evaluate_event_containment(event, auth.tenant_id)

    for event in scoped_events:
        existing = db.query(EventModel.event_id).filter(
            EventModel.event_id == event.event_id,
            EventModel.tenant_id == auth.tenant_id,
        ).first()
        if existing:
            duplicates += 1
            event_ids.append(event.event_id)
            metrics_registry.record_event(
                tenant_id=auth.tenant_id,
                service_id=event.service_id,
                status="duplicate",
            )
            ops_bus.publish(
                component="ingest",
                event_type="ingest.duplicate_filtered",
                level="info",
                message=f"Duplicate event '{event.event_id}' filtered",
                tenant_id=auth.tenant_id,
                service_id=event.service_id,
                trace_id=event.trace_id,
            )
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

            metrics_registry.record_event(
                tenant_id=auth.tenant_id,
                service_id=event.service_id,
                status="accepted",
            )
            if _enqueue_async_event(event, auth.tenant_id):
                queued_any = True
            else:
                # Continuous evaluation across active declarative rules and native safety net
                corr_status, corr_reason = evaluate_and_persist_findings(event, auth.tenant_id, db)
                if corr_status == "degraded":
                    batch_corr_status = "degraded"
                    batch_corr_reason = corr_reason

        except IntegrityError:
            db.rollback()
            duplicates += 1
            event_ids.append(event.event_id)
            metrics_registry.record_event(
                tenant_id=auth.tenant_id,
                service_id=event.service_id,
                status="duplicate",
            )
        except Exception as e:
            db.rollback()
            errors.append({"event_id": event.event_id, "error": "Database error"})

    if queued_any and batch_corr_status == "ok":
        batch_corr_status = "queued"
    metrics_registry.record_latency(time.time() - t_batch_start)

    return IngestResponse(
        accepted=accepted,
        rejected=len(errors),
        duplicates=duplicates,
        event_ids=event_ids,
        errors=errors,
        correlation_status=batch_corr_status,
        correlation_degraded_reason=batch_corr_reason,
    )

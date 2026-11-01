"""
FastAPI router for Querying Ingested Telemetry and Historical Analysis.

Endpoints:
- GET /api/v1/events — List/filter ingested events for authenticated tenant (Event Explorer)
- GET /api/v1/events/search — Bounded historical time-range query with category/severity filtering and period comparison
- GET /api/v1/events/{event_id} — Retrieve detailed canonical event by ID
"""

import datetime
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.db.session import get_db
from backend.core.auth import get_current_auth, AuthContext
from backend.models import EventModel

router = APIRouter(prefix="/api/v1/events", tags=["Events & Historical Analysis"])

SEVERITY_RANKS = {
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}


class EventSchema(BaseModel):
    event_id: str
    schema_version: str
    timestamp: datetime.datetime
    ingested_at: datetime.datetime
    tenant_id: str
    app_id: str
    service_id: str
    event_type: str
    severity: str
    source_resource: Optional[str] = None
    target_resource: Optional[str] = None
    trace_id: Optional[str] = None
    request_id: Optional[str] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)
    provenance: Dict[str, Any] = Field(default_factory=dict)


class HistoricalSummary(BaseModel):
    total_events: int
    by_severity: Dict[str, int]
    by_service: Dict[str, int]


class HistoricalSearchResponse(BaseModel):
    events: List[EventSchema]
    summary: HistoricalSummary
    comparison: Optional[Dict[str, Any]] = None
    query_window: Dict[str, str]


@router.get("", response_model=List[EventSchema])
async def list_events(
    service_id: Optional[str] = Query(None, description="Filter by service name"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    severity: Optional[str] = Query(None, description="Filter by severity level"),
    trace_id: Optional[str] = Query(None, description="Filter by trace ID"),
    limit: int = Query(50, ge=1, le=200, description="Page size limit"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_current_auth),
):
    """
    Lists ingested telemetry events for the authenticated tenant.
    Enforces tenant isolation and chronological descending order.
    """
    query = db.query(EventModel).filter(EventModel.tenant_id == auth.tenant_id)

    if service_id:
        query = query.filter(EventModel.service_id == service_id.strip())
    if event_type:
        query = query.filter(EventModel.event_type == event_type.strip())
    if severity:
        query = query.filter(EventModel.severity == severity.strip().lower())
    if trace_id:
        query = query.filter(EventModel.trace_id == trace_id.strip())

    events = query.order_by(EventModel.timestamp.desc()).offset(offset).limit(limit).all()

    return [
        EventSchema(
            event_id=e.event_id,
            schema_version=e.schema_version,
            timestamp=e.timestamp,
            ingested_at=e.ingested_at,
            tenant_id=e.tenant_id,
            app_id=e.app_id,
            service_id=e.service_id,
            event_type=e.event_type,
            severity=e.severity,
            source_resource=e.source_resource,
            target_resource=e.target_resource,
            trace_id=e.trace_id,
            request_id=e.request_id,
            attributes=e.attributes or {},
            provenance=e.provenance or {},
        )
        for e in events
    ]


def _parse_iso_datetime(dt_str: Optional[str], param_name: str) -> Optional[datetime.datetime]:
    if not dt_str:
        return None
    s = dt_str.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    # Handle case where '+' was URL-decoded into a space
    if " " in s and "+" not in s:
        parts = s.rsplit(" ", 1)
        if len(parts) == 2 and (":" in parts[1] or len(parts[1]) == 4):
            s = f"{parts[0]}+{parts[1]}"
    try:
        dt = datetime.datetime.fromisoformat(s)
        if dt.tzinfo is not None:
            dt = dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        return dt
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid ISO-8601 datetime format for '{param_name}': '{dt_str}'. Expected e.g. 2026-11-01T12:00:00Z",
        )


@router.get("/search", response_model=HistoricalSearchResponse)
async def search_events_historical(
    from_param: Optional[str] = Query(None, alias="from", description="UTC start datetime (ISO-8601)"),
    to_param: Optional[str] = Query(None, alias="to", description="UTC end datetime (ISO-8601)"),
    category: Optional[str] = Query(None, description="Event type category filter (e.g. auth, exfiltration)"),
    min_severity: Optional[str] = Query(None, description="Minimum severity threshold"),
    service_id: Optional[str] = Query(None, description="Filter by service"),
    compare_previous: bool = Query(False, description="Compute delta metrics against equivalent prior time window"),
    limit: int = Query(50, ge=1, le=200, description="Max events to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_current_auth),
):
    """
    Bounded historical search over tenant telemetry.
    Strictly read-only: Historical queries never invoke detection evaluation or triggers.
    Enforces tenant boundaries and indexed timestamp boundaries.
    """
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

    from_time = _parse_iso_datetime(from_param, "from")
    to_time = _parse_iso_datetime(to_param, "to")

    # Default window: last 24 hours if not explicitly provided
    if to_time is None:
        to_time = now
    if from_time is None:
        from_time = to_time - datetime.timedelta(hours=24)

    if from_time >= to_time:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid time range: 'from' must be strictly earlier than 'to'.",
        )

    # Max query duration: 90 days to avoid denial-of-service on database IO
    max_duration = datetime.timedelta(days=90)
    if (to_time - from_time) > max_duration:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Requested time range exceeds maximum allowed query window of 90 days.",
        )

    # Base query scoped to authenticated tenant and time window
    base_query = db.query(EventModel).filter(
        EventModel.tenant_id == auth.tenant_id,
        EventModel.timestamp >= from_time,
        EventModel.timestamp <= to_time,
    )

    if service_id:
        base_query = base_query.filter(EventModel.service_id == service_id.strip())

    if category:
        # Category matches event_type prefix or contains pattern safely
        cat = category.strip().lower()
        base_query = base_query.filter(
            EventModel.event_type.ilike(f"%{cat}%")
        )

    if min_severity:
        sev_target = min_severity.strip().lower()
        target_rank = SEVERITY_RANKS.get(sev_target, 1)
        allowed_sevs = [s for s, rank in SEVERITY_RANKS.items() if rank >= target_rank]
        base_query = base_query.filter(EventModel.severity.in_(allowed_sevs))

    # Aggregates for summary
    total_events = base_query.count()

    # Breakdown by severity
    sev_counts = (
        db.query(EventModel.severity, func.count(EventModel.event_id))
        .filter(
            EventModel.tenant_id == auth.tenant_id,
            EventModel.timestamp >= from_time,
            EventModel.timestamp <= to_time,
        )
        .group_by(EventModel.severity)
        .all()
    )
    by_severity = {sev: count for sev, count in sev_counts}

    # Breakdown by service
    svc_counts = (
        db.query(EventModel.service_id, func.count(EventModel.event_id))
        .filter(
            EventModel.tenant_id == auth.tenant_id,
            EventModel.timestamp >= from_time,
            EventModel.timestamp <= to_time,
        )
        .group_by(EventModel.service_id)
        .all()
    )
    by_service = {svc: count for svc, count in svc_counts}

    # Retrieve paged event items
    items = base_query.order_by(EventModel.timestamp.desc()).offset(offset).limit(limit).all()

    # Period comparison if requested
    comparison_data = None
    if compare_previous:
        window_duration = to_time - from_time
        prev_to = from_time
        prev_from = from_time - window_duration
        prev_total = (
            db.query(func.count(EventModel.event_id))
            .filter(
                EventModel.tenant_id == auth.tenant_id,
                EventModel.timestamp >= prev_from,
                EventModel.timestamp < prev_to,
            )
            .scalar()
            or 0
        )
        delta_events = total_events - prev_total
        pct_change = ((delta_events / prev_total) * 100.0) if prev_total > 0 else 0.0
        comparison_data = {
            "previous_period_from": prev_from.isoformat() + "Z",
            "previous_period_to": prev_to.isoformat() + "Z",
            "previous_total_events": prev_total,
            "delta_events": delta_events,
            "percentage_change": round(pct_change, 2),
        }

    return HistoricalSearchResponse(
        events=[
            EventSchema(
                event_id=e.event_id,
                schema_version=e.schema_version,
                timestamp=e.timestamp,
                ingested_at=e.ingested_at,
                tenant_id=e.tenant_id,
                app_id=e.app_id,
                service_id=e.service_id,
                event_type=e.event_type,
                severity=e.severity,
                source_resource=e.source_resource,
                target_resource=e.target_resource,
                trace_id=e.trace_id,
                request_id=e.request_id,
                attributes=e.attributes or {},
                provenance=e.provenance or {},
            )
            for e in items
        ],
        summary=HistoricalSummary(
            total_events=total_events,
            by_severity=by_severity,
            by_service=by_service,
        ),
        comparison=comparison_data,
        query_window={
            "from": from_time.isoformat() + "Z",
            "to": to_time.isoformat() + "Z",
            "limit": str(limit),
            "offset": str(offset),
        },
    )


@router.get("/{event_id}", response_model=EventSchema)
async def get_event(
    event_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_current_auth),
):
    """
    Retrieves full details for a single ingested event by ID.
    Enforces tenant isolation.
    """
    event = db.query(EventModel).filter(
        EventModel.event_id == event_id,
        EventModel.tenant_id == auth.tenant_id,
    ).first()

    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event '{event_id}' not found.",
        )

    return EventSchema(
        event_id=event.event_id,
        schema_version=event.schema_version,
        timestamp=event.timestamp,
        ingested_at=event.ingested_at,
        tenant_id=event.tenant_id,
        app_id=event.app_id,
        service_id=event.service_id,
        event_type=event.event_type,
        severity=event.severity,
        source_resource=event.source_resource,
        target_resource=event.target_resource,
        trace_id=event.trace_id,
        request_id=event.request_id,
        attributes=event.attributes or {},
        provenance=event.provenance or {},
    )

"""
Evidence Collector for CYBER ENGINE Deep-Investigation Path.

Assembles correlated event timelines, preceding actor context, and service
boundaries across multi-service traces to construct the investigation context.
"""

from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
import datetime

from backend.models import EventModel, SecurityFinding
from backend.schemas.investigation import InvestigationContext


class EvidenceCollector:
    """
    Gathers correlated telemetry, trace timelines, and actor history
    to construct the grounded investigation context.
    """
    def __init__(self, db: Session):
        self.db = db

    def assemble_context(self, finding_id: str) -> Optional[InvestigationContext]:
        finding = self.db.query(SecurityFinding).filter(
            SecurityFinding.finding_id == finding_id
        ).first()
        if not finding:
            return None

        trace_id = None
        if finding.evidence and isinstance(finding.evidence, dict):
            trace_id = finding.evidence.get("trace_id")

        # Query all events matching this trace_id and tenant_id
        events: List[EventModel] = []
        if trace_id:
            events = self.db.query(EventModel).filter(
                EventModel.tenant_id == finding.tenant_id,
                EventModel.trace_id == trace_id
            ).order_by(EventModel.timestamp.asc()).all()

        # If no trace events found but an anchored event_id exists, include that event
        if not events and finding.event_id:
            anchored = self.db.query(EventModel).filter(
                EventModel.tenant_id == finding.tenant_id,
                EventModel.event_id == finding.event_id
            ).first()
            if anchored:
                events = [anchored]

        timeline: List[Dict[str, Any]] = [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat(),
                "service_id": e.service_id,
                "event_type": e.event_type,
                "source_resource": e.source_resource,
                "target_resource": e.target_resource,
                "attributes": e.attributes or {},
            }
            for e in events
        ]

        services = sorted(list({e.service_id for e in events if e.service_id}))
        actors = sorted(list({e.source_resource for e in events if e.source_resource}))

        return InvestigationContext(
            finding_id=finding.finding_id,
            tenant_id=finding.tenant_id,
            trace_id=trace_id,
            finding_title=finding.title,
            finding_severity=finding.severity,
            finding_evidence=finding.evidence or {},
            timeline_events=timeline,
            actors=actors,
            services=services,
        )

    def assemble_query_context(
        self,
        tenant_id: str,
        query: str,
        finding_id: str,
        target_service: Optional[str] = None,
        target_entity: Optional[str] = None,
        trace_id: Optional[str] = None,
        limit: int = 50,
    ) -> InvestigationContext:
        # Collect factual pipeline and telemetry store metrics
        total_events_in_db = self.db.query(EventModel).filter(EventModel.tenant_id == tenant_id).count()
        now = datetime.datetime.now(datetime.timezone.utc)
        one_hour_ago = now - datetime.timedelta(hours=1)
        recent_events_1h = self.db.query(EventModel).filter(
            EventModel.tenant_id == tenant_id,
            EventModel.timestamp >= one_hour_ago,
        ).count()

        latest_event = self.db.query(EventModel).filter(
            EventModel.tenant_id == tenant_id
        ).order_by(EventModel.timestamp.desc()).first()

        active_services_tuples = self.db.query(EventModel.service_id).filter(
            EventModel.tenant_id == tenant_id,
            EventModel.timestamp >= one_hour_ago,
        ).distinct().all()
        active_services = sorted([r[0] for r in active_services_tuples if r[0]])

        if recent_events_1h == 0:
            pipeline_status = "idle"
            pipeline_message = (
                "No telemetry events received in the last hour. "
                "Client microservices and producer applications are inactive/offline "
                "and not transmitting events to /v1/events."
            )
        else:
            pipeline_status = "active"
            pipeline_message = (
                f"Telemetry ingestion active. {recent_events_1h} events received in the last hour "
                f"across active services: {', '.join(active_services)}."
            )

        event_query = self.db.query(EventModel).filter(EventModel.tenant_id == tenant_id)
        if trace_id:
            event_query = event_query.filter(EventModel.trace_id == trace_id)
        if target_service:
            event_query = event_query.filter(EventModel.service_id == target_service)
        if target_entity:
            event_query = event_query.filter(
                (EventModel.source_resource == target_entity) | (EventModel.target_resource == target_entity)
            )

        events: List[EventModel] = event_query.order_by(EventModel.timestamp.desc()).limit(limit).all()
        events = sorted(events, key=lambda e: e.timestamp)

        timeline: List[Dict[str, Any]] = [
            {
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat(),
                "service_id": e.service_id,
                "event_type": e.event_type,
                "source_resource": e.source_resource,
                "target_resource": e.target_resource,
                "attributes": e.attributes or {},
            }
            for e in events
        ]

        services = sorted(list({e.service_id for e in events if e.service_id})) or active_services
        actors = sorted(list({e.source_resource for e in events if e.source_resource}))

        return InvestigationContext(
            finding_id=finding_id,
            tenant_id=tenant_id,
            trace_id=trace_id,
            finding_title=query,
            finding_severity="info" if pipeline_status == "idle" else "medium",
            finding_evidence={
                "query": query,
                "pipeline_status": pipeline_status,
                "pipeline_message": pipeline_message,
                "total_events_in_database": total_events_in_db,
                "recent_events_last_hour": recent_events_1h,
                "latest_event_timestamp": latest_event.timestamp.isoformat() if latest_event else None,
                "active_services": active_services,
                "target_service": target_service,
                "target_entity": target_entity,
                "trace_id": trace_id,
                "events_analyzed": len(timeline),
            },
            timeline_events=timeline,
            actors=actors,
            services=services,
        )


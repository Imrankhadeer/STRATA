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


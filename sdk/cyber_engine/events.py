from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional
import uuid


@dataclass
class Event:
    event_type: str
    app_id: str
    service_id: str
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    severity: str = "info"
    source_resource: Optional[str] = None
    target_resource: Optional[str] = None
    trace_id: Optional[str] = None
    request_id: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    provenance: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        ts = self.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return {
            "event_id": self.event_id,
            "schema_version": "1.0.0",
            "timestamp": ts.isoformat(),
            "app_id": self.app_id,
            "service_id": self.service_id,
            "event_type": self.event_type,
            "severity": self.severity,
            "source_resource": self.source_resource,
            "target_resource": self.target_resource,
            "trace_id": self.trace_id,
            "request_id": self.request_id,
            "attributes": self.attributes,
            "provenance": {
                **self.provenance,
                "sdk_version": "0.1.0",
                "sdk_language": "python"
            }
        }

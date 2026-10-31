from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional
import uuid
import json

from .security import sanitize_attributes, MAX_PAYLOAD_BYTES


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

    def to_dict(self, auto_sanitize: bool = True) -> Dict[str, Any]:
        ts = self.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)

        attrs = sanitize_attributes(self.attributes) if auto_sanitize else self.attributes
        prov = sanitize_attributes(self.provenance) if auto_sanitize else self.provenance

        payload = {
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
            "attributes": attrs,
            "provenance": {
                **prov,
                "sdk_version": "0.1.0",
                "sdk_language": "python"
            }
        }

        # Client-side size pre-check
        encoded = json.dumps(payload)
        if len(encoded.encode("utf-8")) > MAX_PAYLOAD_BYTES:
            raise ValueError(
                f"Payload size ({len(encoded)} bytes) exceeds maximum allowable SDK limit ({MAX_PAYLOAD_BYTES} bytes)"
            )

        return payload

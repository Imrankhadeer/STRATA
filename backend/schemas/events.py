from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional, List
import uuid
import re
from pydantic import BaseModel, Field, field_validator, model_validator


class SeverityLevel(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CanonicalEvent(BaseModel):
    """
    Canonical Event Schema for CYBER ENGINE.
    Treats all incoming data as untrusted, enforcing strict typing, UTC timestamps,
    and size constraints to prevent injection or payload abuse.
    """
    event_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Globally unique identifier for the event (UUID or stable ID)"
    )
    schema_version: str = Field(
        default="1.0.0",
        pattern=r"^\d+\.\d+\.\d+$",
        description="Semantic version of event schema"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the event occurrence"
    )
    tenant_id: Optional[str] = Field(
        default=None,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_\-\.]+$",
        description="Tenant identifier (enforced by ingestion auth)"
    )
    app_id: str = Field(
        ...,
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_\-\.]+$",
        description="Application identifier"
    )
    service_id: str = Field(
        ...,
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_\-\.]+$",
        description="Originating service identifier within the application"
    )
    event_type: str = Field(
        ...,
        min_length=3,
        max_length=128,
        pattern=r"^[a-zA-Z0-9_\-\.]+$",
        description="Standard dot-delimited event domain and action, e.g., 'auth.login_failed'"
    )
    severity: SeverityLevel = Field(
        default=SeverityLevel.INFO,
        description="Standardized severity level"
    )

    source_resource: Optional[str] = Field(
        default=None,
        max_length=256,
        description="Identifier of source actor/resource (e.g. client IP, user ID, ARN)"
    )
    target_resource: Optional[str] = Field(
        default=None,
        max_length=256,
        description="Identifier of target resource (e.g. endpoint, table, bucket)"
    )
    trace_id: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Distributed tracing ID for correlation across services"
    )
    request_id: Optional[str] = Field(
        default=None,
        max_length=128,
        description="HTTP or operational request ID"
    )

    attributes: Dict[str, Any] = Field(
        default_factory=dict,
        description="Structured key-value payload attributes. Keys must be alphanumeric strings."
    )
    provenance: Dict[str, Any] = Field(
        default_factory=dict,
        description="Metadata describing origin, SDK version, host, or sensor info"
    )

    @field_validator("timestamp")
    @classmethod
    def ensure_utc_timestamp(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            # Treat naive datetime as UTC
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)

    @field_validator("attributes")
    @classmethod
    def sanitize_attributes(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(v, dict):
            raise ValueError("attributes must be a dictionary")
        # Ensure keys are sane and payload is bounded
        if len(v) > 200:
            raise ValueError("attributes map cannot exceed 200 keys")
        for k in v.keys():
            if not isinstance(k, str) or not re.match(r"^[a-zA-Z0-9_\-\.]{1,64}$", k):
                raise ValueError(f"Invalid attribute key format: {k}")
        return v


class IngestBatchRequest(BaseModel):
    events: List[CanonicalEvent] = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Batch of canonical events to ingest"
    )


class IngestResponse(BaseModel):
    accepted: int
    rejected: int
    duplicates: int
    event_ids: List[str]
    errors: List[Dict[str, Any]] = Field(default_factory=list)
    correlation_status: str = Field(default="ok", description="Status of threat correlation execution: 'ok' or 'degraded'")
    correlation_degraded_reason: Optional[str] = Field(default=None, description="Explanation if correlation state engine degraded")

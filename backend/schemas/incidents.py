"""
Pydantic Schemas for Phase 2: Incident Management & Aggregation.
"""

import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class IncidentSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class IncidentFindingSummary(BaseModel):
    finding_id: str
    detector_id: str
    title: str
    severity: str
    confidence: str
    created_at: datetime.datetime
    evidence: Dict[str, Any] = Field(default_factory=dict)


class IncidentCreateRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=255)
    summary: Optional[str] = None
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    finding_ids: List[str] = Field(default_factory=list)
    primary_entity_type: Optional[str] = None
    primary_entity_id: Optional[str] = None
    assigned_to: Optional[str] = None


class IncidentUpdateRequest(BaseModel):
    title: Optional[str] = Field(None, min_length=3, max_length=255)
    summary: Optional[str] = None
    severity: Optional[IncidentSeverity] = None
    status: Optional[IncidentStatus] = None
    assigned_to: Optional[str] = None


class IncidentResponse(BaseModel):
    incident_id: str
    tenant_id: str
    title: str
    summary: Optional[str] = None
    severity: IncidentSeverity
    status: IncidentStatus
    lead_detector_id: Optional[str] = None
    primary_entity_type: Optional[str] = None
    primary_entity_id: Optional[str] = None
    trace_ids: List[str] = Field(default_factory=list)
    affected_services: List[str] = Field(default_factory=list)
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    finding_count: int = 1
    assigned_to: Optional[str] = None
    resolved_at: Optional[datetime.datetime] = None
    created_at: datetime.datetime
    updated_at: datetime.datetime

    model_config = ConfigDict(from_attributes=True)


class IncidentDetailResponse(IncidentResponse):
    findings: List[IncidentFindingSummary] = Field(default_factory=list)
    events_timeline: List[Dict[str, Any]] = Field(default_factory=list)


class IncidentContainmentRequest(BaseModel):
    rationale: str = Field(..., min_length=5, description="Operational justification for incident-wide containment")
    contain_ips: bool = True
    contain_credentials: bool = True
    apply_rate_limits: bool = True


class IncidentContainmentResponse(BaseModel):
    incident_id: str
    status: str
    contained_entities_count: int
    actions_triggered: List[Dict[str, Any]] = Field(default_factory=list)
    timestamp: datetime.datetime

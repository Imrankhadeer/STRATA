"""
Pydantic Schemas for Phase 2: Threat Intelligence & Indicators of Compromise (IOC).
"""

import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class IocType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    SHA256 = "sha256"
    USER_AGENT = "user_agent"
    QUERY_PATTERN = "query_pattern"


class IocSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IocConfidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ThreatIntelIocCreateRequest(BaseModel):
    ioc_type: IocType
    value: str = Field(..., min_length=1, max_length=512)
    threat_actor: Optional[str] = None
    description: Optional[str] = None
    severity: IocSeverity = IocSeverity.HIGH
    confidence: IocConfidence = IocConfidence.HIGH
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    source: str = "manual"
    expires_in_days: Optional[int] = None


class ThreatIntelIocResponse(BaseModel):
    ioc_id: str
    tenant_id: str
    ioc_type: IocType
    value: str
    threat_actor: Optional[str] = None
    description: Optional[str] = None
    severity: IocSeverity
    confidence: IocConfidence
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    is_active: bool = True
    source: str
    expires_at: Optional[datetime.datetime] = None
    created_at: datetime.datetime
    updated_at: datetime.datetime

    model_config = ConfigDict(from_attributes=True)


class ThreatIntelMatchRequest(BaseModel):
    query: str = Field(..., min_length=1, description="Indicator, IP, domain, keyword or query pattern to match against telemetry")
    time_window_hours: int = Field(default=24, ge=1, le=720)
    limit: int = Field(default=50, ge=1, le=500)


class ThreatIntelMatchResult(BaseModel):
    query: str
    matched_iocs: List[ThreatIntelIocResponse] = Field(default_factory=list)
    matched_events_count: int = 0
    matched_events: List[Dict[str, Any]] = Field(default_factory=list)
    affected_services: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)


class MitreTechniqueSummary(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    detectors: List[str] = Field(default_factory=list)
    ioc_count: int = 0
    active_findings_count: int = 0
    mitigation_strategy: str


class MitreCoverageResponse(BaseModel):
    total_techniques_covered: int
    techniques: List[MitreTechniqueSummary] = Field(default_factory=list)
    last_evaluated_at: datetime.datetime

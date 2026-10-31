"""
Pydantic schemas for Deep-Investigation findings, hypotheses, and proposals.
"""

from typing import List, Optional, Literal, Dict, Any
from pydantic import BaseModel, Field
import datetime
import uuid


class EvidenceCitation(BaseModel):
    event_id: str
    service_id: str
    timestamp: str
    relevance: str


class Hypothesis(BaseModel):
    hypothesis_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str
    description: str
    likelihood: Literal["low", "medium", "high"]
    nature: Literal["benign", "malicious"]
    supporting_evidence: List[EvidenceCitation] = Field(default_factory=list)


class CandidateDetectorRule(BaseModel):
    rule_id: str = Field(default_factory=lambda: f"candidate.{uuid.uuid4().hex[:8]}")
    title: str
    description: str
    logic_type: Literal["sequence", "threshold", "attribute_match"]
    proposed_thresholds: Dict[str, Any] = Field(default_factory=dict)
    rationale: str
    # Safety invariant: Candidate detectors are strictly proposals until validated
    status: Literal["proposed", "shadow_evaluating", "rejected", "promoted"] = "proposed"


class InvestigationContext(BaseModel):
    finding_id: str
    tenant_id: str
    trace_id: Optional[str] = None
    finding_title: str
    finding_severity: str
    finding_evidence: Dict[str, Any]
    timeline_events: List[Dict[str, Any]]
    actors: List[str]
    services: List[str]


class InvestigationFinding(BaseModel):
    investigation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str
    tenant_id: str
    verdict: Literal["confirmed_threat", "likely_benign", "inconclusive"]
    summary: str
    hypotheses: List[Hypothesis] = Field(default_factory=list)
    candidate_rules: List[CandidateDetectorRule] = Field(default_factory=list)
    recommended_mitigations: List[str] = Field(default_factory=list)
    investigator_provider: str
    investigator_model: str
    completed_at: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
    )


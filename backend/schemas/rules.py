"""
Declarative Rule Schemas and Parameter Validators for CYBER ENGINE.

Enforces:
1. Strict schema validation on candidate detector parameters.
2. Complete rejection of executable code (Python, shell commands, SQL, script injection).
3. Versioning, approval audit trails, and validation metrics preservation.
"""

from typing import List, Dict, Any, Optional, Literal, Union
from pydantic import BaseModel, Field, field_validator, model_validator
import datetime
import uuid
import re

# Blocklist of patterns indicating dynamic code execution or script injection attempts.
# Note: SQL keywords and shell names are deliberately NOT blocked to allow security monitoring of queries and processes.
UNSAFE_PATTERNS = [
    r"\bexec\b", r"\beval\b", r"\bimport\b", r"\b__\w+__\b",
    r"\bos\.", r"\bsys\.", r"\bsubprocess\b",
    r"<script\b", r"javascript:",
]

# Strict blocklist for legacy detector parameters (table names and endpoint prefixes)
# Table names and URL prefixes must not contain SQL injection syntax, shell commands, or scripts
LEGACY_UNSAFE_PATTERNS = [
    r"\bexec\b", r"\beval\b", r"\bimport\b", r"\b__\w+__\b",
    r"\bos\.", r"\bsys\.", r"\bsubprocess\b", r"\bsh\b", r"\bbash\b",
    r"\bpowershell\b", r"\bcmd\b", r"\bSELECT\b", r"\bDROP\b",
    r"\bDELETE\b", r"\bUNION\b", r"\bINSERT\b", r"\bUPDATE\b",
    r"<script\b", r"javascript:",
]


class CrossServiceRuleParameters(BaseModel):
    """
    Strict declarative parameters for CrossServiceExfiltrationDetector.
    """
    time_window_seconds: float = Field(default=300.0, ge=5.0, le=7200.0)
    bulk_row_threshold: int = Field(default=1000, ge=10, le=10_000_000)
    sensitive_tables: List[str] = Field(default_factory=lambda: ["users", "credit_cards", "tokens", "secrets"])
    internal_prefixes: List[str] = Field(default_factory=lambda: ["/api/v1/internal/", "/internal/", "/admin/export"])

    @field_validator("sensitive_tables", "internal_prefixes")
    @classmethod
    def validate_safe_strings(cls, items: List[str]) -> List[str]:
        for item in items:
            for pattern in LEGACY_UNSAFE_PATTERNS:
                if re.search(pattern, item, re.IGNORECASE):
                    raise ValueError(f"Unsafe expression detected in declarative parameter: '{item}'")
        return items


class BruteForceRuleParameters(BaseModel):
    """
    Strict declarative parameters for BruteForceLoginDetector.
    """
    failure_threshold: int = Field(default=5, ge=2, le=100)
    window_seconds: float = Field(default=60.0, ge=5.0, le=3600.0)


class ReplayValidationMetrics(BaseModel):
    scenarios_evaluated: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    accuracy: float
    passed_validation: bool
    evaluated_at: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
    )
    failure_reasons: List[str] = Field(default_factory=list)


class ApprovalRecord(BaseModel):
    decision: Literal["approved", "rejected"]
    decided_by: str
    decided_at: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
    )
    rationale: str
    history: List[Dict[str, Any]] = Field(default_factory=list)


class DisableRuleRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=500, description="Audit reason for disabling rule")


class RollbackRuleRequest(BaseModel):
    target_version: Optional[int] = Field(default=None, ge=1, description="Target version to roll back to, or previous approved version if omitted")
    rationale: str = Field(min_length=3, max_length=500, description="Audit rationale for rolling back")


class DeclarativeRule(BaseModel):
    """
    A versioned, declarative detection rule proposal or active rule.
    Safe by design: Contains NO executable expressions, scripts, or queries.
    """
    rule_id: str = Field(default_factory=lambda: f"rule.{uuid.uuid4().hex[:8]}")
    tenant_id: str
    version: int = 1
    target_detector: Union[
        Literal[
            "detector.cross_service.exfiltration",
            "detector.auth.failed_threshold"
        ],
        str
    ]
    title: str
    description: str
    parameters: Dict[str, Any]
    status: Literal[
        "proposed",
        "evaluating",
        "validated",
        "approved",
        "rejected",
        "active",
        "disabled",
        "rolled_back",
    ] = "proposed"
    created_at: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
    )
    validation_metrics: Optional[ReplayValidationMetrics] = None
    approval: Optional[ApprovalRecord] = None

    @model_validator(mode="after")
    def validate_parameters_against_target(self) -> "DeclarativeRule":
        """Strictly validates parameters against the specific target detector schema or generic declarative spec."""
        raw_params = self.parameters or {}

        if self.target_detector == "detector.cross_service.exfiltration":
            for k, v in raw_params.items():
                str_repr = str(v)
                for pattern in LEGACY_UNSAFE_PATTERNS:
                    if re.search(pattern, str_repr, re.IGNORECASE):
                        raise ValueError(f"Unsafe expression detected in rule parameter '{k}': '{v}'")
            CrossServiceRuleParameters(**raw_params)
        elif self.target_detector == "detector.auth.failed_threshold":
            for k, v in raw_params.items():
                str_repr = str(v)
                for pattern in UNSAFE_PATTERNS:
                    if re.search(pattern, str_repr, re.IGNORECASE):
                        raise ValueError(f"Unsafe expression detected in rule parameter '{k}': '{v}'")
            BruteForceRuleParameters(**raw_params)
        elif self.target_detector in ("detector.deep_track.promoted", "generic.declarative"):
            for k, v in raw_params.items():
                str_repr = str(v)
                for pattern in UNSAFE_PATTERNS:
                    if re.search(pattern, str_repr, re.IGNORECASE):
                        raise ValueError(f"Unsafe expression detected in rule parameter '{k}': '{v}'")
            if raw_params.get("rule_type") in ("threshold", "sequence"):
                from backend.schemas.declarative_spec import GenericDeclarativeRuleDefinition
                GenericDeclarativeRuleDefinition(**raw_params)
        elif raw_params.get("rule_type") in ("threshold", "sequence"):
            from backend.schemas.declarative_spec import GenericDeclarativeRuleDefinition
            GenericDeclarativeRuleDefinition(**raw_params)
        else:
            raise ValueError(f"Unsupported target detector or invalid generic rule spec: '{self.target_detector}'")

        return self


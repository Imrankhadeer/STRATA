"""
Generic Declarative Rule Specification Schemas.

Enforces:
1. Purely declarative, operator-based detection logic.
2. Complete rejection of executable code (eval, exec, import, SQL/shell commands).
3. Bounded sizes on conditions, lists, and thresholds.
4. Support for threshold-based and multi-stage sequence correlation.
"""

from typing import List, Dict, Any, Optional, Literal, Union
from pydantic import BaseModel, Field, field_validator, model_validator
import re

# Blocklist of patterns indicating dynamic code execution or script injection attempts.
# Note: SQL keywords and shell names are deliberately NOT blocked to allow security monitoring of queries and processes.
UNSAFE_PATTERNS = [
    r"\bexec\b", r"\beval\b", r"\bimport\b", r"\b__\w+__\b",
    r"\bos\.", r"\bsys\.", r"\bsubprocess\b",
    r"<script\b", r"javascript:",
]

# Strictly controlled operator allowlist
ComparisonOperator = Literal[
    "equals",
    "not_equals",
    "in",
    "not_in",
    "starts_with",
    "starts_with_any",
    "ends_with",
    "contains",
    "gt",
    "gte",
    "lt",
    "lte",
    "exists",
    "is_true",
    "is_false",
]

SupportedGroupByField = Literal[
    "tenant_id",
    "trace_id",
    "source_resource",
    "target_resource",
    "service_id",
    "app_id",
    "request_id",
]


class FieldCondition(BaseModel):
    """
    Evaluates a single event field against a value using an operator from the allowlist.
    """
    field: str = Field(
        ...,
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_\-\.]+$",
        description="Event field path, e.g. 'event_type', 'service_id', 'attributes.table'",
    )
    operator: ComparisonOperator = Field(
        ...,
        description="Deterministic comparison operator from allowlist",
    )
    value: Optional[Union[str, int, float, bool]] = Field(
        default=None,
        description="Comparison scalar value",
    )
    values: Optional[List[Union[str, int, float]]] = Field(
        default=None,
        max_length=200,
        description="List of values for set operations like 'in', 'not_in', 'starts_with_any'",
    )

    @field_validator("field", "value", mode="before")
    @classmethod
    def sanitize_field_values(cls, v: Any) -> Any:
        if isinstance(v, str):
            for pattern in UNSAFE_PATTERNS:
                if re.search(pattern, v, re.IGNORECASE):
                    raise ValueError(f"Unsafe expression detected in field condition: '{v}'")
        return v

    @field_validator("values")
    @classmethod
    def sanitize_values_list(cls, items: Optional[List[Any]]) -> Optional[List[Any]]:
        if items is None:
            return None
        for item in items:
            if isinstance(item, str):
                for pattern in UNSAFE_PATTERNS:
                    if re.search(pattern, item, re.IGNORECASE):
                        raise ValueError(f"Unsafe expression detected in values list: '{item}'")
        return items

    @model_validator(mode="after")
    def validate_operator_value_coupling(self) -> "FieldCondition":
        if self.operator in ("in", "not_in", "starts_with_any"):
            if not self.values or len(self.values) == 0:
                raise ValueError(f"Operator '{self.operator}' requires a non-empty 'values' list")
        elif self.operator not in ("exists", "is_true", "is_false"):
            if self.value is None:
                raise ValueError(f"Operator '{self.operator}' requires a 'value'")
        return self


class SequenceStage(BaseModel):
    """
    A single stage in a multi-stage cross-service correlation sequence.
    """
    stage_id: str = Field(
        ...,
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_\-]+$",
        description="Unique identifier for the sequence stage, e.g. 'api_trigger', 'worker_anomaly'",
    )
    service_id: Optional[str] = Field(
        default=None,
        max_length=64,
        description="Optional service restriction for this stage",
    )
    conditions: List[FieldCondition] = Field(
        default_factory=list,
        max_length=20,
        description="Field conditions that match for this stage",
    )
    match_mode: Literal["all", "any"] = Field(
        default="all",
        description="Whether 'all' conditions (AND) or 'any' condition (OR) must match",
    )


class ThresholdSpec(BaseModel):
    """
    Defines threshold criteria for single-stream aggregation rules.
    """
    metric: Literal["count", "attribute_sum", "attribute_max"] = Field(
        default="count",
        description="Metric being thresholded",
    )
    metric_field: Optional[str] = Field(
        default=None,
        max_length=64,
        description="Field to sum or aggregate when metric is 'attribute_sum' or 'attribute_max'",
    )
    operator: Literal["gte", "gt", "lte", "lt", "equals"] = Field(
        default="gte",
        description="Comparison operator for threshold",
    )
    value: Union[int, float] = Field(
        ...,
        description="Numerical threshold value",
    )


class GenericDeclarativeRuleDefinition(BaseModel):
    """
    Complete generic declarative rule specification.
    Interpreted deterministically by GenericDeclarativeEvaluator.
    """
    rule_type: Literal["threshold", "sequence"] = Field(
        ...,
        description="Detection architecture: 'threshold' for counter bursts, 'sequence' for multi-stage traces",
    )
    group_by: List[SupportedGroupByField] = Field(
        default_factory=lambda: ["tenant_id", "trace_id"],
        min_length=1,
        max_length=4,
        description="Fields used to partition sliding tracking windows",
    )
    window_seconds: float = Field(
        default=300.0,
        ge=1.0,
        le=86400.0,
        description="Correlation / aggregation window duration in seconds",
    )
    severity: Literal["low", "medium", "high", "critical"] = Field(
        default="high",
        description="Default severity rating for findings produced by this rule",
    )
    evaluation_target_detector: Optional[Literal[
        "detector.auth.failed_threshold",
        "detector.cross_service.exfiltration",
    ]] = Field(
        default=None,
        description="Optional benchmark family used to evaluate a promoted generic rule against matching attack scenarios",
    )

    # Threshold-specific configuration
    conditions: Optional[List[FieldCondition]] = Field(
        default=None,
        max_length=20,
        description="Filter conditions matching candidate events (for 'threshold' rules)",
    )
    threshold: Optional[ThresholdSpec] = Field(
        default=None,
        description="Threshold trigger criteria (for 'threshold' rules)",
    )

    # Sequence-specific configuration
    sequence_stages: Optional[List[SequenceStage]] = Field(
        default=None,
        max_length=10,
        description="Ordered stages required to satisfy cross-service correlation (for 'sequence' rules)",
    )
    require_distinct_services: bool = Field(
        default=False,
        description="If True, each stage must originate from a distinct service_id",
    )

    @model_validator(mode="after")
    def validate_rule_type_requirements(self) -> "GenericDeclarativeRuleDefinition":
        if self.rule_type == "threshold":
            if not self.threshold:
                raise ValueError("Rule type 'threshold' requires a 'threshold' specification")
        elif self.rule_type == "sequence":
            if not self.sequence_stages or len(self.sequence_stages) < 2:
                raise ValueError("Rule type 'sequence' requires at least 2 'sequence_stages'")
        return self


# Canonical Declarative Rule Specifications representing Legacy Detectors
LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC = GenericDeclarativeRuleDefinition(
    rule_type="threshold",
    severity="medium",
    group_by=["tenant_id", "source_resource"],
    window_seconds=60.0,
    conditions=[
        FieldCondition(field="event_type", operator="equals", value="auth.login_failed")
    ],
    threshold=ThresholdSpec(
        metric="count",
        operator="gte",
        value=5,
    ),
)

LEGACY_EXFILTRATION_DECLARATIVE_SPEC = GenericDeclarativeRuleDefinition(
    rule_type="sequence",
    group_by=["tenant_id", "trace_id"],
    window_seconds=300.0,
    require_distinct_services=True,
    sequence_stages=[
        SequenceStage(
            stage_id="api_trigger",
            service_id="api-service",
            conditions=[
                FieldCondition(field="event_type", operator="equals", value="http.request"),
                FieldCondition(
                    field="target_resource",
                    operator="starts_with_any",
                    values=["/api/v1/internal/", "/internal/", "/admin/export"],
                ),
            ],
        ),
        SequenceStage(
            stage_id="worker_anomaly",
            service_id="worker-service",
            match_mode="any",
            conditions=[
                FieldCondition(field="event_type", operator="equals", value="worker.job_anomalous"),
                FieldCondition(field="attributes.anomaly_flag", operator="is_true"),
            ],
        ),
        SequenceStage(
            stage_id="db_bulk_access",
            service_id="database-service",
            conditions=[
                FieldCondition(field="event_type", operator="equals", value="db.bulk_query"),
                FieldCondition(
                    field="attributes.table",
                    operator="in",
                    values=["users", "credit_cards", "tokens", "credentials", "secrets"],
                ),
                FieldCondition(field="attributes.rows_affected", operator="gte", value=1000),
            ],
        ),
    ],
)


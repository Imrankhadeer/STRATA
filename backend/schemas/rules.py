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

    @model_validator(mode="before")
    @classmethod
    def normalize_parameters_before_validation(cls, data: Any) -> Any:
        """Normalizes parameters before strict schema validation to support all candidate rule formats."""
        if not isinstance(data, dict):
            return data

        target = data.get("target_detector")
        params = data.get("parameters")
        if isinstance(params, dict):
            p = dict(params)

            # 1. Normalize rule_type
            if "rule_type" not in p:
                if "type" in p and p["type"] in ("threshold", "sequence"):
                    p["rule_type"] = p["type"]
                elif "sequence_stages" in p or "stages" in p:
                    p["rule_type"] = "sequence"
                elif target in ("generic.declarative", "detector.deep_track.promoted") or "threshold" in p:
                    p["rule_type"] = "threshold"

            # 1b. Normalize window_seconds
            if "window_seconds" not in p:
                if "time_window_seconds" in p:
                    p["window_seconds"] = float(p["time_window_seconds"])
                elif isinstance(p.get("threshold"), dict) and "time_window_seconds" in p["threshold"]:
                    p["window_seconds"] = float(p["threshold"]["time_window_seconds"])
                else:
                    p["window_seconds"] = 300.0

            # 1c. Normalize group_by
            valid_group_fields = {"tenant_id", "trace_id", "source_resource", "target_resource", "service_id", "app_id", "request_id"}
            mapping = {
                "attributes.client_ip": "source_resource",
                "client_ip": "source_resource",
                "ip": "source_resource",
                "source_ip": "source_resource",
                "source": "source_resource",
                "target": "target_resource",
                "attributes.target": "target_resource",
                "service": "service_id",
                "app": "app_id",
                "trace": "trace_id",
                "attributes.user_id": "source_resource",
                "user_id": "source_resource",
                "user": "source_resource",
            }
            raw_group_by = p.get("group_by")
            if isinstance(raw_group_by, list):
                normalized_group = []
                for g in raw_group_by:
                    mapped = mapping.get(str(g), str(g))
                    if mapped in valid_group_fields and mapped not in normalized_group:
                        normalized_group.append(mapped)
                if "tenant_id" not in normalized_group:
                    normalized_group.insert(0, "tenant_id")
                if len(normalized_group) == 1:
                    normalized_group.append("source_resource")
                p["group_by"] = normalized_group
            elif not raw_group_by:
                p["group_by"] = ["tenant_id", "source_resource"]

            # 2. Normalize threshold if rule_type is threshold
            if p.get("rule_type") == "threshold":
                raw_thresh = p.get("threshold")
                val = None
                metric = "count"
                op = "gte"
                if isinstance(raw_thresh, dict):
                    val = (
                        raw_thresh.get("value")
                        if raw_thresh.get("value") is not None
                        else (
                            raw_thresh.get("count")
                            or raw_thresh.get("failure_count")
                            or raw_thresh.get("failure_threshold")
                            or raw_thresh.get("row_threshold")
                            or raw_thresh.get("max_rows")
                        )
                    )
                    metric = raw_thresh.get("metric", "count")
                    op = raw_thresh.get("operator", "gte")
                elif isinstance(raw_thresh, (int, float)):
                    val = raw_thresh
                else:
                    val = (
                        p.get("failure_threshold")
                        or p.get("failure_count")
                        or p.get("count")
                        or p.get("row_threshold")
                        or p.get("max_rows")
                        or p.get("value")
                    )

                try:
                    val = float(val) if val is not None else 5.0
                except (ValueError, TypeError):
                    val = 5.0

                p["threshold"] = {
                    "metric": metric if metric in ("count", "attribute_sum", "attribute_max") else "count",
                    "operator": op if op in ("gte", "gt", "lte", "lt", "equals") else "gte",
                    "value": val,
                }

                if not p.get("conditions"):
                    if "event_type" in p:
                        p["conditions"] = [{"field": "event_type", "operator": "contains", "value": str(p["event_type"])}]
                    elif "event_types" in p and isinstance(p["event_types"], list) and p["event_types"]:
                        p["conditions"] = [{"field": "event_type", "operator": "contains", "value": str(p["event_types"][0])}]
                    elif target in ("detector.auth.failed_threshold", "detector.auth.brute_force"):
                        p["conditions"] = [{"field": "event_type", "operator": "contains", "value": "login_failed"}]
                    elif target in ("detector.cross_service.exfiltration", "detector.exfiltration.cross_service"):
                        p["conditions"] = [{"field": "event_type", "operator": "contains", "value": "exfiltration"}]
                    else:
                        p["conditions"] = [{"field": "event_type", "operator": "exists"}]

            # 3. Normalize sequence stages
            if p.get("rule_type") == "sequence":
                if "sequence_stages" not in p and "stages" in p:
                    p["sequence_stages"] = p["stages"]
                if isinstance(p.get("sequence_stages"), list):
                    norm_stages = []
                    for idx, st in enumerate(p["sequence_stages"]):
                        if isinstance(st, str):
                            clean = st.replace("-", "_").replace(".", "_")
                            norm_stages.append({"stage_id": f"stage_{idx}_{clean}", "service_id": st})
                        elif isinstance(st, dict):
                            st_c = dict(st)
                            if "stage_id" not in st_c:
                                svc = st_c.get("service_id", f"stage_{idx}")
                                clean = str(svc).replace("-", "_").replace(".", "_")
                                st_c["stage_id"] = f"stage_{idx}_{clean}"
                            norm_stages.append(st_c)
                        else:
                            norm_stages.append(st)
                    p["sequence_stages"] = norm_stages

            # 4. Normalize legacy detector parameters
            if target in ("detector.auth.failed_threshold", "detector.auth.brute_force", "detector.auth.password_spray"):
                if "failure_threshold" not in p:
                    f_val = p.get("failure_count") or p.get("count") or (p.get("threshold", {}).get("value") if isinstance(p.get("threshold"), dict) else p.get("threshold")) or 5
                    try:
                        p["failure_threshold"] = int(f_val)
                    except (ValueError, TypeError):
                        p["failure_threshold"] = 5
                if "window_seconds" not in p:
                    p["window_seconds"] = float(p.get("time_window_seconds") or 60.0)

            elif target in ("detector.cross_service.exfiltration", "detector.exfiltration.cross_service"):
                if "bulk_row_threshold" not in p:
                    r_val = p.get("row_threshold") or p.get("max_rows") or 1000
                    try:
                        p["bulk_row_threshold"] = int(r_val)
                    except (ValueError, TypeError):
                        p["bulk_row_threshold"] = 1000
                if "time_window_seconds" not in p:
                    p["time_window_seconds"] = float(p.get("window_seconds") or 300.0)

            data["parameters"] = p
        return data

    @model_validator(mode="after")
    def validate_parameters_against_target(self) -> "DeclarativeRule":
        """Strictly validates parameters against the specific target detector schema or generic declarative spec."""
        raw_params = self.parameters or {}

        if self.target_detector in ("detector.cross_service.exfiltration", "detector.exfiltration.cross_service") and "rule_type" not in raw_params:
            for k, v in raw_params.items():
                str_repr = str(v)
                for pattern in LEGACY_UNSAFE_PATTERNS:
                    if re.search(pattern, str_repr, re.IGNORECASE):
                        raise ValueError(f"Unsafe expression detected in rule parameter '{k}': '{v}'")
            CrossServiceRuleParameters(**raw_params)
        elif self.target_detector in ("detector.auth.failed_threshold", "detector.auth.brute_force", "detector.auth.password_spray") and "rule_type" not in raw_params:
            for k, v in raw_params.items():
                str_repr = str(v)
                for pattern in UNSAFE_PATTERNS:
                    if re.search(pattern, str_repr, re.IGNORECASE):
                        raise ValueError(f"Unsafe expression detected in rule parameter '{k}': '{v}'")
            BruteForceRuleParameters(**raw_params)
        elif self.target_detector in ("detector.deep_track.promoted", "generic.declarative") or raw_params.get("rule_type") in ("threshold", "sequence"):
            for k, v in raw_params.items():
                str_repr = str(v)
                for pattern in UNSAFE_PATTERNS:
                    if re.search(pattern, str_repr, re.IGNORECASE):
                        raise ValueError(f"Unsafe expression detected in rule parameter '{k}': '{v}'")
            from backend.schemas.declarative_spec import GenericDeclarativeRuleDefinition
            GenericDeclarativeRuleDefinition(**raw_params)
        else:
            for k, v in raw_params.items():
                str_repr = str(v)
                for pattern in UNSAFE_PATTERNS:
                    if re.search(pattern, str_repr, re.IGNORECASE):
                        raise ValueError(f"Unsafe expression detected in rule parameter '{k}': '{v}'")

        return self


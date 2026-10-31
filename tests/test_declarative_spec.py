"""
Unit tests for Generic Declarative Rule Specification Schema.

Validates:
1. Valid threshold rule schema passes.
2. Valid sequence correlation rule schema passes.
3. Operators allowlist enforcement.
4. Complete rejection of executable code (eval, exec, import, SQL/script injection).
5. Validation failures on incomplete or malformed specs.
6. DeclarativeRule integration preserving backward compatibility.
"""

import pytest
from pydantic import ValidationError
from backend.schemas.declarative_spec import (
    FieldCondition,
    SequenceStage,
    ThresholdSpec,
    GenericDeclarativeRuleDefinition,
)
from backend.schemas.rules import DeclarativeRule


def test_valid_threshold_spec():
    spec = GenericDeclarativeRuleDefinition(
        rule_type="threshold",
        group_by=["tenant_id", "source_resource"],
        window_seconds=60.0,
        conditions=[
            FieldCondition(field="event_type", operator="equals", value="auth.login_failed")
        ],
        threshold=ThresholdSpec(metric="count", operator="gte", value=5),
    )
    assert spec.rule_type == "threshold"
    assert spec.threshold.value == 5
    assert len(spec.conditions) == 1


def test_valid_sequence_spec():
    spec = GenericDeclarativeRuleDefinition(
        rule_type="sequence",
        group_by=["tenant_id", "trace_id"],
        window_seconds=300.0,
        require_distinct_services=True,
        sequence_stages=[
            SequenceStage(
                stage_id="api_stage",
                service_id="api-service",
                conditions=[
                    FieldCondition(
                        field="target_resource",
                        operator="starts_with_any",
                        values=["/api/v1/internal/", "/admin/export"],
                    )
                ],
            ),
            SequenceStage(
                stage_id="worker_stage",
                service_id="worker-service",
                conditions=[
                    FieldCondition(field="attributes.anomaly_flag", operator="is_true")
                ],
            ),
            SequenceStage(
                stage_id="db_stage",
                service_id="database-service",
                conditions=[
                    FieldCondition(
                        field="attributes.table",
                        operator="in",
                        values=["users", "credit_cards", "tokens"],
                    ),
                    FieldCondition(field="attributes.rows_affected", operator="gte", value=1000),
                ],
            ),
        ],
    )
    assert spec.rule_type == "sequence"
    assert len(spec.sequence_stages) == 3
    assert spec.require_distinct_services is True


def test_rejects_unsafe_executable_code_in_condition():
    with pytest.raises(ValidationError) as exc:
        FieldCondition(field="target", operator="equals", value="__import__('os').system('id')")
    assert "Unsafe expression detected" in str(exc.value)

    with pytest.raises(ValidationError) as exc2:
        FieldCondition(field="target", operator="equals", value="SELECT * FROM users; DROP TABLE events;")
    assert "Unsafe expression detected" in str(exc2.value)


def test_rejects_unsafe_executable_code_in_values_list():
    with pytest.raises(ValidationError) as exc:
        FieldCondition(
            field="target",
            operator="in",
            values=["users", "eval('1+1')"],
        )
    assert "Unsafe expression detected" in str(exc.value)


def test_operator_value_coupling_validation():
    # 'in' requires non-empty values
    with pytest.raises(ValidationError) as exc:
        FieldCondition(field="target", operator="in", values=[])
    assert "requires a non-empty 'values' list" in str(exc.value)

    # 'equals' requires a scalar value
    with pytest.raises(ValidationError) as exc2:
        FieldCondition(field="target", operator="equals", value=None)
    assert "requires a 'value'" in str(exc2.value)


def test_sequence_requires_at_least_two_stages():
    with pytest.raises(ValidationError) as exc:
        GenericDeclarativeRuleDefinition(
            rule_type="sequence",
            sequence_stages=[
                SequenceStage(stage_id="single", conditions=[])
            ],
        )
    assert "requires at least 2 'sequence_stages'" in str(exc.value)


def test_threshold_rule_requires_threshold_spec():
    with pytest.raises(ValidationError) as exc:
        GenericDeclarativeRuleDefinition(
            rule_type="threshold",
            conditions=[],
        )
    assert "requires a 'threshold' specification" in str(exc.value)


def test_declarative_rule_model_accepts_generic_spec():
    rule = DeclarativeRule(
        tenant_id="tenant-alpha",
        target_detector="generic.evaluator.v1",
        title="Custom Resource Burst",
        description="Flags high volume resource requests",
        parameters={
            "rule_type": "threshold",
            "group_by": ["tenant_id", "source_resource"],
            "window_seconds": 30.0,
            "conditions": [
                {"field": "service_id", "operator": "equals", "value": "api-service"}
            ],
            "threshold": {"metric": "count", "operator": "gte", "value": 20},
        },
    )
    assert rule.title == "Custom Resource Burst"
    assert rule.parameters["threshold"]["value"] == 20


def test_backward_compatibility_with_legacy_targets():
    # Legacy cross-service exfiltration parameters still validate properly
    rule_legacy = DeclarativeRule(
        tenant_id="tenant-alpha",
        target_detector="detector.cross_service.exfiltration",
        title="Legacy Exfil Rule",
        description="Legacy threshold parameters",
        parameters={
            "time_window_seconds": 120.0,
            "bulk_row_threshold": 500,
            "sensitive_tables": ["users", "credit_cards"],
            "internal_prefixes": ["/api/v1/internal/"],
        },
    )
    assert rule_legacy.target_detector == "detector.cross_service.exfiltration"
    assert rule_legacy.parameters["bulk_row_threshold"] == 500


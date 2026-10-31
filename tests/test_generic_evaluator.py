"""
Isolated Unit Tests for GenericDeclarativeEvaluator.

Verifies:
1. Every supported operator (equals, not_equals, in, not_in, starts_with, starts_with_any,
   ends_with, contains, gt, gte, lt, lte, exists, is_true, is_false).
2. Threshold counting, aggregation and window reset.
3. Sequence ordering and multi-stage completion.
4. Out-of-order events.
5. Duplicate event handling.
6. Expired time windows.
7. Multiple simultaneous concurrent traces.
8. Tenant boundary isolation.
9. Finding deduplication (no duplicate finding per trace/key).
10. Memory bounds and LRU eviction.
11. Invalid and missing event fields (fail-closed behavior).
"""

import pytest
import datetime
import uuid
from backend.schemas.events import CanonicalEvent, SeverityLevel
from backend.schemas.declarative_spec import (
    GenericDeclarativeRuleDefinition,
    FieldCondition,
    SequenceStage,
    ThresholdSpec,
)
from backend.detection.generic_evaluator import (
    GenericDeclarativeEvaluator,
    _evaluate_condition,
)


def _make_event(
    event_type: str = "test.event",
    service_id: str = "api-service",
    tenant_id: str = "tenant-alpha",
    trace_id: str = "trace-001",
    source_resource: str = "10.0.0.1",
    target_resource: str = "/api/v1/resource",
    attributes: dict = None,
    delta_seconds: float = 0.0,
    event_id: str = None,
) -> CanonicalEvent:
    base_time = datetime.datetime(2026, 10, 30, 12, 0, 0, tzinfo=datetime.timezone.utc)
    ts = base_time + datetime.timedelta(seconds=delta_seconds)
    return CanonicalEvent(
        event_id=event_id or f"evt_{uuid.uuid4().hex[:8]}",
        timestamp=ts,
        tenant_id=tenant_id,
        app_id="app-1",
        service_id=service_id,
        event_type=event_type,
        severity=SeverityLevel.INFO,
        source_resource=source_resource,
        target_resource=target_resource,
        trace_id=trace_id,
        attributes=attributes or {},
    )


# ---------------------------------------------------------------------------
# 1. Operators Allowlist Isolated Tests
# ---------------------------------------------------------------------------

def test_all_comparison_operators():
    ev = _make_event(
        target_resource="/admin/users/export",
        attributes={
            "role": "admin",
            "tier": 2,
            "score": 95.5,
            "flag": True,
            "tag": "sensitive_data",
        },
    )

    # equals / not_equals
    assert _evaluate_condition(ev, FieldCondition(field="attributes.role", operator="equals", value="admin"))
    assert not _evaluate_condition(ev, FieldCondition(field="attributes.role", operator="equals", value="user"))
    assert _evaluate_condition(ev, FieldCondition(field="attributes.role", operator="not_equals", value="guest"))

    # in / not_in
    assert _evaluate_condition(ev, FieldCondition(field="attributes.role", operator="in", values=["admin", "super"]))
    assert not _evaluate_condition(ev, FieldCondition(field="attributes.role", operator="in", values=["dev", "test"]))
    assert _evaluate_condition(ev, FieldCondition(field="attributes.role", operator="not_in", values=["user", "guest"]))

    # starts_with / starts_with_any / ends_with / contains
    assert _evaluate_condition(ev, FieldCondition(field="target_resource", operator="starts_with", value="/admin/"))
    assert _evaluate_condition(ev, FieldCondition(field="target_resource", operator="starts_with_any", values=["/v1/", "/admin/"]))
    assert _evaluate_condition(ev, FieldCondition(field="target_resource", operator="ends_with", value="/export"))
    assert _evaluate_condition(ev, FieldCondition(field="attributes.tag", operator="contains", value="sensitive"))

    # gt / gte / lt / lte
    assert _evaluate_condition(ev, FieldCondition(field="attributes.score", operator="gt", value=90))
    assert _evaluate_condition(ev, FieldCondition(field="attributes.score", operator="gte", value=95.5))
    assert _evaluate_condition(ev, FieldCondition(field="attributes.tier", operator="lt", value=3))
    assert _evaluate_condition(ev, FieldCondition(field="attributes.tier", operator="lte", value=2))

    # exists / is_true / is_false
    assert _evaluate_condition(ev, FieldCondition(field="attributes.flag", operator="exists"))
    assert not _evaluate_condition(ev, FieldCondition(field="attributes.missing", operator="exists"))
    assert _evaluate_condition(ev, FieldCondition(field="attributes.flag", operator="is_true"))
    assert not _evaluate_condition(ev, FieldCondition(field="attributes.flag", operator="is_false"))


# ---------------------------------------------------------------------------
# 2. Threshold Counting, Aggregation & Reset
# ---------------------------------------------------------------------------

def test_threshold_counter_and_reset():
    spec = GenericDeclarativeRuleDefinition(
        rule_type="threshold",
        group_by=["tenant_id", "source_resource"],
        window_seconds=60.0,
        conditions=[
            FieldCondition(field="event_type", operator="equals", value="auth.failed")
        ],
        threshold=ThresholdSpec(metric="count", operator="gte", value=3),
    )
    evaluator = GenericDeclarativeEvaluator(
        rule_id="rule.test.burst",
        version=1,
        title="Auth Burst",
        description="Flags 3 failed auths",
        spec=spec,
    )

    actor = "192.168.1.10"
    # Event 1 & 2 -> no trigger
    assert evaluator.evaluate(_make_event(event_type="auth.failed", source_resource=actor, delta_seconds=1)) is None
    assert evaluator.evaluate(_make_event(event_type="auth.failed", source_resource=actor, delta_seconds=2)) is None

    # Event 3 -> triggers finding
    finding = evaluator.evaluate(_make_event(event_type="auth.failed", source_resource=actor, delta_seconds=3))
    assert finding is not None
    assert finding.detector_id == "rule.test.burst"
    assert finding.detector_version == "1"
    assert finding.evidence["attempt_count"] == 3

    # Finding deduplication: Subsequent matching event within same window is suppressed
    assert evaluator.evaluate(_make_event(event_type="auth.failed", source_resource=actor, delta_seconds=4)) is None

    # Reset clears internal state
    evaluator.reset()
    assert evaluator.evaluate(_make_event(event_type="auth.failed", source_resource=actor, delta_seconds=1)) is None


def test_threshold_attribute_sum_metric():
    spec = GenericDeclarativeRuleDefinition(
        rule_type="threshold",
        group_by=["tenant_id", "source_resource"],
        window_seconds=30.0,
        conditions=[
            FieldCondition(field="event_type", operator="equals", value="db.query")
        ],
        threshold=ThresholdSpec(
            metric="attribute_sum",
            metric_field="attributes.rows",
            operator="gte",
            value=1000,
        ),
    )
    evaluator = GenericDeclarativeEvaluator(
        rule_id="rule.test.sum",
        version=1,
        title="High Query Rows",
        description="Flags total rows >= 1000",
        spec=spec,
    )

    actor = "etl-worker-1"
    # 400 + 400 = 800 -> no trigger
    assert evaluator.evaluate(_make_event(event_type="db.query", source_resource=actor, attributes={"rows": 400}, delta_seconds=1)) is None
    assert evaluator.evaluate(_make_event(event_type="db.query", source_resource=actor, attributes={"rows": 400}, delta_seconds=2)) is None

    # + 300 = 1100 -> triggers finding!
    finding = evaluator.evaluate(_make_event(event_type="db.query", source_resource=actor, attributes={"rows": 300}, delta_seconds=3))
    assert finding is not None
    assert finding.evidence["metric_value"] == 1100.0


# ---------------------------------------------------------------------------
# 3. Sequence Ordering, Cross-Service & Out-Of-Order Events
# ---------------------------------------------------------------------------

def _build_test_sequence_evaluator():
    spec = GenericDeclarativeRuleDefinition(
        rule_type="sequence",
        group_by=["tenant_id", "trace_id"],
        window_seconds=300.0,
        require_distinct_services=True,
        sequence_stages=[
            SequenceStage(
                stage_id="stage_api",
                service_id="api-service",
                conditions=[
                    FieldCondition(field="target_resource", operator="starts_with", value="/api/v1/internal/")
                ],
            ),
            SequenceStage(
                stage_id="stage_worker",
                service_id="worker-service",
                conditions=[
                    FieldCondition(field="attributes.anomaly_flag", operator="is_true")
                ],
            ),
            SequenceStage(
                stage_id="stage_db",
                service_id="database-service",
                conditions=[
                    FieldCondition(field="attributes.table", operator="in", values=["users", "credit_cards"]),
                    FieldCondition(field="attributes.rows", operator="gte", value=500),
                ],
            ),
        ],
    )
    return GenericDeclarativeEvaluator(
        rule_id="rule.test.sequence",
        version=2,
        title="Exfil Sequence",
        description="API -> Worker -> DB sequence",
        spec=spec,
    )


def test_sequence_normal_order_triggers_finding():
    evaluator = _build_test_sequence_evaluator()
    trace = "trc-seq-01"

    ev1 = _make_event(service_id="api-service", target_resource="/api/v1/internal/export", trace_id=trace, delta_seconds=1)
    ev2 = _make_event(service_id="worker-service", attributes={"anomaly_flag": True}, trace_id=trace, delta_seconds=5)
    ev3 = _make_event(service_id="database-service", attributes={"table": "credit_cards", "rows": 800}, trace_id=trace, delta_seconds=10)

    assert evaluator.evaluate(ev1) is None
    assert evaluator.evaluate(ev2) is None
    finding = evaluator.evaluate(ev3)

    assert finding is not None
    assert finding.detector_id == "rule.test.sequence"
    assert finding.detector_version == "2"
    assert finding.evidence["trace_id"] == trace
    assert "stage_api" in finding.evidence["stages"]
    assert "stage_worker" in finding.evidence["stages"]
    assert "stage_db" in finding.evidence["stages"]


def test_sequence_out_of_order_events_still_correlates():
    evaluator = _build_test_sequence_evaluator()
    trace = "trc-seq-ooo"

    # Distributed network latency: DB event arrives before Worker event
    ev_api = _make_event(service_id="api-service", target_resource="/api/v1/internal/export", trace_id=trace, delta_seconds=1)
    ev_db = _make_event(service_id="database-service", attributes={"table": "credit_cards", "rows": 600}, trace_id=trace, delta_seconds=3)
    ev_worker = _make_event(service_id="worker-service", attributes={"anomaly_flag": True}, trace_id=trace, delta_seconds=6)

    assert evaluator.evaluate(ev_api) is None
    assert evaluator.evaluate(ev_db) is None
    finding = evaluator.evaluate(ev_worker)
    assert finding is not None
    assert finding.evidence["trace_id"] == trace


def test_sequence_duplicate_events_ignored():
    evaluator = _build_test_sequence_evaluator()
    trace = "trc-seq-dup"

    ev1 = _make_event(event_id="evt-fixed-1", service_id="api-service", target_resource="/api/v1/internal/export", trace_id=trace, delta_seconds=1)
    # Feed same event multiple times (re-delivery)
    assert evaluator.evaluate(ev1) is None
    assert evaluator.evaluate(ev1) is None

    ev2 = _make_event(service_id="worker-service", attributes={"anomaly_flag": True}, trace_id=trace, delta_seconds=2)
    ev3 = _make_event(service_id="database-service", attributes={"table": "users", "rows": 1000}, trace_id=trace, delta_seconds=3)

    assert evaluator.evaluate(ev2) is None
    finding = evaluator.evaluate(ev3)
    assert finding is not None


def test_sequence_expired_time_window_does_not_trigger():
    evaluator = _build_test_sequence_evaluator()
    trace = "trc-expired"

    # Stage 1 at t=0
    ev1 = _make_event(service_id="api-service", target_resource="/api/v1/internal/export", trace_id=trace, delta_seconds=0)
    # Stage 2 at t=5
    ev2 = _make_event(service_id="worker-service", attributes={"anomaly_flag": True}, trace_id=trace, delta_seconds=5)
    # Stage 3 at t=400s (> window_seconds 300.0)
    ev3 = _make_event(service_id="database-service", attributes={"table": "users", "rows": 1000}, trace_id=trace, delta_seconds=400)

    assert evaluator.evaluate(ev1) is None
    assert evaluator.evaluate(ev2) is None
    assert evaluator.evaluate(ev3) is None  # Window expired!


# ---------------------------------------------------------------------------
# 4. Multi-Tenant & Multi-Trace Isolation
# ---------------------------------------------------------------------------

def test_multiple_concurrent_traces_and_tenant_isolation():
    evaluator = _build_test_sequence_evaluator()

    # Trace A (tenant-alpha) & Trace B (tenant-beta)
    ev_a1 = _make_event(service_id="api-service", target_resource="/api/v1/internal/export", trace_id="trc-shared", tenant_id="tenant-alpha")
    ev_b1 = _make_event(service_id="api-service", target_resource="/api/v1/internal/export", trace_id="trc-shared", tenant_id="tenant-beta")

    assert evaluator.evaluate(ev_a1) is None
    assert evaluator.evaluate(ev_b1) is None

    # Complete only Tenant Alpha's sequence
    ev_a2 = _make_event(service_id="worker-service", attributes={"anomaly_flag": True}, trace_id="trc-shared", tenant_id="tenant-alpha", delta_seconds=2)
    ev_a3 = _make_event(service_id="database-service", attributes={"table": "users", "rows": 500}, trace_id="trc-shared", tenant_id="tenant-alpha", delta_seconds=4)

    assert evaluator.evaluate(ev_a2) is None
    finding_alpha = evaluator.evaluate(ev_a3)
    assert finding_alpha is not None
    assert finding_alpha.tenant_id == "tenant-alpha"

    # Tenant Beta never completed stages 2 & 3, so feeding another event on Beta should not trigger
    ev_b_unrelated = _make_event(service_id="database-service", attributes={"table": "logs", "rows": 10}, trace_id="trc-shared", tenant_id="tenant-beta", delta_seconds=5)
    assert evaluator.evaluate(ev_b_unrelated) is None


# ---------------------------------------------------------------------------
# 5. Missing Fields, Fail-Closed & Memory Bounds
# ---------------------------------------------------------------------------

def test_missing_and_invalid_event_fields_fail_closed():
    evaluator = _build_test_sequence_evaluator()

    # Missing trace_id -> fails closed immediately
    ev_no_trace = _make_event(trace_id=None, service_id="api-service", target_resource="/api/v1/internal/export")
    assert evaluator.evaluate(ev_no_trace) is None

    # Missing tenant_id -> fails closed immediately
    ev_no_tenant = _make_event(tenant_id=None, trace_id="trc-1", service_id="api-service", target_resource="/api/v1/internal/export")
    assert evaluator.evaluate(ev_no_tenant) is None


def test_memory_bounds_and_lru_eviction():
    spec = GenericDeclarativeRuleDefinition(
        rule_type="threshold",
        group_by=["tenant_id", "trace_id"],
        window_seconds=100.0,
        conditions=[FieldCondition(field="event_type", operator="equals", value="ping")],
        threshold=ThresholdSpec(metric="count", operator="gte", value=5),
    )
    # Tiny capacity of 3 items for testing LRU eviction
    evaluator = GenericDeclarativeEvaluator(
        rule_id="rule.lru",
        version=1,
        title="LRU Test",
        description="LRU cap",
        spec=spec,
        max_tracked_keys=3,
    )

    # Insert 3 keys
    evaluator.evaluate(_make_event(event_type="ping", trace_id="t1"))
    evaluator.evaluate(_make_event(event_type="ping", trace_id="t2"))
    evaluator.evaluate(_make_event(event_type="ping", trace_id="t3"))
    assert len(evaluator._threshold_windows) == 3

    # Insert 4th key -> oldest key (t1) evicted
    evaluator.evaluate(_make_event(event_type="ping", trace_id="t4"))
    assert len(evaluator._threshold_windows) == 3
    assert ("tenant-alpha", "t1") not in evaluator._threshold_windows
    assert ("tenant-alpha", "t4") in evaluator._threshold_windows


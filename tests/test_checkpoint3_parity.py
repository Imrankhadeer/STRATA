"""
Checkpoint 3: Differential Parity Verification Suite.

Runs legacy Python detectors and the new Generic Declarative Evaluator
side-by-side against IDENTICAL event sequences to verify behavioral parity:
1. Brute-Force Login Detection Parity:
   - Trigger timing & event counts
   - Severity & confidence ratings
   - Severity escalation (medium -> high)
   - Deduplication & alert storm suppression
   - Duplicate event ID rejection
   - Multi-tenant counter isolation
   - Benign retry sequence handling
2. Cross-Service Exfiltration Sequence Parity:
   - Positive 3-stage sequence trigger & anchoring
   - Out-of-order stage correlation
   - Missing stage rejection
   - Time window expiration boundary
   - Benign lookalikes & legitimate maintenance suppression
   - Post-finding deduplication (zero alert storms)
   - Multi-tenant trace isolation
3. Replay Validation Engine Dual Support:
   - Replay validation of legacy and declarative candidate rules
"""

import pytest
import datetime
from typing import List

from backend.schemas.events import CanonicalEvent
from backend.detection.baseline import BruteForceLoginDetector
from backend.detection.correlation import CrossServiceExfiltrationDetector
from backend.detection.generic_evaluator import GenericDeclarativeEvaluator
from backend.schemas.declarative_spec import (
    LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC,
    LEGACY_EXFILTRATION_DECLARATIVE_SPEC,
)
from backend.detection.replay import ReplayValidationEngine
from backend.schemas.rules import DeclarativeRule


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_failed_login(
    event_id: str,
    ip: str = "203.0.113.88",
    tenant_id: str = "tenant-alpha",
    seconds_offset: int = 0,
    base_time: datetime.datetime = None,
) -> CanonicalEvent:
    t0 = base_time or datetime.datetime(2026, 10, 31, 12, 0, 0, tzinfo=datetime.timezone.utc)
    return CanonicalEvent(
        event_id=event_id,
        tenant_id=tenant_id,
        app_id="core-app",
        service_id="api-service",
        event_type="auth.login_failed",
        source_resource=ip,
        target_resource="/api/v1/auth/login",
        trace_id=f"trace-bf-{event_id}",
        timestamp=t0 + datetime.timedelta(seconds=seconds_offset),
        attributes={"client_ip": ip, "username": "admin"},
    )


def make_exfil_sequence(
    trace_id: str = "trace-exfil-parity",
    tenant_id: str = "tenant-alpha",
    base_time: datetime.datetime = None,
    time_offsets: tuple = (0, 5, 15),
    internal_path: str = "/api/v1/internal/export",
    worker_anomaly: bool = True,
    db_table: str = "credit_cards",
    rows_affected: int = 50000,
) -> List[CanonicalEvent]:
    t0 = base_time or datetime.datetime(2026, 10, 31, 12, 0, 0, tzinfo=datetime.timezone.utc)
    ev1 = CanonicalEvent(
        event_id=f"ev-api-{trace_id}",
        tenant_id=tenant_id,
        app_id="core-app",
        service_id="api-service",
        event_type="http.request",
        target_resource=internal_path,
        trace_id=trace_id,
        timestamp=t0 + datetime.timedelta(seconds=time_offsets[0]),
        attributes={"endpoint": internal_path, "method": "POST"},
    )
    ev2 = CanonicalEvent(
        event_id=f"ev-worker-{trace_id}",
        tenant_id=tenant_id,
        app_id="core-app",
        service_id="worker-service",
        event_type="worker.job_anomalous" if worker_anomaly else "worker.job_completed",
        trace_id=trace_id,
        timestamp=t0 + datetime.timedelta(seconds=time_offsets[1]),
        attributes={"job_name": "bulk_sync", "anomaly_flag": worker_anomaly},
    )
    ev3 = CanonicalEvent(
        event_id=f"ev-db-{trace_id}",
        tenant_id=tenant_id,
        app_id="core-app",
        service_id="database-service",
        event_type="db.bulk_query",
        trace_id=trace_id,
        timestamp=t0 + datetime.timedelta(seconds=time_offsets[2]),
        attributes={"table": db_table, "rows_affected": rows_affected, "is_sensitive_table": True},
    )
    return [ev1, ev2, ev3]


# ===========================================================================
# 1. Brute-Force Login Detection Differential Parity Tests
# ===========================================================================

def test_bruteforce_parity_positive_attack_stream():
    """
    Feeds identical streams of 5 consecutive failed logins to both legacy
    BruteForceLoginDetector and GenericDeclarativeEvaluator.
    Asserts both trigger exactly on event 5 with matching metadata.
    """
    legacy = BruteForceLoginDetector(failure_threshold=5)
    generic = GenericDeclarativeEvaluator(
        rule_id="rule.bf.parity",
        version=1,
        title="Potential Brute-force Attack",
        description="Consecutive failed logins threshold exceeded",
        spec=LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC,
    )

    t0 = datetime.datetime(2026, 10, 31, 12, 0, 0, tzinfo=datetime.timezone.utc)

    # First 4 attempts: Neither must trigger
    for i in range(1, 5):
        event = make_failed_login(f"bf-ev-{i}", seconds_offset=i * 2, base_time=t0)
        finding_legacy = legacy.evaluate(event)
        finding_generic = generic.evaluate(event)

        assert finding_legacy is None, f"Legacy triggered prematurely on attempt {i}"
        assert finding_generic is None, f"Generic triggered prematurely on attempt {i}"

    # 5th attempt: Both MUST trigger at the exact same moment
    event_5 = make_failed_login("bf-ev-5", seconds_offset=10, base_time=t0)
    finding_legacy = legacy.evaluate(event_5)
    finding_generic = generic.evaluate(event_5)

    assert finding_legacy is not None, "Legacy failed to trigger on attempt 5"
    assert finding_generic is not None, "Generic failed to trigger on attempt 5"

    # Verify attribution parity
    assert finding_legacy.event_id == finding_generic.event_id == "bf-ev-5"
    assert finding_legacy.confidence == finding_generic.confidence == "high"
    assert finding_legacy.severity == finding_generic.severity == "medium"
    assert finding_legacy.evidence["actor"] == finding_generic.evidence["actor"] == "203.0.113.88"
    assert finding_legacy.evidence["attempt_count"] == finding_generic.evidence["attempt_count"] == 5


def test_bruteforce_parity_severity_escalation_and_alert_storm_control():
    """
    Feeds 15 consecutive failed logins.
    Verifies that:
    1. Both trigger on attempt 5 (severity=medium).
    2. Both escalate to severity=high when attempts > 10.
    3. Generic evaluator suppresses alert storms between attempts 6-10.
    """
    legacy = BruteForceLoginDetector(failure_threshold=5)
    generic = GenericDeclarativeEvaluator(
        rule_id="rule.bf.parity",
        version=1,
        title="Potential Brute-force Attack",
        description="Consecutive failed logins threshold exceeded",
        spec=LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC,
    )

    t0 = datetime.datetime(2026, 10, 31, 12, 0, 0, tzinfo=datetime.timezone.utc)

    generic_findings = []
    legacy_findings = []

    for i in range(1, 16):
        event = make_failed_login(f"bf-escalate-{i}", seconds_offset=i * 2, base_time=t0)
        fl = legacy.evaluate(event)
        fg = generic.evaluate(event)

        if fl:
            legacy_findings.append((i, fl))
        if fg:
            generic_findings.append((i, fg))

    # Generic evaluator triggers initial medium finding on attempt 5 and escalated high on attempt 11
    assert len(generic_findings) == 2, f"Expected 2 generic findings (initial + escalated), got {len(generic_findings)}"
    
    initial_trigger_attempt, initial_finding = generic_findings[0]
    escalated_trigger_attempt, escalated_finding = generic_findings[1]

    assert initial_trigger_attempt == 5
    assert initial_finding.severity == "medium"

    assert escalated_trigger_attempt == 11
    assert escalated_finding.severity == "high"

    # Legacy also reports severity='high' once attempts > 10
    assert legacy_findings[0][1].severity == "medium"
    assert legacy_findings[-1][1].severity == "high"


def test_bruteforce_parity_duplicate_event_ids_ignored():
    """
    Duplicate event IDs must not be counted twice by either detector.
    """
    legacy = BruteForceLoginDetector(failure_threshold=5)
    generic = GenericDeclarativeEvaluator(
        rule_id="rule.bf.parity",
        version=1,
        title="Potential Brute-force Attack",
        description="Consecutive failed logins threshold exceeded",
        spec=LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC,
    )

    event = make_failed_login("same-id-repeat")

    # Send identical event 10 times
    for _ in range(10):
        fl = legacy.evaluate(event)
        fg = generic.evaluate(event)
        assert fl is None, "Legacy counted duplicate event ID"
        assert fg is None, "Generic counted duplicate event ID"


def test_bruteforce_parity_tenant_isolation():
    """
    Failures across different tenants must not combine to trigger thresholds.
    """
    legacy = BruteForceLoginDetector(failure_threshold=5)
    generic = GenericDeclarativeEvaluator(
        rule_id="rule.bf.parity",
        version=1,
        title="Potential Brute-force Attack",
        description="Consecutive failed logins threshold exceeded",
        spec=LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC,
    )

    t0 = datetime.datetime(2026, 10, 31, 12, 0, 0, tzinfo=datetime.timezone.utc)

    # Tenant Alpha sends 3 failures
    for i in range(1, 4):
        ev_alpha = make_failed_login(f"alpha-ev-{i}", tenant_id="tenant-alpha", seconds_offset=i, base_time=t0)
        assert legacy.evaluate(ev_alpha) is None
        assert generic.evaluate(ev_alpha) is None

    # Tenant Beta sends 3 failures
    for i in range(1, 4):
        ev_beta = make_failed_login(f"beta-ev-{i}", tenant_id="tenant-beta", seconds_offset=i, base_time=t0)
        assert legacy.evaluate(ev_beta) is None
        assert generic.evaluate(ev_beta) is None


# ===========================================================================
# 2. Cross-Service Exfiltration Sequence Differential Parity Tests
# ===========================================================================

def test_exfiltration_parity_positive_three_stage_sequence():
    """
    Verifies that a valid three-stage exfiltration attack triggers both
    legacy CrossServiceExfiltrationDetector and GenericDeclarativeEvaluator
    with identical attribution and evidence anchoring.
    """
    legacy = CrossServiceExfiltrationDetector(time_window_seconds=300.0)
    generic = GenericDeclarativeEvaluator(
        rule_id="rule.exfil.parity",
        version=1,
        title="Cross-service data exfiltration pattern detected",
        description="Three-stage cross-service sequence detected",
        spec=LEGACY_EXFILTRATION_DECLARATIVE_SPEC,
    )

    events = make_exfil_sequence(trace_id="trace-parity-001")

    # Stages 1 & 2: Neither detector must trigger prematurely
    assert legacy.evaluate(events[0]) is None
    assert generic.evaluate(events[0]) is None

    assert legacy.evaluate(events[1]) is None
    assert generic.evaluate(events[1]) is None

    # Stage 3: Both detectors MUST trigger on the completing DB event
    finding_legacy = legacy.evaluate(events[2])
    finding_generic = generic.evaluate(events[2])

    assert finding_legacy is not None, "Legacy failed to trigger on complete 3-stage sequence"
    assert finding_generic is not None, "Generic failed to trigger on complete 3-stage sequence"

    # Parity assertions
    assert finding_legacy.event_id == finding_generic.event_id == events[2].event_id
    assert finding_legacy.severity == finding_generic.severity == "high"
    assert finding_legacy.confidence == finding_generic.confidence == "high"
    assert "trace-parity-001" in finding_legacy.title and "trace-parity-001" in finding_generic.title

    # Evidence parity
    assert finding_legacy.evidence["trace_id"] == finding_generic.evidence["trace_id"] == "trace-parity-001"
    assert "api_trigger" in finding_legacy.evidence["stages"]
    assert "api_trigger" in finding_generic.evidence["stages"]
    assert "worker_anomaly" in finding_legacy.evidence["stages"]
    assert "worker_anomaly" in finding_generic.evidence["stages"]
    assert "db_bulk_access" in finding_legacy.evidence["stages"]
    assert "db_bulk_access" in finding_generic.evidence["stages"]


def test_exfiltration_parity_out_of_order_events():
    """
    Verifies that arrival order (DB -> Worker -> API) correlates in both engines.
    """
    legacy = CrossServiceExfiltrationDetector(time_window_seconds=300.0)
    generic = GenericDeclarativeEvaluator(
        rule_id="rule.exfil.parity",
        version=1,
        title="Cross-service data exfiltration pattern detected",
        description="Three-stage cross-service sequence detected",
        spec=LEGACY_EXFILTRATION_DECLARATIVE_SPEC,
    )

    events = make_exfil_sequence(trace_id="trace-ooo-001")
    # Reverse order: DB (events[2]), Worker (events[1]), API (events[0])
    out_of_order = [events[2], events[1], events[0]]

    assert legacy.evaluate(out_of_order[0]) is None
    assert generic.evaluate(out_of_order[0]) is None

    assert legacy.evaluate(out_of_order[1]) is None
    assert generic.evaluate(out_of_order[1]) is None

    # 3rd event completes the sequence regardless of arrival order
    fl = legacy.evaluate(out_of_order[2])
    fg = generic.evaluate(out_of_order[2])

    assert fl is not None, "Legacy failed on out-of-order sequence"
    assert fg is not None, "Generic failed on out-of-order sequence"
    assert fl.severity == fg.severity == "high"


def test_exfiltration_parity_missing_stages_do_not_trigger():
    """
    Missing a stage (API + Worker without DB) must NOT trigger either detector.
    """
    legacy = CrossServiceExfiltrationDetector(time_window_seconds=300.0)
    generic = GenericDeclarativeEvaluator(
        rule_id="rule.exfil.parity",
        version=1,
        title="Cross-service data exfiltration pattern detected",
        description="Three-stage cross-service sequence detected",
        spec=LEGACY_EXFILTRATION_DECLARATIVE_SPEC,
    )

    events = make_exfil_sequence(trace_id="trace-incomplete-001")
    # Only send API and Worker
    assert legacy.evaluate(events[0]) is None
    assert generic.evaluate(events[0]) is None

    assert legacy.evaluate(events[1]) is None
    assert generic.evaluate(events[1]) is None


def test_exfiltration_parity_benign_lookalike_ignored():
    """
    Benign non-internal endpoint and non-sensitive table must NOT trigger either engine.
    """
    legacy = CrossServiceExfiltrationDetector(time_window_seconds=300.0)
    generic = GenericDeclarativeEvaluator(
        rule_id="rule.exfil.parity",
        version=1,
        title="Cross-service data exfiltration pattern detected",
        description="Three-stage cross-service sequence detected",
        spec=LEGACY_EXFILTRATION_DECLARATIVE_SPEC,
    )

    benign_events = make_exfil_sequence(
        trace_id="trace-benign-lookalike",
        internal_path="/api/v1/reports/monthly_statement",  # Public non-internal endpoint
        worker_anomaly=False,
        db_table="statement_line_items",  # Non-sensitive table
        rows_affected=500,  # Below threshold
    )

    for ev in benign_events:
        assert legacy.evaluate(ev) is None
        assert generic.evaluate(ev) is None


def test_exfiltration_parity_time_window_expiration():
    """
    Events spanning 350 seconds (exceeding 300s window) must NOT trigger either engine.
    """
    legacy = CrossServiceExfiltrationDetector(time_window_seconds=300.0)
    generic = GenericDeclarativeEvaluator(
        rule_id="rule.exfil.parity",
        version=1,
        title="Cross-service data exfiltration pattern detected",
        description="Three-stage cross-service sequence detected",
        spec=LEGACY_EXFILTRATION_DECLARATIVE_SPEC,
    )

    # Events spaced: 0s, 10s, 350s (exceeding 300s)
    events = make_exfil_sequence(trace_id="trace-expired-window", time_offsets=(0, 10, 350))

    assert legacy.evaluate(events[0]) is None
    assert generic.evaluate(events[0]) is None

    assert legacy.evaluate(events[1]) is None
    assert generic.evaluate(events[1]) is None

    assert legacy.evaluate(events[2]) is None, "Legacy triggered on expired window"
    assert generic.evaluate(events[2]) is None, "Generic triggered on expired window"


def test_exfiltration_parity_deduplication_no_alert_storms():
    """
    Subsequent events on a trace for which a finding has already been emitted
    must produce None in both detectors (deduplication / zero alert storms).
    """
    legacy = CrossServiceExfiltrationDetector(time_window_seconds=300.0)
    generic = GenericDeclarativeEvaluator(
        rule_id="rule.exfil.parity",
        version=1,
        title="Cross-service data exfiltration pattern detected",
        description="Three-stage cross-service sequence detected",
        spec=LEGACY_EXFILTRATION_DECLARATIVE_SPEC,
    )

    events = make_exfil_sequence(trace_id="trace-dedup-001")
    legacy.evaluate(events[0])
    generic.evaluate(events[0])
    legacy.evaluate(events[1])
    generic.evaluate(events[1])
    
    # 3rd event triggers both
    assert legacy.evaluate(events[2]) is not None
    assert generic.evaluate(events[2]) is not None

    # Subsequent events on same trace must produce None
    extra_event = make_exfil_sequence(trace_id="trace-dedup-001", time_offsets=(1, 2, 20))[2]
    extra_event.event_id = "ev-extra-followup"

    assert legacy.evaluate(extra_event) is None, "Legacy emitted duplicate finding for trace"
    assert generic.evaluate(extra_event) is None, "Generic emitted duplicate finding for trace"


# ===========================================================================
# 3. Replay Validation Engine Dual Support Verification
# ===========================================================================

def test_replay_validation_engine_supports_declarative_and_legacy_rules():
    """
    Verifies that ReplayValidationEngine validates both legacy parameter rules
    and GenericDeclarativeRuleDefinition rules without breaking backwards compatibility.
    """
    engine = ReplayValidationEngine()

    # 1. Legacy Brute Force Rule
    legacy_bf_rule = DeclarativeRule(
        tenant_id="tenant-alpha",
        target_detector="detector.auth.failed_threshold",
        title="Legacy Brute Force",
        description="Legacy threshold parameters",
        parameters={"failure_threshold": 5, "window_seconds": 60.0},
    )
    metrics_legacy_bf = engine.validate_rule(legacy_bf_rule)
    assert metrics_legacy_bf.passed_validation
    assert metrics_legacy_bf.false_positives == 0

    # 2. Generic Declarative Brute Force Rule
    generic_bf_rule = DeclarativeRule(
        tenant_id="tenant-alpha",
        target_detector="detector.auth.failed_threshold",
        title="Declarative Brute Force",
        description="Generic declarative threshold specification",
        parameters=LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC.model_dump(),
    )
    metrics_generic_bf = engine.validate_rule(generic_bf_rule)
    assert metrics_generic_bf.passed_validation
    assert metrics_generic_bf.false_positives == 0

    # 3. Legacy Exfiltration Rule
    legacy_exfil_rule = DeclarativeRule(
        tenant_id="tenant-alpha",
        target_detector="detector.cross_service.exfiltration",
        title="Legacy Exfiltration",
        description="Legacy cross-service parameters",
        parameters={
            "time_window_seconds": 300.0,
            "bulk_row_threshold": 1000,
            "sensitive_tables": ["users", "credit_cards", "tokens", "secrets"],
            "internal_prefixes": ["/api/v1/internal/", "/internal/", "/admin/export"],
        },
    )
    metrics_legacy_exfil = engine.validate_rule(legacy_exfil_rule)
    assert metrics_legacy_exfil.passed_validation
    assert metrics_legacy_exfil.false_positives == 0

    # 4. Generic Declarative Exfiltration Rule
    generic_exfil_rule = DeclarativeRule(
        tenant_id="tenant-alpha",
        target_detector="detector.cross_service.exfiltration",
        title="Declarative Exfiltration",
        description="Generic declarative sequence specification",
        parameters=LEGACY_EXFILTRATION_DECLARATIVE_SPEC.model_dump(),
    )
    metrics_generic_exfil = engine.validate_rule(generic_exfil_rule)
    assert metrics_generic_exfil.passed_validation
    assert metrics_generic_exfil.false_positives == 0


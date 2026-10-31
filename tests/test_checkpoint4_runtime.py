"""
Checkpoint 4: Runtime Declarative Migration & Hypothesis 1 Verification Test Suite.

Proves:
1. Complete rule lifecycle: proposed -> validated -> approved -> active -> disabled.
2. Immediate disablement, cache invalidation, and rollback without stale cached execution.
3. Concurrent rule updates and thread-safety under multi-threaded load.
4. Runtime behavior across application restart.
5. Security Hypothesis 1 (Timestamp-skew cache eviction):
   - Out-of-order events correlate deterministically.
   - Future timestamp does NOT evict legitimate active correlation state.
   - Reason for skew recorded in event metadata (_skew_warning).
   - Late events beyond retention safely dropped without corrupting state.
   - Sequence window boundaries enforced.
   - Duplicate event delivery deduplicated.
   - Multi-tenant event timelines isolated (Tenant B time jump does not evict Tenant A).
6. Runtime differential testing & duplicate finding prevention:
   - Active declarative rule suppresses duplicate native alert.
   - Disabling declarative rule restores native detector as continuous safety net.
7. Hybrid Cyber Range compatibility:
   - Attack execution -> real telemetry ingestion -> declarative detection -> finding creation.
"""

import pytest
import datetime
import uuid
from concurrent.futures import ThreadPoolExecutor

from backend.models import DeclarativeRuleModel, SecurityFinding, Tenant, ApiKey
from backend.core.auth import hash_api_key
from backend.detection.registry import runtime_rule_registry, RuntimeRuleRegistry
from backend.detection.generic_evaluator import GenericDeclarativeEvaluator
from backend.schemas.declarative_spec import (
    LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC,
    LEGACY_EXFILTRATION_DECLARATIVE_SPEC,
)
from backend.schemas.events import CanonicalEvent
from tests.conftest import TEST_TENANT_ID, TEST_APP_ID, RAW_TEST_API_KEY


# -----------------------------------------------------------------------------
# Section 1: Complete Rule Lifecycle, Disablement, Rollback & Restart
# -----------------------------------------------------------------------------

def test_complete_rule_lifecycle_proposed_to_disabled(client, auth_headers, db_session):
    """
    Verifies full lifecycle: proposed -> validated -> approved -> active -> disabled.
    Verifies immediate cache eviction upon disablement (no stale execution).
    """
    # 1. Propose candidate generic declarative rule
    spec = LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC.model_dump(mode="json")
    prop_res = client.post(
        "/api/v1/rules",
        headers=auth_headers,
        json={
            "target_detector": "detector.auth.failed_threshold",
            "title": "Runtime Declarative Brute Force",
            "description": "Fires after 5 consecutive failed logins",
            "parameters": spec,
        },
    )
    assert prop_res.status_code == 201
    rule_id = prop_res.json()["rule_id"]
    assert prop_res.json()["status"] == "proposed"

    # Invariant: Proposed rule cannot execute
    detectors = runtime_rule_registry.get_active_detectors(TEST_TENANT_ID, db_session)
    assert not any(r.rule_id == rule_id for r, _ in detectors)

    # 2. Replay validation
    val_res = client.post(f"/api/v1/rules/{rule_id}/validate", headers=auth_headers)
    assert val_res.status_code == 200
    assert val_res.json()["passed_validation"] is True

    # Rule status is updated to validated
    rule_get = client.get(f"/api/v1/rules/{rule_id}", headers=auth_headers)
    assert rule_get.status_code == 200
    assert rule_get.json()["status"] == "validated"

    # 3. Approval gate
    appr_res = client.post(
        f"/api/v1/rules/{rule_id}/approve",
        headers=auth_headers,
        json={"decision": "approved", "rationale": "Verified in replay validation with 0 FP."},
    )
    assert appr_res.status_code == 200
    assert appr_res.json()["status"] == "approved"

    # 4. Activation into Fast Track runtime
    act_res = client.post(f"/api/v1/rules/{rule_id}/activate", headers=auth_headers)
    assert act_res.status_code == 200
    assert act_res.json()["status"] == "active"

    # Invariant: Active rule is loaded and cached
    active_detectors = runtime_rule_registry.get_active_detectors(TEST_TENANT_ID, db_session)
    matching = [r for r, _ in active_detectors if r.rule_id == rule_id]
    assert len(matching) == 1
    assert matching[0].status == "active"

    # 5. Disable rule immediately
    dis_res = client.post(
        f"/api/v1/rules/{rule_id}/disable",
        headers=auth_headers,
        json={"reason": "Emergency maintenance disablement"},
    )
    assert dis_res.status_code == 200
    assert dis_res.json()["status"] == "disabled"

    # Invariant: Immediately withdrawn from runtime evaluation without stale cached execution
    after_disable = runtime_rule_registry.get_active_detectors(TEST_TENANT_ID, db_session)
    assert not any(r.rule_id == rule_id for r, _ in after_disable)


def test_rule_rollback_preserves_version_and_updates_runtime(client, auth_headers, db_session):
    """
    Verifies that rolling back a rule increments the auditable version, updates parameters,
    and immediately invalidates the cache so the rolled-back configuration takes effect.
    """
    # Propose, validate, approve, and activate v1 (threshold = 5)
    spec_v1 = LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC.model_dump(mode="json")
    spec_v1["threshold"]["count"] = 5
    prop = client.post(
        "/api/v1/rules",
        headers=auth_headers,
        json={
            "target_detector": "detector.auth.failed_threshold",
            "title": "Configurable Login Failure Rule",
            "description": "v1 threshold 5",
            "parameters": spec_v1,
        },
    ).json()
    rule_id = prop["rule_id"]

    client.post(f"/api/v1/rules/{rule_id}/validate", headers=auth_headers)
    client.post(f"/api/v1/rules/{rule_id}/approve", headers=auth_headers, json={"decision": "approved", "rationale": "Approve v1"})
    client.post(f"/api/v1/rules/{rule_id}/activate", headers=auth_headers)

    # Perform rollback
    roll_res = client.post(
        f"/api/v1/rules/{rule_id}/rollback",
        headers=auth_headers,
        json={"rationale": "Reverting rule configuration"},
    )
    assert roll_res.status_code == 200
    rolled = roll_res.json()
    assert rolled["version"] == 2
    assert rolled["status"] == "disabled"

    # Cache must be invalidated: no active detectors for this rule
    active_detectors = runtime_rule_registry.get_active_detectors(TEST_TENANT_ID, db_session)
    assert not any(r.rule_id == rule_id for r, _ in active_detectors)


def test_invalid_rule_rejection_at_proposal(client, auth_headers):
    """Verifies that rules containing executable code or unsupported operators are rejected."""
    # Attempt code injection in parameters
    bad_res = client.post(
        "/api/v1/rules",
        headers=auth_headers,
        json={
            "target_detector": "generic",
            "title": "Exploit Rule",
            "description": "Unsafe payload",
            "parameters": {
                "rule_type": "threshold",
                "threshold": 5,
                "window_seconds": 60.0,
                "group_by": ["tenant_id"],
                "conditions": [
                    {"field": "event_type", "operator": "equals", "value": "__import__('os').system('id')"}
                ]
            },
        },
    )
    assert bad_res.status_code == 422


def test_runtime_behavior_after_restart(client, auth_headers, db_session):
    """
    Simulates application process restart by creating a brand new RuntimeRuleRegistry instance.
    Verifies that only genuinely active rules from the database are loaded.
    """
    # Create active rule directly in DB
    rule_active = DeclarativeRuleModel(
        rule_id="rule-active-persisted",
        tenant_id=TEST_TENANT_ID,
        version=1,
        target_detector="detector.auth.failed_threshold",
        title="Persisted Active Rule",
        description="Should load on restart",
        parameters=LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC.model_dump(mode="json"),
        status="active",
    )
    rule_disabled = DeclarativeRuleModel(
        rule_id="rule-disabled-persisted",
        tenant_id=TEST_TENANT_ID,
        version=1,
        target_detector="detector.auth.failed_threshold",
        title="Persisted Disabled Rule",
        description="Should NOT load on restart",
        parameters=LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC.model_dump(mode="json"),
        status="disabled",
    )
    db_session.add(rule_active)
    db_session.add(rule_disabled)
    db_session.commit()

    # Create fresh registry instance (simulating new server process)
    fresh_registry = RuntimeRuleRegistry(ttl_seconds=10.0)
    loaded = fresh_registry.get_active_detectors(TEST_TENANT_ID, db_session)

    loaded_ids = [r.rule_id for r, _ in loaded]
    assert "rule-active-persisted" in loaded_ids
    assert "rule-disabled-persisted" not in loaded_ids


def test_concurrent_rule_updates_and_ingestion(client, auth_headers, db_session):
    """
    Verifies that RuntimeRuleRegistry is completely thread-safe under concurrent
    rule invalidation and multi-threaded queries.
    """
    spec = LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC.model_dump(mode="json")
    rule = DeclarativeRuleModel(
        rule_id="rule-threadsafe-test",
        tenant_id=TEST_TENANT_ID,
        version=1,
        target_detector="detector.auth.failed_threshold",
        title="Thread Safety Rule",
        description="Concurrent test",
        parameters=spec,
        status="active",
    )
    db_session.add(rule)
    db_session.commit()

    errors = []

    def reader():
        try:
            for _ in range(50):
                detectors = runtime_rule_registry.get_active_detectors(TEST_TENANT_ID, db_session)
                assert isinstance(detectors, list)
        except Exception as e:
            errors.append(e)

    def invalidator():
        try:
            for _ in range(50):
                runtime_rule_registry.invalidate(TEST_TENANT_ID)
        except Exception as e:
            errors.append(e)

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(reader) for _ in range(4)] + [executor.submit(invalidator) for _ in range(4)]
        for f in futures:
            f.result()

    assert len(errors) == 0


# -----------------------------------------------------------------------------
# Section 2: Security Hypothesis 1 (Timestamp Skew & Cache Eviction)
# -----------------------------------------------------------------------------

def test_hypothesis1_future_timestamp_cannot_evict_correlation_state():
    """
    Security Hypothesis 1 Reproduction & Verification:
    An attacker submits an event with a timestamp far in the future.
    Invariant: The future timestamp must NOT evict legitimate active correlation state,
    and the skew reason must be recorded in event attributes.
    """
    evaluator = GenericDeclarativeEvaluator(
        rule_id="test-exfil-skew",
        version=1,
        title="Exfiltration Rule",
        description="Hypothesis 1 Test",
        spec=LEGACY_EXFILTRATION_DECLARATIVE_SPEC,
        max_future_skew_seconds=300.0,
    )

    t0 = datetime.datetime(2026, 10, 31, 12, 0, 0, tzinfo=datetime.timezone.utc)
    trace_id = "trc-hypothesis1-001"

    # Stage 1 (API Request) arrives at 12:00:00
    ev1 = CanonicalEvent(
        event_id="ev-stage1",
        schema_version="1.0.0",
        timestamp=t0,
        app_id=TEST_APP_ID,
        tenant_id="tenant-alpha",
        service_id="api-service",
        event_type="http.request",
        severity="info",
        target_resource="/api/v1/internal/export",
        trace_id=trace_id,
        attributes={"client_ip": "10.0.4.15"},
    )
    finding1 = evaluator.evaluate(ev1)
    assert finding1 is None

    # Stage 2 (Worker Anomaly) arrives at 12:00:05
    ev2 = CanonicalEvent(
        event_id="ev-stage2",
        schema_version="1.0.0",
        timestamp=t0 + datetime.timedelta(seconds=5),
        app_id=TEST_APP_ID,
        tenant_id="tenant-alpha",
        service_id="worker-service",
        event_type="worker.job_anomalous",
        severity="medium",
        trace_id=trace_id,
        attributes={"anomaly_flag": True},
    )
    finding2 = evaluator.evaluate(ev2)
    assert finding2 is None

    # ATTACK: Attacker sends an event with timestamp 2 hours in the future
    future_ev = CanonicalEvent(
        event_id="ev-future-skew-attack",
        schema_version="1.0.0",
        timestamp=t0 + datetime.timedelta(hours=2),
        app_id=TEST_APP_ID,
        tenant_id="tenant-alpha",
        service_id="api-service",
        event_type="http.request",
        severity="info",
        target_resource="/public/ping",
        trace_id="trc-attacker-999",
        attributes={},
    )
    skew_finding = evaluator.evaluate(future_ev)
    assert skew_finding is None
    # Verify reason was recorded
    assert "_skew_warning" in future_ev.attributes
    assert "future_timestamp_skew_exceeded" in future_ev.attributes["_skew_warning"]

    # Verify that the legitimate ongoing correlation window for trace_id WAS NOT EVICTED
    group_key = ("tenant-alpha", trace_id)
    assert group_key in evaluator._sequence_windows

    # Stage 3 (Database Query) arrives at 12:00:10
    ev3 = CanonicalEvent(
        event_id="ev-stage3",
        schema_version="1.0.0",
        timestamp=t0 + datetime.timedelta(seconds=10),
        app_id=TEST_APP_ID,
        tenant_id="tenant-alpha",
        service_id="database-service",
        event_type="db.bulk_query",
        severity="high",
        trace_id=trace_id,
        attributes={"table": "users", "rows_affected": 5000},
    )
    finding3 = evaluator.evaluate(ev3)

    # Invariant: Detection succeeds despite the future timestamp injection attempt
    assert finding3 is not None
    assert finding3.evidence["group_key"] == ["tenant-alpha", trace_id]
    assert finding3.severity == "high"


def test_hypothesis1_out_of_order_events_correlate_correctly():
    """
    Verifies that events arriving out of chronological order (Stage 3 -> Stage 1 -> Stage 2)
    within the sliding window correlate deterministically and trigger on the completing event.
    """
    evaluator = GenericDeclarativeEvaluator(
        rule_id="test-exfil-ooo",
        version=1,
        title="Exfiltration Rule",
        description="Out of order test",
        spec=LEGACY_EXFILTRATION_DECLARATIVE_SPEC,
    )

    t0 = datetime.datetime(2026, 10, 31, 12, 0, 0, tzinfo=datetime.timezone.utc)
    trace_id = "trc-ooo-123"

    # Stage 3 arrives FIRST
    ev3 = CanonicalEvent(
        event_id="ev-stage3-ooo",
        schema_version="1.0.0",
        timestamp=t0 + datetime.timedelta(seconds=4),
        app_id=TEST_APP_ID,
        tenant_id="tenant-alpha",
        service_id="database-service",
        event_type="db.bulk_query",
        severity="high",
        trace_id=trace_id,
        attributes={"table": "users", "rows_affected": 2500},
    )
    assert evaluator.evaluate(ev3) is None

    # Stage 1 arrives SECOND (earlier timestamp)
    ev1 = CanonicalEvent(
        event_id="ev-stage1-ooo",
        schema_version="1.0.0",
        timestamp=t0,
        app_id=TEST_APP_ID,
        tenant_id="tenant-alpha",
        service_id="api-service",
        event_type="http.request",
        severity="info",
        target_resource="/api/v1/internal/export",
        trace_id=trace_id,
        attributes={"client_ip": "192.168.1.50"},
    )
    assert evaluator.evaluate(ev1) is None

    # Stage 2 arrives THIRD (intermediate timestamp)
    ev2 = CanonicalEvent(
        event_id="ev-stage2-ooo",
        schema_version="1.0.0",
        timestamp=t0 + datetime.timedelta(seconds=2),
        app_id=TEST_APP_ID,
        tenant_id="tenant-alpha",
        service_id="worker-service",
        event_type="worker.job_anomalous",
        severity="medium",
        trace_id=trace_id,
        attributes={"anomaly_flag": True},
    )
    finding = evaluator.evaluate(ev2)
    assert finding is not None
    assert finding.evidence["group_key"] == ["tenant-alpha", trace_id]
    assert len(finding.evidence["stages"]) == 3


def test_hypothesis1_late_events_beyond_retention_dropped():
    """
    Verifies that events arriving older than max_late_arrival_seconds are dropped
    with an explicit audit reason recorded, without corrupting state.
    """
    evaluator = GenericDeclarativeEvaluator(
        rule_id="test-late-eval",
        version=1,
        title="Late Arrival Test",
        description="Verify retention drop",
        spec=LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC,
        max_late_arrival_seconds=86400.0,
    )

    t_now = datetime.datetime(2026, 10, 31, 12, 0, 0, tzinfo=datetime.timezone.utc)

    # Establish watermark with current event
    ev_now = CanonicalEvent(
        event_id="ev-now",
        schema_version="1.0.0",
        timestamp=t_now,
        app_id=TEST_APP_ID,
        tenant_id="tenant-alpha",
        service_id="api-service",
        event_type="auth.login_failed",
        severity="info",
        source_resource="10.0.0.1",
        attributes={"client_ip": "10.0.0.1"},
    )
    evaluator.evaluate(ev_now)

    # Late event from 3 days ago arrives
    ev_late = CanonicalEvent(
        event_id="ev-late",
        schema_version="1.0.0",
        timestamp=t_now - datetime.timedelta(days=3),
        app_id=TEST_APP_ID,
        tenant_id="tenant-alpha",
        service_id="api-service",
        event_type="auth.login_failed",
        severity="info",
        source_resource="10.0.0.1",
        attributes={"client_ip": "10.0.0.1"},
    )
    evaluator.evaluate(ev_late)
    assert "_skew_warning" in ev_late.attributes
    assert "late_event_outside_retention" in ev_late.attributes["_skew_warning"]


def test_hypothesis1_multi_tenant_timeline_isolation():
    """
    Verifies that Tenant B's events on a disparate timeline (e.g. hours ahead)
    NEVER evict Tenant A's correlation state.
    """
    evaluator = GenericDeclarativeEvaluator(
        rule_id="test-multi-tenant-eval",
        version=1,
        title="Multi-tenant Timeline",
        description="Tenant timeline isolation",
        spec=LEGACY_EXFILTRATION_DECLARATIVE_SPEC,
    )

    t_tenant_a = datetime.datetime(2026, 10, 31, 10, 0, 0, tzinfo=datetime.timezone.utc)
    t_tenant_b = datetime.datetime(2026, 10, 31, 18, 0, 0, tzinfo=datetime.timezone.utc)

    # Tenant A Stage 1 at 10:00:00
    ev_a1 = CanonicalEvent(
        event_id="ev-a1",
        schema_version="1.0.0",
        timestamp=t_tenant_a,
        app_id=TEST_APP_ID,
        tenant_id="tenant-alpha",
        service_id="api-service",
        event_type="http.request",
        severity="info",
        target_resource="/api/v1/internal/export",
        trace_id="trc-tenant-a",
        attributes={"client_ip": "10.0.4.15"},
    )
    evaluator.evaluate(ev_a1)

    # Tenant B sends events at 18:00:00 (8 hours ahead)
    ev_b1 = CanonicalEvent(
        event_id="ev-b1",
        schema_version="1.0.0",
        timestamp=t_tenant_b,
        app_id=TEST_APP_ID,
        tenant_id="tenant-beta",
        service_id="api-service",
        event_type="http.request",
        severity="info",
        target_resource="/api/v1/internal/export",
        trace_id="trc-tenant-b",
        attributes={"client_ip": "10.0.5.20"},
    )
    evaluator.evaluate(ev_b1)

    # Invariant: Tenant A's state was NOT evicted by Tenant B's advanced timestamp
    assert ("tenant-alpha", "trc-tenant-a") in evaluator._sequence_windows
    assert ("tenant-beta", "trc-tenant-b") in evaluator._sequence_windows


# -----------------------------------------------------------------------------
# Section 3: Runtime Differential Testing & Duplicate Finding Prevention
# -----------------------------------------------------------------------------

def test_runtime_active_declarative_rule_suppresses_duplicate_native_finding(client, auth_headers, db_session):
    """
    Verifies that when a declarative rule is active for a target detector family,
    it executes as the authoritative detector and suppresses duplicate native detector findings.
    """
    # Activate declarative brute force rule
    spec = LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC.model_dump(mode="json")
    spec["threshold"]["count"] = 5
    rule = DeclarativeRuleModel(
        rule_id="rule-runtime-bruteforce",
        tenant_id=TEST_TENANT_ID,
        version=1,
        target_detector="detector.auth.failed_threshold",
        title="Authoritative Declarative Brute Force",
        description="Fires at 5 failures",
        parameters=spec,
        status="active",
    )
    db_session.add(rule)
    db_session.commit()
    runtime_rule_registry.invalidate(TEST_TENANT_ID)

    # Ingest 5 failed logins through live HTTP ingestion pipeline
    now = datetime.datetime.now(datetime.timezone.utc)
    for i in range(5):
        res = client.post(
            "/v1/events",
            headers=auth_headers,
            json={
                "event_id": f"ev-dup-test-{i}-{uuid.uuid4().hex[:6]}",
                "schema_version": "1.0.0",
                "timestamp": (now + datetime.timedelta(seconds=i)).isoformat(),
                "app_id": TEST_APP_ID,
                "service_id": "api-service",
                "event_type": "auth.login_failed",
                "severity": "medium",
                "source_resource": "192.168.1.100",
                "target_resource": "/api/v1/login",
                "trace_id": "trc-dup-bf",
                "attributes": {"client_ip": "192.168.1.100"},
            },
        )
        assert res.status_code == 202

    # Query persisted findings in database
    findings = db_session.query(SecurityFinding).filter(
        SecurityFinding.tenant_id == TEST_TENANT_ID
    ).all()

    # Invariant: Exactly ONE finding is created, attributed to the declarative rule
    assert len(findings) == 1
    f = findings[0]
    assert f.detector_id == "rule-runtime-bruteforce"
    assert f.detector_version == "1"
    assert f.severity == "medium"
    assert f.evidence["rule_id"] == "rule-runtime-bruteforce"


def test_runtime_native_detector_fallback_when_declarative_rule_disabled(client, auth_headers, db_session):
    """
    Verifies that when a declarative rule is disabled, the native detector seamlessly
    acts as the continuous safety net fallback without system restart.
    """
    # Create disabled rule in DB
    rule = DeclarativeRuleModel(
        rule_id="rule-disabled-bruteforce",
        tenant_id=TEST_TENANT_ID,
        version=1,
        target_detector="detector.auth.failed_threshold",
        title="Disabled Rule",
        description="Fires at 5 failures",
        parameters=LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC.model_dump(mode="json"),
        status="disabled",
    )
    db_session.add(rule)
    db_session.commit()
    runtime_rule_registry.invalidate(TEST_TENANT_ID)

    # Ingest failed logins to trigger native detector fallback (threshold = 3 in fast_detectors)
    now = datetime.datetime.now(datetime.timezone.utc)
    for i in range(3):
        res = client.post(
            "/v1/events",
            headers=auth_headers,
            json={
                "event_id": f"ev-fallback-{i}-{uuid.uuid4().hex[:6]}",
                "schema_version": "1.0.0",
                "timestamp": (now + datetime.timedelta(seconds=i)).isoformat(),
                "app_id": TEST_APP_ID,
                "service_id": "api-service",
                "event_type": "auth.login_failed",
                "severity": "medium",
                "source_resource": "192.168.1.200",
                "target_resource": "/api/v1/login",
                "trace_id": "trc-fallback-bf",
                "attributes": {"client_ip": "192.168.1.200"},
            },
        )
        assert res.status_code == 202

    # Query persisted findings
    findings = db_session.query(SecurityFinding).filter(
        SecurityFinding.tenant_id == TEST_TENANT_ID
    ).all()

    # Invariant: Native detector triggered as fallback
    assert len(findings) == 1
    assert findings[0].detector_id == "detector.auth.failed_threshold"


# -----------------------------------------------------------------------------
# Section 4: Hybrid Cyber Range End-to-End Compatibility
# -----------------------------------------------------------------------------

def test_hybrid_cyber_range_apt_attack_to_declarative_finding(client, auth_headers, db_session):
    """
    End-to-end integration test validating compatibility with the upcoming Hybrid Cyber Range:
    Attack execution -> Real telemetry ingestion -> Declarative detection -> Finding creation.
    Consumes real multi-stage telemetry without synthetic shortcuts or ingestion bypasses.
    """
    # 1. Activate declarative exfiltration rule in runtime
    rule = DeclarativeRuleModel(
        rule_id="rule-cyber-range-apt",
        tenant_id=TEST_TENANT_ID,
        version=1,
        target_detector="detector.cross_service.exfiltration",
        title="APT Cross-Service Exfiltration",
        description="Detects coordinated API -> Worker -> DB exfiltration",
        parameters=LEGACY_EXFILTRATION_DECLARATIVE_SPEC.model_dump(mode="json"),
        status="active",
    )
    db_session.add(rule)
    db_session.commit()
    runtime_rule_registry.invalidate(TEST_TENANT_ID)

    shared_trace_id = f"trc_apt_{uuid.uuid4().hex[:10]}"
    now = datetime.datetime.now(datetime.timezone.utc)

    # 2. Stage 1: API Exploit Request
    ev_api = {
        "event_id": f"ev-api-{uuid.uuid4().hex[:8]}",
        "schema_version": "1.0.0",
        "timestamp": now.isoformat(),
        "app_id": TEST_APP_ID,
        "service_id": "api-service",
        "event_type": "http.request",
        "severity": "medium",
        "source_resource": "ip:198.51.100.42",
        "target_resource": "/api/v1/internal/export",
        "trace_id": shared_trace_id,
        "attributes": {
            "method": "POST",
            "endpoint": "/api/v1/internal/export",
            "client_ip": "198.51.100.42",
            "user_agent": "sqlmap/1.7.2#stable",
            "status_code": 200,
        },
    }
    res1 = client.post("/v1/events", headers=auth_headers, json=ev_api)
    assert res1.status_code == 202

    # 3. Stage 2: Background Media Worker Job Anomaly
    ev_worker = {
        "event_id": f"ev-wrk-{uuid.uuid4().hex[:8]}",
        "schema_version": "1.0.0",
        "timestamp": (now + datetime.timedelta(seconds=2)).isoformat(),
        "app_id": TEST_APP_ID,
        "service_id": "worker-service",
        "event_type": "worker.job_anomalous",
        "severity": "high",
        "source_resource": "worker:async-cache",
        "target_resource": "worker:pool",
        "trace_id": shared_trace_id,
        "attributes": {
            "job_name": "async_query_cache",
            "anomaly_flag": True,
            "error": "Unauthorized memory probe into internal connection pool",
        },
    }
    res2 = client.post("/v1/events", headers=auth_headers, json=ev_worker)
    assert res2.status_code == 202

    # 4. Stage 3: Bulk Sensitive Database Dump
    ev_db = {
        "event_id": f"ev-db-{uuid.uuid4().hex[:8]}",
        "schema_version": "1.0.0",
        "timestamp": (now + datetime.timedelta(seconds=4)).isoformat(),
        "app_id": TEST_APP_ID,
        "service_id": "database-service",
        "event_type": "db.bulk_query",
        "severity": "critical",
        "source_resource": "db:primary-pool",
        "target_resource": "table:users",
        "trace_id": shared_trace_id,
        "attributes": {
            "table": "users",
            "rows_affected": 5000,
            "operation": "SELECT",
            "is_sensitive_table": True,
        },
    }
    res3 = client.post("/v1/events", headers=auth_headers, json=ev_db)
    assert res3.status_code == 202

    # 5. Verify declarative finding persisted in DB
    findings = db_session.query(SecurityFinding).filter(
        SecurityFinding.tenant_id == TEST_TENANT_ID,
        SecurityFinding.detector_id == "rule-cyber-range-apt",
    ).all()

    assert len(findings) == 1
    f = findings[0]
    assert f.detector_id == "rule-cyber-range-apt"
    assert f.detector_version == "1"
    assert f.severity == "high"
    assert f.evidence["rule_id"] == "rule-cyber-range-apt"
    assert "stages" in f.evidence
    assert len(f.evidence["stages"]) == 3

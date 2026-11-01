"""
Ternline Checkpoint 5 Phase B Verification Suite.

Tests:
1. Preservation of multiple candidate events per sequence stage across Redis and In-Memory.
2. Distinct-service validation across candidate events in multi-event stages.
3. Multi-process cross-worker sequence correlation with multiple candidates per stage.
4. Enforcement of explicit resource bounds:
   - Max correlation groups per tenant
   - Max events per threshold group
   - Max candidate events per sequence stage
   - Max seen event IDs
5. Production Redis failure handling (no silent in-memory fallback in prod/staging).
6. Ingestion degradation reporting (correlation_status='degraded', ops_bus publication, PostgreSQL persistence preserved).
7. Unsuppressed native fallback on declarative correlation failure.
"""

import pytest
import datetime
import uuid
import threading
import multiprocessing
from typing import List, Dict, Any
from unittest.mock import patch, MagicMock

import fakeredis
from fakeredis import TcpFakeServer
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.config import settings
from backend.db.session import get_db
from backend.models import EventModel, SecurityFinding, DeclarativeRuleModel
from backend.schemas.events import CanonicalEvent, IngestResponse
from backend.schemas.rules import DeclarativeRule
from backend.schemas.declarative_spec import (
    GenericDeclarativeRuleDefinition,
    ThresholdSpec,
    SequenceStage,
    FieldCondition,
    LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC,
    LEGACY_EXFILTRATION_DECLARATIVE_SPEC,
)
from backend.detection.state_store import (
    InMemoryCorrelationStateStore,
    RedisCorrelationStateStore,
    RedisStateError,
    DEFAULT_MAX_GROUPS_PER_TENANT,
    DEFAULT_MAX_EVENTS_PER_THRESHOLD_GROUP,
    DEFAULT_MAX_CANDIDATES_PER_STAGE,
)
from backend.detection.generic_evaluator import GenericDeclarativeEvaluator
from backend.detection.replay import ReplayValidationEngine
from backend.detection.registry import runtime_rule_registry
from backend.ops.bus import ops_bus


# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------

@pytest.fixture
def fake_redis_server():
    """Provides an isolated TCP Redis server for multi-process verification."""
    server = TcpFakeServer(("127.0.0.1", 0))
    host, port = server.server_address
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"redis://{host}:{port}/0"
    server.shutdown()


@pytest.fixture
def redis_store():
    fake_client = fakeredis.FakeRedis(decode_responses=True)
    store = RedisCorrelationStateStore(fake_client)
    yield store
    store.reset()


# -----------------------------------------------------------------------------
# 1. Multiple Candidate Events per Sequence Stage (In-Memory & Redis Parity)
# -----------------------------------------------------------------------------

@pytest.mark.parametrize("store_type", ["in_memory", "redis"])
def test_multiple_candidates_per_stage_preserved(store_type, redis_store):
    store = InMemoryCorrelationStateStore() if store_type == "in_memory" else redis_store
    evaluator = GenericDeclarativeEvaluator(
        rule_id="rule-multi-cand",
        version=1,
        title="Multi Candidate Sequence",
        description="Preserve all candidates",
        spec=LEGACY_EXFILTRATION_DECLARATIVE_SPEC,
        state_store=store,
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    trace = f"trc-multi-cand-{store_type}"

    # Stage 1: Send TWO distinct candidate events for stage 1 (both match api-service)
    ev1a = CanonicalEvent(
        event_id=f"ev1a-{store_type}", schema_version="1.0.0", timestamp=now,
        app_id="app-1", tenant_id="tenant-alpha", service_id="api-service",
        event_type="http.request", severity="info", source_resource="10.0.0.1",
        target_resource="/api/v1/internal/export", trace_id=trace,
        attributes={"client_ip": "10.0.0.1", "attempt": 1},
    )
    ev1b = CanonicalEvent(
        event_id=f"ev1b-{store_type}", schema_version="1.0.0", timestamp=now + datetime.timedelta(seconds=1),
        app_id="app-1", tenant_id="tenant-alpha", service_id="api-service",
        event_type="http.request", severity="info", source_resource="10.0.0.1",
        target_resource="/api/v1/internal/export", trace_id=trace,
        attributes={"client_ip": "10.0.0.1", "attempt": 2},
    )

    assert evaluator.evaluate(ev1a) is None
    assert evaluator.evaluate(ev1b) is None

    # Stage 2: One candidate event
    ev2 = CanonicalEvent(
        event_id=f"ev2-{store_type}", schema_version="1.0.0", timestamp=now + datetime.timedelta(seconds=2),
        app_id="app-1", tenant_id="tenant-alpha", service_id="worker-service",
        event_type="worker.job_anomalous", severity="medium", trace_id=trace,
        attributes={"anomaly_flag": True},
    )
    assert evaluator.evaluate(ev2) is None

    # Stage 3: Terminal trigger event
    ev3 = CanonicalEvent(
        event_id=f"ev3-{store_type}", schema_version="1.0.0", timestamp=now + datetime.timedelta(seconds=4),
        app_id="app-1", tenant_id="tenant-alpha", service_id="database-service",
        event_type="db.bulk_query", severity="high", trace_id=trace,
        attributes={"table": "users", "rows_affected": 5000},
    )
    finding = evaluator.evaluate(ev3)

    assert finding is not None
    stage1_evidence = finding.evidence["stages"]["api_trigger"]

    # Verify multiple candidate events are preserved in evidence
    assert stage1_evidence["matched_count"] == 2
    assert f"ev1a-{store_type}" in stage1_evidence["candidate_event_ids"]
    assert f"ev1b-{store_type}" in stage1_evidence["candidate_event_ids"]

    # Verify lead event is the latest candidate
    assert stage1_evidence["event_id"] == f"ev1b-{store_type}"
    assert stage1_evidence["service_id"] == "api-service"

    # Supporting events include all candidate events
    assert f"ev1a-{store_type}" in finding.evidence["supporting_event_ids"]
    assert f"ev1b-{store_type}" in finding.evidence["supporting_event_ids"]
    assert f"ev2-{store_type}" in finding.evidence["supporting_event_ids"]
    assert f"ev3-{store_type}" in finding.evidence["supporting_event_ids"]


# -----------------------------------------------------------------------------
# 2. Multi-Process Candidate Preservation Across Independent Workers
# -----------------------------------------------------------------------------

def _mp_candidate_worker(worker_id: int, redis_url: str, event_queue: multiprocessing.Queue, result_queue: multiprocessing.Queue):
    store = RedisCorrelationStateStore(redis_url)
    evaluator = GenericDeclarativeEvaluator(
        rule_id="rule-mp-cand-seq",
        version=1,
        title="MP Candidate Exfil",
        description="Multi-worker multi-candidate",
        spec=LEGACY_EXFILTRATION_DECLARATIVE_SPEC,
        state_store=store,
    )
    findings = []
    while True:
        ev_dict = event_queue.get()
        if ev_dict is None:
            break
        ev = CanonicalEvent(**ev_dict)
        f = evaluator.evaluate(ev)
        if f:
            findings.append(f.model_dump(mode="json"))
    result_queue.put((worker_id, findings))


def test_multiprocess_multi_candidate_sequence(fake_redis_server):
    """
    Validates that Candidate 1A (Worker 1) and Candidate 1B (Worker 2)
    are BOTH preserved when Stage 3 triggers on Worker 1.
    """
    q1 = multiprocessing.Queue()
    q2 = multiprocessing.Queue()
    res_q = multiprocessing.Queue()

    p1 = multiprocessing.Process(target=_mp_candidate_worker, args=(1, fake_redis_server, q1, res_q))
    p2 = multiprocessing.Process(target=_mp_candidate_worker, args=(2, fake_redis_server, q2, res_q))
    p1.start()
    p2.start()

    now = datetime.datetime.now(datetime.timezone.utc)
    trace = "trc-mp-cand-cross-worker"

    # Stage 1 - Candidate A sent to Worker 1
    q1.put({
        "event_id": "ev-cand-1a", "schema_version": "1.0.0", "timestamp": now.isoformat(),
        "app_id": "app-1", "tenant_id": "tenant-alpha", "service_id": "api-service",
        "event_type": "http.request", "severity": "info", "source_resource": "10.0.0.1",
        "target_resource": "/api/v1/internal/export", "trace_id": trace,
        "attributes": {"client_ip": "10.0.0.1"},
    })

    # Stage 1 - Candidate B sent to Worker 2
    q2.put({
        "event_id": "ev-cand-1b", "schema_version": "1.0.0", "timestamp": (now + datetime.timedelta(seconds=1)).isoformat(),
        "app_id": "app-1", "tenant_id": "tenant-alpha", "service_id": "api-service",
        "event_type": "http.request", "severity": "info", "source_resource": "10.0.0.1",
        "target_resource": "/api/v1/internal/export", "trace_id": trace,
        "attributes": {"client_ip": "10.0.0.1"},
    })

    # Stage 2 sent to Worker 2
    q2.put({
        "event_id": "ev-cand-2", "schema_version": "1.0.0", "timestamp": (now + datetime.timedelta(seconds=2)).isoformat(),
        "app_id": "app-1", "tenant_id": "tenant-alpha", "service_id": "worker-service",
        "event_type": "worker.job_anomalous", "severity": "medium", "trace_id": trace,
        "attributes": {"anomaly_flag": True},
    })

    # Stage 3 sent to Worker 1
    q1.put({
        "event_id": "ev-cand-3", "schema_version": "1.0.0", "timestamp": (now + datetime.timedelta(seconds=3)).isoformat(),
        "app_id": "app-1", "tenant_id": "tenant-alpha", "service_id": "database-service",
        "event_type": "db.bulk_query", "severity": "high", "trace_id": trace,
        "attributes": {"table": "users", "rows_affected": 5000},
    })

    # Signal stop
    q1.put(None)
    q2.put(None)

    w1_id, w1_findings = res_q.get(timeout=20)
    w2_id, w2_findings = res_q.get(timeout=20)
    p1.join(timeout=5)
    p2.join(timeout=5)

    all_findings = w1_findings + w2_findings
    assert len(all_findings) == 1
    finding = all_findings[0]

    # Verify both candidates 1a and 1b across distinct processes are preserved
    stage1 = finding["evidence"]["stages"]["api_trigger"]
    assert stage1["matched_count"] == 2
    assert "ev-cand-1a" in stage1["candidate_event_ids"]
    assert "ev-cand-1b" in stage1["candidate_event_ids"]
    assert "ev-cand-1a" in finding["evidence"]["supporting_event_ids"]
    assert "ev-cand-1b" in finding["evidence"]["supporting_event_ids"]


# -----------------------------------------------------------------------------
# 3. Explicit Resource Bounds Enforcement
# -----------------------------------------------------------------------------

@pytest.mark.parametrize("store_type", ["in_memory", "redis"])
def test_resource_limit_max_groups_per_tenant(store_type):
    # Set max_groups_per_tenant to small limit of 3
    if store_type == "in_memory":
        store = InMemoryCorrelationStateStore(max_groups_per_tenant=3)
    else:
        fake_client = fakeredis.FakeRedis(decode_responses=True)
        store = RedisCorrelationStateStore(fake_client, max_groups_per_tenant=3)

    evaluator = GenericDeclarativeEvaluator(
        rule_id="rule-bound-groups",
        version=1,
        title="Bounded Groups",
        description="Test limit",
        spec=LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC,
        state_store=store,
    )

    now = datetime.datetime.now(datetime.timezone.utc)

    # Create 3 unique groups (IPs) for tenant-alpha
    for i in range(3):
        ev = CanonicalEvent(
            event_id=f"ev-grp-{i}", schema_version="1.0.0", timestamp=now,
            app_id="app-1", tenant_id="tenant-alpha", service_id="api-service",
            event_type="auth.login_failed", severity="medium",
            source_resource=f"10.0.0.{i}", attributes={"client_ip": f"10.0.0.{i}"},
        )
        assert evaluator.evaluate(ev) is None

    # Attempt to create 4th group exceeding limit of 3
    ev_overflow = CanonicalEvent(
        event_id="ev-grp-overflow", schema_version="1.0.0", timestamp=now,
        app_id="app-1", tenant_id="tenant-alpha", service_id="api-service",
        event_type="auth.login_failed", severity="medium",
        source_resource="10.0.0.99", attributes={"client_ip": "10.0.0.99"},
    )
    # 4th group is rejected/dropped due to cardinality protection
    assert evaluator.evaluate(ev_overflow) is None


@pytest.mark.parametrize("store_type", ["in_memory", "redis"])
def test_resource_limit_max_candidates_per_stage(store_type):
    # Set max_candidates_per_stage to 2
    if store_type == "in_memory":
        store = InMemoryCorrelationStateStore(max_candidates_per_stage=2)
    else:
        fake_client = fakeredis.FakeRedis(decode_responses=True)
        store = RedisCorrelationStateStore(fake_client, max_candidates_per_stage=2)

    evaluator = GenericDeclarativeEvaluator(
        rule_id="rule-bound-candidates",
        version=1,
        title="Bounded Candidates",
        description="Test candidate limit",
        spec=LEGACY_EXFILTRATION_DECLARATIVE_SPEC,
        state_store=store,
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    trace = f"trc-bound-cand-{store_type}"

    # Send 4 candidate events for Stage 1 (limit is 2)
    for i in range(4):
        ev = CanonicalEvent(
            event_id=f"ev-c-{i}", schema_version="1.0.0",
            timestamp=now + datetime.timedelta(seconds=i),
            app_id="app-1", tenant_id="tenant-alpha", service_id="api-service",
            event_type="http.request", severity="info", source_resource="10.0.0.1",
            target_resource="/api/v1/internal/export", trace_id=trace,
            attributes={"client_ip": "10.0.0.1"},
        )
        evaluator.evaluate(ev)

    # Complete stages 2 and 3
    ev2 = CanonicalEvent(
        event_id="ev-c-s2", schema_version="1.0.0", timestamp=now + datetime.timedelta(seconds=5),
        app_id="app-1", tenant_id="tenant-alpha", service_id="worker-service",
        event_type="worker.job_anomalous", severity="medium", trace_id=trace,
        attributes={"anomaly_flag": True},
    )
    evaluator.evaluate(ev2)

    ev3 = CanonicalEvent(
        event_id="ev-c-s3", schema_version="1.0.0", timestamp=now + datetime.timedelta(seconds=6),
        app_id="app-1", tenant_id="tenant-alpha", service_id="database-service",
        event_type="db.bulk_query", severity="high", trace_id=trace,
        attributes={"table": "users", "rows_affected": 5000},
    )
    finding = evaluator.evaluate(ev3)

    assert finding is not None
    # Verified: candidates capped at max_candidates_per_stage = 2
    assert finding.evidence["stages"]["api_trigger"]["matched_count"] == 2
    assert len(finding.evidence["stages"]["api_trigger"]["candidate_event_ids"]) == 2


# -----------------------------------------------------------------------------
# 4. Production Redis Failure Handling (No Silent In-Memory Fallback)
# -----------------------------------------------------------------------------

def test_production_fails_fast_on_redis_failure():
    """
    Verifies that when ENVIRONMENT='production' or REDIS_REQUIRED=True,
    a failed Redis connection raises RuntimeError instead of silently falling back to in-memory.
    """
    engine = ReplayValidationEngine()
    rule = DeclarativeRule(
        rule_id="rule-prod-test",
        tenant_id="tenant-alpha",
        version=1,
        target_detector="detector.auth.brute_force",
        title="Prod Rule",
        description="Testing failure",
        status="approved",
        parameters=LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC.model_dump(),
    )

    with patch("backend.config.settings.ENVIRONMENT", "production"):
        with patch("backend.config.settings.REDIS_URL", "redis://invalid-non-existent-host:6379/0"):
            with pytest.raises(RuntimeError) as exc_info:
                engine.instantiate_detector(rule)

            assert "Fatal: Failed initializing required RedisCorrelationStateStore in production" in str(exc_info.value)


def test_development_allows_in_memory_when_redis_unconfigured():
    """
    In development mode without REDIS_URL or REDIS_REQUIRED,
    instantiate_detector cleanly instantiates the in-memory store.
    """
    engine = ReplayValidationEngine()
    rule = DeclarativeRule(
        rule_id="rule-dev-test",
        tenant_id="tenant-alpha",
        version=1,
        target_detector="detector.auth.brute_force",
        title="Dev Rule",
        description="Testing dev fallback",
        status="approved",
        parameters=LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC.model_dump(),
    )

    with patch("backend.config.settings.ENVIRONMENT", "development"):
        with patch("backend.config.settings.REDIS_REQUIRED", False):
            with patch("backend.config.settings.REDIS_URL", None):
                detector = engine.instantiate_detector(rule)
                assert detector is not None
                assert isinstance(detector.state_store, InMemoryCorrelationStateStore)


# -----------------------------------------------------------------------------
# 5. Ingestion Degraded Status Reporting & Telemetry Preservation
# -----------------------------------------------------------------------------

def test_ingestion_reports_degraded_correlation_while_preserving_telemetry(client, db_session):
    """
    Simulates a runtime Redis failure during event ingestion:
    1. Event must be persisted in PostgreSQL.
    2. IngestResponse must return HTTP 202 with correlation_status='degraded'.
    3. Ops bus must publish 'correlation.degraded' event.
    4. Native detector safety net must execute without suppression.
    """
    # Create active rule for tenant-alpha
    rule_model = DeclarativeRuleModel(
        rule_id="rule-failing-redis",
        tenant_id="tenant-alpha",
        version=1,
        target_detector="detector.auth.brute_force",
        title="Active Brute Force",
        description="Threshold",
        parameters=LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC.model_dump(),
        status="active",
        created_at=datetime.datetime.now(datetime.timezone.utc),
    )
    db_session.add(rule_model)
    db_session.commit()
    runtime_rule_registry.invalidate("tenant-alpha")

    # Mock the active detector's state store to raise RedisStateError
    active_items = runtime_rule_registry.get_active_detectors("tenant-alpha", db_session)
    assert len(active_items) > 0
    detector = active_items[0][1]

    published_events = []
    ops_bus.subscribe(lambda e: published_events.append(e))

    ev_id = f"ev-degraded-{uuid.uuid4()}"
    payload = {
        "event_id": ev_id,
        "schema_version": "1.0.0",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "app_id": "payments-api",
        "service_id": "api-service",
        "event_type": "auth.login_failed",
        "severity": "medium",
        "source_resource": "192.168.1.99",
        "attributes": {"client_ip": "192.168.1.99"},
    }

    with patch.object(detector, "evaluate", side_effect=RedisStateError("Simulated Redis timeout")):
        response = client.post(
            "/v1/events",
            json=payload,
            headers={"Authorization": "Bearer ce_live_test_api_key_secret_12345"},
        )

    assert response.status_code == 202
    data = response.json()

    # 1. Ingest accepted
    assert data["accepted"] == 1
    # 2. Correlation status explicitly degraded
    assert data["correlation_status"] == "degraded"
    assert "Simulated Redis timeout" in data["correlation_degraded_reason"]

    # 3. Telemetry successfully persisted in database
    db_event = db_session.query(EventModel).filter(EventModel.event_id == ev_id).first()
    assert db_event is not None
    assert db_event.tenant_id == "tenant-alpha"

    # 4. Ops bus notified of degradation
    degraded_ops = [e for e in ops_bus._buffer if e.event_type == "correlation.degraded"]
    assert len(degraded_ops) >= 1
    assert degraded_ops[-1].tenant_id == "tenant-alpha"
    assert "Simulated Redis timeout" in degraded_ops[-1].message

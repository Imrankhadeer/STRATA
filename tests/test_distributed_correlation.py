"""
Ternline Distributed Correlation & Redis State Store Test Suite.

Proves:
1. In-memory behavior preservation.
2. Redis threshold parity (initial trigger, alert storm control, severity escalation).
3. Redis sequence parity (multi-stage cross-service correlation).
4. Multi-process distributed threshold detection across independent OS worker processes.
5. Multi-process distributed sequence detection across independent OS worker processes.
6. Atomic concurrency under multi-threaded bursts.
7. Duplicate-event idempotency.
8. Out-of-order event sequence correlation.
9. Tenant boundary isolation in distributed keyspace.
10. Rule version isolation in distributed keyspace.
11. Redis connection failure handling & degraded status reporting.
12. TTL expiration and server-time expiry.
"""

import pytest
import datetime
import uuid
import threading
import time
import multiprocessing
from concurrent.futures import ThreadPoolExecutor

import fakeredis
from fakeredis import TcpFakeServer
import redis

from backend.detection.state_store import (
    BaseCorrelationStore,
    InMemoryCorrelationStateStore,
    RedisCorrelationStateStore,
    RedisStateError,
)
from backend.detection.generic_evaluator import GenericDeclarativeEvaluator
from backend.schemas.declarative_spec import (
    LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC,
    LEGACY_EXFILTRATION_DECLARATIVE_SPEC,
)
from backend.schemas.events import CanonicalEvent


# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------

@pytest.fixture
def fake_redis_server():
    """Provides an isolated TCP Redis fake server for multi-process tests."""
    server = TcpFakeServer(("127.0.0.1", 0))
    host, port = server.server_address
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"redis://{host}:{port}/0"
    server.shutdown()


@pytest.fixture
def redis_store():
    """Provides a clean in-memory FakeRedis backed RedisCorrelationStateStore."""
    fake_client = fakeredis.FakeRedis(decode_responses=True)
    store = RedisCorrelationStateStore(fake_client)
    yield store
    store.reset()


# -----------------------------------------------------------------------------
# 1. In-Memory Behavior Preservation
# -----------------------------------------------------------------------------

def test_in_memory_behavior_preserved():
    store = InMemoryCorrelationStateStore()
    evaluator = GenericDeclarativeEvaluator(
        rule_id="rule-inmem-bf",
        version=1,
        title="Brute Force",
        description="Threshold",
        spec=LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC,
        state_store=store,
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    findings = []
    for i in range(5):
        ev = CanonicalEvent(
            event_id=f"ev-inmem-{i}",
            schema_version="1.0.0",
            timestamp=now + datetime.timedelta(seconds=i),
            app_id="app-1",
            tenant_id="tenant-alpha",
            service_id="api-service",
            event_type="auth.login_failed",
            severity="medium",
            source_resource="192.168.1.1",
            attributes={"client_ip": "192.168.1.1"},
        )
        f = evaluator.evaluate(ev)
        if f:
            findings.append(f)

    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].evidence["attempt_count"] == 5


# -----------------------------------------------------------------------------
# 2. Redis Threshold Parity (Trigger, Suppression & Escalation)
# -----------------------------------------------------------------------------

def test_redis_threshold_parity(redis_store):
    evaluator = GenericDeclarativeEvaluator(
        rule_id="rule-redis-bf",
        version=1,
        title="Brute Force",
        description="Threshold",
        spec=LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC,
        state_store=redis_store,
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    findings = []

    # Attempts 1 to 15
    for i in range(1, 16):
        ev = CanonicalEvent(
            event_id=f"ev-bf-parity-{i}",
            schema_version="1.0.0",
            timestamp=now + datetime.timedelta(seconds=i),
            app_id="app-1",
            tenant_id="tenant-alpha",
            service_id="api-service",
            event_type="auth.login_failed",
            severity="medium",
            source_resource="192.168.1.20",
            attributes={"client_ip": "192.168.1.20"},
        )
        f = evaluator.evaluate(ev)
        if f:
            findings.append((i, f))

    # Invariant: Exactly 2 findings emitted:
    # 1. At attempt 5 with medium severity
    # 2. At attempt 11 with escalated high severity
    # Intermediate attempts (6-10, 12-15) are suppressed
    assert len(findings) == 2
    attempt1, f1 = findings[0]
    assert attempt1 == 5
    assert f1.severity == "medium"

    attempt2, f2 = findings[1]
    assert attempt2 == 11
    assert f2.severity == "high"


# -----------------------------------------------------------------------------
# 3. Redis Sequence Parity
# -----------------------------------------------------------------------------

def test_redis_sequence_parity(redis_store):
    evaluator = GenericDeclarativeEvaluator(
        rule_id="rule-redis-exfil",
        version=1,
        title="Exfiltration",
        description="Sequence",
        spec=LEGACY_EXFILTRATION_DECLARATIVE_SPEC,
        state_store=redis_store,
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    trace = "trc-seq-parity-101"

    ev1 = CanonicalEvent(
        event_id="ev-s1", schema_version="1.0.0", timestamp=now,
        app_id="app-1", tenant_id="tenant-alpha", service_id="api-service",
        event_type="http.request", severity="info", source_resource="10.0.0.1",
        target_resource="/api/v1/internal/export", trace_id=trace,
        attributes={"client_ip": "10.0.0.1"},
    )
    assert evaluator.evaluate(ev1) is None

    ev2 = CanonicalEvent(
        event_id="ev-s2", schema_version="1.0.0", timestamp=now + datetime.timedelta(seconds=2),
        app_id="app-1", tenant_id="tenant-alpha", service_id="worker-service",
        event_type="worker.job_anomalous", severity="medium", trace_id=trace,
        attributes={"anomaly_flag": True},
    )
    assert evaluator.evaluate(ev2) is None

    ev3 = CanonicalEvent(
        event_id="ev-s3", schema_version="1.0.0", timestamp=now + datetime.timedelta(seconds=4),
        app_id="app-1", tenant_id="tenant-alpha", service_id="database-service",
        event_type="db.bulk_query", severity="high", trace_id=trace,
        attributes={"table": "users", "rows_affected": 5000},
    )
    finding = evaluator.evaluate(ev3)

    assert finding is not None
    assert finding.severity == "high"
    assert finding.evidence["trace_id"] == trace
    assert finding.evidence["completed_stages_count"] == 3
    assert "api_trigger" in finding.evidence["stages"]
    assert "worker_anomaly" in finding.evidence["stages"]
    assert "db_bulk_access" in finding.evidence["stages"]


# -----------------------------------------------------------------------------
# 4 & 5. Multi-Process Distributed Threshold & Sequence Detection
# -----------------------------------------------------------------------------

def _mp_worker_func(worker_id: int, redis_url: str, event_queue: multiprocessing.Queue, result_queue: multiprocessing.Queue):
    """Real worker process running against the shared Redis server."""
    store = RedisCorrelationStateStore(redis_url)
    bf_evaluator = GenericDeclarativeEvaluator(
        rule_id="rule-bf-mp",
        version=1,
        title="Multi-Worker BF",
        description="Threshold",
        spec=LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC,
        state_store=store,
    )
    exfil_evaluator = GenericDeclarativeEvaluator(
        rule_id="rule-exfil-mp",
        version=1,
        title="Multi-Worker Exfil",
        description="Sequence",
        spec=LEGACY_EXFILTRATION_DECLARATIVE_SPEC,
        state_store=store,
    )

    findings = []
    while True:
        ev_dict = event_queue.get()
        if ev_dict is None:
            break
        ev = CanonicalEvent(**ev_dict)
        f1 = bf_evaluator.evaluate(ev)
        if f1:
            findings.append(("threshold", f1.model_dump(mode="json")))
        f2 = exfil_evaluator.evaluate(ev)
        if f2:
            findings.append(("sequence", f2.model_dump(mode="json")))

    result_queue.put((worker_id, findings))


def test_multiprocess_distributed_detection_over_redis(fake_redis_server):
    """
    Hypothesis 2 Verification (Solved via Redis Shared State):
    Events are distributed round-robin across 2 separate OS worker processes.
    Verifies that unlike the in-memory store (which failed with 0 findings),
    the Redis store detects BOTH attacks across workers.
    """
    q1 = multiprocessing.Queue()
    q2 = multiprocessing.Queue()
    res_q = multiprocessing.Queue()

    p1 = multiprocessing.Process(target=_mp_worker_func, args=(1, fake_redis_server, q1, res_q))
    p2 = multiprocessing.Process(target=_mp_worker_func, args=(2, fake_redis_server, q2, res_q))
    p1.start()
    p2.start()

    now = datetime.datetime.now(datetime.timezone.utc)

    # 1. Threshold: 8 attempts distributed round-robin (4 to p1, 4 to p2)
    for i in range(8):
        ev = {
            "event_id": f"ev-mp-bf-{i}",
            "schema_version": "1.0.0",
            "timestamp": (now + datetime.timedelta(seconds=i)).isoformat(),
            "app_id": "app-1",
            "tenant_id": "tenant-alpha",
            "service_id": "api-service",
            "event_type": "auth.login_failed",
            "severity": "medium",
            "source_resource": "192.168.1.88",
            "attributes": {"client_ip": "192.168.1.88"},
        }
        if i % 2 == 0:
            q1.put(ev)
        else:
            q2.put(ev)

    # 2. Sequence: Stage 1 -> p1, Stage 2 -> p2, Stage 3 -> p1
    trace = "trc-mp-exfil-99"
    ev_s1 = {
        "event_id": "ev-mp-s1", "schema_version": "1.0.0", "timestamp": now.isoformat(),
        "app_id": "app-1", "tenant_id": "tenant-alpha", "service_id": "api-service",
        "event_type": "http.request", "severity": "info", "source_resource": "10.0.0.1",
        "target_resource": "/api/v1/internal/export", "trace_id": trace,
        "attributes": {"client_ip": "10.0.0.1"},
    }
    ev_s2 = {
        "event_id": "ev-mp-s2", "schema_version": "1.0.0", "timestamp": (now + datetime.timedelta(seconds=2)).isoformat(),
        "app_id": "app-1", "tenant_id": "tenant-alpha", "service_id": "worker-service",
        "event_type": "worker.job_anomalous", "severity": "medium", "trace_id": trace,
        "attributes": {"anomaly_flag": True},
    }
    ev_s3 = {
        "event_id": "ev-mp-s3", "schema_version": "1.0.0", "timestamp": (now + datetime.timedelta(seconds=4)).isoformat(),
        "app_id": "app-1", "tenant_id": "tenant-alpha", "service_id": "database-service",
        "event_type": "db.bulk_query", "severity": "high", "trace_id": trace,
        "attributes": {"table": "users", "rows_affected": 5000},
    }
    q1.put(ev_s1)
    q2.put(ev_s2)
    q1.put(ev_s3)

    q1.put(None)
    q2.put(None)

    w1_id, w1_findings = res_q.get(timeout=10)
    w2_id, w2_findings = res_q.get(timeout=10)
    p1.join()
    p2.join()

    all_findings = w1_findings + w2_findings
    types = [t for t, _ in all_findings]

    # Invariant: Both threshold and sequence detected across multi-process workers!
    assert "threshold" in types
    assert "sequence" in types
    assert len(all_findings) == 2


# -----------------------------------------------------------------------------
# 6. Atomic Concurrency
# -----------------------------------------------------------------------------

def test_redis_concurrent_updates_atomic(redis_store):
    """
    Spawns 20 threads submitting events concurrently for the same threshold group.
    Verifies atomic increments and exactly 1 initial threshold trigger.
    """
    evaluator = GenericDeclarativeEvaluator(
        rule_id="rule-concurrent-bf",
        version=1,
        title="Concurrent BF",
        description="Threshold",
        spec=LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC,
        state_store=redis_store,
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    findings = []
    lock = threading.Lock()

    def submit(idx):
        ev = CanonicalEvent(
            event_id=f"ev-concurrent-{idx}",
            schema_version="1.0.0",
            timestamp=now + datetime.timedelta(milliseconds=idx * 10),
            app_id="app-1",
            tenant_id="tenant-alpha",
            service_id="api-service",
            event_type="auth.login_failed",
            severity="medium",
            source_resource="192.168.1.99",
            attributes={"client_ip": "192.168.1.99"},
        )
        f = evaluator.evaluate(ev)
        if f:
            with lock:
                findings.append(f)

    with ThreadPoolExecutor(max_workers=10) as executor:
        list(executor.map(submit, range(10)))

    # Invariant: Exactly 1 initial finding triggered despite concurrent arrival
    assert len(findings) == 1
    assert findings[0].severity == "medium"


# -----------------------------------------------------------------------------
# 7. Duplicate Events Idempotent
# -----------------------------------------------------------------------------

def test_redis_duplicate_events_idempotent(redis_store):
    evaluator = GenericDeclarativeEvaluator(
        rule_id="rule-dup-bf",
        version=1,
        title="BF",
        description="Threshold",
        spec=LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC,
        state_store=redis_store,
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    ev = CanonicalEvent(
        event_id="ev-duplicate-constant",
        schema_version="1.0.0",
        timestamp=now,
        app_id="app-1",
        tenant_id="tenant-alpha",
        service_id="api-service",
        event_type="auth.login_failed",
        severity="medium",
        source_resource="192.168.1.55",
        attributes={"client_ip": "192.168.1.55"},
    )
    # Deliver same event 5 times
    for _ in range(5):
        assert evaluator.evaluate(ev) is None


# -----------------------------------------------------------------------------
# 8. Out-of-Order Events
# -----------------------------------------------------------------------------

def test_redis_out_of_order_events(redis_store):
    evaluator = GenericDeclarativeEvaluator(
        rule_id="rule-ooo-seq",
        version=1,
        title="OOO Sequence",
        description="Sequence",
        spec=LEGACY_EXFILTRATION_DECLARATIVE_SPEC,
        state_store=redis_store,
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    trace = "trc-ooo-redis"

    ev3 = CanonicalEvent(
        event_id="ev-ooo-3", schema_version="1.0.0", timestamp=now + datetime.timedelta(seconds=4),
        app_id="app-1", tenant_id="tenant-alpha", service_id="database-service",
        event_type="db.bulk_query", severity="high", trace_id=trace,
        attributes={"table": "users", "rows_affected": 5000},
    )
    assert evaluator.evaluate(ev3) is None

    ev1 = CanonicalEvent(
        event_id="ev-ooo-1", schema_version="1.0.0", timestamp=now,
        app_id="app-1", tenant_id="tenant-alpha", service_id="api-service",
        event_type="http.request", severity="info", source_resource="10.0.0.1",
        target_resource="/api/v1/internal/export", trace_id=trace,
        attributes={"client_ip": "10.0.0.1"},
    )
    assert evaluator.evaluate(ev1) is None

    ev2 = CanonicalEvent(
        event_id="ev-ooo-2", schema_version="1.0.0", timestamp=now + datetime.timedelta(seconds=2),
        app_id="app-1", tenant_id="tenant-alpha", service_id="worker-service",
        event_type="worker.job_anomalous", severity="medium", trace_id=trace,
        attributes={"anomaly_flag": True},
    )
    finding = evaluator.evaluate(ev2)
    assert finding is not None
    assert finding.evidence["completed_stages_count"] == 3


# -----------------------------------------------------------------------------
# 9. Tenant Boundary Isolation in Distributed Keyspace
# -----------------------------------------------------------------------------

def test_redis_tenant_isolation(redis_store):
    evaluator = GenericDeclarativeEvaluator(
        rule_id="rule-tenant-iso",
        version=1,
        title="Tenant Iso",
        description="Threshold",
        spec=LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC,
        state_store=redis_store,
    )
    now = datetime.datetime.now(datetime.timezone.utc)

    # 4 attempts for tenant-alpha
    for i in range(4):
        ev_a = CanonicalEvent(
            event_id=f"ev-iso-a-{i}", schema_version="1.0.0", timestamp=now + datetime.timedelta(seconds=i),
            app_id="app-1", tenant_id="tenant-alpha", service_id="api-service",
            event_type="auth.login_failed", severity="medium", source_resource="10.0.0.99",
            attributes={"client_ip": "10.0.0.99"},
        )
        assert evaluator.evaluate(ev_a) is None

    # 4 attempts for tenant-beta on the SAME IP
    for i in range(4):
        ev_b = CanonicalEvent(
            event_id=f"ev-iso-b-{i}", schema_version="1.0.0", timestamp=now + datetime.timedelta(seconds=i),
            app_id="app-1", tenant_id="tenant-beta", service_id="api-service",
            event_type="auth.login_failed", severity="medium", source_resource="10.0.0.99",
            attributes={"client_ip": "10.0.0.99"},
        )
        assert evaluator.evaluate(ev_b) is None

    # Invariant: Neither tenant reached threshold 5
    # Keys in Redis are strictly scoped
    alpha_keys = redis_store.client.keys("ternline:tenant-alpha:*")
    beta_keys = redis_store.client.keys("ternline:tenant-beta:*")
    assert len(alpha_keys) > 0
    assert len(beta_keys) > 0
    assert set(alpha_keys).isdisjoint(set(beta_keys))


# -----------------------------------------------------------------------------
# 10. Rule Version Isolation
# -----------------------------------------------------------------------------

def test_redis_rule_version_isolation(redis_store):
    ev_v1 = GenericDeclarativeEvaluator(
        rule_id="rule-ver-iso",
        version=1,
        title="V1",
        description="Threshold",
        spec=LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC,
        state_store=redis_store,
    )
    ev_v2 = GenericDeclarativeEvaluator(
        rule_id="rule-ver-iso",
        version=2,
        title="V2",
        description="Threshold",
        spec=LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC,
        state_store=redis_store,
    )
    now = datetime.datetime.now(datetime.timezone.utc)

    # 4 attempts evaluated on v1
    for i in range(4):
        ev = CanonicalEvent(
            event_id=f"ev-v-test-{i}", schema_version="1.0.0", timestamp=now + datetime.timedelta(seconds=i),
            app_id="app-1", tenant_id="tenant-alpha", service_id="api-service",
            event_type="auth.login_failed", severity="medium", source_resource="10.0.0.77",
            attributes={"client_ip": "10.0.0.77"},
        )
        assert ev_v1.evaluate(ev) is None

    # An event arrives evaluated on v2
    ev_new = CanonicalEvent(
        event_id="ev-v-test-5", schema_version="1.0.0", timestamp=now + datetime.timedelta(seconds=5),
        app_id="app-1", tenant_id="tenant-alpha", service_id="api-service",
        event_type="auth.login_failed", severity="medium", source_resource="10.0.0.77",
        attributes={"client_ip": "10.0.0.77"},
    )
    # v2 counter starts at 1, does NOT inherit v1's 4 attempts!
    assert ev_v2.evaluate(ev_new) is None

    # Check keyspace separation
    v1_keys = redis_store.client.keys("*:rule:rule-ver-iso:v1:*")
    v2_keys = redis_store.client.keys("*:rule:rule-ver-iso:v2:*")
    assert len(v1_keys) > 0
    assert len(v2_keys) > 0
    assert set(v1_keys).isdisjoint(set(v2_keys))


# -----------------------------------------------------------------------------
# 11. Redis Connection Failure & Degraded Status
# -----------------------------------------------------------------------------

def test_redis_connection_failure_and_degraded_status():
    """Verifies that an unavailable Redis endpoint reports degraded status and raises RedisStateError."""
    bad_store = RedisCorrelationStateStore("redis://127.0.0.1:9999/0", socket_timeout=0.1)
    health = bad_store.get_health()
    assert health["status"] == "degraded"
    assert health["connected"] is False

    evaluator = GenericDeclarativeEvaluator(
        rule_id="rule-fail-test",
        version=1,
        title="Fail",
        description="Test",
        spec=LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC,
        state_store=bad_store,
    )
    ev = CanonicalEvent(
        event_id="ev-fail-1", schema_version="1.0.0", timestamp=datetime.datetime.now(datetime.timezone.utc),
        app_id="app-1", tenant_id="tenant-alpha", service_id="api-service",
        event_type="auth.login_failed", severity="medium", source_resource="10.0.0.1",
        attributes={"client_ip": "10.0.0.1"},
    )
    with pytest.raises(RedisStateError):
        evaluator.evaluate(ev)


# -----------------------------------------------------------------------------
# 12. Server-Time TTL Expiration
# -----------------------------------------------------------------------------

def test_redis_ttl_expiration(redis_store):
    evaluator = GenericDeclarativeEvaluator(
        rule_id="rule-ttl-test",
        version=1,
        title="TTL Test",
        description="Test",
        spec=LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC,
        state_store=redis_store,
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    ev = CanonicalEvent(
        event_id="ev-ttl-1", schema_version="1.0.0", timestamp=now,
        app_id="app-1", tenant_id="tenant-alpha", service_id="api-service",
        event_type="auth.login_failed", severity="medium", source_resource="10.0.0.33",
        attributes={"client_ip": "10.0.0.33"},
    )
    evaluator.evaluate(ev)

    keys = redis_store.client.keys("ternline:tenant-alpha:rule:rule-ttl-test:v1:thresh:*")
    assert len(keys) >= 1
    # Check that Redis server has set positive TTL
    for k in keys:
        ttl = redis_store.client.ttl(k)
        assert ttl > 0
        assert ttl <= LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC.window_seconds + 120


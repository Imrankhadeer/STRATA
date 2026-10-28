"""
Tests for the CrossServiceExfiltrationDetector.

Covers:
  1. The known suspicious three-stage sequence triggers a finding.
  2. Normal cross-service activity does NOT trigger it.
  3. Missing stages (only 1 or 2 of 3 present) do not trigger.
  4. Mismatched trace IDs across stages do not correlate.
  5. Events outside the configured time window do not trigger.
  6. Replayed (duplicate) events do not create duplicate findings.
  7. Benign lookalike activity is explicitly tested.
  8. Tenant isolation: events from different tenants with same trace ID
     do not cross-correlate.
  9. Out-of-order event arrival still triggers when the pattern completes.
  10. Finding evidence contains all required fields.
"""

import pytest
import uuid
from datetime import datetime, timezone, timedelta

from backend.detection.correlation import CrossServiceExfiltrationDetector
from backend.schemas.events import CanonicalEvent


TENANT = "tenant-test"
APP = "test-app"
TRACE = "trace-exfil-test-001"


def _make_event(
    service_id: str,
    event_type: str,
    trace_id: str = TRACE,
    tenant_id: str = TENANT,
    target_resource: str | None = None,
    attributes: dict | None = None,
    timestamp: datetime | None = None,
    event_id: str | None = None,
) -> CanonicalEvent:
    return CanonicalEvent(
        event_id=event_id or str(uuid.uuid4()),
        tenant_id=tenant_id,
        app_id=APP,
        service_id=service_id,
        event_type=event_type,
        trace_id=trace_id,
        target_resource=target_resource,
        attributes=attributes or {},
        timestamp=timestamp or datetime.now(timezone.utc),
    )


def _api_internal_request(trace_id=TRACE, tenant_id=TENANT, ts=None, event_id=None):
    """Stage 1: API request targeting an internal export endpoint."""
    return _make_event(
        service_id="api-service",
        event_type="http.request",
        trace_id=trace_id,
        tenant_id=tenant_id,
        target_resource="/api/v1/internal/export",
        attributes={"method": "POST", "endpoint": "/api/v1/internal/export", "status_code": 200},
        timestamp=ts,
        event_id=event_id,
    )


def _worker_anomalous(trace_id=TRACE, tenant_id=TENANT, ts=None, event_id=None):
    """Stage 2: Anomalous worker job."""
    return _make_event(
        service_id="worker-service",
        event_type="worker.job_anomalous",
        trace_id=trace_id,
        tenant_id=tenant_id,
        target_resource="job:mass_export_task",
        attributes={"job_name": "mass_export_task", "payload_size_kb": 8500, "anomaly_flag": True},
        timestamp=ts,
        event_id=event_id,
    )


def _db_bulk_sensitive(trace_id=TRACE, tenant_id=TENANT, ts=None, event_id=None,
                       table="credit_cards", rows=50000):
    """Stage 3: Bulk query on a sensitive table."""
    return _make_event(
        service_id="database-service",
        event_type="db.bulk_query",
        trace_id=trace_id,
        tenant_id=tenant_id,
        target_resource=f"pg_cluster:{table}",
        attributes={
            "table": table,
            "operation": "SELECT",
            "rows_affected": rows,
            "is_sensitive_table": table in ("credit_cards", "users", "tokens"),
        },
        timestamp=ts,
        event_id=event_id,
    )


# ---------------------------------------------------------------------------
# 1. Known suspicious sequence triggers a finding
# ---------------------------------------------------------------------------


class TestSuspiciousSequenceTriggers:

    def test_full_three_stage_sequence_triggers_finding(self):
        detector = CrossServiceExfiltrationDetector(time_window_seconds=300)
        now = datetime.now(timezone.utc)

        assert detector.evaluate(_api_internal_request(ts=now)) is None
        assert detector.evaluate(_worker_anomalous(ts=now + timedelta(seconds=1))) is None
        finding = detector.evaluate(_db_bulk_sensitive(ts=now + timedelta(seconds=2)))

        assert finding is not None
        assert finding.detector_id == "detector.cross_service.exfiltration"
        assert finding.detector_version == "1.0.0"
        assert finding.tenant_id == TENANT
        assert finding.severity == "high"
        assert finding.confidence == "high"

    def test_finding_evidence_has_all_required_fields(self):
        detector = CrossServiceExfiltrationDetector(time_window_seconds=300)
        now = datetime.now(timezone.utc)

        detector.evaluate(_api_internal_request(ts=now))
        detector.evaluate(_worker_anomalous(ts=now + timedelta(seconds=1)))
        finding = detector.evaluate(_db_bulk_sensitive(ts=now + timedelta(seconds=2)))

        assert finding is not None
        ev = finding.evidence

        # Top-level evidence fields
        assert ev["trace_id"] == TRACE
        assert "correlation_reason" in ev
        assert isinstance(ev["correlation_reason"], str)
        assert len(ev["correlation_reason"]) > 20

        # Three stages with event IDs and timestamps
        stages = ev["stages"]
        for stage_key in ("api_trigger", "worker_anomaly", "db_bulk_access"):
            assert stage_key in stages
            stage = stages[stage_key]
            assert "event_id" in stage
            assert "timestamp" in stage
            assert "service_id" in stage

        # Supporting event IDs list
        assert "supporting_event_ids" in ev
        assert len(ev["supporting_event_ids"]) == 3

        # Time span
        assert "time_span_seconds" in ev
        assert ev["time_span_seconds"] >= 0

    def test_order_api_then_db_then_worker_still_triggers(self):
        """Out-of-order arrival: the pattern completes once all 3 stages arrive."""
        detector = CrossServiceExfiltrationDetector(time_window_seconds=300)
        now = datetime.now(timezone.utc)

        assert detector.evaluate(_api_internal_request(ts=now)) is None
        assert detector.evaluate(_db_bulk_sensitive(ts=now + timedelta(seconds=1))) is None
        finding = detector.evaluate(_worker_anomalous(ts=now + timedelta(seconds=2)))

        assert finding is not None
        assert finding.detector_id == "detector.cross_service.exfiltration"


# ---------------------------------------------------------------------------
# 2. Normal cross-service activity does NOT trigger
# ---------------------------------------------------------------------------


class TestNormalTrafficDoesNotTrigger:

    def test_normal_four_event_flow_no_finding(self):
        """The normal scenario from run_scenario.py: login + profile + job + select."""
        detector = CrossServiceExfiltrationDetector(time_window_seconds=300)
        now = datetime.now(timezone.utc)
        trace = "trace-normal-flow"

        events = [
            _make_event("api-service", "auth.login_success", trace_id=trace,
                         target_resource="user:alice", timestamp=now),
            _make_event("api-service", "http.request", trace_id=trace,
                         target_resource="/api/v1/profile",
                         attributes={"method": "GET", "endpoint": "/api/v1/profile"},
                         timestamp=now + timedelta(seconds=1)),
            _make_event("worker-service", "worker.job_completed", trace_id=trace,
                         target_resource="job:sync_profile_cache",
                         attributes={"job_name": "sync_profile_cache", "payload_size_kb": 4},
                         timestamp=now + timedelta(seconds=2)),
            _make_event("database-service", "db.query_executed", trace_id=trace,
                         target_resource="pg_cluster:user_profiles",
                         attributes={"table": "user_profiles", "operation": "SELECT",
                                     "rows_affected": 1, "is_sensitive_table": False},
                         timestamp=now + timedelta(seconds=3)),
        ]

        for ev in events:
            finding = detector.evaluate(ev)
            assert finding is None, f"False positive on event {ev.event_type}"


# ---------------------------------------------------------------------------
# 3. Missing stages do not trigger
# ---------------------------------------------------------------------------


class TestMissingStagesDoNotTrigger:

    def test_only_api_event(self):
        detector = CrossServiceExfiltrationDetector(time_window_seconds=300)
        assert detector.evaluate(_api_internal_request()) is None

    def test_only_worker_and_db_events(self):
        """Missing stage 1 (API internal request)."""
        detector = CrossServiceExfiltrationDetector(time_window_seconds=300)
        assert detector.evaluate(_worker_anomalous()) is None
        assert detector.evaluate(_db_bulk_sensitive()) is None

    def test_only_api_and_worker_events(self):
        """Missing stage 3 (bulk DB query)."""
        detector = CrossServiceExfiltrationDetector(time_window_seconds=300)
        assert detector.evaluate(_api_internal_request()) is None
        assert detector.evaluate(_worker_anomalous()) is None

    def test_only_api_and_db_events(self):
        """Missing stage 2 (anomalous worker job)."""
        detector = CrossServiceExfiltrationDetector(time_window_seconds=300)
        assert detector.evaluate(_api_internal_request()) is None
        assert detector.evaluate(_db_bulk_sensitive()) is None


# ---------------------------------------------------------------------------
# 4. Mismatched trace IDs do not correlate
# ---------------------------------------------------------------------------


class TestMismatchedTraceIDs:

    def test_different_traces_no_correlation(self):
        detector = CrossServiceExfiltrationDetector(time_window_seconds=300)
        now = datetime.now(timezone.utc)

        assert detector.evaluate(_api_internal_request(trace_id="trace-A", ts=now)) is None
        assert detector.evaluate(_worker_anomalous(trace_id="trace-B", ts=now + timedelta(seconds=1))) is None
        finding = detector.evaluate(_db_bulk_sensitive(trace_id="trace-C", ts=now + timedelta(seconds=2)))
        assert finding is None

    def test_no_trace_id_ignored(self):
        """Events without trace_id should be silently skipped."""
        detector = CrossServiceExfiltrationDetector(time_window_seconds=300)
        ev = _make_event("api-service", "http.request", trace_id=None)
        # trace_id=None means CanonicalEvent.trace_id is None
        ev.trace_id = None
        assert detector.evaluate(ev) is None


# ---------------------------------------------------------------------------
# 5. Events outside the time window do not trigger
# ---------------------------------------------------------------------------


class TestTimeWindowExpiry:

    def test_stages_outside_window_no_finding(self):
        """Stage 3 arrives 10 minutes after stage 1, beyond the 60s window."""
        detector = CrossServiceExfiltrationDetector(time_window_seconds=60)
        now = datetime.now(timezone.utc)

        assert detector.evaluate(_api_internal_request(ts=now)) is None
        assert detector.evaluate(_worker_anomalous(ts=now + timedelta(seconds=30))) is None
        # DB event 10 minutes later: window span is 600s > 60s limit.
        finding = detector.evaluate(_db_bulk_sensitive(ts=now + timedelta(seconds=600)))
        assert finding is None

    def test_stages_just_within_window_triggers(self):
        """All three stages arrive within the window boundary."""
        detector = CrossServiceExfiltrationDetector(time_window_seconds=60)
        now = datetime.now(timezone.utc)

        assert detector.evaluate(_api_internal_request(ts=now)) is None
        assert detector.evaluate(_worker_anomalous(ts=now + timedelta(seconds=25))) is None
        finding = detector.evaluate(_db_bulk_sensitive(ts=now + timedelta(seconds=55)))
        assert finding is not None


# ---------------------------------------------------------------------------
# 6. Replayed events do not create duplicate findings
# ---------------------------------------------------------------------------


class TestDeduplication:

    def test_replay_same_trace_no_duplicate_finding(self):
        detector = CrossServiceExfiltrationDetector(time_window_seconds=300)
        now = datetime.now(timezone.utc)

        api_ev = _api_internal_request(ts=now)
        worker_ev = _worker_anomalous(ts=now + timedelta(seconds=1))
        db_ev = _db_bulk_sensitive(ts=now + timedelta(seconds=2))

        detector.evaluate(api_ev)
        detector.evaluate(worker_ev)
        first_finding = detector.evaluate(db_ev)
        assert first_finding is not None

        # Replay the entire sequence with the same trace ID.
        assert detector.evaluate(_api_internal_request(ts=now + timedelta(seconds=10))) is None
        assert detector.evaluate(_worker_anomalous(ts=now + timedelta(seconds=11))) is None
        assert detector.evaluate(_db_bulk_sensitive(ts=now + timedelta(seconds=12))) is None

    def test_same_event_id_no_duplicate(self):
        """Replay with identical event_id values."""
        detector = CrossServiceExfiltrationDetector(time_window_seconds=300)
        now = datetime.now(timezone.utc)
        fixed_ids = [str(uuid.uuid4()) for _ in range(3)]

        detector.evaluate(_api_internal_request(ts=now, event_id=fixed_ids[0]))
        detector.evaluate(_worker_anomalous(ts=now + timedelta(seconds=1), event_id=fixed_ids[1]))
        first = detector.evaluate(_db_bulk_sensitive(ts=now + timedelta(seconds=2), event_id=fixed_ids[2]))
        assert first is not None

        # Replay
        assert detector.evaluate(_api_internal_request(ts=now, event_id=fixed_ids[0])) is None
        assert detector.evaluate(_worker_anomalous(ts=now, event_id=fixed_ids[1])) is None
        assert detector.evaluate(_db_bulk_sensitive(ts=now, event_id=fixed_ids[2])) is None


# ---------------------------------------------------------------------------
# 7. Benign lookalike activity
# ---------------------------------------------------------------------------


class TestBenignLookalikes:

    def test_public_endpoint_with_anomalous_worker_and_bulk_query(self):
        """API hit targets a PUBLIC endpoint → stage 1 does not match."""
        detector = CrossServiceExfiltrationDetector(time_window_seconds=300)
        now = datetime.now(timezone.utc)
        trace = "trace-benign-public"

        # Public endpoint, not internal
        api = _make_event("api-service", "http.request", trace_id=trace,
                          target_resource="/api/v1/public/report",
                          attributes={"method": "GET", "endpoint": "/api/v1/public/report"},
                          timestamp=now)
        assert detector.evaluate(api) is None
        assert detector.evaluate(_worker_anomalous(trace_id=trace, ts=now + timedelta(seconds=1))) is None
        assert detector.evaluate(_db_bulk_sensitive(trace_id=trace, ts=now + timedelta(seconds=2))) is None

    def test_internal_endpoint_normal_worker_bulk_query(self):
        """API hits internal endpoint, but worker job is NORMAL (not anomalous)."""
        detector = CrossServiceExfiltrationDetector(time_window_seconds=300)
        now = datetime.now(timezone.utc)
        trace = "trace-benign-normal-worker"

        assert detector.evaluate(_api_internal_request(trace_id=trace, ts=now)) is None

        normal_worker = _make_event("worker-service", "worker.job_completed",
                                     trace_id=trace,
                                     attributes={"job_name": "export_report", "anomaly_flag": False},
                                     timestamp=now + timedelta(seconds=1))
        assert detector.evaluate(normal_worker) is None
        assert detector.evaluate(_db_bulk_sensitive(trace_id=trace, ts=now + timedelta(seconds=2))) is None

    def test_full_stages_but_nonsensitive_table(self):
        """All three stages present, but DB query is on a non-sensitive table."""
        detector = CrossServiceExfiltrationDetector(time_window_seconds=300)
        now = datetime.now(timezone.utc)
        trace = "trace-benign-nonsensitive"

        assert detector.evaluate(_api_internal_request(trace_id=trace, ts=now)) is None
        assert detector.evaluate(_worker_anomalous(trace_id=trace, ts=now + timedelta(seconds=1))) is None

        # Non-sensitive table
        db_ev = _make_event("database-service", "db.bulk_query", trace_id=trace,
                            attributes={"table": "audit_log", "rows_affected": 100000,
                                        "is_sensitive_table": False, "operation": "SELECT"},
                            timestamp=now + timedelta(seconds=2))
        assert detector.evaluate(db_ev) is None

    def test_full_stages_but_low_row_count(self):
        """All three stages, sensitive table, but row count below threshold."""
        detector = CrossServiceExfiltrationDetector(
            time_window_seconds=300, bulk_row_threshold=1000
        )
        now = datetime.now(timezone.utc)
        trace = "trace-benign-low-rows"

        assert detector.evaluate(_api_internal_request(trace_id=trace, ts=now)) is None
        assert detector.evaluate(_worker_anomalous(trace_id=trace, ts=now + timedelta(seconds=1))) is None
        finding = detector.evaluate(_db_bulk_sensitive(
            trace_id=trace, ts=now + timedelta(seconds=2), rows=50  # below 1000
        ))
        assert finding is None


# ---------------------------------------------------------------------------
# 8. Tenant isolation during correlation
# ---------------------------------------------------------------------------


class TestTenantIsolation:

    def test_same_trace_different_tenants_no_correlation(self):
        """Stages from different tenants sharing the same trace ID must NOT correlate."""
        detector = CrossServiceExfiltrationDetector(time_window_seconds=300)
        now = datetime.now(timezone.utc)
        shared_trace = "trace-shared-cross-tenant"

        assert detector.evaluate(
            _api_internal_request(trace_id=shared_trace, tenant_id="tenant-A", ts=now)
        ) is None
        assert detector.evaluate(
            _worker_anomalous(trace_id=shared_trace, tenant_id="tenant-B", ts=now + timedelta(seconds=1))
        ) is None
        finding = detector.evaluate(
            _db_bulk_sensitive(trace_id=shared_trace, tenant_id="tenant-C", ts=now + timedelta(seconds=2))
        )
        assert finding is None

    def test_same_tenant_same_trace_triggers(self):
        """Sanity: same tenant + same trace still triggers."""
        detector = CrossServiceExfiltrationDetector(time_window_seconds=300)
        now = datetime.now(timezone.utc)
        trace = "trace-same-tenant-ok"

        detector.evaluate(_api_internal_request(trace_id=trace, tenant_id="tenant-X", ts=now))
        detector.evaluate(_worker_anomalous(trace_id=trace, tenant_id="tenant-X", ts=now + timedelta(seconds=1)))
        finding = detector.evaluate(
            _db_bulk_sensitive(trace_id=trace, tenant_id="tenant-X", ts=now + timedelta(seconds=2))
        )
        assert finding is not None
        assert finding.tenant_id == "tenant-X"


# ---------------------------------------------------------------------------
# 9. End-to-end: synthetic exfiltration scenario triggers finding via API
# ---------------------------------------------------------------------------


class TestEndToEndCorrelationViaAPI:

    def test_exfiltration_scenario_produces_finding(self, client, auth_headers, db_session):
        """
        Sends the three-stage exfiltration event sequence through the HTTP API
        and verifies a SecurityFinding is persisted in the database.
        """
        from backend.models import SecurityFinding
        from tests.conftest import TEST_TENANT_ID, TEST_APP_ID

        trace = f"trace-e2e-exfil-{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc)

        events = [
            {
                "event_id": str(uuid.uuid4()),
                "app_id": TEST_APP_ID,
                "service_id": "api-service",
                "event_type": "http.request",
                "trace_id": trace,
                "target_resource": "/api/v1/internal/export",
                "attributes": {"method": "POST", "endpoint": "/api/v1/internal/export"},
                "timestamp": now.isoformat(),
            },
            {
                "event_id": str(uuid.uuid4()),
                "app_id": TEST_APP_ID,
                "service_id": "worker-service",
                "event_type": "worker.job_anomalous",
                "trace_id": trace,
                "target_resource": "job:mass_export_task",
                "attributes": {"job_name": "mass_export_task", "payload_size_kb": 8500, "anomaly_flag": True},
                "timestamp": (now + timedelta(seconds=1)).isoformat(),
            },
            {
                "event_id": str(uuid.uuid4()),
                "app_id": TEST_APP_ID,
                "service_id": "database-service",
                "event_type": "db.bulk_query",
                "trace_id": trace,
                "target_resource": "pg_cluster:credit_cards",
                "attributes": {
                    "table": "credit_cards", "operation": "SELECT",
                    "rows_affected": 50000, "is_sensitive_table": True,
                },
                "timestamp": (now + timedelta(seconds=2)).isoformat(),
            },
        ]

        for ev in events:
            res = client.post("/v1/events", headers=auth_headers, json=ev)
            assert res.status_code == 202, f"Failed to ingest {ev['event_type']}: {res.text}"

        # Verify finding persisted
        findings = db_session.query(SecurityFinding).filter(
            SecurityFinding.detector_id == "detector.cross_service.exfiltration",
            SecurityFinding.tenant_id == TEST_TENANT_ID,
        ).all()

        assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"
        f = findings[0]
        assert f.severity == "high"
        assert f.confidence == "high"
        assert trace in f.title
        assert "credit_cards" in f.description
        assert f.evidence["trace_id"] == trace
        assert len(f.evidence["stages"]) == 3

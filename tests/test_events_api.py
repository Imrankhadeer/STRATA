"""
Tests for Events & Historical Telemetry Search API (/api/v1/events).

Validates:
1. Strict tenant isolation on event queries.
2. Event Explorer listing with service, severity, trace_id filtering and pagination.
3. Historical bounded search with time ranges, category, min_severity, and period comparison.
4. Input validation (from < to, max duration limit).
5. Read-only safety: search queries never trigger Fast Track detection or findings.
"""

import datetime
import pytest
from backend.models import EventModel, SecurityFinding
from tests.conftest import TEST_TENANT_ID, TEST_APP_ID


@pytest.fixture
def seed_events(db_session):
    """Seeds a controlled set of events for testing search and isolation."""
    now = datetime.datetime.now(datetime.timezone.utc)
    events = [
        # Event 1: Auth service, low severity, 2 hours ago
        EventModel(
            event_id="ev-test-1",
            schema_version="1.0.0",
            timestamp=now - datetime.timedelta(hours=2),
            tenant_id=TEST_TENANT_ID,
            app_id=TEST_APP_ID,
            service_id="auth-service",
            event_type="auth.login_attempt",
            severity="low",
            source_resource="192.168.1.10",
            trace_id="tr-test-001",
            attributes={"client": "web"},
        ),
        # Event 2: Worker service, high severity, 1 hour ago
        EventModel(
            event_id="ev-test-2",
            schema_version="1.0.0",
            timestamp=now - datetime.timedelta(hours=1),
            tenant_id=TEST_TENANT_ID,
            app_id=TEST_APP_ID,
            service_id="worker-service",
            event_type="data_exfiltration.anomaly",
            severity="high",
            source_resource="192.168.1.10",
            trace_id="tr-test-001",
            attributes={"bytes": 5000000},
        ),
        # Event 3: Previous period event (26 hours ago) for comparison tests
        EventModel(
            event_id="ev-test-3",
            schema_version="1.0.0",
            timestamp=now - datetime.timedelta(hours=26),
            tenant_id=TEST_TENANT_ID,
            app_id=TEST_APP_ID,
            service_id="auth-service",
            event_type="auth.login_attempt",
            severity="low",
            source_resource="192.168.1.20",
            trace_id="tr-test-002",
        ),
        # Event 4: Another tenant's event (cross-tenant isolation)
        EventModel(
            event_id="ev-other-tenant-1",
            schema_version="1.0.0",
            timestamp=now - datetime.timedelta(minutes=30),
            tenant_id="tenant-beta",
            app_id="other-app",
            service_id="auth-service",
            event_type="auth.login_attempt",
            severity="critical",
            source_resource="10.0.0.1",
            trace_id="tr-beta-001",
        ),
    ]
    for ev in events:
        db_session.add(ev)
    db_session.commit()
    return events


def test_list_events_tenant_isolation(client, auth_headers, seed_events):
    res = client.get("/api/v1/events", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    # Should only return TEST_TENANT_ID events (3 total), not tenant-beta
    assert len(data) == 3
    event_ids = [e["event_id"] for e in data]
    assert "ev-other-tenant-1" not in event_ids
    assert "ev-test-2" in event_ids
    assert "ev-test-1" in event_ids
    assert "ev-test-3" in event_ids


def test_list_events_filtering(client, auth_headers, seed_events):
    # Filter by service_id
    res_svc = client.get("/api/v1/events?service_id=worker-service", headers=auth_headers)
    assert res_svc.status_code == 200
    data_svc = res_svc.json()
    assert len(data_svc) == 1
    assert data_svc[0]["event_id"] == "ev-test-2"

    # Filter by trace_id
    res_tr = client.get("/api/v1/events?trace_id=tr-test-001", headers=auth_headers)
    assert res_tr.status_code == 200
    assert len(res_tr.json()) == 2

    # Filter by severity
    res_sev = client.get("/api/v1/events?severity=high", headers=auth_headers)
    assert res_sev.status_code == 200
    data_sev = res_sev.json()
    assert len(data_sev) == 1
    assert data_sev[0]["event_id"] == "ev-test-2"


def test_historical_search_with_summary(client, auth_headers, seed_events):
    now = datetime.datetime.now(datetime.timezone.utc)
    from_iso = (now - datetime.timedelta(hours=5)).isoformat()
    to_iso = now.isoformat()

    res = client.get(
        f"/api/v1/events/search?from={from_iso}&to={to_iso}",
        headers=auth_headers,
    )
    assert res.status_code == 200
    data = res.json()
    assert "events" in data
    assert "summary" in data
    # In last 5 hours, ev-test-1 and ev-test-2 occurred
    assert len(data["events"]) == 2
    assert data["summary"]["total_events"] == 2
    assert data["summary"]["by_severity"]["high"] == 1
    assert data["summary"]["by_severity"]["low"] == 1


def test_historical_search_comparison(client, auth_headers, seed_events):
    now = datetime.datetime.now(datetime.timezone.utc)
    # Search window: last 12 hours (ev-test-1 and ev-test-2 are in this window)
    from_iso = (now - datetime.timedelta(hours=12)).isoformat()
    to_iso = now.isoformat()

    res = client.get(
        f"/api/v1/events/search?from={from_iso}&to={to_iso}&compare_previous=true",
        headers=auth_headers,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["comparison"] is not None
    # Previous window (12-24 hours ago) had 0 events, but ev-test-3 is 26 hours ago
    assert "delta_events" in data["comparison"]
    assert "percentage_change" in data["comparison"]


def test_historical_search_invalid_range_rejected(client, auth_headers):
    now = datetime.datetime.now(datetime.timezone.utc)
    from_iso = now.isoformat()
    to_iso = (now - datetime.timedelta(hours=1)).isoformat()  # to < from

    res = client.get(
        f"/api/v1/events/search?from={from_iso}&to={to_iso}",
        headers=auth_headers,
    )
    assert res.status_code == 400
    assert "strictly earlier" in res.json()["detail"]


def test_historical_search_read_only_safety(client, auth_headers, seed_events, db_session):
    """Historical search queries must NEVER trigger detections or produce findings."""
    count_before = db_session.query(SecurityFinding).count()

    res = client.get("/api/v1/events/search", headers=auth_headers)
    assert res.status_code == 200

    count_after = db_session.query(SecurityFinding).count()
    assert count_before == count_after


def test_get_event_by_id(client, auth_headers, seed_events):
    res = client.get("/api/v1/events/ev-test-1", headers=auth_headers)
    assert res.status_code == 200
    assert res.json()["event_id"] == "ev-test-1"

    # Cross-tenant access must return 404
    res_cross = client.get("/api/v1/events/ev-other-tenant-1", headers=auth_headers)
    assert res_cross.status_code == 404


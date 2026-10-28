import pytest
from datetime import datetime, timezone
import uuid
from backend.models import EventModel
from tests.conftest import TEST_TENANT_ID, TEST_APP_ID


def test_health_check(client):
    """Verifies health check endpoint returns 200 and connectivity."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["database"] == "connected"
    assert "version" in data


def test_missing_or_invalid_auth(client):
    """Verifies unauthenticated requests are rejected with 401."""
    # No auth header
    res_no_auth = client.post("/v1/events", json={})
    assert res_no_auth.status_code == 401

    # Invalid Bearer token
    res_bad_key = client.post(
        "/v1/events",
        headers={"Authorization": "Bearer ce_live_invalid_nonexistent_key"},
        json={}
    )
    assert res_bad_key.status_code == 401


def test_valid_event_ingestion_and_persistence(client, auth_headers, db_session):
    """Verifies valid event schema is accepted, stored, and retrieved correctly."""
    event_id = str(uuid.uuid4())
    payload = {
        "event_id": event_id,
        "schema_version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "app_id": TEST_APP_ID,
        "service_id": "auth-service",
        "event_type": "auth.user_registered",
        "severity": "info",
        "source_resource": "192.168.1.50",
        "target_resource": "user:testuser",
        "trace_id": "trace-101",
        "attributes": {"plan": "pro", "marketing_opt_in": True},
        "provenance": {"origin": "test_suite"}
    }

    res = client.post("/v1/events", headers=auth_headers, json=payload)
    assert res.status_code == 202
    data = res.json()
    assert data["accepted"] == 1
    assert data["duplicates"] == 0
    assert event_id in data["event_ids"]

    # Verify database persistence and tenant isolation enforcement
    stored_event = db_session.query(EventModel).filter(EventModel.event_id == event_id).first()
    assert stored_event is not None
    assert stored_event.tenant_id == TEST_TENANT_ID  # server-enforced tenant
    assert stored_event.app_id == TEST_APP_ID
    assert stored_event.event_type == "auth.user_registered"
    assert stored_event.attributes["plan"] == "pro"


def test_rejection_of_malformed_events(client, auth_headers):
    """Verifies malformed events are strictly rejected with 422 Unprocessable Entity."""
    # Missing required app_id and service_id
    bad_payload_missing_fields = {
        "event_type": "auth.login"
    }
    res1 = client.post("/v1/events", headers=auth_headers, json=bad_payload_missing_fields)
    assert res1.status_code == 422

    # Malformed event_type with invalid injection characters
    bad_payload_injection = {
        "app_id": TEST_APP_ID,
        "service_id": "web",
        "event_type": "auth; DROP TABLE events; --",
    }
    res2 = client.post("/v1/events", headers=auth_headers, json=bad_payload_injection)
    assert res2.status_code == 422


def test_duplicate_event_handling(client, auth_headers):
    """Verifies idempotent duplicate handling does not create duplicate entries or error."""
    event_id = str(uuid.uuid4())
    payload = {
        "event_id": event_id,
        "app_id": TEST_APP_ID,
        "service_id": "api",
        "event_type": "http.request",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "attributes": {"path": "/health"}
    }

    # First ingestion
    res1 = client.post("/v1/events", headers=auth_headers, json=payload)
    assert res1.status_code == 202
    assert res1.json()["accepted"] == 1

    # Second ingestion with same event_id
    res2 = client.post("/v1/events", headers=auth_headers, json=payload)
    assert res2.status_code == 202
    assert res2.json()["duplicates"] == 1
    assert res2.json()["accepted"] == 0


def test_tenant_and_app_scoping_isolation(client, auth_headers):
    """Verifies API key cannot ingest events belonging to another application."""
    mismatched_app_event = {
        "event_id": str(uuid.uuid4()),
        "app_id": "unauthorized-other-app",
        "service_id": "auth-service",
        "event_type": "auth.login",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    res = client.post("/v1/events", headers=auth_headers, json=mismatched_app_event)
    assert res.status_code == 403
    assert "scoped to application" in res.json()["detail"]


def test_batch_ingestion(client, auth_headers):
    """Verifies batch endpoint accepts multiple events and handles duplicate tracking."""
    event1_id = str(uuid.uuid4())
    event2_id = str(uuid.uuid4())
    batch_payload = {
        "events": [
            {
                "event_id": event1_id,
                "app_id": TEST_APP_ID,
                "service_id": "worker",
                "event_type": "job.started",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            {
                "event_id": event2_id,
                "app_id": TEST_APP_ID,
                "service_id": "worker",
                "event_type": "job.finished",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ]
    }
    res = client.post("/v1/events/batch", headers=auth_headers, json=batch_payload)
    assert res.status_code == 202
    data = res.json()
    assert data["accepted"] == 2
    assert data["duplicates"] == 0
    assert len(data["event_ids"]) == 2

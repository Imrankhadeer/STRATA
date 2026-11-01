import asyncio
import time
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.ops.bus import (
    ops_bus,
    OpsEvent,
    sanitize_ops_metadata,
)
from backend.models import SecurityFinding, DeclarativeRuleModel, EventModel, Tenant
from tests.conftest import TEST_TENANT_ID, RAW_TEST_API_KEY


# ---------------------------------------------------------------------------
# 1. OpsEventBus Unit & Isolation Tests
# ---------------------------------------------------------------------------

def test_ops_bus_publish_and_subscribe_isolation():
    ops_bus.clear_buffer()
    tenant_a = "tenant-a"
    tenant_b = "tenant-b"

    # Publish event for Tenant A
    ev_a = OpsEvent(
        level="info",
        component="test",
        event_type="test.event_a",
        message="Hello A",
        tenant_id=tenant_a,
    )
    ops_bus.publish(ev_a)

    # Publish event for Tenant B
    ev_b = OpsEvent(
        level="warn",
        component="test",
        event_type="test.event_b",
        message="Hello B",
        tenant_id=tenant_b,
    )
    ops_bus.publish(ev_b)

    # Tenant A buffer receives only ev_a
    recent_a = ops_bus.get_buffered_events(tenant_id=tenant_a)
    assert len(recent_a) == 1
    assert recent_a[0].message == "Hello A"
    assert recent_a[0].tenant_id == tenant_a

    # Tenant B buffer receives only ev_b
    recent_b = ops_bus.get_buffered_events(tenant_id=tenant_b)
    assert len(recent_b) == 1
    assert recent_b[0].message == "Hello B"
    assert recent_b[0].tenant_id == tenant_b


def test_ops_bus_recent_history_retention_and_filtering():
    ops_bus.clear_buffer()
    tenant_x = "tenant-x"
    tenant_y = "tenant-y"

    for i in range(10):
        ops_bus.publish(OpsEvent(
            level="info",
            component="system",
            event_type="test.tick",
            message=f"Msg X {i}",
            tenant_id=tenant_x,
        ))

    ops_bus.publish(OpsEvent(
        level="info",
        component="system",
        event_type="test.tick",
        message="Msg Y 0",
        tenant_id=tenant_y,
    ))

    recent_x = ops_bus.get_recent(tenant_id=tenant_x, limit=5)
    assert len(recent_x) == 5
    assert all(e.tenant_id == tenant_x for e in recent_x)

    recent_y = ops_bus.get_recent(tenant_id=tenant_y, limit=10)
    assert len(recent_y) >= 1
    assert all(e.tenant_id == tenant_y for e in recent_y)


# ---------------------------------------------------------------------------
# 2. Secret Redaction Tests
# ---------------------------------------------------------------------------

def test_sanitize_ops_metadata_recursive_redaction():
    raw_metadata = {
        "tenant_id": "cust-123",
        "service": "checkout",
        "api_key": "secret-live-key-xyz",
        "bearer_token": "eyJh...sensitive",
        "credentials": {
            "db_password": "supersecretpassword",
            "access_token": "acc_998877",
            "safe_counter": 42
        },
        "cookie_headers": ["session=12345", "theme=dark"],
        "nested_list": [
            {"secret_value": "hide_me", "public_id": "pub_1"}
        ]
    }

    sanitized = sanitize_ops_metadata(raw_metadata)

    assert sanitized["tenant_id"] == "cust-123"
    assert sanitized["service"] == "checkout"
    assert sanitized["api_key"] == "[REDACTED]"
    assert sanitized["bearer_token"] == "[REDACTED]"
    assert sanitized["credentials"]["db_password"] == "[REDACTED]"
    assert sanitized["credentials"]["access_token"] == "[REDACTED]"
    assert sanitized["credentials"]["safe_counter"] == 42
    assert sanitized["nested_list"][0]["secret_value"] == "[REDACTED]"
    assert sanitized["nested_list"][0]["public_id"] == "pub_1"


# ---------------------------------------------------------------------------
# 3. Stream Ticket Security Tests
# ---------------------------------------------------------------------------

def test_stream_ticket_lifecycle():
    tenant = "tenant-secure"
    app_id = "test-app"
    ticket = ops_bus.create_stream_ticket(tenant_id=tenant, app_id=app_id)
    assert ticket.startswith("stk_")

    # First consumption succeeds
    consumed = ops_bus.validate_and_consume_ticket(ticket)
    assert consumed is not None
    assert consumed[0] == tenant
    assert consumed[1] == app_id

    # Replay/second consumption fails
    replay = ops_bus.validate_and_consume_ticket(ticket)
    assert replay is None


def test_stream_ticket_expiration():
    tenant = "tenant-expiring"
    app_id = "test-app"
    ticket = ops_bus.create_stream_ticket(tenant_id=tenant, app_id=app_id)
    # Manually expire ticket in internal map
    ops_bus._tickets[ticket].expires_at = time.time() - 10
    consumed = ops_bus.validate_and_consume_ticket(ticket)
    assert consumed is None


# ---------------------------------------------------------------------------
# 4. API Endpoints: Overview & Stream Tickets
# ---------------------------------------------------------------------------

def test_stream_ticket_endpoint_auth_and_issuance(client, auth_headers):
    # Unauthenticated rejected
    res_unauth = client.post("/api/v1/ops/stream-ticket")
    assert res_unauth.status_code == 401

    # Authenticated generates valid ticket
    res = client.post("/api/v1/ops/stream-ticket", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert "ticket" in data
    assert data["ticket"].startswith("stk_")
    assert data["expires_in_seconds"] == 60


def test_ops_overview_endpoint(client, auth_headers, db_session):
    # Seed findings for TEST_TENANT_ID
    f1 = SecurityFinding(
        finding_id="find-m7-001",
        tenant_id=TEST_TENANT_ID,
        detector_id="sql_detector",
        detector_version="1.0.0",
        title="SQL Injection Detected",
        severity="critical",
        confidence="high",
        description="SQL injection attack detected on payments gateway",
        status="open",
        evidence={"service_id": "payment-gw", "evidence_event_ids": ["evt-1"]},
        created_at=datetime.now(timezone.utc),
    )
    f2 = SecurityFinding(
        finding_id="find-m7-002",
        tenant_id=TEST_TENANT_ID,
        detector_id="token_detector",
        detector_version="1.0.0",
        title="Excessive Token Rotation",
        severity="medium",
        confidence="medium",
        description="High frequency token requests",
        status="resolved",
        evidence={"service_id": "auth-svc", "evidence_event_ids": ["evt-2"]},
        created_at=datetime.now(timezone.utc),
    )
    # Seed finding for another tenant to verify tenant boundary
    f_other = SecurityFinding(
        finding_id="find-other-001",
        tenant_id="tenant-beta",
        detector_id="admin_detector",
        detector_version="1.0.0",
        title="Unauthorized Admin Action",
        severity="critical",
        confidence="high",
        description="Admin action from unrecognized IP",
        status="open",
        evidence={"service_id": "internal-api", "evidence_event_ids": ["evt-x"]},
        created_at=datetime.now(timezone.utc),
    )
    db_session.add_all([f1, f2, f_other])
    db_session.commit()

    res = client.get("/api/v1/ops/overview", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()

    # Verify Security Posture
    posture = data["security_posture"]
    assert posture["open_findings"] == 1  # Only f1 for TEST_TENANT_ID, f_other excluded
    assert posture["by_severity"]["critical"] == 1
    assert posture["by_status"]["open"] == 1
    assert posture["by_status"]["resolved"] == 1

    recent = data["recent_findings"]
    assert any(rf["finding_id"] == "find-m7-001" for rf in recent)
    assert not any(rf["finding_id"] == "find-other-001" for rf in recent)

    # Verify Pipeline Health structure
    health = data["pipeline_health"]
    assert "database_status" in health
    assert health["database_status"] in ("connected", "healthy")
    assert "uninstrumented_metrics" in data

    # Verify Rules Summary
    rules = data["rules"]
    assert "by_status" in rules
    assert "total_rules" in rules


def test_ops_events_stream_security_and_streaming(client, auth_headers):
    # 1. No auth or ticket -> 401
    res_noauth = client.get("/api/v1/ops/events/stream")
    assert res_noauth.status_code == 401

    # 2. Invalid ticket -> 401
    res_bad_ticket = client.get("/api/v1/ops/events/stream?ticket=stk_nonexistent")
    assert res_bad_ticket.status_code == 401

    # 3. Valid ticket consumption with bounded streaming (max_events=1)
    ticket_res = client.post("/api/v1/ops/stream-ticket", headers=auth_headers)
    assert ticket_res.status_code == 200
    ticket = ticket_res.json()["ticket"]

    # Connect using single-use ticket; max_events=1 guarantees immediate clean exit
    response = client.get(f"/api/v1/ops/events/stream?ticket={ticket}&max_events=1")
    assert response.status_code == 200
    assert "text/event-stream" in response.headers["content-type"]
    assert "event: connected" in response.text

    # 4. Reusing consumed ticket immediately rejected with 401
    res_reused = client.get(f"/api/v1/ops/events/stream?ticket={ticket}")
    assert res_reused.status_code == 401


# ---------------------------------------------------------------------------
# 5. Live Ingestion & Rule Lifecycle Event Publishing
# ---------------------------------------------------------------------------

def test_ingest_and_rule_instrumentation_emits_ops_events(client, auth_headers):
    ops_bus.clear_buffer()

    # Ingest a clean event via /v1/events
    event_payload = {
        "event_id": "evt-ops-test-1",
        "schema_version": "1.0.0",
        "event_type": "api_request",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "app_id": "payments-api",
        "service_id": "frontend",
        "source_resource": "192.168.1.100",
        "target_resource": "/health",
        "trace_id": "trace-ops-1",
        "action": "GET",
        "attributes": {"path": "/health"},
    }
    res_ingest = client.post("/v1/events", json=event_payload, headers=auth_headers)
    assert res_ingest.status_code == 202

    # Check that ops_bus received an event
    buffered = ops_bus.get_recent(tenant_id=TEST_TENANT_ID)
    received_types = [ev.event_type for ev in buffered]
    assert "ingest.event_received" in received_types

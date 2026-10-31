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
    tenant_a = "tenant-a"
    tenant_b = "tenant-b"

    sub_a = ops_bus.subscribe(tenant_id=tenant_a)
    sub_b = ops_bus.subscribe(tenant_id=tenant_b)

    try:
        # Publish event for Tenant A
        ev_a = OpsEvent(
            level="INFO",
            component="test",
            event_type="test.event_a",
            message="Hello A",
            tenant_id=tenant_a,
        )
        ops_bus.publish(ev_a)

        # Publish event for Tenant B
        ev_b = OpsEvent(
            level="WARN",
            component="test",
            event_type="test.event_b",
            message="Hello B",
            tenant_id=tenant_b,
        )
        ops_bus.publish(ev_b)

        # Sub A should receive ev_a and NOT ev_b
        assert not sub_a.empty()
        rec_a = sub_a.get_nowait()
        assert rec_a.message == "Hello A"
        assert rec_a.tenant_id == tenant_a
        assert sub_a.empty()

        # Sub B should receive ev_b and NOT ev_a
        assert not sub_b.empty()
        rec_b = sub_b.get_nowait()
        assert rec_b.message == "Hello B"
        assert rec_b.tenant_id == tenant_b
        assert sub_b.empty()

    finally:
        ops_bus.unsubscribe(sub_a)
        ops_bus.unsubscribe(sub_b)


def test_ops_bus_recent_history_retention_and_filtering():
    tenant_x = "tenant-x"
    tenant_y = "tenant-y"

    for i in range(10):
        ops_bus.publish(OpsEvent(
            level="INFO",
            component="test",
            event_type="test.tick",
            message=f"Msg X {i}",
            tenant_id=tenant_x,
        ))

    ops_bus.publish(OpsEvent(
        level="INFO",
        component="test",
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
        id="find-m7-001",
        tenant_id=TEST_TENANT_ID,
        service_id="payment-gw",
        title="SQL Injection Detected",
        severity="critical",
        status="open",
        detector_name="sql_detector",
        evidence_event_ids=["evt-1"],
        created_at=datetime.now(timezone.utc),
    )
    f2 = SecurityFinding(
        id="find-m7-002",
        tenant_id=TEST_TENANT_ID,
        service_id="auth-svc",
        title="Excessive Token Rotation",
        severity="medium",
        status="resolved",
        detector_name="token_detector",
        evidence_event_ids=["evt-2"],
        created_at=datetime.now(timezone.utc),
    )
    # Seed finding for another tenant to verify tenant boundary
    f_other = SecurityFinding(
        id="find-other-001",
        tenant_id="tenant-beta",
        service_id="internal-api",
        title="Unauthorized Admin Action",
        severity="critical",
        status="open",
        detector_name="admin_detector",
        evidence_event_ids=["evt-x"],
        created_at=datetime.now(timezone.utc),
    )
    db_session.add_all([f1, f2, f_other])
    db_session.commit()

    res = client.get("/api/v1/ops/overview", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()

    # Verify Security Posture
    posture = data["security_posture"]
    assert posture["total_open_findings"] == 1  # Only f1 for TEST_TENANT_ID, f_other excluded
    assert posture["open_findings_by_severity"]["critical"] == 1
    assert posture["findings_by_status"]["open"] == 1
    assert posture["findings_by_status"]["resolved"] == 1
    assert posture["affected_services_count"] >= 1
    assert any(rf["id"] == "find-m7-001" for rf in posture["recent_findings"])
    assert not any(rf["id"] == "find-other-001" for rf in posture["recent_findings"])

    # Verify Pipeline Health structure
    health = data["pipeline_health"]
    assert "database_status" in health
    assert health["database_status"] == "healthy"
    assert "uninstrumented_metrics" in health
    assert "host_ebpf_packet_drops" in health["uninstrumented_metrics"]
    assert health["uninstrumented_metrics"]["host_ebpf_packet_drops"]["status"] == "uninstrumented"

    # Verify Rules Summary
    rules = data["rules_summary"]
    assert "rules_by_status" in rules
    assert "total_rules" in rules


def test_ops_events_stream_security_and_streaming(client, auth_headers):
    # 1. No auth or ticket -> 401
    res_noauth = client.get("/api/v1/ops/events/stream")
    assert res_noauth.status_code == 401

    # 2. Invalid ticket -> 401
    res_bad_ticket = client.get("/api/v1/ops/events/stream?ticket=stk_nonexistent")
    assert res_bad_ticket.status_code == 401

    # 3. Valid ticket consumption
    ticket_res = client.post("/api/v1/ops/stream-ticket", headers=auth_headers)
    assert ticket_res.status_code == 200
    ticket = ticket_res.json()["ticket"]

    # Connect using single-use ticket
    # In TestClient, streaming endpoints can be opened with stream=True
    with client.stream("GET", f"/api/v1/ops/events/stream?ticket={ticket}") as response:
        assert response.status_code == 200
        assert "text/event-stream" in response.headers["content-type"]
        # Read the first event chunk (initial connection handshake)
        lines = []
        for line in response.iter_lines():
            if line:
                lines.append(line)
            if len(lines) >= 2:
                break
        
        # Verify SSE event format
        assert any("event: connected" in l for l in lines)

    # 4. Reusing consumed ticket immediately rejected with 401
    res_reused = client.get(f"/api/v1/ops/events/stream?ticket={ticket}")
    assert res_reused.status_code == 401


# ---------------------------------------------------------------------------
# 5. Live Ingestion & Rule Lifecycle Event Publishing
# ---------------------------------------------------------------------------

def test_ingest_and_rule_instrumentation_emits_ops_events(client, auth_headers):
    sub = ops_bus.subscribe(tenant_id=TEST_TENANT_ID)

    try:
        # Ingest a clean event
        event_payload = {
            "events": [
                {
                    "event_id": "evt-ops-test-1",
                    "event_type": "api_request",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "source_service": "frontend",
                    "payload": {"method": "GET", "path": "/health"},
                }
            ]
        }
        res_ingest = client.post("/api/v1/ingest", json=event_payload, headers=auth_headers)
        assert res_ingest.status_code == 200

        # Check that ops_bus received an event
        received_types = []
        while not sub.empty():
            ev = sub.get_nowait()
            received_types.append(ev.event_type)

        assert "ingest.event_received" in received_types

    finally:
        ops_bus.unsubscribe(sub)

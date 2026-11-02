"""
Unit tests for Findings API and Simulation API endpoints (Milestone 5).
Verifies:
- GET /api/v1/findings (listing, filtering, pagination, tenant isolation, 401 unauthorized)
- GET /api/v1/findings/{finding_id} (details, 404, 403 tenant isolation)
- POST /api/v1/findings/{finding_id}/feedback (status updates, audit trail in evidence, 422/404/403)
- POST /api/v1/simulation/run (exfiltration, brute force, normal, production gating)
- GET /api/v1/demo/session (dev-only bootstrap, production gating)
"""

import pytest
import datetime
from unittest.mock import patch

from backend.models import SecurityFinding, Tenant, ApiKey
from backend.core.auth import hash_api_key
from tests.conftest import TEST_TENANT_ID, TEST_APP_ID


@pytest.fixture
def seed_findings(db_session):
    now = datetime.datetime.now(datetime.timezone.utc)
    # Finding 1 for TEST_TENANT_ID (Alpha)
    f1 = SecurityFinding(
        finding_id="find-alpha-001",
        tenant_id=TEST_TENANT_ID,
        detector_id="cross_service_exfil_detector",
        detector_version="1.0.0",
        title="Cross-Service Data Exfiltration Sequence",
        severity="critical",
        confidence="high",
        description="Suspicious internal export followed by DB exfil",
        evidence={"trace_id": "tr-001", "services": ["api", "worker", "db"]},
        status="open",
        created_at=now - datetime.timedelta(minutes=10),
    )
    # Finding 2 for TEST_TENANT_ID (Alpha)
    f2 = SecurityFinding(
        finding_id="find-alpha-002",
        tenant_id=TEST_TENANT_ID,
        detector_id="brute_force_login_detector",
        detector_version="1.0.0",
        title="Multiple Failed Authentication Attempts",
        severity="medium",
        confidence="medium",
        description="5 failed logins from single IP",
        evidence={"ip": "1.2.3.4", "count": 5},
        status="resolved",
        created_at=now - datetime.timedelta(minutes=5),
    )
    # Finding 3 for Beta tenant (to test tenant isolation)
    beta_tenant = db_session.query(Tenant).filter(Tenant.id == "tenant-beta").first()
    if not beta_tenant:
        beta_tenant = Tenant(id="tenant-beta", name="Beta Corp", is_active=True)
        db_session.add(beta_tenant)
        db_session.commit()
    f3 = SecurityFinding(
        finding_id="find-beta-001",
        tenant_id="tenant-beta",
        detector_id="cross_service_exfil_detector",
        detector_version="1.0.0",
        title="Beta finding",
        severity="critical",
        confidence="high",
        description="Secret beta breach",
        evidence={},
        status="open",
        created_at=now,
    )
    db_session.add_all([f1, f2, f3])
    db_session.commit()
    return f1, f2, f3


def test_list_findings_unauthorized(client):
    response = client.get("/api/v1/findings")
    assert response.status_code == 401


def test_list_findings_tenant_isolation(client, auth_headers, seed_findings):
    response = client.get("/api/v1/findings", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    # Verify only tenant-alpha findings are present
    finding_ids = [f["finding_id"] for f in data]
    assert "find-alpha-001" in finding_ids
    assert "find-alpha-002" in finding_ids
    assert "find-beta-001" not in finding_ids


def test_list_findings_filtering(client, auth_headers, seed_findings):
    # Filter by status=open
    res_open = client.get("/api/v1/findings?status=open", headers=auth_headers)
    assert res_open.status_code == 200
    data_open = res_open.json()
    assert len(data_open) == 1
    assert data_open[0]["finding_id"] == "find-alpha-001"

    # Filter by severity=medium
    res_med = client.get("/api/v1/findings?severity=medium", headers=auth_headers)
    assert res_med.status_code == 200
    data_med = res_med.json()
    assert len(data_med) == 1
    assert data_med[0]["finding_id"] == "find-alpha-002"


def test_list_findings_pagination(client, auth_headers, seed_findings):
    res_p1 = client.get("/api/v1/findings?limit=1&offset=0", headers=auth_headers)
    assert res_p1.status_code == 200
    assert len(res_p1.json()) == 1

    res_p2 = client.get("/api/v1/findings?limit=1&offset=1", headers=auth_headers)
    assert res_p2.status_code == 200
    assert len(res_p2.json()) == 1
    assert res_p1.json()[0]["finding_id"] != res_p2.json()[0]["finding_id"]


def test_get_finding_detail(client, auth_headers, seed_findings):
    res = client.get("/api/v1/findings/find-alpha-001", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["finding_id"] == "find-alpha-001"
    assert data["title"] == "Cross-Service Data Exfiltration Sequence"
    assert data["evidence"]["trace_id"] == "tr-001"


def test_get_finding_not_found(client, auth_headers):
    res = client.get("/api/v1/findings/non-existent-id", headers=auth_headers)
    assert res.status_code == 404


def test_get_finding_cross_tenant_forbidden(client, auth_headers, seed_findings):
    res = client.get("/api/v1/findings/find-beta-001", headers=auth_headers)
    assert res.status_code == 403


def test_submit_finding_feedback(client, auth_headers, seed_findings):
    # Resolve finding
    res = client.post(
        "/api/v1/findings/find-alpha-001/feedback",
        headers=auth_headers,
        json={"status": "resolved", "reason": "Verified benign load testing run"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "resolved"
    assert "feedback_history" in data["evidence"]
    history = data["evidence"]["feedback_history"]
    assert len(history) == 1
    assert history[0]["status"] == "resolved"
    assert history[0]["reason"] == "Verified benign load testing run"

    # Mark as false positive
    res2 = client.post(
        "/api/v1/findings/find-alpha-001/feedback",
        headers=auth_headers,
        json={"status": "false_positive", "reason": "Rule threshold too aggressive"},
    )
    assert res2.status_code == 200
    data2 = res2.json()
    assert data2["status"] == "false_positive"
    assert len(data2["evidence"]["feedback_history"]) == 2


def test_submit_finding_feedback_invalid(client, auth_headers, seed_findings):
    # Invalid status
    res = client.post(
        "/api/v1/findings/find-alpha-001/feedback",
        headers=auth_headers,
        json={"status": "invalid_status", "reason": "Test reason"},
    )
    assert res.status_code == 422

    # Reason too short (<3 chars)
    res_short = client.post(
        "/api/v1/findings/find-alpha-001/feedback",
        headers=auth_headers,
        json={"status": "resolved", "reason": "ok"},
    )
    assert res_short.status_code == 422


def test_submit_finding_feedback_cross_tenant(client, auth_headers, seed_findings):
    res = client.post(
        "/api/v1/findings/find-beta-001/feedback",
        headers=auth_headers,
        json={"status": "resolved", "reason": "Attempting cross-tenant resolve"},
    )
    assert res.status_code == 403


def test_simulation_run_exfiltration(client, auth_headers):
    res = client.post(
        "/api/v1/simulation/run",
        headers=auth_headers,
        json={"scenario": "exfiltration"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "completed"
    assert data["scenario"] == "exfiltration"
    assert data["events_emitted"] == 3
    assert data["findings_generated"] >= 1
    assert len(data["finding_ids"]) >= 1

    # Check that finding is now listed via findings API
    res_list = client.get("/api/v1/findings", headers=auth_headers)
    assert res_list.status_code == 200
    findings = res_list.json()
    assert any(f["finding_id"] in data["finding_ids"] for f in findings)


def test_simulation_run_brute_force(client, auth_headers):
    res = client.post(
        "/api/v1/simulation/run",
        headers=auth_headers,
        json={"scenario": "brute_force"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "completed"
    assert data["scenario"] == "brute_force"
    assert data["events_emitted"] == 5
    assert data["findings_generated"] >= 1


def test_simulation_run_normal(client, auth_headers):
    res = client.post(
        "/api/v1/simulation/run",
        headers=auth_headers,
        json={"scenario": "normal"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "completed"
    assert data["scenario"] == "normal"
    assert data["events_emitted"] == 4
    assert data["findings_generated"] == 0


def test_simulation_run_invalid_scenario(client, auth_headers):
    res = client.post(
        "/api/v1/simulation/run",
        headers=auth_headers,
        json={"scenario": "malicious_injection_code"},
    )
    assert res.status_code == 422


def test_simulation_gated_in_production(client, auth_headers):
    with patch("backend.api.simulation.settings.ENVIRONMENT", "production"):
        res = client.post(
            "/api/v1/simulation/run",
            headers=auth_headers,
            json={"scenario": "exfiltration"},
        )
        assert res.status_code == 403
        assert "strictly disabled in production" in res.json()["detail"]


def test_demo_session_bootstrap(client):
    res = client.get("/api/v1/demo/session")
    assert res.status_code == 200
    data = res.json()
    assert data["api_key"] == "ce_live_test_api_key_secret_12345"
    assert data["tenant_id"] == "tenant-alpha"


def test_demo_session_gated_in_production(client):
    with patch("backend.api.simulation.settings.ENVIRONMENT", "production"):
        res = client.get("/api/v1/demo/session")
        assert res.status_code == 403


def test_root_serves_landing_page(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "TERNLINE" in res.text
    assert "Live Console" in res.text


def test_console_serves_interactive_console(client):
    res = client.get("/console")
    assert res.status_code == 200
    assert "TERNLINE CONTROL ROOM" in res.text
    assert "Fast Track" in res.text
    assert "Deep Track" in res.text

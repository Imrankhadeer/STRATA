import datetime
import uuid
import pytest
from starlette.testclient import TestClient

from backend.main import app
from backend.models import (
    Tenant,
    SecurityFinding,
    DefenseAuditLogModel,
    DefenseActionModel,
)


def test_plan_defense_action_for_finding_endpoint(client, db_session, auth_headers):
    # Setup test finding
    finding_id = f"find-{uuid.uuid4().hex[:8]}"
    finding = SecurityFinding(
        finding_id=finding_id,
        tenant_id="tenant-alpha",
        detector_id="detector.auth.brute_force",
        detector_version="1.0.0",
        title="Excessive authentication failures",
        severity="high",
        confidence="high",
        description="Repeated failed logins from IP 198.51.100.99",
        evidence={"source_ip": "198.51.100.99"},
        status="open",
        created_at=datetime.datetime.now(datetime.timezone.utc),
    )
    db_session.add(finding)
    db_session.commit()

    # Call POST /api/v1/defense/actions/plan/{finding_id}
    res = client.post(f"/api/v1/defense/actions/plan/{finding_id}", headers=auth_headers)
    assert res.status_code == 200
    actions = res.json()
    assert len(actions) >= 1
    assert any(a["target_entity_id"] == "198.51.100.99" for a in actions)
    assert any(a["action_type"] == "temporary_ip_block" for a in actions)


def test_list_defense_audit_logs_endpoint(client, db_session, auth_headers):
    # Setup audit log entry
    log_id = f"log-{uuid.uuid4().hex[:8]}"
    entry = DefenseAuditLogModel(
        log_id=log_id,
        action_id=None,
        tenant_id="tenant-alpha",
        from_status="observe",
        to_status="assisted",
        transition_trigger="defense.policy_updated",
        actor="operator:alice@security.org",
        details={"reason": "audit test verification"},
        timestamp=datetime.datetime.now(datetime.timezone.utc),
    )
    db_session.add(entry)
    db_session.commit()

    # Call GET /api/v1/defense/audit
    res = client.get("/api/v1/defense/audit", headers=auth_headers)
    assert res.status_code == 200
    logs = res.json()
    assert len(logs) >= 1
    target = next((l for l in logs if l["log_id"] == log_id), None)
    assert target is not None
    assert target["actor"] == "operator:alice@security.org"
    assert target["to_status"] == "assisted"


def test_deep_search_query_endpoint(client, db_session, auth_headers):
    # Test POST /api/v1/investigations/query
    res = client.post(
        "/api/v1/investigations/query",
        headers=auth_headers,
        json={"query": "Investigate potential exfiltration pattern across api-service and worker-service"},
    )
    assert res.status_code == 200
    report = res.json()
    assert report["investigation_id"] is not None
    assert report["verdict"] in ("confirmed_threat", "likely_benign", "inconclusive")
    assert report["summary"] is not None
    assert len(report["hypotheses"]) >= 1
    assert len(report["recommended_mitigations"]) >= 1

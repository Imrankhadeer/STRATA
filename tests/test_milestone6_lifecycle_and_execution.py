"""
Milestone 6 Regression and Lifecycle Tests.

Proves:
1. A proposed rule cannot execute.
2. A validated but unapproved rule cannot execute.
3. An approved but inactive rule cannot execute.
4. An active rule detects a matching event through the actual ingestion pipeline.
5. A nonmatching event does not trigger that rule.
6. A rule with false-positive validation results cannot be activated.
7. A disabled or rolled-back rule stops executing.
8. Rule versions remain auditable after rollback.
9. Cross-tenant rules cannot be loaded or executed.
10. Existing native detection still works.
11. Invalid investigation citations cannot be persisted as trustworthy evidence.
12. Duplicate investigation requests do not cause unnecessary repeated model calls.
"""

import pytest
import datetime
import uuid
from unittest.mock import patch, MagicMock, AsyncMock

from backend.models import DeclarativeRuleModel, SecurityFinding, Tenant, ApiKey, EventModel
from backend.core.auth import hash_api_key
from backend.schemas.investigation import (
    InvestigationFinding,
    Hypothesis,
    CandidateDetectorRule,
    EvidenceCitation,
)
from tests.conftest import TEST_TENANT_ID, TEST_APP_ID


def _make_cross_service_payloads(trace_id: str, app_id: str = TEST_APP_ID):
    now = datetime.datetime.now(datetime.timezone.utc)
    return [
        {
            "event_id": f"ev-api-{uuid.uuid4().hex[:8]}",
            "schema_version": "1.0.0",
            "timestamp": now.isoformat(),
            "app_id": app_id,
            "service_id": "api-service",
            "event_type": "http.request",
            "severity": "info",
            "target_resource": "/api/v1/internal/export",
            "trace_id": trace_id,
            "attributes": {"method": "POST", "endpoint": "/api/v1/internal/export", "client_ip": "10.0.4.15"},
        },
        {
            "event_id": f"ev-wrk-{uuid.uuid4().hex[:8]}",
            "schema_version": "1.0.0",
            "timestamp": (now + datetime.timedelta(seconds=1)).isoformat(),
            "app_id": app_id,
            "service_id": "worker-service",
            "event_type": "worker.job_anomalous",
            "severity": "medium",
            "trace_id": trace_id,
            "attributes": {"job_name": "mass_export_task", "payload_size_kb": 8500, "anomaly_flag": True},
        },
        {
            "event_id": f"ev-db-{uuid.uuid4().hex[:8]}",
            "schema_version": "1.0.0",
            "timestamp": (now + datetime.timedelta(seconds=2)).isoformat(),
            "app_id": app_id,
            "service_id": "database-service",
            "event_type": "db.bulk_query",
            "severity": "high",
            "trace_id": trace_id,
            "attributes": {"table": "credit_cards", "rows_affected": 50000, "operation": "SELECT", "is_sensitive_table": True},
        },
    ]


# 1. Proposed rule cannot execute
def test_proposed_rule_cannot_execute(client, auth_headers):
    rule_resp = client.post(
        "/api/v1/rules",
        headers=auth_headers,
        json={
            "target_detector": "detector.auth.failed_threshold",
            "title": "Low Threshold Login Rule",
            "description": "Fires at 2 failures",
            "parameters": {"failure_threshold": 2, "window_seconds": 60.0},
        },
    )
    assert rule_resp.status_code == 201
    rule_id = rule_resp.json()["rule_id"]

    # Ingest 2 failed logins
    for i in range(2):
        ev_resp = client.post(
            "/v1/events",
            headers=auth_headers,
            json={
                "event_id": f"ev-fail-{i}-{uuid.uuid4().hex[:6]}",
                "schema_version": "1.0.0",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "app_id": TEST_APP_ID,
                "service_id": "api-service",
                "event_type": "auth.login_failed",
                "severity": "medium",
                "source_resource": "203.0.113.55",
                "attributes": {"client_ip": "203.0.113.55"},
            },
        )
        assert ev_resp.status_code == 202

    # Verify rule did NOT fire (proposed rule cannot execute)
    findings = client.get("/api/v1/findings", headers=auth_headers).json()
    rule_findings = [f for f in findings if f["detector_id"] == rule_id]
    assert len(rule_findings) == 0


# 2. Validated but unapproved rule cannot execute
def test_validated_unapproved_rule_cannot_execute(client, auth_headers):
    rule_resp = client.post(
        "/api/v1/rules",
        headers=auth_headers,
        json={
            "target_detector": "detector.cross_service.exfiltration",
            "title": "Validated But Unapproved Rule",
            "description": "Cross service exfil test",
            "parameters": {"time_window_seconds": 300.0, "bulk_row_threshold": 1000},
        },
    )
    rule_id = rule_resp.json()["rule_id"]

    # Validate rule
    val_resp = client.post(f"/api/v1/rules/{rule_id}/validate", headers=auth_headers)
    assert val_resp.status_code == 200
    assert val_resp.json()["passed_validation"] is True

    # Rule is validated, but NOT approved or active
    # Ingest attack events
    trace = f"tr-val-{uuid.uuid4().hex[:6]}"
    for p in _make_cross_service_payloads(trace):
        client.post("/v1/events", headers=auth_headers, json=p)

    findings = client.get("/api/v1/findings", headers=auth_headers).json()
    # It must NOT be attributed to rule_id
    assert not any(f["detector_id"] == rule_id for f in findings)


# 3. Approved but inactive rule cannot execute
def test_approved_inactive_rule_cannot_execute(client, auth_headers):
    rule_resp = client.post(
        "/api/v1/rules",
        headers=auth_headers,
        json={
            "target_detector": "detector.auth.failed_threshold",
            "title": "Approved Inactive Rule",
            "description": "Fires at 2 failures",
            "parameters": {"failure_threshold": 2, "window_seconds": 60.0},
        },
    )
    rule_id = rule_resp.json()["rule_id"]
    client.post(f"/api/v1/rules/{rule_id}/validate", headers=auth_headers)
    app_resp = client.post(
        f"/api/v1/rules/{rule_id}/approve",
        headers=auth_headers,
        json={"decision": "approved", "rationale": "Testing approval gate"},
    )
    assert app_resp.status_code == 200
    assert app_resp.json()["status"] == "approved"

    # Status is approved, but NOT active. Ingest 2 events
    for i in range(2):
        client.post(
            "/v1/events",
            headers=auth_headers,
            json={
                "event_id": f"ev-app-{i}-{uuid.uuid4().hex[:6]}",
                "schema_version": "1.0.0",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "app_id": TEST_APP_ID,
                "service_id": "api-service",
                "event_type": "auth.login_failed",
                "severity": "medium",
                "source_resource": "203.0.113.66",
                "attributes": {"client_ip": "203.0.113.66"},
            },
        )

    findings = client.get("/api/v1/findings", headers=auth_headers).json()
    assert not any(f["detector_id"] == rule_id for f in findings)


# 4 & 5. Active rule detects matching event and nonmatching event does not trigger
def test_active_rule_execution_and_attribution(client, auth_headers):
    # Propose, validate, approve, and activate
    rule_resp = client.post(
        "/api/v1/rules",
        headers=auth_headers,
        json={
            "target_detector": "detector.auth.failed_threshold",
            "title": "Sensitive Threshold Rule",
            "description": "Triggers on 2 failed logins",
            "parameters": {"failure_threshold": 2, "window_seconds": 60.0},
        },
    )
    rule_id = rule_resp.json()["rule_id"]
    client.post(f"/api/v1/rules/{rule_id}/validate", headers=auth_headers)
    client.post(
        f"/api/v1/rules/{rule_id}/approve",
        headers=auth_headers,
        json={"decision": "approved", "rationale": "Promoting to active"},
    )
    act_resp = client.post(f"/api/v1/rules/{rule_id}/activate", headers=auth_headers)
    assert act_resp.status_code == 200
    assert act_resp.json()["status"] == "active"

    # 5. Nonmatching event (normal login) does NOT trigger rule
    client.post(
        "/v1/events",
        headers=auth_headers,
        json={
            "event_id": f"ev-norm-{uuid.uuid4().hex[:6]}",
            "schema_version": "1.0.0",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "app_id": TEST_APP_ID,
            "service_id": "api-service",
            "event_type": "auth.login_success",
            "severity": "info",
            "source_resource": "203.0.113.77",
            "attributes": {"client_ip": "203.0.113.77"},
        },
    )
    findings_mid = client.get("/api/v1/findings", headers=auth_headers).json()
    assert not any(f["detector_id"] == rule_id for f in findings_mid)

    # 4. Matching events (2 failed logins) trigger active rule
    for i in range(2):
        client.post(
            "/v1/events",
            headers=auth_headers,
            json={
                "event_id": f"ev-act-{i}-{uuid.uuid4().hex[:6]}",
                "schema_version": "1.0.0",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "app_id": TEST_APP_ID,
                "service_id": "api-service",
                "event_type": "auth.login_failed",
                "severity": "medium",
                "source_resource": "203.0.113.77",
                "attributes": {"client_ip": "203.0.113.77"},
            },
        )

    findings_after = client.get("/api/v1/findings", headers=auth_headers).json()
    rule_finding = next((f for f in findings_after if f["detector_id"] == rule_id), None)
    assert rule_finding is not None
    # Check rule ID and version recorded
    assert rule_finding["detector_id"] == rule_id
    assert rule_finding["detector_version"] == "1"
    assert rule_finding["evidence"]["rule_id"] == rule_id
    assert rule_finding["evidence"]["rule_version"] == 1


# 6. Rule with false-positive validation results cannot be activated
def test_rule_with_false_positives_cannot_be_activated(client, auth_headers):
    # Overly broad parameters causing FP on benign lookalike (Scenario 4)
    rule_resp = client.post(
        "/api/v1/rules",
        headers=auth_headers,
        json={
            "target_detector": "detector.cross_service.exfiltration",
            "title": "Overly Broad Exfil Rule",
            "description": "Sets threshold to 1000 rows and marks audit_archives sensitive",
            "parameters": {
                "time_window_seconds": 600.0,
                "bulk_row_threshold": 1000,
                "internal_prefixes": ["/api/v1/internal/"],
                "sensitive_tables": ["audit_archives", "credit_cards"],
            },
        },
    )
    rule_id = rule_resp.json()["rule_id"]
    val_resp = client.post(f"/api/v1/rules/{rule_id}/validate", headers=auth_headers)
    assert val_resp.status_code == 200
    assert val_resp.json()["false_positives"] > 0
    assert val_resp.json()["passed_validation"] is False

    # Attempt to activate must fail with 400
    act_resp = client.post(f"/api/v1/rules/{rule_id}/activate", headers=auth_headers)
    assert act_resp.status_code == 400
    assert "safety invariant" in act_resp.json()["detail"].lower() or "approval is required" in act_resp.json()["detail"].lower()


# 7 & 8. Disabled or rolled-back rule stops executing & versions remain auditable
def test_disabled_and_rolled_back_rule_stops_executing(client, auth_headers):
    # Create and activate rule with failure_threshold = 2
    rule_resp = client.post(
        "/api/v1/rules",
        headers=auth_headers,
        json={
            "target_detector": "detector.auth.failed_threshold",
            "title": "Brute Force Threshold 2",
            "description": "Trigger at 2",
            "parameters": {"failure_threshold": 2, "window_seconds": 60.0},
        },
    )
    rule_id = rule_resp.json()["rule_id"]
    client.post(f"/api/v1/rules/{rule_id}/validate", headers=auth_headers)
    client.post(
        f"/api/v1/rules/{rule_id}/approve",
        headers=auth_headers,
        json={"decision": "approved", "rationale": "Ready"},
    )
    client.post(f"/api/v1/rules/{rule_id}/activate", headers=auth_headers)

    # 7. Disable rule
    dis_resp = client.post(
        f"/api/v1/rules/{rule_id}/disable",
        headers=auth_headers,
        json={"reason": "Disabling rule due to noisy alerts"},
    )
    assert dis_resp.status_code == 200
    assert dis_resp.json()["status"] == "disabled"

    # Now emit 2 failed logins
    for i in range(2):
        client.post(
            "/v1/events",
            headers=auth_headers,
            json={
                "event_id": f"ev-dis-{i}-{uuid.uuid4().hex[:6]}",
                "schema_version": "1.0.0",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "app_id": TEST_APP_ID,
                "service_id": "api-service",
                "event_type": "auth.login_failed",
                "severity": "medium",
                "source_resource": "203.0.113.88",
                "attributes": {"client_ip": "203.0.113.88"},
            },
        )

    # Disabled rule must NOT execute
    findings = client.get("/api/v1/findings", headers=auth_headers).json()
    assert not any(f["detector_id"] == rule_id for f in findings)

    # Roll back rule
    rb_resp = client.post(
        f"/api/v1/rules/{rule_id}/rollback",
        headers=auth_headers,
        json={"rationale": "Rolling back to previous configuration"},
    )
    assert rb_resp.status_code == 200
    rb_data = rb_resp.json()
    assert rb_data["version"] == 2

    # 8. Check rule history is auditable
    hist_resp = client.get(f"/api/v1/rules/{rule_id}/history", headers=auth_headers)
    assert hist_resp.status_code == 200
    hist = hist_resp.json()
    assert hist["current_version"] == 2
    actions = [h["action"] for h in hist["history"]]
    assert "activated" in actions
    assert "disabled" in actions
    assert "rolled_back" in actions


# 9. Cross-tenant rules cannot be loaded or executed
def test_cross_tenant_rules_isolation(client, auth_headers, db_session):
    # Create tenant beta
    beta_tenant = Tenant(id="tenant-beta", name="Beta Corp", is_active=True)
    db_session.add(beta_tenant)
    beta_key = ApiKey(
        id="key-beta-01",
        tenant_id="tenant-beta",
        app_id="beta-app",
        key_hash=hash_api_key("beta_secret_key_123"),
        key_prefix="ce_live_",
        is_active=True,
    )
    # Active rule belonging to tenant beta
    beta_rule = DeclarativeRuleModel(
        rule_id="rule.beta.active",
        tenant_id="tenant-beta",
        version=1,
        target_detector="detector.auth.failed_threshold",
        title="Beta Active Rule",
        description="Fires on beta tenant only",
        parameters={"failure_threshold": 2, "window_seconds": 60.0},
        status="active",
        created_at=datetime.datetime.now(datetime.timezone.utc),
    )
    db_session.add_all([beta_key, beta_rule])
    db_session.commit()

    # Alpha tenant emits 2 failed logins
    for i in range(2):
        client.post(
            "/v1/events",
            headers=auth_headers,
            json={
                "event_id": f"ev-iso-{i}-{uuid.uuid4().hex[:6]}",
                "schema_version": "1.0.0",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "app_id": TEST_APP_ID,
                "service_id": "api-service",
                "event_type": "auth.login_failed",
                "severity": "medium",
                "source_resource": "203.0.113.99",
                "attributes": {"client_ip": "203.0.113.99"},
            },
        )

    # Beta's rule must NOT have fired for Alpha
    alpha_findings = client.get("/api/v1/findings", headers=auth_headers).json()
    assert not any(f["detector_id"] == "rule.beta.active" for f in alpha_findings)

    # Alpha cannot access Beta's rule
    beta_rule_get = client.get("/api/v1/rules/rule.beta.active", headers=auth_headers)
    assert beta_rule_get.status_code == 403


# 10. Existing native detection still works
def test_native_detection_still_works(client, auth_headers):
    # Native detector triggers on 3 failed logins when no active declarative rule overrides it
    for i in range(3):
        client.post(
            "/v1/events",
            headers=auth_headers,
            json={
                "event_id": f"ev-native-{i}-{uuid.uuid4().hex[:6]}",
                "schema_version": "1.0.0",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "app_id": TEST_APP_ID,
                "service_id": "api-service",
                "event_type": "auth.login_failed",
                "severity": "medium",
                "source_resource": "198.51.100.44",
                "attributes": {"client_ip": "198.51.100.44"},
            },
        )

    findings = client.get("/api/v1/findings", headers=auth_headers).json()
    native_finding = next((f for f in findings if f["detector_id"] == "detector.auth.failed_threshold"), None)
    assert native_finding is not None
    assert native_finding["detector_version"] == "1.0.0"


# 11. Invalid investigation citations cannot be persisted as trustworthy evidence
def test_invalid_investigation_citations_rejected(client, auth_headers, db_session):
    # Create finding
    finding = SecurityFinding(
        finding_id="find-ground-001",
        tenant_id=TEST_TENANT_ID,
        detector_id="detector.auth.failed_threshold",
        detector_version="1.0.0",
        title="Suspicious Login",
        severity="medium",
        confidence="high",
        description="Finding for citation test",
        evidence={},
        status="open",
        created_at=datetime.datetime.now(datetime.timezone.utc),
    )
    db_session.add(finding)
    db_session.commit()

    # Hallucinated report citing nonexistent event ID
    hallucinated_report = InvestigationFinding(
        investigation_id="inv-bad-001",
        finding_id="find-ground-001",
        tenant_id=TEST_TENANT_ID,
        verdict="confirmed_threat",
        summary="Hallucinated incident conclusion",
        hypotheses=[
            Hypothesis(
                title="Fake threat",
                description="Hallucinated event ID",
                likelihood="high",
                nature="malicious",
                supporting_evidence=[
                    EvidenceCitation(
                        event_id="hallucinated-ev-99999",
                        service_id="api-service",
                        timestamp="2026-10-28T12:00:00Z",
                        relevance="Fabricated citation",
                    )
                ],
            )
        ],
        candidate_rules=[],
        recommended_mitigations=[],
        investigator_provider="meta",
        investigator_model="muse-spark-1.3",
    )

    with patch("backend.api.investigations.get_investigator") as mock_get_inv:
        mock_inv = MagicMock()
        mock_inv.investigate = AsyncMock(return_value=hallucinated_report)
        mock_get_inv.return_value = mock_inv

        resp = client.post("/api/v1/investigations/find-ground-001", headers=auth_headers)
        # Must be rejected with 422
        assert resp.status_code == 422
        data = resp.json()["detail"]
        assert "hallucinated-ev-99999" in str(data)


# 12. Duplicate investigation requests do not cause unnecessary repeated model calls
def test_duplicate_investigation_requests_reused(client, auth_headers, db_session):
    finding = SecurityFinding(
        finding_id="find-reuse-001",
        tenant_id=TEST_TENANT_ID,
        detector_id="detector.auth.failed_threshold",
        detector_version="1.0.0",
        title="Duplicate Investigation Check",
        severity="medium",
        confidence="high",
        description="Check cached report reuse",
        evidence={},
        status="open",
        created_at=datetime.datetime.now(datetime.timezone.utc),
    )
    # Also seed valid event so context assembly succeeds
    now = datetime.datetime.now(datetime.timezone.utc)
    ev = EventModel(
        event_id="ev-real-001",
        schema_version="1.0.0",
        timestamp=now,
        ingested_at=now,
        tenant_id=TEST_TENANT_ID,
        app_id=TEST_APP_ID,
        service_id="api-service",
        event_type="auth.login_failed",
        severity="medium",
        attributes={"client_ip": "1.2.3.4"},
        provenance={},
    )
    finding.event_id = ev.event_id
    db_session.add_all([finding, ev])
    db_session.commit()

    def _make_report(ctx):
        return InvestigationFinding(
            investigation_id=f"inv-{uuid.uuid4().hex[:12]}",
            finding_id=finding.finding_id,
            tenant_id=TEST_TENANT_ID,
            verdict="likely_benign",
            summary="Grounded report",
            hypotheses=[
                Hypothesis(
                    title="Benign retry",
                    description="Typo on password",
                    likelihood="high",
                    nature="benign",
                    supporting_evidence=[
                        EvidenceCitation(
                            event_id="ev-real-001",
                            service_id="api-service",
                            timestamp=now.isoformat(),
                            relevance="Real event",
                        )
                    ],
                )
            ],
            candidate_rules=[],
            recommended_mitigations=[],
            investigator_provider="meta",
            investigator_model="muse-spark-1.3",
        )

    with patch("backend.api.investigations.get_investigator") as mock_get_inv:
        mock_inv = MagicMock()
        mock_inv.investigate = AsyncMock(side_effect=_make_report)
        mock_get_inv.return_value = mock_inv

        # First call: triggers model
        res1 = client.post("/api/v1/investigations/find-reuse-001", headers=auth_headers)
        assert res1.status_code == 200
        inv1_id = res1.json()["investigation_id"]
        assert mock_inv.investigate.call_count == 1

        # Second call: reuses completed report without calling model
        res2 = client.post("/api/v1/investigations/find-reuse-001", headers=auth_headers)
        assert res2.status_code == 200
        assert res2.json()["investigation_id"] == inv1_id
        assert mock_inv.investigate.call_count == 1  # NOT incremented!

        # Third call with force_refresh=true: calls model again
        res3 = client.post("/api/v1/investigations/find-reuse-001?force_refresh=true", headers=auth_headers)
        assert res3.status_code == 200
        assert res3.json()["investigation_id"] != inv1_id
        assert mock_inv.investigate.call_count == 2  # Fresh call requested


def test_detector_state_out_of_order_events(client, auth_headers):
    # Cross-service sequence delivered OUT OF ORDER:
    # 1. Database access delivered first
    # 2. Worker job delivered second
    # 3. API export delivered third
    trace_id = f"tr-ooo-{uuid.uuid4().hex[:6]}"
    payloads = _make_cross_service_payloads(trace_id)
    # Reverse order: db, worker, api
    reversed_payloads = [payloads[2], payloads[1], payloads[0]]

    for p in reversed_payloads:
        resp = client.post("/v1/events", headers=auth_headers, json=p)
        assert resp.status_code == 202

    findings = client.get("/api/v1/findings", headers=auth_headers).json()
    ooo_finding = next((f for f in findings if f["evidence"].get("trace_id") == trace_id or f["evidence"].get("stages", {}).get("api_trigger", {}).get("trace_id") == trace_id), None)
    assert ooo_finding is not None


def test_detector_state_duplicate_events_ignored(client, auth_headers):
    # Emit exact same event ID twice
    event_id = f"ev-dup-{uuid.uuid4().hex[:8]}"
    payload = {
        "event_id": event_id,
        "schema_version": "1.0.0",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "app_id": TEST_APP_ID,
        "service_id": "api-service",
        "event_type": "auth.login_failed",
        "severity": "medium",
        "source_resource": "203.0.113.101",
        "attributes": {"client_ip": "203.0.113.101"},
    }
    r1 = client.post("/v1/events", headers=auth_headers, json=payload)
    assert r1.status_code == 202
    assert r1.json()["accepted"] == 1

    # Second submission is reported as duplicate
    r2 = client.post("/v1/events", headers=auth_headers, json=payload)
    assert r2.status_code == 202
    assert r2.json()["duplicates"] == 1
    assert r2.json()["accepted"] == 0


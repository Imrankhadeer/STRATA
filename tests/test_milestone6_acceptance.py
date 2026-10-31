"""
Ternline Milestone 6: Complete End-to-End Acceptance Test

Proves the complete 10-step lifecycle and execution loop:
1. Generate a predefined synthetic attack scenario.
2. Confirm the Fast Track creates the expected finding.
3. Investigate the finding with the configured provider and retrieve candidate detection rule(s).
4. Run validation replay against suspicious and benign scenarios.
5. Approve and activate the passing rule.
6. Replay the attack through the actual ingestion pipeline.
7. Confirm that the newly activated rule executes and records its `rule_id` and `version` on the resulting finding.
8. Roll back or disable the rule.
9. Replay the attack again.
10. Confirm that the disabled/rolled-back version no longer executes.
"""

import uuid
import datetime
import pytest
from unittest.mock import patch, MagicMock, AsyncMock

from backend.schemas.investigation import (
    InvestigationFinding,
    Hypothesis,
    CandidateDetectorRule,
    EvidenceCitation,
)
from tests.conftest import TEST_TENANT_ID, TEST_APP_ID


def test_milestone6_complete_acceptance_loop(client, auth_headers):
    print("\n--- STEP 1: Generate predefined synthetic attack scenario ---")
    sim_resp = client.post(
        "/api/v1/simulation/run",
        headers=auth_headers,
        json={"scenario": "exfiltration"}
    )
    assert sim_resp.status_code == 200, f"Simulation failed: {sim_resp.text}"
    sim_data = sim_resp.json()
    assert sim_data["status"] == "completed"
    assert sim_data["findings_generated"] >= 1
    initial_finding_id = sim_data["finding_ids"][0]
    initial_trace_id = sim_data["trace_id"]
    print(f"Step 1 OK: Generated finding {initial_finding_id} on trace {initial_trace_id}")

    print("\n--- STEP 2: Confirm Fast Track creates the expected finding ---")
    get_finding_resp = client.get(f"/api/v1/findings/{initial_finding_id}", headers=auth_headers)
    assert get_finding_resp.status_code == 200
    finding_obj = get_finding_resp.json()
    assert finding_obj["detector_id"] == "detector.cross_service.exfiltration"
    assert finding_obj["severity"] in ["high", "critical"]
    # Evidence must contain supporting events and stage information
    evidence = finding_obj["evidence"]
    assert "stages" in evidence
    supporting_event_ids = evidence.get("supporting_event_ids", [])
    assert len(supporting_event_ids) >= 3
    print(f"Step 2 OK: Fast Track created verified finding with {len(supporting_event_ids)} evidence events")

    print("\n--- STEP 3: Investigate finding with configured provider and retrieve candidate detection rule ---")
    candidate_rule_spec = {
        "target_detector": "detector.cross_service.exfiltration",
        "title": "Hardened Multi-Service Exfil Detection",
        "description": "Candidate rule generated from investigation of trace exfiltration pattern",
        "parameters": {
            "sensitive_tables": ["credit_cards", "tokens"],
            "internal_prefixes": ["/api/v1/internal/"],
            "bulk_row_threshold": 10000,
            "time_window_seconds": 300.0,
        },
    }

    mock_investigation = InvestigationFinding(
        investigation_id="inv-acc-001",
        finding_id=initial_finding_id,
        tenant_id=TEST_TENANT_ID,
        verdict="confirmed_threat",
        summary="Confirmed distributed exfiltration attack across API, Worker, and DB.",
        hypotheses=[
            Hypothesis(
                title="Cross-service exfiltration pipeline",
                description="Malicious API call scheduled a bulk job querying sensitive credit_cards.",
                likelihood="high",
                nature="malicious",
                supporting_evidence=[
                    EvidenceCitation(
                        event_id=supporting_event_ids[0],
                        service_id="api-service",
                        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        relevance="Triggered export request",
                    ),
                    EvidenceCitation(
                        event_id=supporting_event_ids[2],
                        service_id="database-service",
                        timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        relevance="Exfiltrated 50,000 credit card records",
                    ),
                ],
            )
        ],
        candidate_rules=[
            CandidateDetectorRule(
                rule_id="cand-acc-001",
                title=candidate_rule_spec["title"],
                description=candidate_rule_spec["description"],
                logic_type="sequence",
                proposed_thresholds=candidate_rule_spec["parameters"],
                rationale="Detected 3-stage cross-service attack with high volume data exfiltration",
            )
        ],
        recommended_mitigations=["Revoke client IP access", "Activate declarative detector rule"],
        investigator_provider="meta",
        investigator_model="muse-spark-1.3",
    )

    with patch("backend.api.investigations.get_investigator") as mock_get_inv:
        mock_inv = MagicMock()
        mock_inv.investigate = AsyncMock(return_value=mock_investigation)
        mock_get_inv.return_value = mock_inv

        inv_resp = client.post(f"/api/v1/investigations/{initial_finding_id}", headers=auth_headers)
        assert inv_resp.status_code == 200, f"Investigation failed: {inv_resp.text}"
        inv_data = inv_resp.json()
        assert len(inv_data["candidate_rules"]) >= 1
        retrieved_cand = inv_data["candidate_rules"][0]
        print(f"Step 3 OK: Retrieved candidate rule '{retrieved_cand['title']}' from investigation")

    print("\n--- STEP 4: Run validation replay against suspicious and benign scenarios ---")
    create_rule_resp = client.post(
        "/api/v1/rules",
        headers=auth_headers,
        json=candidate_rule_spec
    )
    assert create_rule_resp.status_code == 201
    created_rule = create_rule_resp.json()
    rule_id = created_rule["rule_id"]
    assert created_rule["status"] == "proposed"

    val_resp = client.post(f"/api/v1/rules/{rule_id}/validate", headers=auth_headers)
    assert val_resp.status_code == 200, f"Validation failed: {val_resp.text}"
    metrics = val_resp.json()
    assert metrics["passed_validation"] is True
    assert metrics["false_positives"] == 0

    rule_get = client.get(f"/api/v1/rules/{rule_id}", headers=auth_headers).json()
    assert rule_get["status"] == "validated"
    print(f"Step 4 OK: Validation replay passed with 0 FPs across benchmark scenarios, status='validated'")

    print("\n--- STEP 5: Approve and activate the passing rule ---")
    app_resp = client.post(
        f"/api/v1/rules/{rule_id}/approve",
        headers=auth_headers,
        json={"decision": "approved", "rationale": "Approved for Milestone 6 acceptance test run"}
    )
    assert app_resp.status_code == 200
    assert app_resp.json()["status"] == "approved"

    act_resp = client.post(f"/api/v1/rules/{rule_id}/activate", headers=auth_headers)
    assert act_resp.status_code == 200
    assert act_resp.json()["status"] == "active"
    print(f"Step 5 OK: Rule {rule_id} is approved and active in RuntimeRuleRegistry")

    print("\n--- STEP 6: Replay attack through actual ingestion pipeline (/v1/events) ---")
    attack_trace_2 = f"trace-acc-replay-{uuid.uuid4().hex[:8]}"
    now = datetime.datetime.now(datetime.timezone.utc)
    attack_events = [
        {
            "event_id": f"ev-rep-api-{uuid.uuid4().hex[:8]}",
            "schema_version": "1.0.0",
            "timestamp": now.isoformat(),
            "app_id": TEST_APP_ID,
            "service_id": "api-service",
            "event_type": "http.request",
            "severity": "info",
            "target_resource": "/api/v1/internal/export",
            "trace_id": attack_trace_2,
            "attributes": {"method": "POST", "endpoint": "/api/v1/internal/export", "client_ip": "192.168.1.100"},
        },
        {
            "event_id": f"ev-rep-wrk-{uuid.uuid4().hex[:8]}",
            "schema_version": "1.0.0",
            "timestamp": (now + datetime.timedelta(seconds=1)).isoformat(),
            "app_id": TEST_APP_ID,
            "service_id": "worker-service",
            "event_type": "worker.job_anomalous",
            "severity": "medium",
            "trace_id": attack_trace_2,
            "attributes": {"job_name": "mass_export_task", "payload_size_kb": 9200, "anomaly_flag": True},
        },
        {
            "event_id": f"ev-rep-db-{uuid.uuid4().hex[:8]}",
            "schema_version": "1.0.0",
            "timestamp": (now + datetime.timedelta(seconds=2)).isoformat(),
            "app_id": TEST_APP_ID,
            "service_id": "database-service",
            "event_type": "db.bulk_query",
            "severity": "high",
            "trace_id": attack_trace_2,
            "attributes": {"table": "credit_cards", "rows_affected": 25000, "operation": "SELECT", "is_sensitive_table": True},
        },
    ]

    for ev in attack_events:
        ingest_res = client.post("/v1/events", headers=auth_headers, json=ev)
        assert ingest_res.status_code == 202
    print(f"Step 6 OK: Replayed attack telemetry sequence with trace {attack_trace_2}")

    print("\n--- STEP 7: Confirm newly activated rule executes and records rule_id and version ---")
    findings_resp = client.get("/api/v1/findings", headers=auth_headers)
    assert findings_resp.status_code == 200
    all_findings = findings_resp.json()
    rule_finding = next(
        (f for f in all_findings if f["evidence"].get("trace_id") == attack_trace_2 and f["detector_id"] == rule_id),
        None
    )
    assert rule_finding is not None, f"Expected finding generated by rule {rule_id}"
    assert rule_finding["detector_id"] == rule_id
    assert rule_finding["detector_version"] == "1"
    assert rule_finding["evidence"]["rule_id"] == rule_id
    assert rule_finding["evidence"]["rule_version"] == 1
    # Verify native detector finding was suppressed to prevent duplicate alert
    native_duplicate = next(
        (f for f in all_findings if f["evidence"].get("trace_id") == attack_trace_2 and f["detector_id"] == "detector.cross_service.exfiltration"),
        None
    )
    assert native_duplicate is None, "Native detector must be suppressed when active declarative rule fires"
    print(f"Step 7 OK: Rule finding {rule_finding['finding_id']} emitted with rule_id={rule_id}, v={rule_finding['detector_version']}")

    print("\n--- STEP 8: Roll back or disable the rule ---")
    dis_resp = client.post(
        f"/api/v1/rules/{rule_id}/disable",
        headers=auth_headers,
        json={"reason": "Step 8 acceptance test rollback verification"}
    )
    assert dis_resp.status_code == 200
    dis_data = dis_resp.json()
    assert dis_data["status"] == "disabled"

    # Confirm rule history records the lifecycle change
    hist_resp = client.get(f"/api/v1/rules/{rule_id}/history", headers=auth_headers)
    assert hist_resp.status_code == 200
    history = hist_resp.json()["history"]
    assert any(h.get("action") == "disabled" or h.get("status") == "disabled" for h in history)
    print(f"Step 8 OK: Rule {rule_id} disabled and audit history logged")

    print("\n--- STEP 9: Replay attack again ---")
    attack_trace_3 = f"trace-acc-disabled-{uuid.uuid4().hex[:8]}"
    now_3 = datetime.datetime.now(datetime.timezone.utc)
    attack_events_3 = [
        {
            "event_id": f"ev-dis-api-{uuid.uuid4().hex[:8]}",
            "schema_version": "1.0.0",
            "timestamp": now_3.isoformat(),
            "app_id": TEST_APP_ID,
            "service_id": "api-service",
            "event_type": "http.request",
            "severity": "info",
            "target_resource": "/api/v1/internal/export",
            "trace_id": attack_trace_3,
            "attributes": {"method": "POST", "endpoint": "/api/v1/internal/export", "client_ip": "192.168.1.100"},
        },
        {
            "event_id": f"ev-dis-wrk-{uuid.uuid4().hex[:8]}",
            "schema_version": "1.0.0",
            "timestamp": (now_3 + datetime.timedelta(seconds=1)).isoformat(),
            "app_id": TEST_APP_ID,
            "service_id": "worker-service",
            "event_type": "worker.job_anomalous",
            "severity": "medium",
            "trace_id": attack_trace_3,
            "attributes": {"job_name": "mass_export_task", "payload_size_kb": 9200, "anomaly_flag": True},
        },
        {
            "event_id": f"ev-dis-db-{uuid.uuid4().hex[:8]}",
            "schema_version": "1.0.0",
            "timestamp": (now_3 + datetime.timedelta(seconds=2)).isoformat(),
            "app_id": TEST_APP_ID,
            "service_id": "database-service",
            "event_type": "db.bulk_query",
            "severity": "high",
            "trace_id": attack_trace_3,
            "attributes": {"table": "credit_cards", "rows_affected": 25000, "operation": "SELECT", "is_sensitive_table": True},
        },
    ]

    for ev in attack_events_3:
        ingest_res = client.post("/v1/events", headers=auth_headers, json=ev)
        assert ingest_res.status_code == 202
    print(f"Step 9 OK: Replayed attack telemetry sequence with trace {attack_trace_3}")

    print("\n--- STEP 10: Confirm that disabled/rolled-back version no longer executes ---")
    findings_resp_after = client.get("/api/v1/findings", headers=auth_headers)
    assert findings_resp_after.status_code == 200
    all_findings_after = findings_resp_after.json()

    # Rule must NOT have executed
    disabled_finding = next(
        (f for f in all_findings_after if f["evidence"].get("trace_id") == attack_trace_3 and f["detector_id"] == rule_id),
        None
    )
    assert disabled_finding is None, f"Disabled rule {rule_id} must NEVER execute!"

    # Native baseline detector should have caught the incident instead (safety net preserved)
    fallback_finding = next(
        (f for f in all_findings_after if f["evidence"].get("trace_id") == attack_trace_3 and f["detector_id"] == "detector.cross_service.exfiltration"),
        None
    )
    assert fallback_finding is not None, "Native baseline detector should still provide fallback protection"
    print(f"Step 10 OK: Disabled rule did not execute; native safety net executed fallback finding {fallback_finding['finding_id']}")
    print("\n=== ALL 10 ACCEPTANCE STEPS SUCCESSFULLY VERIFIED ===")

"""
Milestone 5 Full End-to-End Verification Test Suite.

Simulates the complete user and analyst workflow across the live console:
1. Frontend delivery of landing page and console (/ and /console)
2. Development session bootstrap (/api/v1/demo/session)
3. Simulated attack execution (/api/v1/simulation/run) triggering deterministic Fast Track
4. Security finding observation and filtering (/api/v1/findings)
5. Deep Track investigation activation with evidence grounding
6. Candidate rule proposal, replay validation against test suite, approval gate, and promotion to Fast Track
7. Human analyst feedback audit trail on findings
"""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock

from backend.schemas.investigation import (
    InvestigationFinding,
    Hypothesis,
    CandidateDetectorRule,
    EvidenceCitation,
)


def test_full_console_lifecycle_e2e(client, auth_headers):
    # 1. UI Navigation checks
    root_resp = client.get("/")
    assert root_resp.status_code == 200
    assert "TERNLINE" in root_resp.text

    console_resp = client.get("/console")
    assert console_resp.status_code == 200
    assert "Interactive Security Console" in console_resp.text

    # 2. Bootstrap demo session
    session_resp = client.get("/api/v1/demo/session")
    assert session_resp.status_code == 200
    session_data = session_resp.json()
    assert session_data["tenant_id"] == "tenant-alpha"
    active_headers = {"Authorization": f"Bearer {session_data['api_key']}"}

    # 3. Trigger attack simulation: cross-service exfiltration
    sim_resp = client.post(
        "/api/v1/simulation/run",
        headers=active_headers,
        json={"scenario": "exfiltration"},
    )
    assert sim_resp.status_code == 200
    sim_data = sim_resp.json()
    assert sim_data["status"] == "completed"
    assert sim_data["events_emitted"] == 3
    assert sim_data["findings_generated"] >= 1
    finding_id = sim_data["finding_ids"][0]

    # 4. Findings Dashboard listing & verification
    findings_resp = client.get("/api/v1/findings", headers=active_headers)
    assert findings_resp.status_code == 200
    findings = findings_resp.json()
    assert len(findings) >= 1
    target_finding = next((f for f in findings if f["finding_id"] == finding_id), None)
    assert target_finding is not None
    assert target_finding["severity"] in ("high", "critical")
    assert target_finding["status"] == "open"
    assert "stages" in target_finding["evidence"]

    # 5. Deep Track Investigation
    # Mocking investigator model inference return to ensure test is deterministic & fast
    supporting_events = target_finding["evidence"].get("supporting_event_ids", [])
    cited_event_id = supporting_events[0] if supporting_events else target_finding.get("event_id")

    mock_report = InvestigationFinding(
        investigation_id="inv-e2e-001",
        finding_id=finding_id,
        tenant_id="tenant-alpha",
        verdict="confirmed_threat",
        summary="E2E test: Verified correlated exfiltration sequence across API, worker, and database.",
        hypotheses=[
            Hypothesis(
                title="Cross-Service Data Exfiltration",
                description="Exfiltration orchestrated via internal export endpoint.",
                likelihood="high",
                nature="malicious",
                supporting_evidence=[
                    EvidenceCitation(
                        event_id=cited_event_id,
                        service_id="api-service",
                        timestamp="2026-10-28T12:00:00Z",
                        relevance="Initial export trigger",
                    )
                ],
            )
        ],
        candidate_rules=[
            CandidateDetectorRule(
                title="Tighter Exfil Correlation Rule",
                description="Flags internal export followed by anomalous database access",
                logic_type="sequence",
                proposed_thresholds={"time_window_seconds": 120.0, "bulk_row_threshold": 1000},
                rationale="Prevents repeat recurrence",
            )
        ],
        recommended_mitigations=["Revoke token 10.0.4.15", "Rotate DB secrets"],
        investigator_provider="meta",
        investigator_model="muse-spark-1.3",
    )

    with patch("backend.api.investigations.get_investigator") as mock_get_inv:
        mock_inv = MagicMock()
        mock_inv.investigate = AsyncMock(return_value=mock_report)
        mock_get_inv.return_value = mock_inv

        inv_resp = client.post(f"/api/v1/investigations/{finding_id}", headers=active_headers)
        assert inv_resp.status_code == 200
        inv_data = inv_resp.json()
        assert inv_data["verdict"] == "confirmed_threat"
        assert inv_data["investigator_model"] == "muse-spark-1.3"
        assert len(inv_data["candidate_rules"]) == 1
        rule_spec = inv_data["candidate_rules"][0]

    # 6. Candidate Rule Discovery, Replay Validation, and Promotion
    # Propose candidate rule discovered by Deep Track
    rule_create_resp = client.post(
        "/api/v1/rules",
        headers=active_headers,
        json={
            "target_detector": "detector.cross_service.exfiltration",
            "title": rule_spec["title"],
            "description": rule_spec["description"],
            "parameters": rule_spec["proposed_thresholds"],
        },
    )
    assert rule_create_resp.status_code == 201
    created_rule = rule_create_resp.json()
    rule_id = created_rule["rule_id"]
    assert created_rule["status"] == "proposed"

    # Replay Validation against historical test suite
    val_resp = client.post(f"/api/v1/rules/{rule_id}/validate", headers=active_headers)
    assert val_resp.status_code == 200
    val_metrics = val_resp.json()
    assert val_metrics["passed_validation"] is True
    assert val_metrics["false_positives"] == 0
    assert val_metrics["true_positives"] >= 1

    # Human/Policy Approval Gate
    approve_resp = client.post(
        f"/api/v1/rules/{rule_id}/approve",
        headers=active_headers,
        json={
            "decision": "approved",
            "rationale": "Analyst verified 0 false positives during Milestone 5 E2E run.",
        },
    )
    assert approve_resp.status_code == 200
    assert approve_resp.json()["status"] == "approved"

    # Promote to active in Fast Track
    activate_resp = client.post(f"/api/v1/rules/{rule_id}/activate", headers=active_headers)
    assert activate_resp.status_code == 200
    assert activate_resp.json()["status"] == "active"

    # 7. Analyst Finding Feedback and Audit Trail
    feedback_resp = client.post(
        f"/api/v1/findings/{finding_id}/feedback",
        headers=active_headers,
        json={
            "status": "resolved",
            "reason": "Root cause identified as compromised internal export token. Revoked and mitigated.",
        },
    )
    assert feedback_resp.status_code == 200
    feedback_data = feedback_resp.json()
    assert feedback_data["status"] == "resolved"
    assert "feedback_history" in feedback_data["evidence"]
    audit_entry = feedback_data["evidence"]["feedback_history"][0]
    assert audit_entry["status"] == "resolved"
    assert "compromised internal export token" in audit_entry["reason"].lower()

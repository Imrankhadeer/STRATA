import pytest
from starlette.testclient import TestClient
from backend.main import app

client = TestClient(app)
AUTH_HEADERS = {"Authorization": "Bearer ce_live_test_api_key_secret_12345"}


def test_finding_and_investigation_feedback_lifecycle():
    # 1. Trigger simulation
    sim_res = client.post("/api/v1/simulation/run", json={"scenario": "exfiltration"}, headers=AUTH_HEADERS)
    assert sim_res.status_code == 200
    finding_id = sim_res.json()["finding_ids"][0]

    # 2. Mark finding as resolved
    fb_res = client.post(
        f"/api/v1/findings/{finding_id}/feedback",
        json={"status": "resolved", "reason": "Verified benign admin export activity"},
        headers=AUTH_HEADERS,
    )
    assert fb_res.status_code == 200
    assert fb_res.json()["status"] == "resolved"

    # 3. Mark finding as false positive
    fp_res = client.post(
        f"/api/v1/findings/{finding_id}/feedback",
        json={"status": "false_positive", "reason": "Expected automated test batch"},
        headers=AUTH_HEADERS,
    )
    assert fp_res.status_code == 200
    assert fp_res.json()["status"] == "false_positive"

    # 4. Deep Track investigation
    inv_res = client.post(f"/api/v1/investigations/{finding_id}", headers=AUTH_HEADERS)
    assert inv_res.status_code == 200
    inv_id = inv_res.json()["investigation_id"]

    # 5. Update investigation disposition
    disp_res = client.post(
        f"/api/v1/investigations/{inv_id}/disposition",
        json={"disposition": "false_positive", "reason": "Analyst determined false positive"},
        headers=AUTH_HEADERS,
    )
    assert disp_res.status_code == 200
    assert disp_res.json()["verdict"] == "likely_benign"

    # 6. Rate investigation quality
    rate_res = client.post(
        f"/api/v1/investigations/{inv_id}/rate",
        json={"rating": "accurate", "feedback": "Trace citations deterministically matched database records"},
        headers=AUTH_HEADERS,
    )
    assert rate_res.status_code == 200
    assert rate_res.json()["status"] == "recorded"

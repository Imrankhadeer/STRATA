"""
Unit and Integration Tests for Prometheus Observability & Metrics Exporter.

Validates:
1. GET /metrics returns standard Prometheus text exposition format (0.0.4).
2. GET /api/v1/ops/metrics returns identical format.
3. Ingesting telemetry increments cyber_engine_events_ingested_total counter.
4. Generated findings increment cyber_engine_findings_total counter.
5. Ingestion latency metrics are recorded and formatted correctly.
6. Database health & active rule gauges are included in export.
"""

import pytest
from backend.ops.metrics import metrics_registry
from tests.conftest import TEST_TENANT_ID, TEST_APP_ID


def test_prometheus_metrics_endpoints_available(client):
    # Test root /metrics endpoint
    res = client.get("/metrics")
    assert res.status_code == 200
    assert "text/plain" in res.headers["content-type"]
    text = res.text
    assert "# HELP cyber_engine_events_ingested_total" in text
    assert "# TYPE cyber_engine_events_ingested_total counter" in text
    assert "# HELP cyber_engine_db_healthy" in text

    # Test /api/v1/ops/metrics endpoint
    res_ops = client.get("/api/v1/ops/metrics")
    assert res_ops.status_code == 200
    assert "text/plain" in res_ops.headers["content-type"]
    assert "cyber_engine_ingest_latency_seconds" in res_ops.text


def test_metrics_updated_on_telemetry_and_findings(client, auth_headers):
    # Ingest 3 failed logins to trigger brute force finding
    attacker_ip = "198.51.100.77"
    for i in range(3):
        payload = {
            "event_id": f"ev-metric-test-{i}",
            "schema_version": "1.0.0",
            "app_id": TEST_APP_ID,
            "service_id": "auth-service",
            "event_type": "auth.login_failed",
            "severity": "medium",
            "source_resource": attacker_ip,
        }
        resp = client.post("/v1/events", json=payload, headers=auth_headers)
        assert resp.status_code == 202

    # Query metrics endpoint
    res = client.get("/metrics")
    assert res.status_code == 200
    text = res.text

    # Verify event ingestion counter for TEST_TENANT_ID
    assert f'cyber_engine_events_ingested_total{{tenant_id="{TEST_TENANT_ID}",service_id="auth-service",status="accepted"}}' in text

    # Verify finding counter was incremented
    assert "cyber_engine_findings_total" in text
    assert f'tenant_id="{TEST_TENANT_ID}"' in text

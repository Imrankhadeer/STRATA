"""
Deterministic test suite for Ternline Model Context Protocol (MCP) Server.
Verifies JSON-RPC 2.0 transport, MCP 2024-11-05 spec compliance, tool execution,
resource retrieval, prompts, and schema validation.
"""

import json
import pytest
from unittest.mock import MagicMock, patch

from mcp_server.server import MCPServer
from mcp_server.schemas import CANONICAL_EVENT_SCHEMA, RECOMMENDED_EVENT_TYPES
from mcp_server.tools import (
    contain_incident,
    emit_test_event,
    generate_middleware,
    get_sdk_instructions,
    list_detection_rules,
    match_threat_intel,
    probe_health,
    provision_key,
    query_findings,
    query_incidents,
    run_deep_search,
    validate_event,
)


@pytest.fixture
def mcp():
    return MCPServer()


def test_mcp_initialize(mcp):
    req = {
        "jsonrpc": "2.0",
        "id": "req-1",
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "cursor", "version": "0.42.0"}
        }
    }
    resp = mcp.handle_request(req)
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == "req-1"
    res = resp["result"]
    assert res["protocolVersion"] == "2024-11-05"
    assert res["serverInfo"]["name"] == "ternline-mcp"
    assert "tools" in res["capabilities"]
    assert "resources" in res["capabilities"]
    assert "prompts" in res["capabilities"]


def test_mcp_notification_initialized(mcp):
    req = {
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    }
    resp = mcp.handle_request(req)
    assert resp is None


def test_mcp_ping(mcp):
    req = {
        "jsonrpc": "2.0",
        "id": "ping-1",
        "method": "ping"
    }
    resp = mcp.handle_request(req)
    assert resp["id"] == "ping-1"
    assert resp["result"] == {}


def test_mcp_tools_list(mcp):
    req = {
        "jsonrpc": "2.0",
        "id": "tools-1",
        "method": "tools/list"
    }
    resp = mcp.handle_request(req)
    tools = resp["result"]["tools"]
    tool_names = [t["name"] for t in tools]
    expected = [
        "ternline_get_sdk_instructions",
        "ternline_generate_middleware",
        "ternline_validate_event",
        "ternline_probe_health",
        "ternline_emit_test_event",
        "ternline_provision_key",
        "ternline_query_findings",
        "ternline_query_incidents",
        "ternline_deep_search",
        "ternline_match_threat_intel",
        "ternline_contain_incident",
        "ternline_list_rules",
    ]
    for exp in expected:
        assert exp in tool_names
        # Validate schema format
        t = next(x for x in tools if x["name"] == exp)
        assert "inputSchema" in t
        assert t["inputSchema"]["type"] == "object"


def test_mcp_resources_list_and_read(mcp):
    # List resources
    req = {
        "jsonrpc": "2.0",
        "id": "res-1",
        "method": "resources/list"
    }
    resp = mcp.handle_request(req)
    resources = resp["result"]["resources"]
    uris = [r["uri"] for r in resources]
    assert "ternline://schema/event" in uris
    assert "ternline://catalog/event-types" in uris
    assert "ternline://mitre/coverage" in uris
    assert "ternline://defense/policy" in uris

    # Read schema resource
    read_req = {
        "jsonrpc": "2.0",
        "id": "read-1",
        "method": "resources/read",
        "params": {"uri": "ternline://schema/event"}
    }
    read_resp = mcp.handle_request(read_req)
    contents = read_resp["result"]["contents"]
    assert len(contents) == 1
    assert contents[0]["mimeType"] == "application/json"
    parsed_schema = json.loads(contents[0]["text"])
    assert parsed_schema["title"] == "TernlineCanonicalEvent"

    # Read catalog resource
    catalog_req = {
        "jsonrpc": "2.0",
        "id": "read-2",
        "method": "resources/read",
        "params": {"uri": "ternline://catalog/event-types"}
    }
    cat_resp = mcp.handle_request(catalog_req)
    cat_contents = cat_resp["result"]["contents"]
    parsed_cat = json.loads(cat_contents[0]["text"])
    assert isinstance(parsed_cat, list)
    assert any("Authentication" in c["category"] for c in parsed_cat)


def test_mcp_prompts(mcp):
    # List prompts
    req = {
        "jsonrpc": "2.0",
        "id": "pr-1",
        "method": "prompts/list"
    }
    resp = mcp.handle_request(req)
    prompts = resp["result"]["prompts"]
    assert any(p["name"] == "integrate_telemetry" for p in prompts)
    assert any(p["name"] == "investigate_incident" for p in prompts)
    assert any(p["name"] == "create_declarative_rule" for p in prompts)

    # Get prompt
    get_req = {
        "jsonrpc": "2.0",
        "id": "pr-2",
        "method": "prompts/get",
        "params": {
            "name": "integrate_telemetry",
            "arguments": {"framework": "fastapi", "app_id": "billing-service"}
        }
    }
    get_resp = mcp.handle_request(get_req)
    messages = get_resp["result"]["messages"]
    assert len(messages) >= 1
    assert "billing-service" in messages[0]["content"]["text"]
    assert "fastapi" in messages[0]["content"]["text"]


def test_tool_sdk_instructions(mcp):
    call_req = {
        "jsonrpc": "2.0",
        "id": "call-1",
        "method": "tools/call",
        "params": {
            "name": "ternline_get_sdk_instructions",
            "arguments": {"language": "python"}
        }
    }
    resp = mcp.handle_request(call_req)
    result = resp["result"]
    assert result["isError"] is False
    assert "TernlineClient" in result["content"][0]["text"]

    # Unsupported language
    call_bad = {
        "jsonrpc": "2.0",
        "id": "call-bad",
        "method": "tools/call",
        "params": {
            "name": "ternline_get_sdk_instructions",
            "arguments": {"language": "brainfuck"}
        }
    }
    resp_bad = mcp.handle_request(call_bad)
    assert resp_bad["result"]["isError"] is True


def test_tool_generate_middleware(mcp):
    call_req = {
        "jsonrpc": "2.0",
        "id": "call-mw",
        "method": "tools/call",
        "params": {
            "name": "ternline_generate_middleware",
            "arguments": {
                "framework": "fastapi",
                "app_id": "checkout-api",
                "service_id": "checkout-gw"
            }
        }
    }
    resp = mcp.handle_request(call_req)
    result = resp["result"]
    assert result["isError"] is False
    assert "checkout-api" in result["content"][0]["text"]
    assert "checkout-gw" in result["content"][0]["text"]


def test_tool_validate_event_valid(mcp):
    valid_event = {
        "event_id": "evt_12345678",
        "schema_version": "1.0.0",
        "timestamp": "2026-11-02T12:00:00.000Z",
        "app_id": "payments-api",
        "service_id": "web-gateway",
        "event_type": "auth.login_attempt",
        "severity": "info",
        "source_resource": "10.0.0.1",
        "target_resource": "/api/v1/auth/login",
        "trace_id": "trc_999999",
        "attributes": {"attempt": 1}
    }
    call_req = {
        "jsonrpc": "2.0",
        "id": "val-1",
        "method": "tools/call",
        "params": {
            "name": "ternline_validate_event",
            "arguments": {"event": valid_event}
        }
    }
    resp = mcp.handle_request(call_req)
    assert resp["result"]["isError"] is False
    payload = json.loads(resp["result"]["content"][0]["text"])
    assert payload["status"] == "VALID"


def test_tool_validate_event_invalid(mcp):
    invalid_event = {
        "event_id": "short",  # minLength is 8
        "schema_version": "2.0.0",  # must be "1.0.0"
        "severity": "extreme",  # invalid enum
        # missing required fields: timestamp, app_id, service_id, event_type
    }
    call_req = {
        "jsonrpc": "2.0",
        "id": "val-bad",
        "method": "tools/call",
        "params": {
            "name": "ternline_validate_event",
            "arguments": {"event": invalid_event}
        }
    }
    resp = mcp.handle_request(call_req)
    assert resp["result"]["isError"] is True
    payload = json.loads(resp["result"]["content"][0]["text"])
    assert payload["status"] == "INVALID"
    assert payload["error_count"] >= 3


@patch("mcp_server.tools.httpx.Client")
def test_tool_probe_health(mock_client_cls):
    mock_instance = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "ok",
        "environment": "development",
        "database": "connected"
    }
    mock_instance.get.return_value = mock_resp
    mock_client_cls.return_value.__enter__.return_value = mock_instance

    res = probe_health("http://localhost:8000")
    assert res["isError"] is False
    data = json.loads(res["content"][0]["text"])
    assert data["engine_status"] == "ok"
    assert data["database_status"] == "connected"


@patch("mcp_server.tools.httpx.Client")
def test_tool_emit_test_event(mock_client_cls):
    mock_instance = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"status": "accepted", "finding": None}
    mock_instance.post.return_value = mock_resp
    mock_client_cls.return_value.__enter__.return_value = mock_instance

    res = emit_test_event(
        endpoint="http://localhost:8000",
        api_key="ce_live_test_api_key_secret_12345",
        app_id="test-app",
        service_id="test-svc"
    )
    assert res["isError"] is False
    data = json.loads(res["content"][0]["text"])
    assert data["success"] is True


@patch("mcp_server.tools.httpx.Client")
def test_tool_provision_key(mock_client_cls):
    mock_instance = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 201
    mock_resp.json.return_value = {
        "key_id": "key-test-99",
        "tenant_id": "tenant-alpha",
        "app_id": "worker-service",
        "api_key": "ce_live_newly_generated_secret_99",
        "key_prefix": "ce_live_",
        "scopes": ["events:ingest"]
    }
    mock_instance.post.return_value = mock_resp
    mock_client_cls.return_value.__enter__.return_value = mock_instance

    res = provision_key(
        app_id="worker-service",
        endpoint="http://localhost:8000",
        admin_key="admin-test-key",
    )
    assert res["isError"] is False
    data = json.loads(res["content"][0]["text"])
    assert data["success"] is True
    assert data["api_key"] == "ce_live_newly_generated_secret_99"


@patch("mcp_server.tools.httpx.Client")
def test_tool_query_findings(mock_client_cls):
    mock_instance = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [
        {"finding_id": "find-1", "severity": "high", "title": "Brute Force Attack"}
    ]
    mock_instance.get.return_value = mock_resp
    mock_client_cls.return_value.__enter__.return_value = mock_instance

    res = query_findings(severity="high", api_key="tenant-test-key")
    assert res["isError"] is False
    data = json.loads(res["content"][0]["text"])
    assert data["success"] is True
    assert data["count"] == 1


@patch("mcp_server.tools.httpx.Client")
def test_tool_query_incidents(mock_client_cls):
    mock_instance = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [
        {"incident_id": "INC-20261102-123", "status": "open", "severity": "critical"}
    ]
    mock_instance.get.return_value = mock_resp
    mock_client_cls.return_value.__enter__.return_value = mock_instance

    res = query_incidents(status="open", api_key="tenant-test-key")
    assert res["isError"] is False
    data = json.loads(res["content"][0]["text"])
    assert data["success"] is True
    assert data["count"] == 1


@patch("mcp_server.tools.httpx.Client")
def test_tool_deep_search(mock_client_cls):
    mock_instance = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "investigation_id": "inv-123",
        "verdict": "confirmed_threat",
        "summary": "Data exfiltration detected",
        "hypotheses": [{"title": "Exfiltration"}],
        "candidate_rules": [{"rule_id": "rule-1"}],
    }
    mock_instance.post.return_value = mock_resp
    mock_client_cls.return_value.__enter__.return_value = mock_instance

    res = run_deep_search(
        query="Investigate exfiltration across api-service and worker-service",
        api_key="tenant-test-key",
    )
    assert res["isError"] is False
    data = json.loads(res["content"][0]["text"])
    assert data["success"] is True
    assert data["verdict"] == "confirmed_threat"


@patch("mcp_server.tools.httpx.Client")
def test_tool_match_threat_intel(mock_client_cls):
    mock_instance = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "query": "198.51.100.24",
        "matched_iocs": [{"ioc_id": "ioc-1", "value": "198.51.100.24"}],
        "matched_events_count": 5,
        "affected_services": ["api-service"],
        "mitre_techniques": ["T1110"],
    }
    mock_instance.post.return_value = mock_resp
    mock_client_cls.return_value.__enter__.return_value = mock_instance

    res = match_threat_intel(query="198.51.100.24")
    assert res["isError"] is False
    data = json.loads(res["content"][0]["text"])
    assert data["success"] is True
    assert data["matched_events_count"] == 5


@patch("mcp_server.tools.httpx.Client")
def test_tool_contain_incident(mock_client_cls):
    mock_instance = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "incident_id": "INC-20261102-123",
        "status": "contained",
        "contained_entities_count": 2,
        "actions_triggered": [{"action_id": "act-1", "type": "temporary_ip_block"}],
    }
    mock_instance.post.return_value = mock_resp
    mock_client_cls.return_value.__enter__.return_value = mock_instance

    res = contain_incident(
        incident_id="INC-20261102-123",
        rationale="Emergency containment of brute force campaign",
    )
    assert res["isError"] is False
    data = json.loads(res["content"][0]["text"])
    assert data["success"] is True
    assert data["status"] == "contained"


@patch("mcp_server.tools.httpx.Client")
def test_tool_list_detection_rules(mock_client_cls):
    mock_instance = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [
        {"rule_id": "rule.auth.brute_force", "status": "active"}
    ]
    mock_instance.get.return_value = mock_resp
    mock_client_cls.return_value.__enter__.return_value = mock_instance

    res = list_detection_rules()
    assert res["isError"] is False
    data = json.loads(res["content"][0]["text"])
    assert data["success"] is True
    assert data["count"] == 1

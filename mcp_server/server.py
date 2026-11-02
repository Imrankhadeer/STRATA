"""
Ternline Model Context Protocol (MCP) Server.
Standard-compliant JSON-RPC 2.0 stdio server implementing MCP specification (2024-11-05).
Exposes tools, resources, and prompts for AI coding assistants (Cursor, Claude Desktop, Antigravity).
"""

import json
import logging
import sys
from typing import Any, Dict, List, Optional

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

# Diagnostic logs must strictly go to sys.stderr so stdout remains pure JSON-RPC framing
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(asctime)s [ternline-mcp] %(levelname)s: %(message)s"
)
logger = logging.getLogger("ternline_mcp")

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "ternline-mcp"
SERVER_VERSION = "1.0.0"

# Tool Definitions compliant with MCP Tool schema
TOOLS_REGISTRY: List[Dict[str, Any]] = [
    {
        "name": "ternline_get_sdk_instructions",
        "description": "Get integration guides, SDK setup patterns, and security practices for a specific programming language (python, go, nodejs, java, rust).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "language": {
                    "type": "string",
                    "description": "Target programming language (e.g. 'python', 'go', 'nodejs', 'java', 'rust')",
                    "enum": ["python", "go", "nodejs", "java", "rust"]
                }
            },
            "required": ["language"]
        }
    },
    {
        "name": "ternline_generate_middleware",
        "description": "Generate drop-in telemetry middleware tailored for FastAPI, Express, or Go Gin with automatic trace correlation and non-blocking background dispatch.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "framework": {
                    "type": "string",
                    "description": "Target web framework",
                    "enum": ["fastapi", "express", "gin"]
                },
                "app_id": {
                    "type": "string",
                    "description": "Application or service identifier (e.g. 'payments-api')"
                },
                "service_id": {
                    "type": "string",
                    "description": "Specific component or worker identifier (e.g. 'api-gateway')"
                }
            },
            "required": ["framework"]
        }
    },
    {
        "name": "ternline_validate_event",
        "description": "Validate a telemetry JSON event payload offline against the Canonical Event Schema Draft 7 without network roundtrips.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "event": {
                    "type": "object",
                    "description": "The telemetry event object to validate"
                }
            },
            "required": ["event"]
        }
    },
    {
        "name": "ternline_probe_health",
        "description": "Probe the reachability, latency, and database status of the Ternline security engine.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "endpoint": {
                    "type": "string",
                    "description": "Ternline engine endpoint URL (defaults to TERNLINE_ENDPOINT or http://localhost:8000)"
                }
            }
        }
    },
    {
        "name": "ternline_emit_test_event",
        "description": "Construct and emit a canonical telemetry event directly to the Ternline engine to verify end-to-end ingestion and Fast Track detection.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "endpoint": {
                    "type": "string",
                    "description": "Ternline engine endpoint URL"
                },
                "api_key": {
                    "type": "string",
                    "description": "Tenant API key (Bearer token)"
                },
                "app_id": {
                    "type": "string",
                    "description": "Application identifier (defaults to 'mcp-probe')"
                },
                "service_id": {
                    "type": "string",
                    "description": "Service identifier (defaults to 'probe-service')"
                },
                "event_type": {
                    "type": "string",
                    "description": "Dot-delimited event type (defaults to 'mcp.health_probe')"
                },
                "severity": {
                    "type": "string",
                    "enum": ["info", "low", "medium", "high", "critical"],
                    "description": "Event severity"
                },
                "attributes": {
                    "type": "object",
                    "description": "Custom contextual event attributes"
                }
            }
        }
    },
    {
        "name": "ternline_provision_key",
        "description": "Register a new application/microservice and provision a scoped, cryptographically hashed API key.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "app_id": {
                    "type": "string",
                    "description": "Identifier for the application receiving the key (e.g. 'worker-service')"
                },
                "endpoint": {
                    "type": "string",
                    "description": "Ternline engine endpoint URL"
                },
                "admin_key": {
                    "type": "string",
                    "description": "Administrator Bearer token with 'keys:admin' scope"
                },
                "scopes": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "RBAC permission scopes (defaults to ['events:ingest'])"
                },
                "expires_in_days": {
                    "type": "integer",
                    "description": "Optional expiration lifespan in days"
                }
            },
            "required": ["app_id"]
        }
    },
    {
        "name": "ternline_query_findings",
        "description": "Query real-time security findings detected across microservices by Fast Track detectors.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "enum": ["info", "low", "medium", "high", "critical"],
                    "description": "Filter findings by severity"
                },
                "detector_id": {
                    "type": "string",
                    "description": "Filter by detector identifier (e.g. 'detector.auth.brute_force')"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum findings to return (default: 20)"
                },
                "endpoint": {"type": "string", "description": "Ternline engine endpoint URL"},
                "api_key": {"type": "string", "description": "Tenant API key"}
            }
        }
    },
    {
        "name": "ternline_query_incidents",
        "description": "Query aggregated multi-service incident cases correlated by the Incident Correlator.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": ["open", "investigating", "contained", "resolved", "false_positive"],
                    "description": "Filter incidents by lifecycle status"
                },
                "severity": {
                    "type": "string",
                    "enum": ["low", "medium", "high", "critical"],
                    "description": "Filter incidents by composite severity"
                },
                "service": {
                    "type": "string",
                    "description": "Filter incidents affecting a specific microservice"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum incidents to return (default: 20)"
                },
                "endpoint": {"type": "string", "description": "Ternline engine endpoint URL"},
                "api_key": {"type": "string", "description": "Tenant API key"}
            }
        }
    },
    {
        "name": "ternline_deep_search",
        "description": "Execute an AI Deep Search investigation against telemetry events using Meta Muse AI with mathematical citation audits.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Investigation prompt or forensic question (e.g. 'Investigate exfiltration across api-service and worker-service')"
                },
                "endpoint": {"type": "string", "description": "Ternline engine endpoint URL"},
                "api_key": {"type": "string", "description": "Tenant API key"}
            },
            "required": ["query"]
        }
    },
    {
        "name": "ternline_match_threat_intel",
        "description": "Cross-reference an IP address, domain, query pattern, or keyword against active Indicators of Compromise (IOCs) and stored telemetry to determine microservice blast radius.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Indicator value, IP address, or keyword to match"
                },
                "time_window_hours": {
                    "type": "integer",
                    "description": "Hours of historical telemetry to scan (default: 24)"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum events to return (default: 20)"
                },
                "endpoint": {"type": "string", "description": "Ternline engine endpoint URL"},
                "api_key": {"type": "string", "description": "Tenant API key"}
            },
            "required": ["query"]
        }
    },
    {
        "name": "ternline_contain_incident",
        "description": "Trigger coordinated active defense containment for an incident across all attacker IPs and compromised credentials.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "incident_id": {
                    "type": "string",
                    "description": "Target incident identifier (e.g. 'INC-20261102-ABC123')"
                },
                "rationale": {
                    "type": "string",
                    "description": "Operational justification for emergency containment"
                },
                "contain_ips": {
                    "type": "boolean",
                    "description": "Whether to apply perimeter IP blocks (default: true)"
                },
                "contain_credentials": {
                    "type": "boolean",
                    "description": "Whether to revoke compromised API keys (default: true)"
                },
                "endpoint": {"type": "string", "description": "Ternline engine endpoint URL"},
                "api_key": {"type": "string", "description": "Tenant API key"}
            },
            "required": ["incident_id", "rationale"]
        }
    },
    {
        "name": "ternline_list_rules",
        "description": "List active Fast Track declarative detection rules configured in the Ternline engine.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "endpoint": {"type": "string", "description": "Ternline engine endpoint URL"},
                "api_key": {"type": "string", "description": "Tenant API key"}
            }
        }
    }
]

# MCP Resources
RESOURCES_REGISTRY: List[Dict[str, Any]] = [
    {
        "uri": "ternline://schema/event",
        "name": "Canonical Event Schema",
        "mimeType": "application/json",
        "description": "JSON Schema Draft 7 for canonical microservice telemetry events."
    },
    {
        "uri": "ternline://catalog/event-types",
        "name": "Standard Event Types Catalog",
        "mimeType": "application/json",
        "description": "Recommended event categories and schemas for microservice instrumentation."
    },
    {
        "uri": "ternline://mitre/coverage",
        "name": "MITRE ATT&CK Matrix Coverage",
        "mimeType": "application/json",
        "description": "Real-time MITRE ATT&CK detection coverage across detectors, rules, and active findings."
    },
    {
        "uri": "ternline://defense/policy",
        "name": "Active Defense Protection Policy",
        "mimeType": "application/json",
        "description": "Tenant Active Defense containment configuration and protection mode."
    }
]

# MCP Prompts
PROMPTS_REGISTRY: List[Dict[str, Any]] = [
    {
        "name": "integrate_telemetry",
        "description": "Step-by-step instructions for instrumenting an application with Ternline security telemetry.",
        "arguments": [
            {
                "name": "framework",
                "description": "Web framework (fastapi, express, gin)",
                "required": True
            },
            {
                "name": "app_id",
                "description": "Application or microservice identifier",
                "required": False
            }
        ]
    },
    {
        "name": "investigate_incident",
        "description": "Prompt for performing deep forensic root-cause analysis on an active incident case.",
        "arguments": [
            {
                "name": "incident_id",
                "description": "Identifier of the incident to triage (e.g. 'INC-20261102-ABC123')",
                "required": True
            }
        ]
    },
    {
        "name": "create_declarative_rule",
        "description": "Prompt for authoring, parameterizing, and validating a new declarative Fast Track detection rule.",
        "arguments": [
            {
                "name": "threat_scenario",
                "description": "Description of the attack pattern to detect (e.g. 'SQL injection in search endpoint')",
                "required": True
            }
        ]
    }
]


class MCPServer:
    """
    Standard MCP JSON-RPC 2.0 stdio server.
    """

    def __init__(self):
        self.is_running = True

    def handle_request(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Dispatches incoming JSON-RPC 2.0 requests to the appropriate handler.
        """
        req_id = request.get("id")
        method = request.get("method")
        params = request.get("params", {})

        logger.debug("Received request: method=%s id=%s", method, req_id)

        # Handle notifications (requests without id)
        if req_id is None:
            if method == "notifications/initialized":
                logger.info("Client completed initialization handshake.")
            return None

        # Dispatch RPC methods
        if method == "initialize":
            return self._reply_success(req_id, {
                "protocolVersion": PROTOCOL_VERSION,
                "serverInfo": {
                    "name": SERVER_NAME,
                    "version": SERVER_VERSION
                },
                "capabilities": {
                    "tools": {},
                    "resources": {},
                    "prompts": {}
                }
            })

        elif method == "ping":
            return self._reply_success(req_id, {})

        elif method == "tools/list":
            return self._reply_success(req_id, {"tools": TOOLS_REGISTRY})

        elif method == "tools/call":
            tool_name = params.get("name")
            args = params.get("arguments", {})
            return self._execute_tool(req_id, tool_name, args)

        elif method == "resources/list":
            return self._reply_success(req_id, {"resources": RESOURCES_REGISTRY})

        elif method == "resources/read":
            uri = params.get("uri")
            return self._read_resource(req_id, uri)

        elif method == "prompts/list":
            return self._reply_success(req_id, {"prompts": PROMPTS_REGISTRY})

        elif method == "prompts/get":
            prompt_name = params.get("name")
            prompt_args = params.get("arguments", {})
            return self._get_prompt(req_id, prompt_name, prompt_args)

        else:
            return self._reply_error(req_id, -32601, f"Method '{method}' not found")

    def _execute_tool(self, req_id: Any, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes a registered tool and wraps result in MCP content format.
        """
        try:
            if name == "ternline_get_sdk_instructions":
                res = get_sdk_instructions(args.get("language", "python"))
            elif name == "ternline_generate_middleware":
                res = generate_middleware(
                    framework=args.get("framework", "fastapi"),
                    app_id=args.get("app_id"),
                    service_id=args.get("service_id")
                )
            elif name == "ternline_validate_event":
                res = validate_event(args.get("event", {}))
            elif name == "ternline_probe_health":
                res = probe_health(args.get("endpoint"))
            elif name == "ternline_emit_test_event":
                res = emit_test_event(
                    endpoint=args.get("endpoint"),
                    api_key=args.get("api_key"),
                    app_id=args.get("app_id"),
                    service_id=args.get("service_id"),
                    event_type=args.get("event_type"),
                    severity=args.get("severity"),
                    attributes=args.get("attributes")
                )
            elif name == "ternline_provision_key":
                res = provision_key(
                    app_id=args.get("app_id", "my-app"),
                    endpoint=args.get("endpoint"),
                    admin_key=args.get("admin_key"),
                    scopes=args.get("scopes"),
                    expires_in_days=args.get("expires_in_days")
                )
            elif name == "ternline_query_findings":
                res = query_findings(
                    severity=args.get("severity"),
                    detector_id=args.get("detector_id"),
                    limit=args.get("limit", 20),
                    endpoint=args.get("endpoint"),
                    api_key=args.get("api_key")
                )
            elif name == "ternline_query_incidents":
                res = query_incidents(
                    status=args.get("status"),
                    severity=args.get("severity"),
                    service=args.get("service"),
                    limit=args.get("limit", 20),
                    endpoint=args.get("endpoint"),
                    api_key=args.get("api_key")
                )
            elif name == "ternline_deep_search":
                res = run_deep_search(
                    query=args.get("query", ""),
                    endpoint=args.get("endpoint"),
                    api_key=args.get("api_key")
                )
            elif name == "ternline_match_threat_intel":
                res = match_threat_intel(
                    query=args.get("query", ""),
                    time_window_hours=args.get("time_window_hours", 24),
                    limit=args.get("limit", 20),
                    endpoint=args.get("endpoint"),
                    api_key=args.get("api_key")
                )
            elif name == "ternline_contain_incident":
                res = contain_incident(
                    incident_id=args.get("incident_id", ""),
                    rationale=args.get("rationale", ""),
                    contain_ips=args.get("contain_ips", True),
                    contain_credentials=args.get("contain_credentials", True),
                    endpoint=args.get("endpoint"),
                    api_key=args.get("api_key")
                )
            elif name == "ternline_list_rules":
                res = list_detection_rules(
                    endpoint=args.get("endpoint"),
                    api_key=args.get("api_key")
                )
            else:
                return self._reply_error(req_id, -32602, f"Unknown tool: '{name}'")

            return self._reply_success(req_id, res)
        except Exception as e:
            logger.exception("Error executing tool %s: %s", name, e)
            return self._reply_success(req_id, {
                "content": [{"type": "text", "text": f"Tool execution failed: {str(e)}"}],
                "isError": True
            })

    def _read_resource(self, req_id: Any, uri: str) -> Dict[str, Any]:
        """
        Returns resource content for known URIs.
        """
        if uri == "ternline://schema/event":
            return self._reply_success(req_id, {
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": "application/json",
                        "text": json.dumps(CANONICAL_EVENT_SCHEMA, indent=2)
                    }
                ]
            })
        elif uri == "ternline://catalog/event-types":
            return self._reply_success(req_id, {
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": "application/json",
                        "text": json.dumps(RECOMMENDED_EVENT_TYPES, indent=2)
                    }
                ]
            })
        elif uri == "ternline://mitre/coverage":
            return self._reply_success(req_id, {
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": "application/json",
                        "text": json.dumps({
                            "techniques_covered": ["T1078", "T1048", "T1005", "T1110", "T1190"],
                            "description": "Baseline MITRE ATT&CK coverage matrix across Ternline detectors."
                        }, indent=2)
                    }
                ]
            })
        elif uri == "ternline://defense/policy":
            return self._reply_success(req_id, {
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": "application/json",
                        "text": json.dumps({
                            "modes": ["observe", "assisted", "enforced"],
                            "default_mode": "observe",
                            "safeguards": ["dual_custody", "anti_self_approval", "out_of_band_verification", "redis_ttl_reconciliation"]
                        }, indent=2)
                    }
                ]
            })
        else:
            return self._reply_error(req_id, -32602, f"Resource URI not found: '{uri}'")

    def _get_prompt(self, req_id: Any, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Returns dynamic prompt messages for code generation and integration workflows.
        """
        if name == "integrate_telemetry":
            fw = args.get("framework", "fastapi")
            app = args.get("app_id", "my-service")
            prompt_text = (
                f"You are instrumenting the microservice '{app}' using the {fw} framework.\n"
                f"Use the `ternline_generate_middleware` tool with framework='{fw}' and app_id='{app}' "
                f"to obtain drop-in middleware. Integrate it into the application entry point, ensure trace_id "
                f"headers are propagated, and use `ternline_validate_event` to test sample telemetry payloads."
            )
            return self._reply_success(req_id, {
                "description": f"Telemetry integration guide for {fw}",
                "messages": [
                    {
                        "role": "user",
                        "content": {
                            "type": "text",
                            "text": prompt_text
                        }
                    }
                ]
            })
        elif name == "investigate_incident":
            inc_id = args.get("incident_id", "INC-XXXX")
            prompt_text = (
                f"You are conducting a forensic root-cause analysis on Ternline incident '{inc_id}'.\n"
                f"1. Call `ternline_query_incidents` to inspect the incident's affected services, traces, and severity.\n"
                f"2. Use `ternline_deep_search` with query='Investigate incident {inc_id} across affected traces' "
                f"to obtain evidence-grounded hypotheses and audited database citations.\n"
                f"3. Check for external IOC matches using `ternline_match_threat_intel`.\n"
                f"4. If containment is necessary, invoke `ternline_contain_incident` with operational rationale."
            )
            return self._reply_success(req_id, {
                "description": f"Forensic investigation workflow for incident {inc_id}",
                "messages": [
                    {
                        "role": "user",
                        "content": {
                            "type": "text",
                            "text": prompt_text
                        }
                    }
                ]
            })
        elif name == "create_declarative_rule":
            scenario = args.get("threat_scenario", "brute force authentication")
            prompt_text = (
                f"You are authoring a new Ternline declarative Fast Track detection rule for: '{scenario}'.\n"
                f"1. Use `ternline_list_rules` to inspect existing rules and prevent family collisions.\n"
                f"2. Formulate a declarative rule specification adhering to Canonical Event Schema Draft 7.\n"
                f"3. Ensure the rule includes: rule_id, rule_version, event_type, condition expressions, "
                f"sliding window (seconds), threshold, and recommended mitigation."
            )
            return self._reply_success(req_id, {
                "description": f"Declarative rule authoring guide for {scenario}",
                "messages": [
                    {
                        "role": "user",
                        "content": {
                            "type": "text",
                            "text": prompt_text
                        }
                    }
                ]
            })
        else:
            return self._reply_error(req_id, -32602, f"Prompt not found: '{name}'")

    def _reply_success(self, req_id: Any, result: Any) -> Dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": result
        }

    def _reply_error(self, req_id: Any, code: int, message: str, data: Any = None) -> Dict[str, Any]:
        err_obj: Dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            err_obj["data"] = data
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": err_obj
        }

    def run(self):
        """
        Main stdio execution loop. Reads newline-delimited JSON from stdin and writes to stdout.
        """
        logger.info("Starting Ternline MCP Server (protocol %s, v%s)...", PROTOCOL_VERSION, SERVER_VERSION)
        
        while self.is_running:
            try:
                line = sys.stdin.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue

                try:
                    payload = json.loads(line)
                except json.JSONDecodeError as jde:
                    err_resp = self._reply_error(None, -32700, f"Parse error: {jde}")
                    sys.stdout.write(json.dumps(err_resp) + "\n")
                    sys.stdout.flush()
                    continue

                response = self.handle_request(payload)
                if response is not None:
                    sys.stdout.write(json.dumps(response) + "\n")
                    sys.stdout.flush()

            except (KeyboardInterrupt, SystemExit):
                logger.info("Shutdown signal received.")
                break
            except Exception as e:
                logger.exception("Unexpected error in MCP stdio loop: %s", e)


def main():
    server = MCPServer()
    server.run()


if __name__ == "__main__":
    main()


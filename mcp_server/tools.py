"""
Tool implementations for the Ternline MCP Server.
Provides SDK integration guidance, middleware generation, schema validation,
health probing, end-to-end ingestion tests, and API key provisioning.
"""

import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx
import jsonschema

from mcp_server.schemas import CANONICAL_EVENT_SCHEMA, TEMPLATES, RECOMMENDED_EVENT_TYPES

DEFAULT_ENDPOINT = os.getenv("TERNLINE_ENDPOINT", "http://localhost:8000")
DEFAULT_API_KEY = os.getenv("TERNLINE_API_KEY")


# --- Tool 1: Get SDK Integration Instructions ---
def get_sdk_instructions(language: str) -> Dict[str, Any]:
    """
    Returns step-by-step developer integration instructions for the specified programming language.
    """
    lang = (language or "python").lower().strip()
    
    if lang in ("python", "py"):
        content = """# Ternline Python SDK Integration Guide

## 1. Environment Configuration
Ensure your service has access to the Ternline Security Engine:
```env
TERNLINE_ENDPOINT=http://localhost:8000
TERNLINE_API_KEY=your_api_key_here
```

## 2. In-Tree Client Usage
If using the repository's native Python SDK:
```python
from sdk.client import TernlineClient

client = TernlineClient(
    endpoint="http://localhost:8000",
    api_key="your_api_key_here",
    app_id="orders-service",
    service_id="checkout-worker"
)

# Non-blocking async event dispatch
client.emit_event(
    event_type="auth.login_attempt",
    severity="info",
    source_resource="192.168.1.50",
    target_resource="/api/v1/login",
    attributes={"user_id": "usr_9981", "mfa_used": True}
)
```

## 3. Web Framework Middleware
For FastAPI applications, use the `ternline_generate_middleware` MCP tool with `framework="fastapi"` to generate drop-in telemetry middleware.

## 4. Best Practices
- Never await telemetry calls on critical user paths.
- Propagate `trace_id` from OpenTelemetry / W3C TraceContext headers.
- Categorize events using dot-separated types (e.g. `auth.login`, `db.query`).
"""
    elif lang in ("go", "golang"):
        content = """# Ternline Go SDK Integration Guide

## 1. Environment Configuration
```env
TERNLINE_ENDPOINT=http://localhost:8000
TERNLINE_API_KEY=your_api_key_here
```

## 2. Standard Event Struct
```go
type TernlineEvent struct {
    EventID        string                 `json:"event_id"`
    SchemaVersion  string                 `json:"schema_version"`
    Timestamp      string                 `json:"timestamp"`
    AppID          string                 `json:"app_id"`
    ServiceID      string                 `json:"service_id"`
    EventType      string                 `json:"event_type"`
    Severity       string                 `json:"severity"`
    SourceResource string                 `json:"source_resource,omitempty"`
    TargetResource string                 `json:"target_resource,omitempty"`
    TraceID        string                 `json:"trace_id,omitempty"`
    Attributes     map[string]interface{} `json:"attributes,omitempty"`
}
```

## 3. Non-Blocking Ingestion
Dispatch telemetry using goroutines with a bounded worker pool or buffered channel:
```go
go func(ev TernlineEvent) {
    body, _ := json.Marshal(ev)
    req, _ := http.NewRequest("POST", endpoint + "/v1/events", bytes.NewBuffer(body))
    req.Header.Set("Authorization", "Bearer " + apiKey)
    req.Header.Set("Content-Type", "application/json")
    client := &http.Client{Timeout: 2 * time.Second}
    client.Do(req)
}(event)
```

## 4. Web Framework Middleware
Use the `ternline_generate_middleware` MCP tool with `framework="gin"` to generate drop-in Gin middleware.
"""
    elif lang in ("nodejs", "node", "javascript", "typescript", "ts", "js"):
        content = """# Ternline Node.js / TypeScript SDK Integration Guide

## 1. Environment Configuration
```env
TERNLINE_ENDPOINT=http://localhost:8000
TERNLINE_API_KEY=your_api_key_here
```

## 2. Asynchronous Ingestion Helper
```typescript
import axios from 'axios';
import { randomUUID } from 'crypto';

export interface TernlineEvent {
  event_id: string;
  schema_version: '1.0.0';
  timestamp: string;
  app_id: string;
  service_id: string;
  event_type: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  source_resource?: string;
  target_resource?: string;
  trace_id?: string;
  attributes?: Record<string, unknown>;
}

export function emitTelemetry(event: Partial<TernlineEvent>): void {
  const payload: TernlineEvent = {
    event_id: `evt_${randomUUID()}`,
    schema_version: '1.0.0',
    timestamp: new Date().toISOString(),
    app_id: process.env.TERNLINE_APP_ID || 'node-service',
    service_id: process.env.TERNLINE_SERVICE_ID || 'api',
    event_type: event.event_type || 'custom.event',
    severity: event.severity || 'info',
    ...event
  };

  // Fire-and-forget
  axios.post(`${process.env.TERNLINE_ENDPOINT}/v1/events`, payload, {
    headers: {
      Authorization: `Bearer ${process.env.TERNLINE_API_KEY}`,
      'Content-Type': 'application/json'
    },
    timeout: 2000
  }).catch(err => {
    console.error('[Ternline] Telemetry dispatch failed:', err.message);
  });
}
```

## 3. Web Framework Middleware
Use the `ternline_generate_middleware` MCP tool with `framework="express"` to generate drop-in Express middleware.
"""
    elif lang in ("java", "kotlin"):
        content = """# Ternline Java / Spring Boot Integration Guide

## 1. Environment Configuration
```properties
ternline.endpoint=http://localhost:8000
ternline.api-key=your_api_key_here
ternline.app-id=banking-backend
```

## 2. Dispatch via Async RestClient
```java
@Async
public CompletableFuture<Void> emitTelemetry(TernlineEvent event) {
    restClient.post()
        .uri(endpoint + "/v1/events")
        .header("Authorization", "Bearer " + apiKey)
        .contentType(MediaType.APPLICATION_JSON)
        .body(event)
        .retrieve()
        .toBodilessEntity();
    return CompletableFuture.completedFuture(null);
}
```
"""
    elif lang in ("rust", "rs"):
        content = """# Ternline Rust Integration Guide

## 1. Dependencies (Cargo.toml)
```toml
[dependencies]
reqwest = { version = "0.11", features = ["json"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tokio = { version = "1", features = ["full"] }
uuid = { version = "1", features = ["v4"] }
chrono = { version = "0.4", features = ["serde"] }
```

## 2. Non-blocking Task Spawn
```rust
tokio::spawn(async move {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(1500))
        .build()
        .unwrap();
    let _ = client.post(format!("{}/v1/events", endpoint))
        .bearer_auth(api_key)
        .json(&event)
        .send()
        .await;
});
```
"""
    else:
        content = f"Unsupported language: '{language}'. Supported options: python, go, nodejs, java, rust."
        return {"content": [{"type": "text", "text": content}], "isError": True}

    return {"content": [{"type": "text", "text": content}], "isError": False}


# --- Tool 2: Generate Drop-in Middleware ---
def generate_middleware(framework: str, app_id: Optional[str] = None, service_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Generates drop-in telemetry middleware tailored to the target web framework and service names.
    """
    fw = (framework or "fastapi").lower().strip()
    app = app_id or "payments-api"
    svc = service_id or "api-service"

    template = TEMPLATES.get(fw)
    if not template:
        supported = ", ".join(TEMPLATES.keys())
        return {
            "content": [{
                "type": "text",
                "text": f"Framework '{framework}' is not supported. Choose one of: {supported}"
            }],
            "isError": True
        }

    # Customize placeholders
    code = template.replace('app_id: str = "payments-api"', f'app_id: str = "{app}"')
    code = code.replace('service_id: str = "api-service"', f'service_id: str = "{svc}"')
    code = code.replace("app_id = process.env.TERNLINE_APP_ID || 'payments-api'", f"app_id = process.env.TERNLINE_APP_ID || '{app}'")
    code = code.replace("service_id = process.env.TERNLINE_SERVICE_ID || 'api-service'", f"service_id = process.env.TERNLINE_SERVICE_ID || '{svc}'")
    code = code.replace('appID string = "payments-api"', f'appID string = "{app}"')
    code = code.replace('serviceID string = "api-service"', f'serviceID string = "{svc}"')

    summary = f"""### Ternline {framework.upper()} Telemetry Middleware
Tailored for:
- Application ID: `{app}`
- Service ID:     `{svc}`
- Protocol:       Canonical Event Schema v1.0.0
- Execution:      Non-blocking asynchronous background emission

```
{code}
```
"""
    return {"content": [{"type": "text", "text": summary}], "isError": False}


# --- Tool 3: Validate Telemetry Event Offline ---
def validate_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validates a telemetry JSON event payload against the Canonical Event Schema Draft 7 without network round-trips.
    """
    if not isinstance(event, dict):
        return {
            "content": [{"type": "text", "text": "Validation Error: Input event must be a JSON object (dictionary)."}],
            "isError": True
        }

    Validator = getattr(jsonschema, "Draft7Validator", getattr(jsonschema, "Draft4Validator", jsonschema.Draft3Validator))
    validator = Validator(CANONICAL_EVENT_SCHEMA)
    errors = sorted(validator.iter_errors(event), key=lambda e: e.path)

    if not errors:
        out = {
            "status": "VALID",
            "message": "Event is fully compliant with Ternline Canonical Event Schema v1.0.0.",
            "event_id": event.get("event_id"),
            "event_type": event.get("event_type"),
            "severity": event.get("severity"),
            "app_id": event.get("app_id"),
            "service_id": event.get("service_id")
        }
        return {"content": [{"type": "text", "text": json.dumps(out, indent=2)}], "isError": False}

    formatted_errors = []
    for err in errors:
        loc = ".".join(str(p) for p in err.path) if err.path else "root"
        formatted_errors.append({
            "field": loc,
            "message": err.message,
            "rule": err.validator
        })

    out = {
        "status": "INVALID",
        "error_count": len(errors),
        "validation_errors": formatted_errors
    }
    return {"content": [{"type": "text", "text": json.dumps(out, indent=2)}], "isError": True}


# --- Tool 4: Engine Health Probe ---
def probe_health(endpoint: Optional[str] = None) -> Dict[str, Any]:
    """
    Tests network reachability, engine health, and database connectivity.
    """
    target = (endpoint or DEFAULT_ENDPOINT).rstrip("/")
    url = f"{target}/health"

    start = time.perf_counter()
    try:
        with httpx.Client(timeout=3.0) as client:
            resp = client.get(url)
            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
            
            if resp.status_code == 200:
                data = resp.json()
                result = {
                    "reachable": True,
                    "status_code": resp.status_code,
                    "engine_status": data.get("status"),
                    "environment": data.get("environment"),
                    "database_status": data.get("database"),
                    "latency_ms": elapsed_ms,
                    "endpoint": target,
                    "message": "Ternline engine is healthy and actively receiving telemetry."
                }
                return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}], "isError": False}
            else:
                result = {
                    "reachable": True,
                    "status_code": resp.status_code,
                    "error_response": resp.text,
                    "latency_ms": elapsed_ms,
                    "endpoint": target,
                    "message": f"Engine returned non-200 status: {resp.status_code}"
                }
                return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}], "isError": True}
    except Exception as e:
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        result = {
            "reachable": False,
            "error": str(e),
            "latency_ms": elapsed_ms,
            "endpoint": target,
            "message": "Failed to connect to Ternline engine. Verify the engine process is running."
        }
        return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}], "isError": True}


# --- Tool 5: Emit Test Event ---
def emit_test_event(
    endpoint: Optional[str] = None,
    api_key: Optional[str] = None,
    app_id: Optional[str] = None,
    service_id: Optional[str] = None,
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    attributes: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Constructs a compliant Canonical Event and emits it directly to the Ternline engine.
    Verifies end-to-end ingestion pipeline and authentication.
    """
    target = (endpoint or DEFAULT_ENDPOINT).rstrip("/")
    key = api_key or DEFAULT_API_KEY
    url = f"{target}/v1/events"

    now_iso = datetime.now(timezone.utc).isoformat()
    event_payload = {
        "event_id": f"evt_probe_{uuid.uuid4().hex[:16]}",
        "schema_version": "1.0.0",
        "timestamp": now_iso,
        "app_id": app_id or "mcp-probe",
        "service_id": service_id or "probe-service",
        "event_type": event_type or "mcp.health_probe",
        "severity": severity or "info",
        "source_resource": "mcp-agent",
        "target_resource": f"{target}/v1/events",
        "trace_id": f"trc_probe_{uuid.uuid4().hex[:12]}",
        "attributes": attributes or {
            "probe_origin": "ternline-mcp-server",
            "test_mode": True
        }
    }

    # Offline schema validation check first
    val_res = validate_event(event_payload)
    if val_res.get("isError"):
        return {
            "content": [{"type": "text", "text": f"Event construction failed validation: {val_res['content'][0]['text']}"}],
            "isError": True
        }

    start = time.perf_counter()
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json"
    }

    try:
        with httpx.Client(timeout=3.0) as client:
            resp = client.post(url, json=event_payload, headers=headers)
            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)

            if resp.status_code in (200, 202):
                data = resp.json()
                result = {
                    "success": True,
                    "status_code": resp.status_code,
                    "event_id": event_payload["event_id"],
                    "latency_ms": elapsed_ms,
                    "engine_response": data,
                    "message": "Telemetry event successfully ingested and evaluated by Fast Track."
                }
                return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}], "isError": False}
            else:
                result = {
                    "success": False,
                    "status_code": resp.status_code,
                    "event_id": event_payload["event_id"],
                    "latency_ms": elapsed_ms,
                    "error_response": resp.text,
                    "message": f"Engine rejected event with HTTP {resp.status_code}."
                }
                return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}], "isError": True}
    except Exception as e:
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        result = {
            "success": False,
            "error": str(e),
            "latency_ms": elapsed_ms,
            "message": f"Connection to {url} failed."
        }
        return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}], "isError": True}


# --- Tool 6: Provision API Key ---
def provision_key(
    app_id: str,
    endpoint: Optional[str] = None,
    admin_key: Optional[str] = None,
    scopes: Optional[List[str]] = None,
    expires_in_days: Optional[int] = None
) -> Dict[str, Any]:
    """
    Registers a new microservice and issues a cryptographically hashed API key.
    Requires an active administrator API key.
    """
    target = (endpoint or DEFAULT_ENDPOINT).rstrip("/")
    key = admin_key or DEFAULT_API_KEY
    if not key:
        return {"content": [{"type": "text", "text": "An admin API key is required. Set TERNLINE_API_KEY or pass admin_key."}], "isError": True}
    url = f"{target}/api/v1/keys"

    payload: Dict[str, Any] = {
        "app_id": app_id,
        "scopes": scopes or ["events:ingest"]
    }
    if expires_in_days is not None:
        payload["expires_in_days"] = expires_in_days

    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json"
    }

    try:
        with httpx.Client(timeout=3.0) as client:
            resp = client.post(url, json=payload, headers=headers)
            if resp.status_code in (200, 201):
                data = resp.json()
                result = {
                    "success": True,
                    "app_id": data.get("app_id"),
                    "key_id": data.get("key_id"),
                    "key_prefix": data.get("key_prefix"),
                    "api_key": data.get("api_key"),
                    "tenant_id": data.get("tenant_id"),
                    "scopes": data.get("scopes"),
                    "instructions": (
                        "Save this API key immediately in your microservice's .env file:\n"
                        f"TERNLINE_API_KEY={data.get('api_key')}\n"
                        f"TERNLINE_APP_ID={data.get('app_id')}\n"
                        f"TERNLINE_ENDPOINT={target}"
                    )
                }
                return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}], "isError": False}
            else:
                result = {
                    "success": False,
                    "status_code": resp.status_code,
                    "error_response": resp.text,
                    "message": "Key provisioning failed. Ensure your admin key has 'keys:admin' permissions."
                }
                return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}], "isError": True}
    except Exception as e:
        result = {
            "success": False,
            "error": str(e),
            "message": f"Connection to {url} failed."
        }
        return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}], "isError": True}


# --- Tool 7: Query Security Findings ---
def query_findings(
    severity: Optional[str] = None,
    detector_id: Optional[str] = None,
    limit: int = 20,
    endpoint: Optional[str] = None,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Queries real-time security findings detected across microservices by Fast Track detectors.
    """
    target = (endpoint or DEFAULT_ENDPOINT).rstrip("/")
    key = api_key or DEFAULT_API_KEY
    if not key:
        return {"content": [{"type": "text", "text": "An API key is required. Set TERNLINE_API_KEY or pass api_key."}], "isError": True}
    url = f"{target}/api/v1/findings"

    params: Dict[str, Any] = {"limit": min(limit, 100)}
    if severity:
        params["severity"] = severity.lower().strip()
    if detector_id:
        params["detector_id"] = detector_id.strip()

    headers = {"Authorization": f"Bearer {key}"}

    try:
        with httpx.Client(timeout=4.0) as client:
            resp = client.get(url, params=params, headers=headers)
            if resp.status_code == 200:
                findings = resp.json()
                result = {
                    "success": True,
                    "count": len(findings),
                    "findings": findings,
                }
                return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}], "isError": False}
            else:
                return {
                    "content": [{"type": "text", "text": f"Error querying findings: HTTP {resp.status_code} - {resp.text}"}],
                    "isError": True,
                }
    except Exception as e:
        return {"content": [{"type": "text", "text": f"Connection failed to {url}: {e}"}], "isError": True}


# --- Tool 8: Query Incidents ---
def query_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    service: Optional[str] = None,
    limit: int = 20,
    endpoint: Optional[str] = None,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Queries aggregated multi-service incident cases correlated by the Incident Correlator.
    """
    target = (endpoint or DEFAULT_ENDPOINT).rstrip("/")
    key = api_key or DEFAULT_API_KEY
    if not key:
        return {"content": [{"type": "text", "text": "An API key is required. Set TERNLINE_API_KEY or pass api_key."}], "isError": True}
    url = f"{target}/api/v1/incidents"

    params: Dict[str, Any] = {"limit": max(1, min(limit, 200))}
    if status:
        params["status"] = status.lower().strip()
    if severity:
        params["severity"] = severity.lower().strip()
    if service:
        params["service"] = service.strip()

    headers = {"Authorization": f"Bearer {key}"}

    try:
        with httpx.Client(timeout=4.0) as client:
            resp = client.get(url, params=params, headers=headers)
            if resp.status_code == 200:
                incidents = resp.json()
                result = {
                    "success": True,
                    "count": len(incidents),
                    "incidents": incidents,
                }
                return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}], "isError": False}
            else:
                return {
                    "content": [{"type": "text", "text": f"Error querying incidents: HTTP {resp.status_code} - {resp.text}"}],
                    "isError": True,
                }
    except Exception as e:
        return {"content": [{"type": "text", "text": f"Connection failed to {url}: {e}"}], "isError": True}


def get_defense_policy(
    endpoint: Optional[str] = None,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Fetches the authenticated tenant's current Active Defense policy."""
    target = (endpoint or DEFAULT_ENDPOINT).rstrip("/")
    key = api_key or DEFAULT_API_KEY
    if not key:
        return {"content": [{"type": "text", "text": "An API key is required. Set TERNLINE_API_KEY or pass api_key."}], "isError": True}
    url = f"{target}/api/v1/defense/policy"
    headers = {"Authorization": f"Bearer {key}"}
    try:
        with httpx.Client(timeout=4.0) as client:
            response = client.get(url, headers=headers)
            if response.status_code == 200:
                return {
                    "content": [{"type": "text", "text": json.dumps(response.json(), indent=2)}],
                    "isError": False,
                }
            return {
                "content": [{"type": "text", "text": f"Error querying defense policy: HTTP {response.status_code} - {response.text}"}],
                "isError": True,
            }
    except Exception as exc:
        return {"content": [{"type": "text", "text": f"Connection failed to {url}: {exc}"}], "isError": True}


# --- Tool 9: Deep Search AI Investigation ---
def run_deep_search(
    query: str,
    endpoint: Optional[str] = None,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Executes a Deep Track AI investigation against telemetry events using Meta Muse AI with mathematical citation audits.
    """
    target = (endpoint or DEFAULT_ENDPOINT).rstrip("/")
    key = api_key or DEFAULT_API_KEY
    if not key:
        return {"content": [{"type": "text", "text": "An API key is required. Set TERNLINE_API_KEY or pass api_key."}], "isError": True}
    url = f"{target}/api/v1/investigations/query"

    payload = {"query": query.strip()}
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }

    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(url, json=payload, headers=headers)
            if resp.status_code in (200, 201):
                report = resp.json()
                result = {
                    "success": True,
                    "investigation_id": report.get("investigation_id"),
                    "verdict": report.get("verdict"),
                    "summary": report.get("summary"),
                    "hypotheses": report.get("hypotheses", []),
                    "candidate_rules": report.get("candidate_rules", []),
                    "recommended_mitigations": report.get("recommended_mitigations", []),
                }
                return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}], "isError": False}
            else:
                return {
                    "content": [{"type": "text", "text": f"Investigation failed: HTTP {resp.status_code} - {resp.text}"}],
                    "isError": True,
                }
    except Exception as e:
        return {"content": [{"type": "text", "text": f"Connection failed to {url}: {e}"}], "isError": True}


# --- Tool 10: Match Threat Intelligence ---
def match_threat_intel(
    query: str,
    time_window_hours: int = 24,
    limit: int = 20,
    endpoint: Optional[str] = None,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Cross-references an IP address, domain, query pattern, or keyword against active Indicators of Compromise (IOCs)
    and stored telemetry to determine microservice blast radius.
    """
    target = (endpoint or DEFAULT_ENDPOINT).rstrip("/")
    key = api_key or DEFAULT_API_KEY
    url = f"{target}/api/v1/threat-intelligence/match"

    payload = {
        "query": query.strip(),
        "time_window_hours": time_window_hours,
        "limit": min(limit, 100),
    }
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }

    try:
        with httpx.Client(timeout=4.0) as client:
            resp = client.post(url, json=payload, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                result = {
                    "success": True,
                    "query": data.get("query"),
                    "matched_iocs_count": len(data.get("matched_iocs", [])),
                    "matched_events_count": data.get("matched_events_count", 0),
                    "affected_services": data.get("affected_services", []),
                    "mitre_techniques": data.get("mitre_techniques", []),
                    "matched_iocs": data.get("matched_iocs", []),
                }
                return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}], "isError": False}
            else:
                return {
                    "content": [{"type": "text", "text": f"Threat intel match failed: HTTP {resp.status_code} - {resp.text}"}],
                    "isError": True,
                }
    except Exception as e:
        return {"content": [{"type": "text", "text": f"Connection failed to {url}: {e}"}], "isError": True}


# --- Tool 11: Coordinated Incident Containment ---
def contain_incident(
    incident_id: str,
    rationale: str,
    contain_ips: bool = True,
    contain_credentials: bool = True,
    endpoint: Optional[str] = None,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Triggers active defense containment for an incident across all attacker IPs and compromised credentials.
    """
    target = (endpoint or DEFAULT_ENDPOINT).rstrip("/")
    key = api_key or DEFAULT_API_KEY
    url = f"{target}/api/v1/incidents/{incident_id.strip()}/contain"

    payload = {
        "rationale": rationale.strip(),
        "contain_ips": contain_ips,
        "contain_credentials": contain_credentials,
    }
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }

    try:
        with httpx.Client(timeout=4.0) as client:
            resp = client.post(url, json=payload, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                result = {
                    "success": True,
                    "incident_id": data.get("incident_id"),
                    "status": data.get("status"),
                    "contained_entities_count": data.get("contained_entities_count"),
                    "actions_triggered": data.get("actions_triggered", []),
                }
                return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}], "isError": False}
            else:
                return {
                    "content": [{"type": "text", "text": f"Incident containment failed: HTTP {resp.status_code} - {resp.text}"}],
                    "isError": True,
                }
    except Exception as e:
        return {"content": [{"type": "text", "text": f"Connection failed to {url}: {e}"}], "isError": True}


# --- Tool 12: List Declarative Detection Rules ---
def list_detection_rules(
    endpoint: Optional[str] = None,
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Lists active Fast Track declarative detection rules configured in the Ternline engine.
    """
    target = (endpoint or DEFAULT_ENDPOINT).rstrip("/")
    key = api_key or DEFAULT_API_KEY
    url = f"{target}/api/v1/rules"

    headers = {"Authorization": f"Bearer {key}"}

    try:
        with httpx.Client(timeout=4.0) as client:
            resp = client.get(url, params={"status_filter": "active"}, headers=headers)
            if resp.status_code == 200:
                rules = resp.json()
                result = {
                    "success": True,
                    "count": len(rules),
                    "rules": rules,
                }
                return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}], "isError": False}
            else:
                return {
                    "content": [{"type": "text", "text": f"Error listing rules: HTTP {resp.status_code} - {resp.text}"}],
                    "isError": True,
                }
    except Exception as e:
        return {"content": [{"type": "text", "text": f"Connection failed to {url}: {e}"}], "isError": True}

# CYBER ENGINE Universal SDK Specification & Wire Contract

This document specifies the exact wire format, client-side safety invariants, and implementation patterns for building official or third-party CYBER ENGINE SDKs in any language (Go, Node.js/TypeScript, Java/Kotlin, Rust, C#/.NET, PHP, etc.).

---

## 1. Core Architectural Invariants

Every CYBER ENGINE SDK must adhere to the following rules:

1. **Pure HTTP/JSON Wire Protocol:** All events are transmitted via standard HTTP `POST` requests. No proprietary binary or language-dependent serialization formats are used.
2. **Strict Cryptographic Authentication:** All requests must include the header:
   ```http
   Authorization: Bearer <API_KEY>
   ```
3. **Server-Enforced Multi-Tenancy:** The SDK does **not** specify `tenant_id`. The server extracts and cryptographically binds the tenant from the API key.
4. **Client-Side Secret & PII Sanitization:** SDKs must automatically scan and redact sensitive fields before serialization.
5. **Transport Security:** Remote endpoints must enforce `https://`. Insecure `http://` is prohibited except for `localhost` or explicit testing overrides.
6. **Bounded Queues & Backpressure:** In buffered mode, queues must have a hard maximum limit (e.g. 1,000 items) and reject or block rather than silently exhausting RAM.

---

## 2. Ingestion API Endpoints

### Endpoint A: Single Event
- **Method:** `POST /v1/events`
- **Headers:**
  - `Authorization: Bearer <api_key>`
  - `Content-Type: application/json`
  - `User-Agent: cyber-engine-sdk-<language>/<version>`
- **Payload Schema:** See Canonical Event JSON below.
- **Expected Success Response:** `HTTP 202 Accepted` or `HTTP 200 OK`
  ```json
  {
    "accepted": 1,
    "rejected": 0,
    "duplicates": 0,
    "event_ids": ["evt_4a2c1f90-128a-4efb-8812-78d102914aa1"]
  }
  ```

### Endpoint B: Batch Ingestion
- **Method:** `POST /v1/events/batch`
- **Headers:** Same as above
- **Payload:**
  ```json
  {
    "events": [ /* Array of Canonical Event objects, max 100 per batch */ ]
  }
  ```

---

## 3. Canonical Event Wire Schema

```json
{
  "event_id": "string (UUID v4 recommended)",
  "schema_version": "1.0.0",
  "timestamp": "string (ISO-8601 UTC timestamp, e.g. '2026-10-31T12:00:00.000Z')",
  "app_id": "string (1-64 chars, regex: ^[a-zA-Z0-9_\\-\\.]+$)",
  "service_id": "string (1-64 chars, regex: ^[a-zA-Z0-9_\\-\\.]+$)",
  "event_type": "string (dot-separated, e.g. 'auth.login_failed', 'http.request', 'db.query')",
  "severity": "string ('info' | 'low' | 'medium' | 'high' | 'critical')",
  "source_resource": "optional string (max 256 chars, e.g. IP address, actor ID)",
  "target_resource": "optional string (max 256 chars, e.g. URL path, table name)",
  "trace_id": "optional string (max 128 chars, OpenTelemetry/W3C trace ID)",
  "request_id": "optional string (max 128 chars)",
  "attributes": {
    "key": "value (JSON object, max 200 keys, strings capped at 10,000 chars)"
  },
  "provenance": {
    "sdk_version": "string (e.g. '0.1.0')",
    "sdk_language": "string (e.g. 'go', 'node', 'python', 'rust')",
    "hostname": "optional string"
  }
}
```

---

## 4. Multi-Language Implementation Reference

### Go (Golang) Example
```go
package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"
)

type CyberEngine struct {
	APIKey   string
	AppID    string
	Service  string
	Endpoint string
	Client   *http.Client
}

func (c *CyberEngine) Emit(eventType string, attributes map[string]interface{}) error {
	payload := map[string]interface{}{
		"schema_version": "1.0.0",
		"timestamp":      time.Now().UTC().Format(time.RFC3339Nano),
		"app_id":         c.AppID,
		"service_id":     c.Service,
		"event_type":     eventType,
		"severity":       "info",
		"attributes":     attributes, // apply redaction here
		"provenance": map[string]string{
			"sdk_language": "go",
			"sdk_version":  "0.1.0",
		},
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", c.Endpoint+"/v1/events", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
```

### TypeScript / Node.js Example
```typescript
import axios, { AxiosInstance } from 'axios';

export class CyberEngine {
  private client: AxiosInstance;

  constructor(
    private apiKey: string,
    private appId: string,
    private service: string = 'default-service',
    private endpoint: string = 'https://api.cyberengine.internal'
  ) {
    this.client = axios.create({
      baseURL: endpoint,
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'User-Agent': 'cyber-engine-sdk-node/0.1.0',
      },
      timeout: 5000,
    });
  }

  async emit(eventType: string, attributes: Record<string, any> = {}, traceId?: string) {
    const payload = {
      schema_version: '1.0.0',
      timestamp: new Date().toISOString(),
      app_id: this.appId,
      service_id: this.service,
      event_type: eventType,
      severity: 'info',
      trace_id: traceId,
      attributes: attributes, // scrubbed
      provenance: { sdk_language: 'node', sdk_version: '0.1.0' },
    };
    return (await this.client.post('/v1/events', payload)).data;
  }
}
```


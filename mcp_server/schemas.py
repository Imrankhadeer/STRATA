"""
Canonical Schemas, Event Catalogs, and Code Generation Templates for Ternline MCP Server.
Compliant with JSON Schema Draft 7 and MCP Specification standards.
"""

from typing import Dict, Any

CANONICAL_EVENT_SCHEMA: Dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "TernlineCanonicalEvent",
    "type": "object",
    "required": [
        "event_id",
        "schema_version",
        "timestamp",
        "app_id",
        "service_id",
        "event_type",
        "severity"
    ],
    "properties": {
        "event_id": {
            "type": "string",
            "minLength": 8,
            "maxLength": 64,
            "description": "Unique event identifier (UUID v4 recommended)"
        },
        "schema_version": {
            "type": "string",
            "enum": ["1.0.0"],
            "description": "Canonical wire format version"
        },
        "timestamp": {
            "type": "string",
            "format": "date-time",
            "description": "ISO-8601 UTC timestamp (e.g. 2026-11-02T12:00:00.000Z)"
        },
        "app_id": {
            "type": "string",
            "minLength": 1,
            "maxLength": 64,
            "pattern": r"^[a-zA-Z0-9_\-\.]+$",
            "description": "Global application identifier"
        },
        "service_id": {
            "type": "string",
            "minLength": 1,
            "maxLength": 64,
            "pattern": r"^[a-zA-Z0-9_\-\.]+$",
            "description": "Microservice identifier"
        },
        "event_type": {
            "type": "string",
            "minLength": 3,
            "maxLength": 128,
            "description": "Dot-separated hierarchical event type (e.g. auth.login_failed, db.query)"
        },
        "severity": {
            "type": "string",
            "enum": ["info", "low", "medium", "high", "critical"],
            "description": "Telemetry severity level"
        },
        "source_resource": {
            "type": ["string", "null"],
            "maxLength": 256,
            "description": "Initiating actor, user ID, client IP, or source container"
        },
        "target_resource": {
            "type": ["string", "null"],
            "maxLength": 256,
            "description": "Target endpoint, database table, record, or API route"
        },
        "trace_id": {
            "type": ["string", "null"],
            "maxLength": 128,
            "description": "Distributed trace ID (W3C TraceContext or OpenTelemetry)"
        },
        "request_id": {
            "type": ["string", "null"],
            "maxLength": 128,
            "description": "Local HTTP request ID"
        },
        "attributes": {
            "type": "object",
            "description": "Structured contextual metadata. Keys must not exceed 200 items."
        },
        "provenance": {
            "type": "object",
            "description": "Client SDK origin metadata"
        }
    },
    "additionalProperties": False
}

RECOMMENDED_EVENT_TYPES = [
    {
        "category": "Authentication & Identity",
        "types": [
            {"type": "auth.login_attempt", "severity": "info", "desc": "User authentication attempt initiated"},
            {"type": "auth.login_failed", "severity": "medium", "desc": "Bad credentials or locked account"},
            {"type": "auth.login_success", "severity": "info", "desc": "Successful user authentication"},
            {"type": "auth.mfa_challenged", "severity": "info", "desc": "MFA step presented to actor"},
            {"type": "auth.token_revoked", "severity": "low", "desc": "Session or JWT revoked"}
        ]
    },
    {
        "category": "API & Ingress (HTTP)",
        "types": [
            {"type": "http.request", "severity": "info", "desc": "Standard incoming API request processed"},
            {"type": "http.client_error", "severity": "low", "desc": "4xx HTTP responses (400, 404)"},
            {"type": "http.rate_limited", "severity": "medium", "desc": "429 Too Many Requests detected"},
            {"type": "http.unauthorized", "severity": "medium", "desc": "401/403 access control rejection"},
            {"type": "http.server_error", "severity": "high", "desc": "5xx Internal Server Error or unhandled exception"}
        ]
    },
    {
        "category": "Database & Storage",
        "types": [
            {"type": "db.query", "severity": "info", "desc": "Standard database query execution"},
            {"type": "db.bulk_query", "severity": "medium", "desc": "Query returning >1,000 rows or large table scan"},
            {"type": "db.table_dump", "severity": "high", "desc": "SELECT * query without LIMIT on sensitive table"},
            {"type": "db.connection_failed", "severity": "high", "desc": "Database pool exhaustion or connectivity drop"}
        ]
    },
    {
        "category": "Workers & Task Queues",
        "types": [
            {"type": "worker.job_started", "severity": "info", "desc": "Background job processing initiated"},
            {"type": "worker.job_failed", "severity": "medium", "desc": "Background job failed with exception"},
            {"type": "worker.job_anomalous", "severity": "high", "desc": "Job execution outside scheduled maintenance windows"}
        ]
    }
]

MIDDLEWARE_TEMPLATES = {
    "fastapi": '''# FastAPI / Starlette Ternline Middleware
import time
from fastapi import FastAPI, Request
from cyber_engine import CyberEngine

app = FastAPI()

# Initialize Ternline SDK
engine = CyberEngine(
    api_key="{api_key}",
    app="{app_id}",
    service="{service_id}",
    endpoint="{endpoint}",
    buffered=True
)

@app.middleware("http")
async def ternline_telemetry_middleware(request: Request, call_next):
    start_time = time.time()
    trace_id = request.headers.get("x-trace-id") or request.headers.get("traceparent")
    client_ip = request.client.host if request.client else "unknown"

    try:
        response = await call_next(request)
        duration_ms = round((time.time() - start_time) * 1000, 2)

        severity = "info"
        if response.status_code >= 500:
            severity = "high"
        elif response.status_code in (401, 403, 429):
            severity = "medium"

        engine.emit(
            event_type="http.request",
            severity=severity,
            source_resource=client_ip,
            target_resource=f"{request.method} {request.url.path}",
            trace_id=trace_id,
            attributes={
                "status_code": response.status_code,
                "duration_ms": duration_ms,
                "user_agent": request.headers.get("user-agent", "unknown")
            }
        )
        return response
    except Exception as exc:
        duration_ms = round((time.time() - start_time) * 1000, 2)
        engine.emit(
            event_type="http.server_error",
            severity="critical",
            source_resource=client_ip,
            target_resource=f"{request.method} {request.url.path}",
            trace_id=trace_id,
            attributes={
                "error": str(exc),
                "duration_ms": duration_ms
            }
        )
        raise
''',
    "express": '''// Express.js Ternline Telemetry Middleware
const axios = require('axios');
const crypto = require('crypto');

const TERNLINE_ENDPOINT = process.env.TERNLINE_ENDPOINT || 'http://localhost:8000';
const TERNLINE_API_KEY = process.env.TERNLINE_API_KEY;
if (!TERNLINE_API_KEY) { console.error('[Ternline] TERNLINE_API_KEY is not set. Telemetry will be rejected.'); }
const APP_ID = process.env.TERNLINE_APP_ID || 'payments-api';
const SERVICE_ID = process.env.TERNLINE_SERVICE_ID || 'api-service';

function ternlineMiddleware(req, res, next) {
    const startTime = Date.now();
    const traceId = req.headers['x-trace-id'] || req.headers['traceparent'] || crypto.randomUUID();
    const clientIp = req.ip || req.connection.remoteAddress;

    res.on('finish', () => {
        const durationMs = Date.now() - startTime;
        let severity = 'info';
        if (res.statusCode >= 500) severity = 'high';
        else if ([401, 403, 429].includes(res.statusCode)) severity = 'medium';

        const payload = {
            event_id: 'evt_' + crypto.randomUUID(),
            schema_version: '1.0.0',
            timestamp: new Date().toISOString(),
            app_id: APP_ID,
            service_id: SERVICE_ID,
            event_type: 'http.request',
            severity: severity,
            source_resource: clientIp,
            target_resource: `${req.method} ${req.path}`,
            trace_id: traceId,
            attributes: {
                status_code: res.statusCode,
                duration_ms: durationMs,
                user_agent: req.headers['user-agent']
            }
        };

        // Asynchronous non-blocking dispatch
        axios.post(`${TERNLINE_ENDPOINT}/v1/events`, payload, {
            headers: { 'Authorization': `Bearer ${TERNLINE_API_KEY}` },
            timeout: 2000
        }).catch(err => console.error('[Ternline] Ingestion error:', err.message));
    });

    next();
}

module.exports = ternlineMiddleware;
''',
    "go": '''// Go Gin Ternline Telemetry Middleware
package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

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

func TernlineMiddleware() gin.HandlerFunc {
	endpoint := os.Getenv("TERNLINE_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:8000"
	}
	apiKey := os.Getenv("TERNLINE_API_KEY")
	appID := "payments-api"
	serviceID := "api-service"

	return func(c *gin.Context) {
		start := time.Now()
		traceID := c.GetHeader("x-trace-id")
		if traceID == "" {
			traceID = uuid.New().String()
		}

		c.Next()

		durationMs := time.Since(start).Milliseconds()
		statusCode := c.Writer.Status()
		severity := "info"
		if statusCode >= 500 {
			severity = "high"
		} else if statusCode == 401 || statusCode == 403 || statusCode == 429 {
			severity = "medium"
		}

		event := TernlineEvent{
			EventID:        "evt_" + uuid.New().String(),
			SchemaVersion:  "1.0.0",
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
			AppID:          appID,
			ServiceID:      serviceID,
			EventType:      "http.request",
			Severity:       severity,
			SourceResource: c.ClientIP(),
			TargetResource: fmt.Sprintf("%s %s", c.Request.Method, c.Request.URL.Path),
			TraceID:        traceID,
			Attributes: map[string]interface{}{
				"status_code": statusCode,
				"duration_ms": durationMs,
			},
		}

		// Asynchronous non-blocking dispatch
		go func(ev TernlineEvent) {
			body, _ := json.Marshal(ev)
			req, _ := http.NewRequest("POST", endpoint+"/v1/events", bytes.NewBuffer(body))
			req.Header.Set("Authorization", "Bearer "+apiKey)
			req.Header.Set("Content-Type", "application/json")
			client := &http.Client{Timeout: 2 * time.Second}
			client.Do(req)
		}(event)
	}
}
'''
}

MIDDLEWARE_TEMPLATES["gin"] = MIDDLEWARE_TEMPLATES["go"]
TEMPLATES = MIDDLEWARE_TEMPLATES

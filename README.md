# Ternline (Cyber Engine)

> **Integrate once. Detect continuously. Investigate intelligently. Improve detection safely.**

Ternline is an active security intelligence platform designed for microservices and distributed applications. It bridges sub-millisecond, deterministic threat detection (Fast Track) with evidence-grounded AI investigations (Deep Track) and self-hardening declarative rule authoring.

---

## 1. Core Architecture

```
                       [ Incoming Telemetry Stream ]
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        FAST TRACK (Real-Time)                          │
│  • Ingest & Canonicalize Telemetry (POST /v1/events)                   │
│  • Dynamic Runtime Rule Registry (Active Declarative Rules)            │
│  • Pluggable Correlation State (InMemory / Atomic Redis Lua)           │
│  • Zero-LLM deterministic alerts (<1ms latency)                        │
│  • Multi-stage cross-service correlation (preserves stage candidates)  │
│  • Bounded cardinality (ZSET group limits, max seen event IDs)         │
│  • Native baseline fallback safety net with duplicate suppression      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                         Persists Security Findings
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        DEEP TRACK (On-Demand)                          │
│  • Evidence Gathering & Bounding (Multi-Service Context Assembly)      │
│  • Meta Model Investigation (Hypothesis Generation & Root Cause)       │
│  • Quality Audit Gate (Rejects Hallucinated / Ungrounded Citations)    │
│  • Cached Report Reuse & Concurrent Lock (Cost & Duplicate Protection) │
│  • Candidate Rule Proposal (Pure Declarative Parameter Overrides)      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                 RULE LIFECYCLE & VALIDATION LOOP                       │
│  1. Proposed: Discovered candidate rule with declarative thresholds    │
│  2. Validated: Replay against benchmark attack & benign scenarios      │
│     (Safety invariant: FPs > 0 blocks approval & activation)           │
│  3. Approved: Explicit audit authorization with rationale              │
│  4. Active: Dynamically loaded by RuntimeRuleRegistry across workers   │
│  5. Disabled / Rolled Back: Immediate runtime cache invalidation       │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Configuration & Startup Options

Ternline supports two operational modes:

### Mode A: Zero-Dependency Local Inspection (Development / CI)
Requires **no external database or Redis**. Uses in-memory SQLite and `InMemoryCorrelationStateStore`:
```bash
# 1. Clone & create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .\.venv\Scripts\Activate.ps1

# 2. Install dependencies
pip install -r requirements.txt

# 3. Create .env with dev defaults
cp .env.example .env

# 4. Start the server (Single Worker)
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```
* Interactive API Documentation: `http://localhost:8000/docs`
* Web Console & Landing Page: `http://localhost:8000/`

---

### Mode B: Full Distributed Production Stack (Docker Compose)
Runs **PostgreSQL 16**, **Redis 7 (AOF + Volatile-LRU)**, and the containerized backend:
```bash
# Boot complete production stack
docker compose up -d

# Check health
docker compose ps
```

---

## 3. Environment Variables Reference

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `ENVIRONMENT` | `development` | `development`, `testing`, `staging`, or `production`. |
| `SECRET_KEY` | `dev-insecure...` | Internal JWT/API key signature. Must be $\ge 32$ chars in production. |
| `DATABASE_URL` | `postgresql+psycopg2://...` | PostgreSQL connection string. |
| `ALLOW_SQLITE_TEST_FALLBACK` | `true` | Allows automated SQLite fallback in local test environments. |
| `WORKERS` | `1` | Worker process count. If $>1$, `REDIS_URL` is mandatory. |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis 7+ connection URL for distributed state. |
| `REDIS_REQUIRED` | `false` | When `true`, startup fails fast if Redis is unreachable. |
| `REDIS_STATE_TIMEOUT_MS` | `500` | Redis socket timeout in milliseconds. |
| `INVESTIGATOR_PROVIDER` | `mock` | `mock` (no API key required), `meta`, or `openai_compatible`. |
| `INVESTIGATOR_MODEL` | `Llama-3.3-70B-Instruct` | Model identifier for Deep Track investigations. |

---

## 4. Test Suite Execution

All 166 backend tests can be verified with `pytest`:

```bash
# Run full automated regression suite (166 tests)
python -m pytest tests/ --ignore=tests/test_milestone7_ops.py -k "not test_live_meta_model_inference" -v

# Run Checkpoint 5 Distributed Correlation & Multi-Worker tests
python -m pytest tests/test_checkpoint5_completion.py tests/test_distributed_correlation.py -v

# Run Checkpoint 4 Runtime Migration & Clock-Skew tests
python -m pytest tests/test_checkpoint4_runtime.py -v

# Run Checkpoint 3 Differential Parity tests
python -m pytest tests/test_checkpoint3_parity.py -v
```

---

## 5. Security & Isolation Invariants

1. **Deterministic Fast Track:** Fast Track evaluation executes in pure Python and atomic Redis Lua scripts in $<1\text{ms}$. Zero LLM calls are made on the ingestion path.
2. **Tenant Boundary Enforcement:** All Redis state keys, PostgreSQL queries, and API authorizations are strictly tenant-scoped (`ternline:{tenant_id}:...`). Cross-tenant leakage is architecturally prohibited.
3. **No Silent Fallback:** In production or staging, if Redis is unavailable, the engine fails fast at startup and reports `correlation_status="degraded"` at runtime while preserving PostgreSQL event durability.
4. **Grounded Deep Track:** Every event cited in AI investigation reports is programmatically audited against stored database records by `InvestigationQualityAuditor`. Hallucinated citations are rejected with `HTTP 422`.

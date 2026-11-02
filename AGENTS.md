# AGENTS.md — Instructions for Autonomous Coding Agents (Google Jules)

This document provides explicit instructions, configuration references, and execution workflows for autonomous coding agents (including Google Jules and CI/CD agents) operating on the Ternline (CYBER ENGINE) codebase.

---

## 1. Tech Stack & Environment

* **Language:** Python 3.12+
* **Framework:** FastAPI / Starlette / Uvicorn
* **Database Layer:** SQLAlchemy 2.0 / Alembic (PostgreSQL 16 exclusively; SQLite is strictly prohibited)
* **Distributed State:** Redis 7+ with Lua scripting (or `InMemoryCorrelationStateStore` for single-worker/local test)
* **Validation:** Pydantic v2
* **Testing:** Pytest / AnyIO / Starlette TestClient / FakeRedis

---

## 2. Quickstart & Bootstrapping

The repository comes pre-configured with a `.env` file containing functional development credentials and settings.

### Installation & Dependency Resolution
```bash
pip install -r requirements.txt
```

### Starting the Server
```bash
uvicorn backend.main:app --host 0.0.0.0 --port 8000
```
* **PostgreSQL Mandatory:** Ternline requires a running PostgreSQL instance (PostgreSQL 16). SQLite is not supported in any environment. Distributed correlation state optionally connects to Redis 7+ or uses in-memory single-worker state in development.
* **API Documentation:** `http://localhost:8000/docs`

---

## 3. Pre-Seeded Development Credentials & Tokens

The application automatically seeds a baseline development tenant on startup:

* **Tenant ID:** `tenant-alpha`
* **Application ID:** `payments-api`
* **API Key:** `ce_live_test_api_key_secret_12345`
* **HTTP Authorization Header:** `Authorization: Bearer ce_live_test_api_key_secret_12345`

Use these credentials for all API requests to `/v1/events`, `/api/v1/findings`, `/api/v1/investigations`, `/api/v1/rules`, and `/api/v1/keys`.

---

## 4. Test Suite Execution

All tests are designed to execute deterministically without external services:

```bash
# Run the complete test suite (188 tests, zero exclusions)
python -m pytest tests/ -k "not test_live_meta_model_inference" -q

# Run Distributed Correlation & Redis State Store tests (includes multi-process tests)
python -m pytest tests/test_checkpoint5_completion.py tests/test_distributed_correlation.py -v

# Run Declarative Rule Lifecycle & Parity tests
python -m pytest tests/test_checkpoint4_runtime.py tests/test_checkpoint3_parity.py -v

# Run API Key Lifecycle, Prometheus Metrics & Async Telemetry Worker tests
python -m pytest tests/test_api_keys.py tests/test_metrics.py tests/test_async_worker.py -v
```

---

## 5. End-to-End Operational Verification Workflow

To verify that the engine is functioning end-to-end:

### Step 1: Trigger Built-In Attack Simulation
```bash
curl -X POST http://localhost:8000/api/v1/simulation/run \
  -H "Authorization: Bearer ce_live_test_api_key_secret_12345" \
  -H "Content-Type: application/json" \
  -d '{"scenario": "exfiltration"}'
```
*Emits a 3-stage cross-service attack sequence (`api-service` -> `worker-service` -> `database-service`) and generates security findings.*

### Step 2: Query Findings
```bash
curl -X GET http://localhost:8000/api/v1/findings \
  -H "Authorization: Bearer ce_live_test_api_key_secret_12345"
```
*Returns detected security findings, including `detector_id`, severity, and cross-service evidence.*

### Step 3: Trigger Deep-Track Investigation
```bash
curl -X POST "http://localhost:8000/api/v1/investigations/{finding_id}" \
  -H "Authorization: Bearer ce_live_test_api_key_secret_12345"
```
*Gathers trace evidence, runs the investigation adapter (mock provider configured in `.env`), audits citations against database records, and outputs candidate rules.*

### Step 4: Scrape Prometheus Observability Metrics
```bash
curl -X GET http://localhost:8000/metrics
```
*Returns standard Prometheus 0.0.4 text format exposing ingestion counters, detection latencies, active rule counts, and database health.*

### Step 5: Provision or Rotate API Keys
```bash
curl -X POST http://localhost:8000/api/v1/keys \
  -H "Authorization: Bearer ce_live_test_api_key_secret_12345" \
  -H "Content-Type: application/json" \
  -d '{"app_id": "audit-worker", "name": "Worker Ingest Key"}'
```
*Provisions a new cryptographically hashed API key scoped strictly to the caller tenant.*

---

## 6. Architectural Constraints & Code Rules

1. **Backend Only:** All changes must be strictly backend engineering. Do not modify or redesign frontend files (`TERNLINE_Control_Room_Enhanced.html`, `index.html`, etc.).
2. **Zero Ingestion Latency Impact:** Fast Track detection must remain deterministic in pure Python/Redis Lua (<1ms). Never place synchronous LLM API calls on the ingestion path.
3. **Tenant Boundary Enforcement:** All Redis keys, PostgreSQL queries, and state storage must remain strictly scoped by `tenant_id`.
4. **No Silent In-Memory Fallback in Production:** In `production`/`staging` environments, required Redis dependencies must fail fast rather than silently falling back to process-local state.


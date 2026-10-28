# CYBER ENGINE — Adaptive Infrastructure Security Platform

CYBER ENGINE is a developer-friendly security layer designed for application infrastructure: APIs, servers, cloud environments, and distributed microservices.

---

## 1. System Architecture: Two Paths

```mermaid
flowchart TD
    subgraph Client Application / Microservices
        SDK[Python SDK / cyber_engine]
        S1[api-service] -->|auth / http events| SDK
        S2[worker-service] -->|task events| SDK
        S3[database-service] -->|access events| SDK
    end

    subgraph CYBER ENGINE Ingestion & Fast Path
        Ingest["Telemetry Ingestion API (/v1/events)"]
        AuthVal["Tenant Isolation & App Key Auth"]
        DB[(PostgreSQL Store)]
        FastDet["Fast Path Detectors (Continuous / Deterministic)"]
        Findings[(Security Findings)]

        SDK -->|Bearer Token & Canonical Events| Ingest
        Ingest --> AuthVal
        AuthVal -->|Persist Valid Event| DB
        AuthVal -->|Stream Event| FastDet
        FastDet -->|Triggered Anomaly / Threshold| Findings
    end

    subgraph Deep Investigation Path (Future Stage)
        Findings -->|High-Severity Incident Alert| DeepInv["AI Investigation Engine (Meta Model)"]
        DeepInv -->|Evidence Gathering| DB
        DeepInv -->|Hypothesis Testing & Candidate Detectors| SandBox["Evaluation & Shadow Mode"]
    end
```

### Two-Path Architecture Principles:
- **Fast Path (Continuous Protection)**: Ingests routine telemetry, enforces tenant isolation, handles duplicate events, and detects known patterns without requiring an LLM call per event. Operates even when external AI providers are offline.
- **Deep-Investigation Path (Discovery & Improvement)**: Activated selectively for high-priority or ambiguous security incidents, proposing candidate detectors validated against historical test sets before human-supervised promotion.

---

## 2. Directory Structure

```
CYBER ENGINE/
├── backend/                  # FastAPI telemetry ingestion engine
│   ├── api/
│   │   └── ingest.py         # /v1/events and /v1/events/batch endpoints
│   ├── core/
│   │   └── auth.py           # Scoped API key auth and tenant isolation
│   ├── db/
│   │   └── session.py        # SQLAlchemy engine & session factory
│   ├── detection/
│   │   └── baseline.py       # BaseDetector interface & BruteForceLoginDetector
│   ├── schemas/
│   │   └── events.py         # Pydantic CanonicalEvent specification
│   ├── config.py             # Pydantic Settings configuration
│   ├── main.py               # Application entrypoint & health check
│   └── models.py             # PostgreSQL ORM models
├── migrations/               # Alembic database migrations
│   ├── versions/
│   │   └── 001_initial_schema.py # Initial PostgreSQL schema migration
│   └── env.py
├── sdk/                      # Installable Python SDK
│   ├── cyber_engine/
│   │   ├── client.py         # CyberEngine client with buffering & timeouts
│   │   ├── events.py         # Event dataclass
│   │   └── __init__.py
│   └── setup.py
├── scenarios/                # Synthetic distributed microservices
│   ├── synthetic_services/
│   │   ├── api_service.py    # Generates request and auth events
│   │   ├── worker_service.py # Emits background job telemetry
│   │   └── database_service.py # Simulates data access telemetry
│   └── run_scenario.py       # Reproducible distributed workload runner
├── tests/                    # Automated pytest suite
│   ├── conftest.py           # Test fixtures & database isolation
│   ├── test_api_ingest.py    # Ingestion, validation, auth, duplicates
│   ├── test_detection.py     # Deterministic detector triggers & findings
│   ├── test_scenarios.py     # End-to-end multi-service scenario tests
│   └── test_sdk.py           # SDK emission & configuration tests
├── docker-compose.yml        # PostgreSQL & backend container definition
├── Dockerfile                # Backend container image
├── requirements.txt          # Python dependencies
└── .env.example              # Environment variables template
```

---

## 3. Getting Started & Local Development

### Prerequisites
- Python 3.12+
- Docker & Docker Compose (optional for local SQLite testing, required for production PostgreSQL)

### 1. Configure Environment
```bash
cp .env.example .env
```

### 2. Install Dependencies & SDK
```bash
pip install -r requirements.txt
pip install -e ./sdk
```

### 3. Database Migration (PostgreSQL)
Run Alembic migrations against your target PostgreSQL database:
```bash
python -m alembic upgrade head
```

### 4. Running via Docker Compose
To launch PostgreSQL and the Backend together:
```bash
docker compose up -d
```

### 5. Running the Backend Locally
```bash
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```
- Health Check: `GET http://localhost:8000/health`
- Interactive OpenAPI Docs: `http://localhost:8000/docs`

---

## 4. Running Automated Tests

Run the test suite verifying all 14 test cases across ingestion, authentication, database persistence, detector behavior, synthetic distributed workloads, and the Python SDK:

```bash
python -m pytest -v
```

All 14 tests run deterministically:
```
tests/test_api_ingest.py::test_health_check PASSED
tests/test_api_ingest.py::test_missing_or_invalid_auth PASSED
tests/test_api_ingest.py::test_valid_event_ingestion_and_persistence PASSED
tests/test_api_ingest.py::test_rejection_of_malformed_events PASSED
tests/test_api_ingest.py::test_duplicate_event_handling PASSED
tests/test_api_ingest.py::test_tenant_and_app_scoping_isolation PASSED
tests/test_api_ingest.py::test_batch_ingestion PASSED
tests/test_detection.py::test_detector_threshold_trigger PASSED
tests/test_detection.py::test_detector_ignores_benign_events PASSED
tests/test_detection.py::test_end_to_end_detection_persistence PASSED
tests/test_scenarios.py::test_synthetic_services_and_scenario_runner PASSED
tests/test_sdk.py::test_sdk_emit_single_event PASSED
tests/test_sdk.py::test_sdk_validation_errors PASSED
tests/test_sdk.py::test_sdk_context_manager PASSED
============================= 14 passed in 1.83s ==============================
```

---

## 5. Security & Isolation Invariants

- **Server-Side Tenant Isolation**: Ingestion authentication maps API keys to specific tenants and application scopes server-side. Payloads attempting to spoof `tenant_id` or cross application scopes are forbidden with HTTP 403.
- **Untrusted Input Handling**: All telemetry is validated with strict regex patterns for keys, timestamps are parsed as UTC, and payloads exceeding bounds (1 MB request size, 200 attribute keys) are rejected.
- **Safe Baseline Fast Path**: `BruteForceLoginDetector` operates in-memory without AI dependency, logging security findings directly into `security_findings` with provenance evidence.

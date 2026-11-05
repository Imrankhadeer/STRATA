# Ternline (Cyber Engine)

> **Integrate once. Detect continuously. Investigate intelligently. Improve detection safely.**

Ternline is an active security intelligence platform designed for microservices and modern distributed applications. It bridges sub-millisecond, deterministic threat detection (**Fast Track**) with evidence-grounded AI investigations (**Deep Track**), automated mitigation (**Active Defense**), and self-hardening declarative detection rule authoring.

---

## 🌐 Live Platform & Evaluation Links

* **Live Web Console:** [https://ternline.vercel.app/console](https://ternline.vercel.app/console)
* **Landing Page:** [https://ternline.vercel.app](https://ternline.vercel.app)
* **Comprehensive Documentation & Guide:** [https://ternline.vercel.app/docs](https://ternline.vercel.app/docs) (or [`/documentation`](https://ternline.vercel.app/documentation))
* **Local Web Console:** [http://localhost:8000/console](http://localhost:8000/console)
* **Interactive OpenAPI / Swagger UI:** [http://localhost:8000/swagger](http://localhost:8000/swagger) (or [`/api/docs`](http://localhost:8000/api/docs))
* **Prometheus Observability Metrics:** [http://localhost:8000/metrics](http://localhost:8000/metrics)
* **Service Health Probe:** [http://localhost:8000/health](http://localhost:8000/health)

---

## ⚡ 30-Second Quickstart (Judges & Evaluators)

Anyone can clone the repository and boot the complete stack with a single command:

### 1. Clone & Start
```bash
git clone https://github.com/Imrankhadeer/Ternline.git
cd Ternline

# Option A: Automatic startup (Mac / Linux / WSL)
./start.sh

# Option B: Automatic startup (Windows)
start.bat
# or in PowerShell: .\start.ps1

# Option C: Docker Compose direct (Cross-Platform)
docker compose up --build
```
> The startup script boots **PostgreSQL 16** (port `5433`), **Redis 7** (port `6379`), applies all Alembic database migrations, and launches the Ternline backend and Web Console on port `8000`.

---

### 2. Live 3-Click Evaluation Walkthrough

1. **Open the Web Console:** Navigate to **`http://localhost:8000/console`** (or [live on Vercel](https://ternline.vercel.app/console)).
2. **Instant 1-Click Login:** Click the prominent **`⚡ 1-Click Demo Login (Hackathon Judges)`** button on the login gate. You are instantly authenticated into the pre-seeded `tenant-alpha` workspace with full administrator permissions.
3. **Trigger Live Multi-Service Attack Simulation:** On the **Overview** dashboard, click **`⚡ Trigger Attack Simulation`**.
   - Emits a real-time 3-stage cross-service attack sequence: `api-service` → `worker-service` → `database-service`.
   - The deterministic Fast Track engine processes the stream in pure Python/Redis Lua in **`<1ms`**.
   - Immediate security findings and correlated incidents appear on your dashboard!
4. **Inspect & Run AI Deep Track:**
   - Click **Findings & Incidents** on the sidebar.
   - Click **`⌘ Deep Track`** on the detected finding.
   - Watch the live SSE investigation stream reconstruct the cross-service sequence, formulate grounded hypotheses, audit evidence citations against database records, and propose candidate declarative detection rules.
5. **Validate & Promote Rule to Fast Track:**
   - Open **Rule Registry** → click **Validate (replay)** to replay the candidate rule against historical attack and benign benchmarks.
   - Click **Approve** and **Activate** to hot-deploy the rule directly into the active Fast Track engine without downtime or server restart.

---

## 🔑 Pre-Seeded Evaluation Credentials

When running in development mode (`ENVIRONMENT=development`), the application automatically seeds baseline credentials:

* **Tenant ID:** `tenant-alpha`
* **Application ID:** `payments-api`
* **API Key:** `ce_live_test_api_key_secret_12345`
* **HTTP Authorization Header:** `Authorization: Bearer ce_live_test_api_key_secret_12345`

Use these credentials for all API requests to `/v1/events`, `/api/v1/findings`, `/api/v1/investigations`, `/api/v1/rules`, and `/api/v1/keys`.

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
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                 ACTIVE DEFENSE & MITIGATION WORKFLOW                   │
│  • Configurable Posture: OBSERVE, ASSISTED (Human-in-the-loop),        │
│    or ENFORCED (Autonomous Low-Risk Execution)                         │
│  • Containment Actions: Rate limiting, IP blocking, token revocation   │
│  • Full Auditability: Reversible actions with rollback capabilities    │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Key Platform Capabilities

| Capability | Module | Description |
| :--- | :--- | :--- |
| **Deterministic Fast Track** | `backend/detection/` | Sub-millisecond stream evaluation in Python & atomic Redis Lua. Emits structured `SecurityFinding` objects with zero LLM overhead. |
| **AI Deep Track Investigations** | `backend/investigation/` | On-demand forensic investigations powered by Meta AI Spark. Reconstructs execution flows, formulates hypotheses, and cites audited evidence. |
| **Evidence Citation Audit** | `backend/investigation/scope.py` | Programmatically audits all event citations in AI reports against PostgreSQL records. Hallucinated or cross-tenant citations are rejected. |
| **Declarative Detection Rules** | `backend/schemas/rules.py` | Versioned declarative rules supporting thresholds and sequence stages. Validated via historical replay with zero code deployment. |
| **Active Defense & Mitigation** | `backend/defense/` | Multi-mode response orchestrator (Observe, Assisted, Enforced) supporting rate limiting, IP blocking, and session revocation. |
| **Threat Hunting & MITRE ATT&CK** | `backend/api/events.py` | Multi-dimensional telemetry search, service topology reconstruction, and interactive MITRE ATT&CK matrix coverage mapping. |
| **IOC Registry** | `backend/api/threat_intelligence.py` | Curated Indicators of Compromise (IPs, domains, hashes) with CIDR range matching and automatic hit detection. |
| **AI Security Copilot** | `backend/api/assistant.py` | Interactive LLM assistant grounded in tenant security posture, active findings, and event streams. |
| **Multi-Tenant Workspaces & RBAC** | `backend/api/auth.py` | Tenant-isolated workspaces with role-based access control (`owner`, `admin`, `analyst`, `observer`) and hashed API keys. |
| **Attack Simulation Engine** | `backend/api/simulation.py` | Realistic cross-service multi-stage attack generator (`api` → `worker` → `db`) for instant evaluation and drills. |

---

## 3. Configuration & Startup Options

Ternline supports two operational modes:

### Mode A: Automated Startup Script or Docker Compose (Recommended)
```bash
./start.sh          # Linux/macOS
start.bat           # Windows
docker compose up --build
```

### Mode B: Local Development (Without Docker)
Requires a running **PostgreSQL 16** database and optionally Redis 7+:
```bash
# 1. Clone & create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .\.venv\Scripts\Activate.ps1

# 2. Install dependencies
pip install -r requirements.txt

# 3. Create .env with dev defaults
cp .env.example .env

# 4. Apply database migrations
alembic upgrade head

# 5. Start the server (Single Worker)
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## 4. Environment Variables Reference

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `ENVIRONMENT` | `development` | `development`, `testing`, `staging`, or `production`. |
| `SECRET_KEY` | `dev-insecure...` | Internal JWT/API key signature. Must be $\ge 32$ chars in production. |
| `DATABASE_URL` | `postgresql+psycopg2://...` | PostgreSQL connection string (mandatory; SQLite is strictly prohibited). |
| `WORKERS` | `1` | Worker process count. If $>1$, `REDIS_URL` is mandatory. |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis 7+ connection URL for distributed state. |
| `REDIS_REQUIRED` | `false` | When `true`, startup fails fast if Redis is unreachable. |
| `REDIS_STATE_TIMEOUT_MS` | `500` | Redis socket timeout in milliseconds. |
| `INVESTIGATOR_PROVIDER` | `muse` | `muse` (Meta AI Spark), `mock` (deterministic local tests), or `openai_compatible`. |
| `INVESTIGATOR_MODEL` | `muse-spark-1.3` | Model identifier for Deep Track investigations. |

---

## 5. Test Suite Execution

All tests execute deterministically without external network services:

```bash
# Run the complete test suite
python -m pytest tests/ -k "not test_live_meta_model_inference" -q

# Run Distributed Correlation & Redis State Store tests
python -m pytest tests/test_checkpoint5_completion.py tests/test_distributed_correlation.py -v

# Run Declarative Rule Lifecycle & Parity tests
python -m pytest tests/test_checkpoint4_runtime.py tests/test_checkpoint3_parity.py -v

# Run API Key Lifecycle, Metrics & Console E2E tests
python -m pytest tests/test_api_keys.py tests/test_metrics.py tests/test_milestone5_e2e_console_workflow.py -v

# Run Documentation Integrity tests
python -m pytest tests/test_documentation_integrity.py -v
```

---

## 6. Security & Isolation Invariants

1. **Deterministic Fast Track:** Fast Track evaluation executes in pure Python and atomic Redis Lua scripts in $<1\text{ms}$. Zero LLM calls are made on the ingestion path.
2. **Tenant Boundary Enforcement:** All Redis state keys, PostgreSQL queries, and API authorizations are strictly tenant-scoped (`ternline:{tenant_id}:...`). Cross-tenant leakage is architecturally prohibited.
3. **No Silent Fallback:** In production or staging, if Redis is unavailable, the engine fails fast at startup and reports `correlation_status="degraded"` at runtime while preserving PostgreSQL event durability.
4. **Grounded Deep Track:** Every event cited in AI investigation reports is programmatically audited against stored database records by `InvestigationQualityAuditor`. Hallucinated citations are rejected with `HTTP 422`.
5. **Declarative Rule Safety:** Candidate detection rules contain NO executable code, eval statements, or arbitrary SQL. All rules compile strictly to validated declarative schemas evaluated in-memory.

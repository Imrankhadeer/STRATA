# Ternline (Cyber Engine)

> **Integrate once. Detect continuously. Investigate intelligently. Improve detection safely.**

Ternline is a security intelligence platform designed for applications and distributed infrastructure. It bridges deterministic, real-time threat detection with evidence-grounded AI investigations and declarative rule authoring.

---

## 1. Two-Path Architecture

```
                       [ Incoming Telemetry Stream ]
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        FAST TRACK (Real-Time)                          │
│  • Ingest & Canonicalize Telemetry (/v1/events)                        │
│  • Dynamic Runtime Rule Registry (Active Declarative Rules)            │
│  • Cross-Service In-Memory Correlation (Trace & Time Window)           │
│  • Zero-LLM deterministic alerts (<10ms latency)                       │
│  • Suppresses duplicate baseline alerts when active rules fire         │
│  • Native baseline fallback safety net                                 │
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

## 2. Deployment Architecture & Supported Constraints

- **Process Model:** **Single-worker per instance (`uvicorn --workers 1`)** is the supported deployment mode. Fast Track cross-service correlation maintains in-memory sliding trace windows (`_windows` and `_emitted`).
- **Restart Recovery:** All events, findings, and declarative rules are durably persisted in PostgreSQL. Ingested events and rules survive application restarts.
- **Cache Invalidation:** The `RuntimeRuleRegistry` uses a 10-second TTL cache with explicit, immediate invalidation triggers (`runtime_rule_registry.invalidate(tenant_id)`) upon rule activation, disabling, or rollback. Changes take effect with zero latency and without server restarts.

---

## 3. Quickstart & Verification

### Running the Backend

```bash
# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Start Uvicorn Server (Single Worker Mode)
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

### Running the Test Suite

```bash
# Run complete test suite (91 passing tests)
python -m pytest -v

# Run Milestone 6 Lifecycle & Execution Integrity tests
python -m pytest -v tests/test_milestone6_lifecycle_and_execution.py

# Run Complete 10-Step End-to-End Acceptance Loop
python -m pytest -v -s tests/test_milestone6_acceptance.py
```

---

## 4. Milestone 6 Verification Summary

All Milestone 6 requirements have been implemented and verified:
1. **Dynamic Fast Track Rule Execution:** Active declarative rules loaded dynamically per tenant, stamping `rule_id` and `rule_version` into findings and suppressing duplicate alerts.
2. **Rule Lifecycle & Rollback:** Complete transition lifecycle (`proposed -> validated -> approved -> active -> disabled / rolled back`) with audit trails and sub-millisecond cache invalidation.
3. **Investigation Integrity & Cost Controls:** Real-time quality audit gate rejecting ungrounded event citations with `HTTP 422`, cached report reuse (`force_refresh=False`), and in-flight concurrency lock (`HTTP 409`).
4. **Detector State Reliability:** Deduplication of repeated event IDs and dynamic window expansion for out-of-order event streams.
5. **Full Acceptance Test:** Verified 10-step end-to-end loop in `tests/test_milestone6_acceptance.py`.


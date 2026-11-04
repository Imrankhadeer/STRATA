import logging
import os
import sys
import uuid
from pathlib import Path

# Ensure workspace root and SDK directory are in sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
SDK_DIR = REPO_ROOT / "sdk"
for p in (str(REPO_ROOT), str(SDK_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    from cyber_engine import CyberEngine
except ImportError:
    from sdk.cyber_engine import CyberEngine

from scenarios.synthetic_services import (
    ApiServiceSimulator,
    WorkerServiceSimulator,
    DatabaseServiceSimulator
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("scenario_runner")


def run_synthetic_scenario(engine_client: CyberEngine):
    """
    Executes a reproducible distributed synthetic workload across 3 services:
    1. Normal user login and browsing flow with cross-service trace correlation.
    2. Suspicious credential brute-force attack from a malicious IP.
    3. Cross-service bulk exfiltration flow (API -> Worker -> Database).
    """
    api = ApiServiceSimulator(engine_client)
    worker = WorkerServiceSimulator(engine_client)
    db = DatabaseServiceSimulator(engine_client)

    logger.info("--- Step 1: Normal Distributed Telemetry Flow ---")
    trace_1 = f"trace-norm-{uuid.uuid4().hex[:8]}"
    api.handle_login(username="alice", client_ip="198.51.100.12", success=True, trace_id=trace_1)
    api.handle_request(endpoint="/api/v1/profile", client_ip="198.51.100.12", trace_id=trace_1)
    worker.process_job(job_name="sync_profile_cache", payload_size_kb=4, trace_id=trace_1, is_suspicious=False)
    db.record_access(table="user_profiles", operation="SELECT", rows_affected=1, trace_id=trace_1, is_bulk_exfil=False)

    logger.info("--- Step 2: Suspicious Credential Brute-Force Telemetry ---")
    attacker_ip = "203.0.113.88"
    for i in range(5):
        api.handle_login(
            username="admin",
            client_ip=attacker_ip,
            success=False,
            trace_id=f"trace-bf-{i}"
        )

    logger.info("--- Step 3: Cross-Service Bulk Exfiltration Telemetry ---")
    trace_exfil = f"trace-exfil-{uuid.uuid4().hex[:8]}"
    api.handle_request(endpoint="/api/v1/internal/export", client_ip="10.0.4.15", method="POST", trace_id=trace_exfil)
    worker.process_job(job_name="mass_export_task", payload_size_kb=8500, trace_id=trace_exfil, is_suspicious=True)
    db.record_access(table="credit_cards", operation="SELECT", rows_affected=50000, trace_id=trace_exfil, is_bulk_exfil=True)

    logger.info("Synthetic scenario completed successfully.")


if __name__ == "__main__":
    # Test client using default local endpoint and dummy key
    client = CyberEngine(
        api_key="ce_live_synthetic_test_key",
        app="synthetic-app",
        endpoint="http://localhost:8000"
    )
    try:
        run_synthetic_scenario(client)
    finally:
        client.close()

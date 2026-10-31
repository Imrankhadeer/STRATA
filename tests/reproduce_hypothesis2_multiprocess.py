"""
Reproduction script for Security Hypothesis 2: Distributed Correlation State Audit.

Demonstrates that splitting event streams across independent OS worker processes
causes 100% false negative evasion for both threshold and sequence detection rules,
because correlation state is process-local in memory.
"""

import sys
import os
import datetime
import multiprocessing
from typing import List, Dict, Any

# Ensure project root in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.schemas.declarative_spec import (
    LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC,
    LEGACY_EXFILTRATION_DECLARATIVE_SPEC,
)
from backend.detection.generic_evaluator import GenericDeclarativeEvaluator
from backend.schemas.events import CanonicalEvent


def worker_main(worker_id: int, event_queue: multiprocessing.Queue, result_queue: multiprocessing.Queue):
    """Simulates an isolated backend worker running in a distinct OS process."""
    bf_evaluator = GenericDeclarativeEvaluator(
        rule_id="rule-bf-worker",
        version=1,
        title="Worker Brute Force",
        description="Threshold Rule",
        spec=LEGACY_BRUTE_FORCE_DECLARATIVE_SPEC,
    )
    exfil_evaluator = GenericDeclarativeEvaluator(
        rule_id="rule-exfil-worker",
        version=1,
        title="Worker Exfiltration",
        description="Sequence Rule",
        spec=LEGACY_EXFILTRATION_DECLARATIVE_SPEC,
    )

    findings: List[Dict[str, Any]] = []

    while True:
        event_dict = event_queue.get()
        if event_dict is None:
            break

        ev = CanonicalEvent(**event_dict)

        f1 = bf_evaluator.evaluate(ev)
        if f1:
            findings.append({"worker": worker_id, "type": "threshold", "finding": f1.model_dump(mode="json")})

        f2 = exfil_evaluator.evaluate(ev)
        if f2:
            findings.append({"worker": worker_id, "type": "sequence", "finding": f2.model_dump(mode="json")})

    result_queue.put((worker_id, findings))


def run_reproduction():
    q1 = multiprocessing.Queue()
    q2 = multiprocessing.Queue()
    res_q = multiprocessing.Queue()

    p1 = multiprocessing.Process(target=worker_main, args=(1, q1, res_q))
    p2 = multiprocessing.Process(target=worker_main, args=(2, q2, res_q))
    p1.start()
    p2.start()

    now = datetime.datetime.now(datetime.timezone.utc)

    # 1. Threshold Test: 8 login failures (Threshold is 5).
    # Distributed round-robin across Worker 1 and Worker 2 (4 attempts each).
    for i in range(8):
        ev = {
            "event_id": f"ev-bf-{i}",
            "schema_version": "1.0.0",
            "timestamp": (now + datetime.timedelta(seconds=i)).isoformat(),
            "app_id": "payments-api",
            "tenant_id": "tenant-alpha",
            "service_id": "api-service",
            "event_type": "auth.login_failed",
            "severity": "medium",
            "source_resource": "192.168.1.100",
            "target_resource": "/api/v1/login",
            "trace_id": "trc-bf-multiworker",
            "attributes": {"client_ip": "192.168.1.100"},
        }
        if i % 2 == 0:
            q1.put(ev)
        else:
            q2.put(ev)

    # 2. Sequence Test: 3 stages of an APT exfiltration attack.
    # Stage 1 -> Worker 1, Stage 2 -> Worker 2, Stage 3 -> Worker 1.
    trace = "trc-apt-multiworker"
    ev_s1 = {
        "event_id": "ev-s1",
        "schema_version": "1.0.0",
        "timestamp": now.isoformat(),
        "app_id": "payments-api",
        "tenant_id": "tenant-alpha",
        "service_id": "api-service",
        "event_type": "http.request",
        "severity": "info",
        "source_resource": "10.0.4.15",
        "target_resource": "/api/v1/internal/export",
        "trace_id": trace,
        "attributes": {"client_ip": "10.0.4.15"},
    }
    ev_s2 = {
        "event_id": "ev-s2",
        "schema_version": "1.0.0",
        "timestamp": (now + datetime.timedelta(seconds=2)).isoformat(),
        "app_id": "payments-api",
        "tenant_id": "tenant-alpha",
        "service_id": "worker-service",
        "event_type": "worker.job_anomalous",
        "severity": "medium",
        "trace_id": trace,
        "attributes": {"anomaly_flag": True},
    }
    ev_s3 = {
        "event_id": "ev-s3",
        "schema_version": "1.0.0",
        "timestamp": (now + datetime.timedelta(seconds=4)).isoformat(),
        "app_id": "payments-api",
        "tenant_id": "tenant-alpha",
        "service_id": "database-service",
        "event_type": "db.bulk_query",
        "severity": "high",
        "trace_id": trace,
        "attributes": {"table": "users", "rows_affected": 5000},
    }

    q1.put(ev_s1)
    q2.put(ev_s2)
    q1.put(ev_s3)

    q1.put(None)
    q2.put(None)

    w1_id, w1_findings = res_q.get(timeout=10)
    w2_id, w2_findings = res_q.get(timeout=10)
    p1.join()
    p2.join()

    total_findings = len(w1_findings) + len(w2_findings)
    print(f"REPRODUCTION RESULTS:")
    print(f"Worker 1 findings: {len(w1_findings)}")
    print(f"Worker 2 findings: {len(w2_findings)}")
    print(f"Total findings emitted across 2 workers: {total_findings} (EXPECTED in single-process: 2)")

    return total_findings


if __name__ == "__main__":
    multiprocessing.freeze_support()
    run_reproduction()


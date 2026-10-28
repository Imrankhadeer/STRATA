import uuid
from typing import Dict, Any, Optional
from cyber_engine import CyberEngine


class WorkerServiceSimulator:
    """
    Simulates asynchronous background jobs, task workers, and cross-service actions.
    """
    def __init__(self, client: CyberEngine):
        self.client = client
        self.service_name = "worker-service"

    def process_job(self, job_name: str, payload_size_kb: int, trace_id: str, is_suspicious: bool = False) -> None:
        severity = "medium" if is_suspicious else "info"
        event_type = "worker.job_anomalous" if is_suspicious else "worker.job_completed"

        self.client.emit(
            event_type=event_type,
            severity=severity,
            service=self.service_name,
            source_resource="queue:default_jobs",
            target_resource=f"job:{job_name}",
            trace_id=trace_id,
            attributes={
                "job_name": job_name,
                "payload_size_kb": payload_size_kb,
                "cpu_time_ms": 1420 if is_suspicious else 120,
                "anomaly_flag": is_suspicious
            }
        )

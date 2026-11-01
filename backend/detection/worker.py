"""
Asynchronous Telemetry Ingestion Worker for Decoupled Threat Detection.

Architecture:
- In high-throughput production clusters, HTTP ingestion (/v1/events) persists the event
  and enqueues it to Redis Streams / List for asynchronous evaluation.
- The TelemetryWorker continuously drains the queue, executing Fast Track declarative rules
  and native fallback detectors in worker threads without impacting client HTTP latency.
- Graceful shutdown: Flushes in-flight events before terminating.
"""

import json
import logging
import time
import threading
from typing import Optional, Any
from sqlalchemy.orm import Session

from backend.config import settings
from backend.db.session import engine
from backend.schemas.events import CanonicalEvent
from backend.detection.registry import runtime_rule_registry
from backend.api.ingest import evaluate_and_persist_findings
from backend.ops.metrics import metrics_registry

logger = logging.getLogger("cyber_engine.worker")


class TelemetryWorker:
    """
    Background worker that consumes queued telemetry events and executes
    Fast Track threat detection asynchronously.
    """

    def __init__(
        self,
        redis_client: Optional[Any] = None,
        queue_key: str = "cyber_engine:telemetry_queue",
    ):
        self.queue_key = queue_key
        self.client = redis_client
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def enqueue(self, event_dict: dict, tenant_id: str) -> bool:
        """Pushes an event payload to the queue for background processing."""
        if not self.client:
            return False
        try:
            payload = json.dumps({"event": event_dict, "tenant_id": tenant_id})
            self.client.rpush(self.queue_key, payload)
            return True
        except Exception as e:
            logger.error("Failed to enqueue event to %s: %s", self.queue_key, e)
            return False

    def process_one(self, db: Session, timeout: int = 1) -> bool:
        """Pops and evaluates a single event from the queue. Returns True if an event was processed."""
        if not self.client:
            return False
        try:
            item = self.client.lpop(self.queue_key)
            if not item:
                return False

            if isinstance(item, bytes):
                item = item.decode("utf-8")

            data = json.loads(item)
            raw_event = data["event"]
            tenant_id = data["tenant_id"]

            event = CanonicalEvent(**raw_event)
            t_start = time.time()
            corr_status, corr_reason = evaluate_and_persist_findings(event, tenant_id, db)
            elapsed = time.time() - t_start
            metrics_registry.record_latency(elapsed)
            return True
        except Exception as e:
            logger.error("Error processing async telemetry event: %s", e, exc_info=True)
            return False

    def run_worker_loop(self) -> None:
        """Blocking worker loop."""
        self._running = True
        logger.info("TelemetryWorker started on queue '%s'", self.queue_key)
        while self._running:
            with Session(engine) as db:
                processed = self.process_one(db)
                if not processed:
                    time.sleep(0.05)
        logger.info("TelemetryWorker stopped")

    def start(self) -> None:
        """Starts worker in background daemon thread."""
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self.run_worker_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Signals worker to stop."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None


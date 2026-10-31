import logging
import threading
import queue
import time
import random
from typing import Any, Dict, Optional, List
from dataclasses import dataclass
import httpx

from .events import Event
from .security import validate_endpoint_url

logger = logging.getLogger("cyber_engine.sdk")


class CyberEngineError(Exception):
    """Base exception for CYBER ENGINE SDK errors."""
    pass


class IngestError(CyberEngineError):
    """Raised when ingestion fails or returns an error response."""
    pass


class NetworkTimeoutError(CyberEngineError):
    """Raised on endpoint timeout."""
    pass


@dataclass
class IngestResult:
    accepted: int
    rejected: int
    duplicates: int
    event_ids: List[str]
    success: bool


class CyberEngine:
    """
    Developer-friendly Python client for CYBER ENGINE telemetry ingestion.
    Supports explicit synchronous emission and bounded buffered delivery with auto-redaction and HTTPS enforcement.
    """

    def __init__(
        self,
        api_key: str,
        app: str,
        service: Optional[str] = None,
        endpoint: str = "http://localhost:8000",
        timeout_seconds: float = 5.0,
        buffered: bool = False,
        buffer_size: int = 1000,
        flush_interval_seconds: float = 2.0,
        max_batch_size: int = 50,
        auto_sanitize: bool = True,
        allow_insecure_http: bool = False,
        max_retries: int = 3,
    ):
        if not api_key or not isinstance(api_key, str):
            raise ValueError("api_key must be a non-empty string")
        if not app or not isinstance(app, str):
            raise ValueError("app must be a non-empty string identifier")

        self.api_key = api_key.strip()
        self.app = app.strip()
        self.service = service.strip() if service else "default-service"
        self.endpoint = validate_endpoint_url(endpoint, allow_insecure_http=allow_insecure_http)
        self.timeout_seconds = timeout_seconds
        self.auto_sanitize = auto_sanitize
        self.max_retries = max_retries

        self._headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "cyber-engine-sdk-python/0.1.0",
        }

        self._client = httpx.Client(
            base_url=self.endpoint,
            headers=self._headers,
            timeout=self.timeout_seconds,
        )

        self.buffered = buffered
        self.buffer_size = buffer_size
        self.flush_interval_seconds = flush_interval_seconds
        self.max_batch_size = max_batch_size

        if self.buffered:
            self._queue: queue.Queue = queue.Queue(maxsize=self.buffer_size)
            self._stop_event = threading.Event()
            self._worker_thread = threading.Thread(
                target=self._flusher_loop,
                daemon=True,
                name="CyberEngineFlusher"
            )
            self._worker_thread.start()
        else:
            self._queue = None
            self._worker_thread = None

    def emit(
        self,
        event_type: str,
        attributes: Optional[Dict[str, Any]] = None,
        severity: str = "info",
        source_resource: Optional[str] = None,
        target_resource: Optional[str] = None,
        trace_id: Optional[str] = None,
        request_id: Optional[str] = None,
        service: Optional[str] = None,
        provenance: Optional[Dict[str, Any]] = None,
    ) -> IngestResult:
        """
        Emits a security event to CYBER ENGINE.
        In non-buffered mode, sends synchronously and returns IngestResult.
        In buffered mode, queues event into a bounded queue with automatic backpressure.
        """
        svc = service or self.service
        event = Event(
            event_type=event_type,
            app_id=self.app,
            service_id=svc,
            severity=severity,
            source_resource=source_resource,
            target_resource=target_resource,
            trace_id=trace_id,
            request_id=request_id,
            attributes=attributes or {},
            provenance=provenance or {},
        )

        if self.buffered and self._queue is not None:
            try:
                self._queue.put(event, timeout=1.0)
                return IngestResult(
                    accepted=1,
                    rejected=0,
                    duplicates=0,
                    event_ids=[event.event_id],
                    success=True
                )
            except queue.Full:
                raise IngestError("CyberEngine buffer is full; event could not be queued.")

        return self._send_single_event(event)

    def _send_single_event(self, event: Event) -> IngestResult:
        payload = event.to_dict(auto_sanitize=self.auto_sanitize)
        
        # Exponential backoff retry loop for transient network/server glitches
        last_error = None
        for attempt in range(self.max_retries):
            try:
                resp = self._client.post("/v1/events", json=payload, headers=self._headers)
                
                if resp.status_code == 401:
                    raise CyberEngineError("Authentication failed: invalid or expired API key")
                if resp.status_code == 403:
                    raise CyberEngineError(f"Access forbidden: {resp.text}")
                if 400 <= resp.status_code < 500:
                    raise IngestError(f"Ingestion rejected (HTTP {resp.status_code}): {resp.text}")
                if resp.status_code >= 500:
                    # Retry server errors
                    last_error = IngestError(f"Server error (HTTP {resp.status_code}): {resp.text}")
                    time.sleep(0.1 * (2 ** attempt) + random.uniform(0.01, 0.05))
                    continue

                data = resp.json()
                return IngestResult(
                    accepted=data.get("accepted", 0),
                    rejected=data.get("rejected", 0),
                    duplicates=data.get("duplicates", 0),
                    event_ids=data.get("event_ids", []),
                    success=True
                )
            except (httpx.TimeoutException, httpx.RequestError) as e:
                last_error = e
                time.sleep(0.1 * (2 ** attempt) + random.uniform(0.01, 0.05))

        if isinstance(last_error, httpx.TimeoutException):
            raise NetworkTimeoutError(f"Request to {self.endpoint} timed out after {self.timeout_seconds}s") from last_error
        raise CyberEngineError(f"Failed communicating with CYBER ENGINE after {self.max_retries} attempts: {last_error}")

    def flush(self) -> None:
        """Flushes buffered events synchronously."""
        if not self.buffered or not self._queue:
            return

        batch: List[Event] = []
        while not self._queue.empty() and len(batch) < self.max_batch_size:
            try:
                item = self._queue.get_nowait()
                batch.append(item)
            except queue.Empty:
                break

        if batch:
            self._send_batch(batch)
            for _ in batch:
                self._queue.task_done()

    def _send_batch(self, events: List[Event]) -> None:
        payload = {"events": [e.to_dict(auto_sanitize=self.auto_sanitize) for e in events]}
        for attempt in range(self.max_retries):
            try:
                resp = self._client.post("/v1/events/batch", json=payload, headers=self._headers)
                if resp.status_code < 400:
                    return
                if resp.status_code < 500:
                    logger.error("Failed to send buffered batch (client error %d): %s", resp.status_code, resp.text)
                    return
                # Server error: retry with backoff
                time.sleep(0.1 * (2 ** attempt) + random.uniform(0.01, 0.05))
            except Exception as e:
                time.sleep(0.1 * (2 ** attempt) + random.uniform(0.01, 0.05))
                if attempt == self.max_retries - 1:
                    logger.error("Error during background batch flush after %d attempts: %s", self.max_retries, str(e))

    def _flusher_loop(self) -> None:
        while not self._stop_event.is_set():
            time.sleep(self.flush_interval_seconds)
            try:
                self.flush()
            except Exception as e:
                logger.error("Error in buffer flush loop: %s", str(e))

    def close(self) -> None:
        """Flushes pending events and closes client connections."""
        if self.buffered:
            self._stop_event.set()
            try:
                while not self._queue.empty():
                    self.flush()
            except Exception as e:
                logger.warning("Error draining queue on close: %s", str(e))
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

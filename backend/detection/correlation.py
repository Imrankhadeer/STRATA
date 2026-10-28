"""
Cross-Service Correlation Detector for CYBER ENGINE.

Detects suspicious activity spanning multiple services within a shared trace,
using deterministic sequence matching and configurable time windows.

This is a baseline deterministic detector. It does NOT use AI or external model
calls. It matches a known suspicious pattern: an API request targeting an
internal endpoint, followed by an anomalous worker job, followed by bulk
database access on a sensitive table — all sharing the same trace ID within
a configurable time window.

A shared trace ID alone is never treated as proof of malicious behavior.
The full event sequence, service attribution, and relevant attributes
(endpoint path, anomaly flags, table sensitivity, row counts) are all
evaluated before producing a finding.
"""

import datetime
import logging
from typing import Dict, List, Optional, Set, Tuple, Any

from backend.detection.baseline import BaseDetector, Finding
from backend.schemas.events import CanonicalEvent

logger = logging.getLogger(__name__)

# Sensitive tables that escalate a bulk query into a potential exfiltration signal.
DEFAULT_SENSITIVE_TABLES = frozenset({"users", "credit_cards", "tokens", "credentials", "secrets"})

# Internal endpoint path prefixes whose access is considered an escalation signal.
DEFAULT_INTERNAL_PREFIXES = ("/api/v1/internal/", "/internal/", "/admin/export")

# Minimum row count on a bulk query to be considered an exfiltration signal.
DEFAULT_BULK_ROW_THRESHOLD = 1000


class _TraceWindow:
    """
    Accumulates events within a single (tenant_id, trace_id) correlation
    window. Immutable once a finding has been emitted from this window.
    """
    __slots__ = (
        "tenant_id", "trace_id", "first_seen", "last_seen",
        "api_events", "worker_events", "db_events",
        "all_event_ids", "finding_emitted",
    )

    def __init__(self, tenant_id: str, trace_id: str, timestamp: datetime.datetime):
        self.tenant_id: str = tenant_id
        self.trace_id: str = trace_id
        self.first_seen: datetime.datetime = timestamp
        self.last_seen: datetime.datetime = timestamp
        self.api_events: List[CanonicalEvent] = []
        self.worker_events: List[CanonicalEvent] = []
        self.db_events: List[CanonicalEvent] = []
        self.all_event_ids: List[str] = []
        self.finding_emitted: bool = False

    def add(self, event: CanonicalEvent) -> None:
        ts = event.timestamp
        if ts < self.first_seen:
            self.first_seen = ts
        if ts > self.last_seen:
            self.last_seen = ts

        self.all_event_ids.append(event.event_id)

        if event.service_id == "api-service":
            self.api_events.append(event)
        elif event.service_id == "worker-service":
            self.worker_events.append(event)
        elif event.service_id == "database-service":
            self.db_events.append(event)


class CrossServiceExfiltrationDetector(BaseDetector):
    """
    Deterministic cross-service correlation detector.

    Pattern detected (all within a single shared trace_id and time window):
      1. api-service emits an http.request targeting an internal/export endpoint.
      2. worker-service emits a worker.job_anomalous event.
      3. database-service emits a db.bulk_query against a sensitive table
         with rows_affected exceeding the bulk threshold.

    All three stages must be present and attributed to different services
    sharing the same tenant and trace. A shared trace ID alone is not
    sufficient evidence.

    Deduplication: only one finding is emitted per (tenant_id, trace_id).
    Subsequent events on the same trace update the window but do not produce
    duplicate findings.
    """

    detector_id = "detector.cross_service.exfiltration"
    detector_version = "1.0.0"
    description = (
        "Detects cross-service exfiltration sequences: internal API access → "
        "anomalous worker task → bulk sensitive data query, correlated by trace ID"
    )

    def __init__(
        self,
        time_window_seconds: float = 300.0,
        sensitive_tables: frozenset | None = None,
        internal_prefixes: tuple | None = None,
        bulk_row_threshold: int = DEFAULT_BULK_ROW_THRESHOLD,
        max_tracked_traces: int = 10_000,
    ):
        self.time_window = datetime.timedelta(seconds=time_window_seconds)
        self.sensitive_tables: frozenset = sensitive_tables or DEFAULT_SENSITIVE_TABLES
        self.internal_prefixes: tuple = internal_prefixes or DEFAULT_INTERNAL_PREFIXES
        self.bulk_row_threshold: int = bulk_row_threshold
        self.max_tracked_traces: int = max_tracked_traces

        # Keyed on (tenant_id, trace_id) → _TraceWindow
        self._windows: Dict[Tuple[str, str], _TraceWindow] = {}

        # Set of (tenant_id, trace_id) for which a finding has already been emitted,
        # persisted even after the window is evicted.
        self._emitted: Set[Tuple[str, str]] = set()

    def reset(self) -> None:
        """Reset all tracked windows and emitted traces."""
        self._windows.clear()
        self._emitted.clear()

    def evaluate(self, event: CanonicalEvent) -> Optional[Finding]:
        # Only process events that have a trace_id and tenant_id — correlation
        # is impossible without them.
        if not event.trace_id or not event.tenant_id:
            return None

        # Only process events from the three services we correlate.
        if event.service_id not in ("api-service", "worker-service", "database-service"):
            return None

        window_key = (event.tenant_id, event.trace_id)

        # If we already emitted a finding for this trace, absorb the event
        # but do not emit a duplicate.
        if window_key in self._emitted:
            return None

        # Evict stale windows before inserting.
        self._evict_stale(event.timestamp)

        # Create or extend the window.
        window = self._windows.get(window_key)
        if window is None:
            if len(self._windows) >= self.max_tracked_traces:
                # Hard cap on memory; evict oldest window.
                self._evict_oldest()
            window = _TraceWindow(event.tenant_id, event.trace_id, event.timestamp)
            self._windows[window_key] = window

        window.add(event)

        # Check time window validity.
        if (window.last_seen - window.first_seen) > self.time_window:
            return None

        # Evaluate the full pattern.
        return self._check_pattern(window)

    # ----- Pattern matching -----

    def _check_pattern(self, window: _TraceWindow) -> Optional[Finding]:
        """
        Checks whether the accumulated events in the window satisfy the
        three-stage exfiltration pattern. Returns a Finding only when all
        three stages are present with supporting attribute evidence.
        """
        # Stage 1: API request targeting an internal/export endpoint.
        api_match = self._find_api_trigger(window.api_events)
        if api_match is None:
            return None

        # Stage 2: Anomalous worker job.
        worker_match = self._find_worker_anomaly(window.worker_events)
        if worker_match is None:
            return None

        # Stage 3: Bulk database query on a sensitive table.
        db_match = self._find_bulk_sensitive_query(window.db_events)
        if db_match is None:
            return None

        # All three stages matched — produce finding.
        window.finding_emitted = True
        key = (window.tenant_id, window.trace_id)
        self._emitted.add(key)

        evidence = {
            "trace_id": window.trace_id,
            "correlation_reason": (
                "Three-stage cross-service sequence detected within time window: "
                "internal API endpoint access, anomalous worker job execution, "
                "and bulk query on sensitive data — all sharing the same trace ID."
            ),
            "stages": {
                "api_trigger": {
                    "event_id": api_match.event_id,
                    "timestamp": api_match.timestamp.isoformat(),
                    "endpoint": api_match.target_resource,
                    "method": api_match.attributes.get("method"),
                    "service_id": api_match.service_id,
                },
                "worker_anomaly": {
                    "event_id": worker_match.event_id,
                    "timestamp": worker_match.timestamp.isoformat(),
                    "job_name": worker_match.attributes.get("job_name"),
                    "payload_size_kb": worker_match.attributes.get("payload_size_kb"),
                    "service_id": worker_match.service_id,
                },
                "db_bulk_access": {
                    "event_id": db_match.event_id,
                    "timestamp": db_match.timestamp.isoformat(),
                    "table": db_match.attributes.get("table"),
                    "rows_affected": db_match.attributes.get("rows_affected"),
                    "service_id": db_match.service_id,
                },
            },
            "supporting_event_ids": window.all_event_ids[:],
            "time_span_seconds": (window.last_seen - window.first_seen).total_seconds(),
        }

        return Finding(
            tenant_id=window.tenant_id,
            detector_id=self.detector_id,
            detector_version=self.detector_version,
            title=(
                f"Cross-service data exfiltration pattern detected "
                f"(trace: {window.trace_id})"
            ),
            severity="high",
            confidence="high",
            description=(
                f"A coordinated cross-service sequence was detected on trace "
                f"'{window.trace_id}': an API request to internal endpoint "
                f"'{api_match.target_resource}', an anomalous worker job "
                f"'{worker_match.attributes.get('job_name', 'unknown')}', "
                f"and a bulk query retrieving "
                f"{db_match.attributes.get('rows_affected', '?')} rows from "
                f"sensitive table '{db_match.attributes.get('table', 'unknown')}'. "
                f"All events occurred within "
                f"{(window.last_seen - window.first_seen).total_seconds():.1f}s."
            ),
            event_id=db_match.event_id,  # anchored to the final stage
            evidence=evidence,
        )

    def _find_api_trigger(self, api_events: List[CanonicalEvent]) -> Optional[CanonicalEvent]:
        """Finds the first API event targeting an internal endpoint."""
        for ev in api_events:
            if ev.event_type != "http.request":
                continue
            target = ev.target_resource or ""
            endpoint = ev.attributes.get("endpoint", "")
            # Check either the target_resource or the attributes.endpoint.
            for prefix in self.internal_prefixes:
                if target.startswith(prefix) or endpoint.startswith(prefix):
                    return ev
        return None

    def _find_worker_anomaly(self, worker_events: List[CanonicalEvent]) -> Optional[CanonicalEvent]:
        """Finds a worker event flagged as anomalous."""
        for ev in worker_events:
            if ev.event_type == "worker.job_anomalous":
                return ev
            # Also accept if the anomaly_flag attribute is explicitly set.
            if ev.attributes.get("anomaly_flag") is True:
                return ev
        return None

    def _find_bulk_sensitive_query(self, db_events: List[CanonicalEvent]) -> Optional[CanonicalEvent]:
        """Finds a bulk database query against a sensitive table."""
        for ev in db_events:
            if ev.event_type != "db.bulk_query":
                continue
            table = ev.attributes.get("table", "")
            rows = ev.attributes.get("rows_affected", 0)
            is_sensitive = (
                ev.attributes.get("is_sensitive_table") is True
                or table in self.sensitive_tables
            )
            if is_sensitive and isinstance(rows, (int, float)) and rows >= self.bulk_row_threshold:
                return ev
        return None

    # ----- Window management -----

    def _evict_stale(self, now: datetime.datetime) -> None:
        """Removes windows whose last_seen is older than the time window."""
        stale_keys = [
            k for k, w in self._windows.items()
            if (now - w.last_seen) > self.time_window
        ]
        for k in stale_keys:
            del self._windows[k]

    def _evict_oldest(self) -> None:
        """Removes the oldest window to enforce the memory cap."""
        if not self._windows:
            return
        oldest_key = min(self._windows, key=lambda k: self._windows[k].first_seen)
        del self._windows[oldest_key]

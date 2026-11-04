"""
Prometheus Metrics Exporter for Ternline (CYBER ENGINE).

Provides standard Prometheus text exposition format (0.0.4) for:
- Telemetry ingestion throughput & error counts
- Fast Track detection latency & finding volumes
- Active declarative rule counts
- Database connection health & latency
- Live console SSE subscriber counts
"""

import threading
import time
from typing import Dict, Tuple, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func, text

from backend.models import SecurityFinding, DeclarativeRuleModel, EventModel
from backend.ops.bus import ops_bus


class MetricsRegistry:
    """Thread-safe in-memory metric accumulator for high-throughput counters and latencies."""

    def __init__(self):
        self._lock = threading.Lock()
        # (tenant_id, service_id, status) -> count
        self._event_counters: Dict[Tuple[str, str, str], int] = {}
        # (tenant_id, detector_id, severity) -> count
        self._finding_counters: Dict[Tuple[str, str, str], int] = {}
        # Latency tracking
        self._total_ingest_time: float = 0.0
        self._total_ingest_count: int = 0
        self._last_ingest_latency: float = 0.0

    def record_event(self, tenant_id: str, service_id: str, status: str = "accepted", count: int = 1) -> None:
        with self._lock:
            key = (tenant_id or "default", service_id or "unknown", status)
            self._event_counters[key] = self._event_counters.get(key, 0) + count

    def record_finding(self, tenant_id: str, detector_id: str, severity: str) -> None:
        with self._lock:
            key = (tenant_id or "default", detector_id or "generic", severity or "medium")
            self._finding_counters[key] = self._finding_counters.get(key, 0) + 1

    def record_latency(self, latency_seconds: float) -> None:
        with self._lock:
            self._total_ingest_time += latency_seconds
            self._total_ingest_count += 1
            self._last_ingest_latency = latency_seconds

    @staticmethod
    def _escape_label(value: str) -> str:
        return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')

    def export_prometheus(
        self,
        db: Optional[Session] = None,
        tenant_id: Optional[str] = None,
    ) -> str:
        """Renders standard Prometheus exposition text."""
        lines = []

        # 1. Events Ingested Total
        lines.append("# HELP cyber_engine_events_ingested_total Total telemetry events ingested by status")
        lines.append("# TYPE cyber_engine_events_ingested_total counter")
        with self._lock:
            for (t, s, st), count in self._event_counters.items():
                if tenant_id is not None and t != tenant_id:
                    continue
                labels = tuple(self._escape_label(v) for v in (t, s, st))
                lines.append(
                    f'cyber_engine_events_ingested_total{{tenant_id="{labels[0]}",service_id="{labels[1]}",status="{labels[2]}"}} {count}'
                )
            if not self._event_counters:
                if tenant_id is None:
                    lines.append('cyber_engine_events_ingested_total{tenant_id="default",service_id="system",status="accepted"} 0')

        # 2. Ingestion Latency
        lines.append("# HELP cyber_engine_ingest_latency_seconds Latency of last ingestion execution in seconds")
        lines.append("# TYPE cyber_engine_ingest_latency_seconds gauge")
        with self._lock:
            lines.append(f"cyber_engine_ingest_latency_seconds {self._last_ingest_latency:.6f}")

            avg_latency = (self._total_ingest_time / self._total_ingest_count) if self._total_ingest_count > 0 else 0.0
            lines.append("# HELP cyber_engine_ingest_latency_avg_seconds Average ingestion latency in seconds")
            lines.append("# TYPE cyber_engine_ingest_latency_avg_seconds gauge")
            lines.append(f"cyber_engine_ingest_latency_avg_seconds {avg_latency:.6f}")

        # 3. Security Findings
        lines.append("# HELP cyber_engine_findings_total Total detected security findings by detector and severity")
        lines.append("# TYPE cyber_engine_findings_total counter")
        with self._lock:
            for (t, det, sev), count in self._finding_counters.items():
                if tenant_id is not None and t != tenant_id:
                    continue
                labels = tuple(self._escape_label(v) for v in (t, det, sev))
                lines.append(
                    f'cyber_engine_findings_total{{tenant_id="{labels[0]}",detector_id="{labels[1]}",severity="{labels[2]}"}} {count}'
                )
            if not self._finding_counters:
                if tenant_id is None:
                    lines.append('cyber_engine_findings_total{tenant_id="default",detector_id="none",severity="none"} 0')

        # 4. Live Subscribers
        lines.append("# HELP cyber_engine_ops_subscribers_connected Live SSE console clients connected")
        lines.append("# TYPE cyber_engine_ops_subscribers_connected gauge")
        lines.append(f"cyber_engine_ops_subscribers_connected {ops_bus.subscriber_count()}")

        # 5. Database Health & Aggregates (if db provided)
        if db is not None:
            t_start = time.time()
            db_healthy = 1
            try:
                db.execute(text("SELECT 1")).scalar()
                db_latency = time.time() - t_start
            except Exception:
                db_healthy = 0
                db_latency = 0.0

            lines.append("# HELP cyber_engine_db_healthy Database connection status (1 = healthy, 0 = degraded)")
            lines.append("# TYPE cyber_engine_db_healthy gauge")
            lines.append(f"cyber_engine_db_healthy {db_healthy}")

            lines.append("# HELP cyber_engine_db_ping_seconds Database query ping latency in seconds")
            lines.append("# TYPE cyber_engine_db_ping_seconds gauge")
            lines.append(f"cyber_engine_db_ping_seconds {db_latency:.6f}")

            # Active declarative rules from DB
            try:
                rule_query = db.query(func.count(DeclarativeRuleModel.rule_id)).filter(
                    DeclarativeRuleModel.status == "active"
                )
                if tenant_id is not None:
                    rule_query = rule_query.filter(DeclarativeRuleModel.tenant_id == tenant_id)
                active_rules_count = rule_query.scalar() or 0
                lines.append("# HELP cyber_engine_active_rules_total Total currently active declarative rules in engine")
                lines.append("# TYPE cyber_engine_active_rules_total gauge")
                lines.append(f"cyber_engine_active_rules_total {active_rules_count}")
            except Exception:
                pass

        return "\n".join(lines) + "\n"


# Global metrics registry singleton
metrics_registry = MetricsRegistry()

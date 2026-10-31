"""
Process-Local Operational Event Bus for Ternline Live Console and SSE Streaming.

Architecture & Constraints:
- Process-local: Events are published in memory and streamed via SSE to connected clients.
- Single-worker per instance constraint: Matches the in-memory Fast Track correlation design.
- Bounded buffering: Retains the last 500 events in memory (collections.deque) for replay on connect.
- Zero PostgreSQL logging: Routine debug/ops events are NOT persisted to the database.
- Tenant isolation: Clients only receive events matching their tenant_id (or system-wide events if tenant is None).
- Secret redaction: Strips tokens, passwords, API keys, and connection strings before emission.
- Short-lived Stream Tickets: Implements a 60-second single-use ticket mechanism for browser EventSource
  connections to prevent exposing long-lived API keys in query parameters or URL logs.
"""

import asyncio
import collections
import datetime
import logging
import re
import secrets
import time
import uuid
from typing import Any, AsyncGenerator, Dict, List, Literal, Optional, Set
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Patterns for sensitive keys to redact from event metadata
SENSITIVE_KEY_PATTERNS = re.compile(
    r"(key|token|secret|password|auth|authorization|cred|cookie|bearer|database_url)",
    re.IGNORECASE
)


def sanitize_ops_metadata(meta: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Recursively redacts sensitive values such as tokens, API keys, passwords,
    and connection strings from operational event metadata.
    """
    if not meta or not isinstance(meta, dict):
        return {}

    sanitized: Dict[str, Any] = {}
    for k, v in meta.items():
        if SENSITIVE_KEY_PATTERNS.search(str(k)):
            sanitized[k] = "[REDACTED]"
        elif isinstance(v, dict):
            sanitized[k] = sanitize_ops_metadata(v)
        elif isinstance(v, list):
            sanitized[k] = [
                sanitize_ops_metadata(item) if isinstance(item, dict) else str(item)[:128]
                for item in v[:20]
            ]
        elif isinstance(v, str):
            # Redact raw Bearer tokens or high-entropy credentials if present in strings
            if "Bearer " in v or "ce_live_" in v or "postgres:" in v or "postgresql://" in v:
                sanitized[k] = "[REDACTED_SECRET]"
            else:
                sanitized[k] = v[:256]
        else:
            sanitized[k] = v
    return sanitized


class OpsEvent(BaseModel):
    """Structured operational event for real-time operations console."""
    event_id: str = Field(default_factory=lambda: f"ops-{uuid.uuid4().hex[:12]}")
    timestamp: str = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    level: Literal["info", "warn", "error", "success"] = "info"
    component: Literal[
        "ingest",
        "fast-track",
        "deep-track",
        "rules",
        "auth",
        "system",
        "simulation",
        "correlation"
    ]
    event_type: str
    message: str
    tenant_id: Optional[str] = None
    service_id: Optional[str] = None
    trace_id: Optional[str] = None
    finding_id: Optional[str] = None
    investigation_id: Optional[str] = None
    rule_id: Optional[str] = None
    rule_version: Optional[int] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class _StreamTicket(BaseModel):
    ticket_id: str
    tenant_id: str
    app_id: str
    expires_at: float


class OpsEventBus:
    """
    In-memory bounded operational event bus supporting tenant-isolated SSE subscriptions.
    """
    def __init__(self, max_buffer_size: int = 500, ticket_ttl_seconds: float = 60.0):
        self.max_buffer_size = max_buffer_size
        self.ticket_ttl = ticket_ttl_seconds
        self._buffer: collections.deque[OpsEvent] = collections.deque(maxlen=max_buffer_size)
        self._subscribers: Set[tuple[asyncio.Queue, str]] = set()
        self._tickets: Dict[str, _StreamTicket] = {}
        self._lock = asyncio.Lock()

    def create_stream_ticket(self, tenant_id: str, app_id: str) -> str:
        """
        Creates a short-lived (60s), single-use stream ticket for SSE connections.
        Prevents long-lived API keys from appearing in browser URL query strings.
        """
        self._purge_expired_tickets()
        ticket_id = f"stk_{secrets.token_urlsafe(24)}"
        self._tickets[ticket_id] = _StreamTicket(
            ticket_id=ticket_id,
            tenant_id=tenant_id,
            app_id=app_id,
            expires_at=time.time() + self.ticket_ttl,
        )
        return ticket_id

    def validate_and_consume_ticket(self, ticket_id: str) -> Optional[tuple[str, str]]:
        """
        Validates and single-use consumes a stream ticket.
        Returns (tenant_id, app_id) if valid, None otherwise.
        """
        self._purge_expired_tickets()
        ticket = self._tickets.pop(ticket_id, None)
        if not ticket:
            return None
        if time.time() > ticket.expires_at:
            return None
        return ticket.tenant_id, ticket.app_id

    def _purge_expired_tickets(self) -> None:
        now = time.time()
        expired = [tid for tid, t in self._tickets.items() if t.expires_at < now]
        for tid in expired:
            self._tickets.pop(tid, None)

    def publish(
        self,
        component: Literal["ingest", "fast-track", "deep-track", "rules", "auth", "system", "simulation", "correlation"],
        event_type: str,
        message: str,
        level: Literal["info", "warn", "error", "success"] = "info",
        tenant_id: Optional[str] = None,
        service_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        finding_id: Optional[str] = None,
        investigation_id: Optional[str] = None,
        rule_id: Optional[str] = None,
        rule_version: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> OpsEvent:
        """
        Publishes an operational event to the buffer and active subscriber queues.
        Guaranteed non-blocking: drops queue put if a subscriber queue is full.
        Safe against unhandled exceptions breaking the caller.
        """
        try:
            event = OpsEvent(
                level=level,
                component=component,
                event_type=event_type,
                message=message,
                tenant_id=tenant_id,
                service_id=service_id,
                trace_id=trace_id,
                finding_id=finding_id,
                investigation_id=investigation_id,
                rule_id=rule_id,
                rule_version=rule_version,
                metadata=sanitize_ops_metadata(metadata),
            )

            # Store in bounded circular buffer
            self._buffer.append(event)

            # Dispatch to active subscribers matching tenant
            dead_queues = []
            for queue, sub_tenant in list(self._subscribers):
                if sub_tenant == tenant_id or tenant_id is None:
                    try:
                        queue.put_nowait(event)
                    except asyncio.QueueFull:
                        pass
                    except Exception:
                        dead_queues.append((queue, sub_tenant))

            for dead in dead_queues:
                self._subscribers.discard(dead)

            return event
        except Exception as e:
            logger.debug("Failed publishing ops event (non-fatal): %s", e)
            return None

    def get_buffered_events(self, tenant_id: str, limit: int = 50) -> List[OpsEvent]:
        """Returns recent buffered events for a tenant, up to limit."""
        matching = [
            e for e in self._buffer
            if e.tenant_id == tenant_id or e.tenant_id is None
        ]
        return matching[-limit:]

    async def subscribe(
        self, tenant_id: str, replay_limit: int = 50
    ) -> AsyncGenerator[OpsEvent, None]:
        """
        Async generator for SSE streaming.
        Replays up to replay_limit recent buffered events, then yields real-time events.
        """
        queue: asyncio.Queue[OpsEvent] = asyncio.Queue(maxsize=100)
        sub_pair = (queue, tenant_id)
        self._subscribers.add(sub_pair)

        try:
            # 1. Replay recent events from the in-memory buffer
            for event in self.get_buffered_events(tenant_id, limit=replay_limit):
                yield event

            # 2. Stream real-time events from queue
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield event
                except asyncio.TimeoutError:
                    # Timeout produces heartbeat ping via caller or SSE comment
                    yield None
        finally:
            self._subscribers.discard(sub_pair)

    def subscriber_count(self, tenant_id: Optional[str] = None) -> int:
        """Returns number of active subscriber connections."""
        if tenant_id is None:
            return len(self._subscribers)
        return sum(1 for _, t in self._subscribers if t == tenant_id)

    def clear_buffer(self) -> None:
        """Clears the in-memory buffer (used in tests)."""
        self._buffer.clear()
        self._tickets.clear()


# Global singleton instance
ops_bus = OpsEventBus()


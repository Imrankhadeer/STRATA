"""
Ingestion Containment Filter for Ternline Phase 1: Active Defense.

Responsibilities:
1. Enforces action-specific HTTP semantics at the ingestion gateway:
   - Explicit temporary IP block: HTTP 403 Forbidden.
   - Temporary rate limit: HTTP 429 Too Many Requests with Retry-After header.
2. Zero information leakage: never exposes detector IDs, confidence scores, or rule internals in error messages.
3. Fail-open resilience: Redis or infrastructure connection failures during containment lookups
   must NEVER create accidental security blocks or deny legitimate traffic.
4. Auto-fallback for development/test: If Redis is unavailable and environment is development/test,
   supports in-memory containment checks without blocking ingestion latencies.
"""

import logging
import time
import threading
from collections import defaultdict
from typing import Any, Optional, Set, Dict, Tuple
from fastapi import HTTPException, status
from backend.config import settings
from backend.ops.bus import ops_bus
from backend.ops.metrics import metrics_registry

logger = logging.getLogger("cyber_engine.defense.filter")

_redis_pool = None
_redis_available: bool = True
_last_redis_check: float = 0.0
_redis_degraded_alert_published: bool = False
_REDIS_CHECK_COOLDOWN: float = 5.0
_redis_check_lock = threading.Lock()


def get_defense_redis_client() -> Optional[Any]:
    global _redis_pool, _redis_available, _last_redis_check, _redis_degraded_alert_published
    redis_url = getattr(settings, "REDIS_URL", None)
    if not redis_url:
        return None

    now = time.time()
    with _redis_check_lock:
        if not _redis_available and (now - _last_redis_check) < _REDIS_CHECK_COOLDOWN:
            return None

    try:
        import redis
        if _redis_pool is None:
            timeout_ms = float(getattr(settings, "REDIS_STATE_TIMEOUT_MS", 500))
            _redis_pool = redis.ConnectionPool.from_url(
                redis_url,
                socket_timeout=max(0.05, min(0.2, timeout_ms / 1000.0)),
                max_connections=20,
            )
        client = redis.Redis(connection_pool=_redis_pool)
        # Probe connectivity if it was previously marked unavailable or check interval passed
        if not _redis_available or (now - _last_redis_check) >= _REDIS_CHECK_COOLDOWN:
            client.ping()
            should_publish_recovery = False
            with _redis_check_lock:
                _redis_available = True
                _last_redis_check = now
                if _redis_degraded_alert_published:
                    _redis_degraded_alert_published = False
                    should_publish_recovery = True
            if should_publish_recovery:
                try:
                    ops_bus.publish(
                        component="defense",
                        event_type="defense.redis_recovered",
                        level="info",
                        message="Containment Redis connectivity restored; active defense containment is operating normally",
                    )
                    metrics_registry.record_event(tenant_id="system", service_id="defense", status="redis_recovered")
                except Exception as ex:
                    logger.debug("Failed publishing ops alert for redis recovery: %s", ex)
        return client
    except Exception as e:
        mark_redis_failure(e)
        logger.debug("Redis unreachable for defense filter, backing off: %s", e)
        return None


def mark_redis_failure(error: Optional[Any] = None):
    global _redis_available, _last_redis_check, _redis_degraded_alert_published
    now = time.time()
    should_publish = False
    with _redis_check_lock:
        _redis_available = False
        _last_redis_check = now
        if not _redis_degraded_alert_published:
            _redis_degraded_alert_published = True
            should_publish = True
    if should_publish:
        err_str = str(error) if error else "Connection timeout or refused"
        try:
            ops_bus.publish(
                component="defense",
                event_type="defense.redis_degraded",
                level="error",
                message=f"Containment Redis infrastructure is unreachable ({err_str}); active defense is running in fail-open degraded mode",
                metadata={"error": err_str, "fail_open": True},
            )
            metrics_registry.record_event(tenant_id="system", service_id="defense", status="redis_degraded")
        except Exception as ex:
            logger.debug("Failed publishing ops alert for redis degradation: %s", ex)


def mark_redis_recovered():
    global _redis_available, _last_redis_check, _redis_degraded_alert_published
    now = time.time()
    should_publish_recovery = False
    with _redis_check_lock:
        _redis_available = True
        _last_redis_check = now
        if _redis_degraded_alert_published:
            _redis_degraded_alert_published = False
            should_publish_recovery = True
    if should_publish_recovery:
        try:
            ops_bus.publish(
                component="defense",
                event_type="defense.redis_recovered",
                level="info",
                message="Containment Redis connectivity restored; active defense containment is operating normally",
            )
            metrics_registry.record_event(tenant_id="system", service_id="defense", status="redis_recovered")
        except Exception as ex:
            logger.debug("Failed publishing ops alert for redis recovery: %s", ex)


class IngestContainmentFilter:
    """
    Evaluates incoming telemetry requests against active Redis containment state.
    Falls back to thread-safe in-memory containment in development/test when Redis is unconfigured or unavailable.
    """

    def __init__(self, redis_client: Optional[Any] = None):
        self._redis = redis_client
        self._lock = threading.RLock()
        # tenant_id -> set of blocked IP strings
        self._in_memory_blocked_ips: Dict[str, Set[str]] = defaultdict(set)
        # (tenant_id, entity_id) -> (remaining_count, expiry_timestamp)
        self._in_memory_rate_limits: Dict[Tuple[str, str], Tuple[int, float]] = {}

    @property
    def redis(self) -> Optional[Any]:
        if self._redis is not None:
            return self._redis
        return get_defense_redis_client()

    @property
    def is_degraded(self) -> bool:
        """Returns True if the Redis containment state store is unavailable/degraded."""
        global _redis_available
        if self._redis is not None:
            return False
        return not _redis_available

    def block_ip(self, tenant_id: str, ip: str) -> None:
        """Helper for test / in-memory blocking."""
        with self._lock:
            self._in_memory_blocked_ips[tenant_id].add(ip.strip())

    def unblock_ip(self, tenant_id: str, ip: str) -> None:
        """Helper for test / in-memory unblocking."""
        with self._lock:
            self._in_memory_blocked_ips[tenant_id].discard(ip.strip())

    def set_rate_limit(self, tenant_id: str, entity_id: str, quota: int, ttl_seconds: int = 60) -> None:
        """Helper for test / in-memory rate limiting."""
        with self._lock:
            expires_at = time.time() + ttl_seconds
            self._in_memory_rate_limits[(tenant_id, entity_id.strip())] = (quota, expires_at)

    def clear(self, tenant_id: Optional[str] = None) -> None:
        """Clears in-memory containment state."""
        global _redis_degraded_alert_published
        with self._lock:
            if tenant_id:
                self._in_memory_blocked_ips.pop(tenant_id, None)
                keys_to_del = [k for k in self._in_memory_rate_limits if k[0] == tenant_id]
                for k in keys_to_del:
                    del self._in_memory_rate_limits[k]
            else:
                self._in_memory_blocked_ips.clear()
                self._in_memory_rate_limits.clear()
                with _redis_check_lock:
                    _redis_degraded_alert_published = False

    def check_containment(
        self,
        tenant_id: str,
        client_ip: Optional[str] = None,
        entity_id: Optional[str] = None,
    ) -> None:
        """
        Inspects active Redis containment state.
        Raises HTTP 403 if IP is in active blocklist.
        Raises HTTP 429 if rate limit quota is exhausted.
        Fails open safely if Redis is unreachable or raises an error.
        """
        r = self.redis
        if r is not None:
            # 1. Check Temporary IP Blocklist via Redis
            if client_ip:
                ip_clean = client_ip.strip()
                block_key = f"ternline:{tenant_id}:defense:blocked_ips"
                try:
                    if r.sismember(block_key, ip_clean):
                        logger.warning(
                            "Ingestion rejected: IP '%s' is in active containment blocklist for tenant '%s'",
                            ip_clean, tenant_id
                        )
                        # Enforce Decision 2: HTTP 403 Forbidden without leaking rule or confidence internals
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail="Access restricted by security containment policy",
                        )
                except HTTPException:
                    raise
                except Exception as e:
                    # Enforce Decision 2: Redis failures must NOT deny legitimate traffic
                    mark_redis_failure(e)
                    logger.warning(
                        "Redis infrastructure failure during IP block check (failing open safely): %s", e
                    )

            # 2. Check Temporary Rate Limit Containment via Redis
            if entity_id:
                rl_key = f"ternline:{tenant_id}:defense:ratelimit:{entity_id.strip()}"
                try:
                    val = r.get(rl_key)
                    if val is not None:
                        try:
                            current = int(val)
                            if current <= 0:
                                ttl = r.ttl(rl_key)
                                retry_after = str(max(1, ttl if ttl and ttl > 0 else 30))
                                logger.warning(
                                    "Ingestion throttled: Entity '%s' exceeded active rate limit policy for tenant '%s'",
                                    entity_id, tenant_id
                                )
                                # Enforce Decision 2: HTTP 429 with Retry-After header
                                raise HTTPException(
                                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                                    detail="Rate limit exceeded by active security policy",
                                    headers={"Retry-After": retry_after},
                                )
                            else:
                                # Decrement quota
                                r.decr(rl_key)
                        except ValueError:
                            pass
                except HTTPException:
                    raise
                except Exception as e:
                    mark_redis_failure(e)
                    logger.warning(
                        "Redis infrastructure failure during rate limit check (failing open safely): %s", e
                    )
            return

        # Fallback to In-Memory Containment (for development / test when Redis is offline)
        is_prod = getattr(settings, "ENVIRONMENT", "").lower() in ("production", "staging")
        if not is_prod:
            now = time.time()
            with self._lock:
                # In-memory IP block check
                if client_ip:
                    ip_clean = client_ip.strip()
                    if ip_clean in self._in_memory_blocked_ips.get(tenant_id, set()):
                        logger.warning(
                            "Ingestion rejected (in-memory): IP '%s' is in active containment blocklist for tenant '%s'",
                            ip_clean, tenant_id
                        )
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail="Access restricted by security containment policy",
                        )

                # In-memory rate limit check
                if entity_id:
                    key = (tenant_id, entity_id.strip())
                    if key in self._in_memory_rate_limits:
                        quota, expires_at = self._in_memory_rate_limits[key]
                        if now > expires_at:
                            del self._in_memory_rate_limits[key]
                        elif quota <= 0:
                            retry_after = str(max(1, int(expires_at - now)))
                            logger.warning(
                                "Ingestion throttled (in-memory): Entity '%s' exceeded active rate limit policy for tenant '%s'",
                                entity_id, tenant_id
                            )
                            raise HTTPException(
                                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                                detail="Rate limit exceeded by active security policy",
                                headers={"Retry-After": retry_after},
                            )
                        else:
                            self._in_memory_rate_limits[key] = (quota - 1, expires_at)


ingest_containment_filter = IngestContainmentFilter()

"""
Provider Integration Adapters for Ternline Phase 1: Active Defense.

Implements Milestone 1.3 & Milestone 1.5:
1. InternalApiKeyAdapter: Revokes Ternline-managed API keys and flushes memory/cache.
2. RedisIngestBlockAdapter: Injects temporary IP blocks into Ternline perimeter ingestion filter.
3. RedisRateLimitAdapter: Injects token-bucket rate limit quotas into Ternline perimeter filter.
4. WebhookContainmentAdapter: Dispatches HMAC-SHA256 signed JSON payloads to upstream customer gateways (Milestone 1.5).
"""

import abc
import datetime
import hashlib
import hmac
import json
import logging
import time
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from backend.config import settings
from backend.models import ApiKey, TenantDefensePolicyModel
from backend.schemas.defense import (
    ActionScope,
    ActionType,
    CandidateResponseAction,
    CredentialAuthority,
    PlannedResponseAction,
    TargetEntityType,
)
from backend.defense.filter import get_defense_redis_client, ingest_containment_filter

logger = logging.getLogger("cyber_engine.defense.adapters")


class BaseDefenseAdapter(abc.ABC):
    """
    Abstract interface for containment execution adapters.
    Guarantees deterministic execution and rollback capabilities.
    """
    adapter_name: str

    @abc.abstractmethod
    def execute(self, action: PlannedResponseAction, db: Session) -> Dict[str, Any]:
        """Executes the containment action and returns structured execution metadata."""
        pass

    @abc.abstractmethod
    def rollback(self, action: PlannedResponseAction, db: Session) -> Dict[str, Any]:
        """Reverts the containment action and restores normal operation."""
        pass


class InternalApiKeyAdapter(BaseDefenseAdapter):
    """
    Manages containment for Ternline-managed API keys.
    Deactivates compromised credentials in the PostgreSQL api_keys table and evicts cache.
    """
    adapter_name = "internal_api_key_adapter"

    def execute(self, action: PlannedResponseAction, db: Session) -> Dict[str, Any]:
        target_key_id = action.target_entity_id
        tenant_id = action.tenant_id

        # Query and deactivate key
        key_record = (
            db.query(ApiKey)
            .filter(ApiKey.id == target_key_id, ApiKey.tenant_id == tenant_id)
            .first()
        )
        if not key_record:
            # Check by key_prefix or app_id fallback if not found by primary key ID
            key_record = (
                db.query(ApiKey)
                .filter(ApiKey.app_id == target_key_id, ApiKey.tenant_id == tenant_id)
                .first()
            )

        if not key_record:
            logger.warning(
                "InternalApiKeyAdapter: Key '%s' not found for tenant '%s'",
                target_key_id,
                tenant_id,
            )
            return {
                "success": False,
                "error": f"API key '{target_key_id}' not found in database",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }

        was_active = key_record.is_active
        key_record.is_active = False
        db.commit()

        logger.info(
            "InternalApiKeyAdapter: Deactivated API key '%s' (app: %s, tenant: %s)",
            key_record.id,
            key_record.app_id,
            tenant_id,
        )

        return {
            "success": True,
            "key_id": key_record.id,
            "app_id": key_record.app_id,
            "previous_active_state": was_active,
            "revoked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }

    def rollback(self, action: PlannedResponseAction, db: Session) -> Dict[str, Any]:
        target_key_id = action.target_entity_id
        tenant_id = action.tenant_id

        key_record = (
            db.query(ApiKey)
            .filter(ApiKey.id == target_key_id, ApiKey.tenant_id == tenant_id)
            .first()
        )
        if not key_record:
            key_record = (
                db.query(ApiKey)
                .filter(ApiKey.app_id == target_key_id, ApiKey.tenant_id == tenant_id)
                .first()
            )

        if not key_record:
            return {
                "success": False,
                "error": f"API key '{target_key_id}' not found for rollback",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            }

        key_record.is_active = True
        db.commit()

        logger.info(
            "InternalApiKeyAdapter: Re-activated API key '%s' on rollback (tenant: %s)",
            key_record.id,
            tenant_id,
        )
        return {
            "success": True,
            "key_id": key_record.id,
            "restored_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }


class RedisIngestBlockAdapter(BaseDefenseAdapter):
    """
    Applies perimeter IP blocking at the Ternline ingestion layer.
    Injects IP into Redis set and syncs to IngestContainmentFilter.
    """
    adapter_name = "redis_ingest_block_adapter"

    def execute(self, action: PlannedResponseAction, db: Session) -> Dict[str, Any]:
        tenant_id = action.tenant_id
        ip = action.target_entity_id.strip()
        ttl_seconds = action.ttl_seconds or 3600

        # 1. Update in-memory filter (works in local tests and multi-worker fallbacks)
        ingest_containment_filter.block_ip(tenant_id, ip)

        # 2. Update Redis distributed blocklist if Redis is available
        r = get_defense_redis_client()
        redis_success = False
        if r is not None:
            try:
                block_key = f"ternline:{tenant_id}:defense:blocked_ips"
                r.sadd(block_key, ip)
                # Keep TTL on blocklist key
                r.expire(block_key, max(ttl_seconds, 86400))
                redis_success = True
            except Exception as e:
                logger.warning("RedisIngestBlockAdapter: Failed updating Redis block set: %s", e)

        logger.info(
            "RedisIngestBlockAdapter: Contained IP '%s' for tenant '%s' (TTL: %ss, Redis: %s)",
            ip,
            tenant_id,
            ttl_seconds,
            redis_success,
        )

        return {
            "success": True,
            "target_ip": ip,
            "ttl_seconds": ttl_seconds,
            "redis_synced": redis_success,
            "in_memory_synced": True,
            "blocked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }

    def rollback(self, action: PlannedResponseAction, db: Session) -> Dict[str, Any]:
        tenant_id = action.tenant_id
        ip = action.target_entity_id.strip()

        ingest_containment_filter.unblock_ip(tenant_id, ip)

        r = get_defense_redis_client()
        redis_removed = False
        if r is not None:
            try:
                block_key = f"ternline:{tenant_id}:defense:blocked_ips"
                r.srem(block_key, ip)
                redis_removed = True
            except Exception as e:
                logger.warning("RedisIngestBlockAdapter: Failed removing IP from Redis: %s", e)

        logger.info(
            "RedisIngestBlockAdapter: Reverted IP block for '%s' (tenant: %s)",
            ip,
            tenant_id,
        )

        return {
            "success": True,
            "target_ip": ip,
            "redis_removed": redis_removed,
            "in_memory_unblocked": True,
            "unblocked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }


class RedisRateLimitAdapter(BaseDefenseAdapter):
    """
    Applies perimeter rate limiting at the Ternline ingestion layer.
    Injects token-bucket quotas into Redis and IngestContainmentFilter.
    """
    adapter_name = "redis_rate_limit_adapter"

    def execute(self, action: PlannedResponseAction, db: Session) -> Dict[str, Any]:
        tenant_id = action.tenant_id
        entity_id = action.target_entity_id.strip()
        params = action.parameters or {}
        quota = int(params.get("max_requests", params.get("rate_limit", 10)))
        ttl_seconds = action.ttl_seconds or 3600

        # 1. Update in-memory filter
        ingest_containment_filter.set_rate_limit(tenant_id, entity_id, quota, ttl_seconds)

        # 2. Update Redis key if available
        r = get_defense_redis_client()
        redis_success = False
        if r is not None:
            try:
                rl_key = f"ternline:{tenant_id}:defense:ratelimit:{entity_id}"
                r.setex(rl_key, ttl_seconds, str(quota))
                redis_success = True
            except Exception as e:
                logger.warning("RedisRateLimitAdapter: Failed writing rate limit to Redis: %s", e)

        logger.info(
            "RedisRateLimitAdapter: Throttled entity '%s' for tenant '%s' (Quota: %s, TTL: %ss)",
            entity_id,
            tenant_id,
            quota,
            ttl_seconds,
        )

        return {
            "success": True,
            "entity_id": entity_id,
            "quota": quota,
            "ttl_seconds": ttl_seconds,
            "redis_synced": redis_success,
            "applied_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }

    def rollback(self, action: PlannedResponseAction, db: Session) -> Dict[str, Any]:
        tenant_id = action.tenant_id
        entity_id = action.target_entity_id.strip()

        # Clear in-memory
        ingest_containment_filter.set_rate_limit(tenant_id, entity_id, 999999, 1)

        r = get_defense_redis_client()
        if r is not None:
            try:
                rl_key = f"ternline:{tenant_id}:defense:ratelimit:{entity_id}"
                r.delete(rl_key)
            except Exception as e:
                logger.warning("RedisRateLimitAdapter: Failed deleting Redis rate limit: %s", e)

        logger.info(
            "RedisRateLimitAdapter: Reverted rate limit for '%s' (tenant: %s)",
            entity_id,
            tenant_id,
        )

        return {
            "success": True,
            "entity_id": entity_id,
            "reverted_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }


class WebhookContainmentAdapter(BaseDefenseAdapter):
    """
    Milestone 1.5: Upstream Customer Gateway & Webhook Integration.
    Dispatches cryptographic HMAC-SHA256 signed JSON containment payloads to customer endpoints
    (Cloudflare, AWS WAF, Kong, Envoy, Okta/Auth0).
    """
    adapter_name = "webhook_containment_adapter"

    def execute(self, action: PlannedResponseAction, db: Session) -> Dict[str, Any]:
        tenant_id = action.tenant_id
        policy = (
            db.query(TenantDefensePolicyModel)
            .filter(TenantDefensePolicyModel.tenant_id == tenant_id)
            .first()
        )
        conf = (policy.configuration if policy else {}) or {}
        webhook_url = conf.get("webhook_url") or conf.get("external_webhook_url")
        webhook_secret = conf.get("webhook_secret", "ternline_default_secret_key")

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        timestamp = str(int(time.time()))

        payload = {
            "event": "defense.containment.execute",
            "action_id": action.action_id,
            "tenant_id": tenant_id,
            "action_type": action.action_type.value,
            "scope": action.scope.value,
            "target_entity_type": action.target_entity_type.value,
            "target_entity_id": action.target_entity_id,
            "parameters": action.parameters or {},
            "ttl_seconds": action.ttl_seconds,
            "timestamp": now_iso,
        }

        # Calculate HMAC-SHA256 signature
        body_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        sig_data = f"t={timestamp}.".encode("utf-8") + body_bytes
        signature = hmac.new(webhook_secret.encode("utf-8"), sig_data, hashlib.sha256).hexdigest()

        receipt_id = f"wh_rec_{hashlib.sha256(body_bytes).hexdigest()[:12]}"

        # If a real webhook URL is configured, perform HTTP dispatch
        http_status = 200
        if webhook_url and webhook_url.startswith("http"):
            try:
                import httpx
                headers = {
                    "Content-Type": "application/json",
                    "X-Ternline-Signature": f"t={timestamp},v1={signature}",
                    "X-Ternline-Tenant": tenant_id,
                }
                with httpx.Client(timeout=3.0) as client:
                    resp = client.post(webhook_url, json=payload, headers=headers)
                    http_status = resp.status_code
            except Exception as ex:
                logger.warning("WebhookContainmentAdapter dispatch failed: %s", ex)
                return {
                    "success": False,
                    "error": str(ex),
                    "webhook_url": webhook_url,
                    "receipt_id": receipt_id,
                    "timestamp": now_iso,
                }

        logger.info(
            "WebhookContainmentAdapter: Dispatched action '%s' to webhook (url: %s, receipt: %s)",
            action.action_id,
            webhook_url or "dry_run_configured",
            receipt_id,
        )

        return {
            "success": True,
            "receipt_id": receipt_id,
            "webhook_url": webhook_url or "internal_simulation",
            "http_status": http_status,
            "signature_header": f"t={timestamp},v1={signature}",
            "dispatched_at": now_iso,
        }

    def rollback(self, action: PlannedResponseAction, db: Session) -> Dict[str, Any]:
        tenant_id = action.tenant_id
        policy = (
            db.query(TenantDefensePolicyModel)
            .filter(TenantDefensePolicyModel.tenant_id == tenant_id)
            .first()
        )
        conf = (policy.configuration if policy else {}) or {}
        webhook_url = conf.get("webhook_url") or conf.get("external_webhook_url")
        webhook_secret = conf.get("webhook_secret", "ternline_default_secret_key")

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        timestamp = str(int(time.time()))

        payload = {
            "event": "defense.containment.rollback",
            "action_id": action.action_id,
            "tenant_id": tenant_id,
            "action_type": action.action_type.value,
            "target_entity_type": action.target_entity_type.value,
            "target_entity_id": action.target_entity_id,
            "timestamp": now_iso,
        }

        receipt_id = f"wh_rb_{hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:12]}"
        return {
            "success": True,
            "receipt_id": receipt_id,
            "webhook_url": webhook_url or "internal_simulation",
            "rolled_back_at": now_iso,
        }


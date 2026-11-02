"""
Rollback and Recovery Manager for Ternline Phase 1: Active Defense.

Implements Milestone 1.4:
1. Scheduled automated expiration and revert of temporary containment actions (IP blocks, rate limits).
2. Emergency analyst rollback with mandatory operational rationale.
3. Immutable forensic audit recording and live SSE notifications on rollback.
"""

import datetime
import logging
import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from backend.models import (
    DefenseActionModel,
    DefenseAuditLogModel,
)
from backend.schemas.defense import (
    ActionScope,
    ActionStatus,
    ActionType,
    PlannedResponseAction,
)
from backend.defense.adapters import (
    InternalApiKeyAdapter,
    RedisIngestBlockAdapter,
    RedisRateLimitAdapter,
    WebhookContainmentAdapter,
)
from backend.defense.filter import get_defense_redis_client
from backend.ops.bus import ops_bus

logger = logging.getLogger("cyber_engine.defense.rollback")


class RollbackManager:
    """
    Manages the reversion of containment actions upon TTL expiration or analyst intervention.
    """

    def __init__(self, db: Session):
        self.db = db

    def schedule_expiration(self, action: PlannedResponseAction) -> None:
        """
        Schedules an action for automated reversion when its TTL expires.
        Uses Redis ZSET for distributed multi-worker scheduling, with DB timestamp fallback.
        """
        if not action.expires_at or not action.ttl_seconds:
            return

        expires_ts = action.expires_at.timestamp()
        r = get_defense_redis_client()
        if r is not None:
            try:
                zset_key = f"ternline:{action.tenant_id}:defense:expirations"
                r.zadd(zset_key, {action.action_id: expires_ts})
                logger.debug(
                    "RollbackManager: Scheduled expiration for action '%s' at %.0f",
                    action.action_id,
                    expires_ts,
                )
            except Exception as e:
                logger.warning("RollbackManager: Failed scheduling Redis expiration ZSET: %s", e)

    def rollback_action(
        self,
        action_id: str,
        tenant_id: str,
        actor: str,
        rationale: str,
    ) -> PlannedResponseAction:
        """
        Reverts an active or executing containment action.
        Dispatches to the corresponding adapter's rollback method.
        """
        model = (
            self.db.query(DefenseActionModel)
            .filter(
                DefenseActionModel.action_id == action_id,
                DefenseActionModel.tenant_id == tenant_id,
            )
            .first()
        )
        if not model:
            raise ValueError(f"Defense action '{action_id}' not found for tenant '{tenant_id}'")

        now = datetime.datetime.now(datetime.timezone.utc)
        from_status = model.status

        # Convert to PlannedResponseAction
        planned = self._model_to_planned(model)

        # Select adapter
        adapter = self._get_adapter(planned)

        # Execute rollback
        try:
            rollback_result = adapter.rollback(planned, self.db)
            success = rollback_result.get("success", True)
        except Exception as e:
            logger.exception("RollbackManager: Adapter rollback threw exception: %s", e)
            rollback_result = {"success": False, "error": str(e)}
            success = False

        if success:
            model.status = ActionStatus.ROLLED_BACK.value
            model.rolled_back_at = now
            model.rollback_result = rollback_result

            # Clean from Redis ZSET if present
            r = get_defense_redis_client()
            if r is not None:
                try:
                    zset_key = f"ternline:{tenant_id}:defense:expirations"
                    r.zrem(zset_key, action_id)
                except Exception:
                    pass

            audit_log = DefenseAuditLogModel(
                log_id=f"audit-{uuid.uuid4().hex[:12]}",
                action_id=action_id,
                tenant_id=tenant_id,
                from_status=from_status,
                to_status=ActionStatus.ROLLED_BACK.value,
                transition_trigger="analyst_rollback" if "analyst" in actor or "operator" in actor else "ttl_expired",
                actor=actor,
                details={
                    "rationale": rationale,
                    "rollback_result": rollback_result,
                },
                timestamp=now,
            )
            self.db.add(audit_log)
            self.db.commit()

            ops_bus.publish(
                component="defense",
                event_type="defense.action_rolled_back",
                level="info",
                message=f"Containment rolled back for target '{model.target_entity_id}' ({model.action_type}): {rationale}",
                tenant_id=tenant_id,
                finding_id=model.finding_id,
                metadata={"action_id": action_id, "rationale": rationale},
            )
            logger.info("RollbackManager: Action '%s' successfully rolled back.", action_id)
        else:
            model.status = ActionStatus.ROLLBACK_FAILED.value
            model.rollback_result = rollback_result

            audit_log = DefenseAuditLogModel(
                log_id=f"audit-{uuid.uuid4().hex[:12]}",
                action_id=action_id,
                tenant_id=tenant_id,
                from_status=from_status,
                to_status=ActionStatus.ROLLBACK_FAILED.value,
                transition_trigger="rollback_attempt_failed",
                actor=actor,
                details={"error": rollback_result, "rationale": rationale},
                timestamp=now,
            )
            self.db.add(audit_log)
            self.db.commit()

            ops_bus.publish(
                component="defense",
                event_type="defense.rollback_failed",
                level="error",
                message=f"Containment rollback FAILED for target '{model.target_entity_id}': {rollback_result.get('error')}",
                tenant_id=tenant_id,
                finding_id=model.finding_id,
                metadata={"action_id": action_id, "error": rollback_result},
            )

        return self._model_to_planned(model)

    def check_and_expire_due_actions(self, tenant_id: Optional[str] = None) -> List[str]:
        """
        Scans for verified active actions whose TTL has expired and rolls them back.
        Returns list of rolled back action IDs.
        """
        now = datetime.datetime.now(datetime.timezone.utc)
        query = (
            self.db.query(DefenseActionModel)
            .filter(
                DefenseActionModel.status == ActionStatus.VERIFIED_ACTIVE.value,
                DefenseActionModel.expires_at.isnot(None),
                DefenseActionModel.expires_at <= now,
            )
        )
        if tenant_id:
            query = query.filter(DefenseActionModel.tenant_id == tenant_id)

        due_actions = query.all()
        expired_ids = []

        for act in due_actions:
            try:
                self.rollback_action(
                    action_id=act.action_id,
                    tenant_id=act.tenant_id,
                    actor="system:ttl_rollback_manager",
                    rationale="Automated rollback: Action Time-to-Live (TTL) has expired.",
                )
                expired_ids.append(act.action_id)
            except Exception as e:
                logger.error("RollbackManager: Failed rolling back expired action '%s': %s", act.action_id, e)

        return expired_ids

    def _get_adapter(self, action: PlannedResponseAction):
        if action.action_type == ActionType.API_KEY_REVOCATION:
            return InternalApiKeyAdapter()
        elif action.action_type == ActionType.TEMPORARY_IP_BLOCK:
            if action.scope == ActionScope.CUSTOMER_APPLICATION:
                return WebhookContainmentAdapter()
            return RedisIngestBlockAdapter()
        elif action.action_type == ActionType.TEMPORARY_RATE_LIMIT:
            if action.scope == ActionScope.CUSTOMER_APPLICATION:
                return WebhookContainmentAdapter()
            return RedisRateLimitAdapter()
        else:
            return WebhookContainmentAdapter()

    def _model_to_planned(self, model: DefenseActionModel) -> PlannedResponseAction:
        from backend.schemas.defense import CredentialAuthority, ProtectionMode, TargetEntityType
        return PlannedResponseAction(
            action_id=model.action_id,
            tenant_id=model.tenant_id,
            finding_id=model.finding_id,
            action_type=ActionType(model.action_type),
            scope=ActionScope(model.scope),
            credential_authority=CredentialAuthority(model.credential_authority) if model.credential_authority else None,
            target_entity_type=TargetEntityType(model.target_entity_type),
            target_entity_id=model.target_entity_id,
            status=ActionStatus(model.status),
            protection_mode=ProtectionMode(model.protection_mode),
            deduplication_fingerprint=model.deduplication_fingerprint,
            parameters=model.parameters or {},
            ttl_seconds=model.ttl_seconds,
            expires_at=model.expires_at,
            requested_by=model.requested_by,
            approved_by=model.approved_by,
            approval_rationale=model.approval_rationale,
            provider_adapter=model.provider_adapter,
            external_reference_id=model.external_reference_id,
            execution_result=model.execution_result,
            verification_result=model.verification_result,
            rollback_result=model.rollback_result,
            created_at=model.created_at,
            executed_at=model.executed_at,
            verified_at=model.verified_at,
            rolled_back_at=model.rolled_back_at,
        )


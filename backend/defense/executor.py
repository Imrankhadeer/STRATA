"""
Response Executor for Ternline Phase 1: Active Defense.

Implements Milestone 1.3:
1. Orchestrates the physical dispatch and execution of approved/autonomous containment actions.
2. Acquires tenant-scoped distributed locks to prevent duplicate concurrent executions.
3. Durably commits state transitions in PostgreSQL prior to outward network dispatch.
4. Delegates to specialized provider adapters (InternalApiKeyAdapter, RedisIngestBlockAdapter, RedisRateLimitAdapter, WebhookContainmentAdapter).
5. Seamlessly hands off to VerificationManager and RollbackManager.
"""

import datetime
import logging
import uuid
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from backend.models import (
    DefenseActionModel,
    DefenseAuditLogModel,
)
from backend.schemas.defense import (
    ActionScope,
    ActionStatus,
    ActionType,
    CredentialAuthority,
    PlannedResponseAction,
    ProtectionMode,
    TargetEntityType,
)
from backend.defense.adapters import (
    BaseDefenseAdapter,
    InternalApiKeyAdapter,
    RedisIngestBlockAdapter,
    RedisRateLimitAdapter,
    WebhookContainmentAdapter,
)
from backend.defense.filter import get_defense_redis_client
from backend.defense.verification import VerificationManager
from backend.defense.rollback import RollbackManager
from backend.ops.bus import ops_bus

logger = logging.getLogger("cyber_engine.defense.executor")


class ResponseExecutor:
    """
    Executes containment actions against target systems with strict isolation and locking.
    """

    def __init__(self, db: Session):
        self.db = db
        self.verification_manager = VerificationManager(db)
        self.rollback_manager = RollbackManager(db)

    def execute_action(
        self,
        action_id: str,
        tenant_id: str,
        actor: str = "system:response_executor",
    ) -> PlannedResponseAction:
        """
        Executes a planned defense action.
        Validates action state, commits EXECUTING status before dispatch,
        invokes provider adapter, and initiates verification.
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

        if model.status != ActionStatus.APPROVED.value:
            raise ValueError(
                f"Action '{action_id}' cannot be executed from status '{model.status}'. "
                f"Must be approved prior to dispatch."
            )

        now = datetime.datetime.now(datetime.timezone.utc)
        from_status = model.status

        # 1. Distributed Lock to prevent duplicate concurrent execution
        r = get_defense_redis_client()
        lock_acquired = False
        lock_key = f"ternline:{tenant_id}:defense:lock:{model.deduplication_fingerprint}"
        if r is not None:
            try:
                lock_acquired = bool(r.set(lock_key, action_id, nx=True, ex=30))
                if not lock_acquired:
                    logger.warning(
                        "ResponseExecutor: Concurrent execution blocked by lock '%s' for action '%s'",
                        lock_key,
                        action_id,
                    )
            except Exception as e:
                logger.warning("ResponseExecutor: Redis lock check failed (proceeding): %s", e)

        # 2. Durable commit of EXECUTING status in PostgreSQL BEFORE dispatch
        model.status = ActionStatus.EXECUTING.value
        model.executed_at = now
        if model.ttl_seconds:
            model.expires_at = now + datetime.timedelta(seconds=model.ttl_seconds)

        audit_executing = DefenseAuditLogModel(
            log_id=f"audit-{uuid.uuid4().hex[:12]}",
            action_id=action_id,
            tenant_id=tenant_id,
            from_status=from_status,
            to_status=ActionStatus.EXECUTING.value,
            transition_trigger="execution_dispatched",
            actor=actor,
            details={"dispatched_at": now.isoformat()},
            timestamp=now,
        )
        self.db.add(audit_executing)
        self.db.commit()

        planned = self._model_to_planned(model)

        # 3. Select and invoke provider adapter
        adapter = self._select_adapter(planned)
        model.provider_adapter = adapter.adapter_name

        try:
            execution_result = adapter.execute(planned, self.db)
            success = execution_result.get("success", False)
        except Exception as e:
            logger.exception("ResponseExecutor: Adapter execution failed with exception: %s", e)
            execution_result = {"success": False, "error": str(e)}
            success = False

        model.execution_result = execution_result

        # Release distributed lock
        if r is not None and lock_acquired:
            try:
                r.delete(lock_key)
            except Exception:
                pass

        if not success:
            model.status = ActionStatus.EXECUTION_FAILED.value
            audit_failed = DefenseAuditLogModel(
                log_id=f"audit-{uuid.uuid4().hex[:12]}",
                action_id=action_id,
                tenant_id=tenant_id,
                from_status=ActionStatus.EXECUTING.value,
                to_status=ActionStatus.EXECUTION_FAILED.value,
                transition_trigger="adapter_execution_error",
                actor=actor,
                details=execution_result,
                timestamp=datetime.datetime.now(datetime.timezone.utc),
            )
            self.db.add(audit_failed)
            self.db.commit()

            ops_bus.publish(
                component="defense",
                event_type="defense.execution_failed",
                level="error",
                message=f"Containment execution FAILED for target '{model.target_entity_id}': {execution_result.get('error')}",
                tenant_id=tenant_id,
                finding_id=model.finding_id,
                metadata={"action_id": action_id, "error": execution_result},
            )
            return self._model_to_planned(model)

        # 4. Out-of-band Verification Probe (Milestone 1.4)
        verified = self.verification_manager.verify_action(action_id, tenant_id)

        # 5. Schedule TTL Expiration if verified and TTL is defined (Milestone 1.4)
        if verified and model.ttl_seconds and model.expires_at:
            planned_verified = self._model_to_planned(model)
            self.rollback_manager.schedule_expiration(planned_verified)

        return self._model_to_planned(model)

    def _select_adapter(self, action: PlannedResponseAction) -> BaseDefenseAdapter:
        """Routes action to the correct specialized provider adapter."""
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
        elif action.action_type == ActionType.ACCOUNT_SESSION_CONTAINMENT:
            return WebhookContainmentAdapter()
        else:
            return WebhookContainmentAdapter()

    def _model_to_planned(self, model: DefenseActionModel) -> PlannedResponseAction:
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

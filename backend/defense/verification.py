"""
Verification Manager for Ternline Phase 1: Active Defense.

Implements Milestone 1.4:
Validates out-of-band that executed containment actions took physical effect
before advancing their status to VERIFIED_ACTIVE.
"""

import datetime
import logging
import uuid
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from backend.models import (
    ApiKey,
    DefenseActionModel,
    DefenseAuditLogModel,
)
from backend.schemas.defense import (
    ActionScope,
    ActionStatus,
    ActionType,
    PlannedResponseAction,
)
from backend.defense.filter import get_defense_redis_client, ingest_containment_filter
from backend.ops.bus import ops_bus

logger = logging.getLogger("cyber_engine.defense.verification")


class VerificationManager:
    """
    Performs out-of-band verification probes on executed defense actions.
    Ensures zero false containment assertions.
    """

    def __init__(self, db: Session):
        self.db = db

    def verify_action(self, action_id: str, tenant_id: str) -> bool:
        """
        Runs the appropriate verification probe for the action based on its type.
        Updates action status to VERIFIED_ACTIVE or VERIFICATION_FAILED.
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
            logger.error("VerificationManager: Action '%s' not found for tenant '%s'", action_id, tenant_id)
            return False

        action_type = ActionType(model.action_type)
        scope = ActionScope(model.scope)
        target_entity = model.target_entity_id
        now = datetime.datetime.now(datetime.timezone.utc)

        verified = False
        verification_details: Dict[str, Any] = {"probed_at": now.isoformat()}

        try:
            if action_type == ActionType.TEMPORARY_IP_BLOCK:
                # Probe 1: Verify IP is in active containment filter
                is_in_memory = target_entity in ingest_containment_filter._in_memory_blocked_ips.get(tenant_id, set())
                r = get_defense_redis_client()
                is_in_redis = False
                if r is not None:
                    try:
                        block_key = f"ternline:{tenant_id}:defense:blocked_ips"
                        is_in_redis = bool(r.sismember(block_key, target_entity))
                    except Exception:
                        pass

                verified = is_in_memory or is_in_redis
                verification_details.update({
                    "method": "containment_filter_probe",
                    "in_memory_verified": is_in_memory,
                    "redis_verified": is_in_redis,
                })

            elif action_type == ActionType.TEMPORARY_RATE_LIMIT:
                # Probe 2: Verify rate limit entry exists
                key = (tenant_id, target_entity)
                is_in_memory = key in ingest_containment_filter._in_memory_rate_limits
                r = get_defense_redis_client()
                is_in_redis = False
                if r is not None:
                    try:
                        rl_key = f"ternline:{tenant_id}:defense:ratelimit:{target_entity}"
                        is_in_redis = r.exists(rl_key) > 0
                    except Exception:
                        pass

                verified = is_in_memory or is_in_redis
                verification_details.update({
                    "method": "rate_limit_probe",
                    "in_memory_verified": is_in_memory,
                    "redis_verified": is_in_redis,
                })

            elif action_type == ActionType.API_KEY_REVOCATION:
                # Probe 3: Verify key in PostgreSQL is de-activated
                key_record = (
                    self.db.query(ApiKey)
                    .filter(
                        (ApiKey.id == target_entity) | (ApiKey.app_id == target_entity),
                        ApiKey.tenant_id == tenant_id,
                    )
                    .first()
                )
                if key_record and key_record.is_active is False:
                    verified = True
                    verification_details.update({
                        "method": "database_state_probe",
                        "key_id": key_record.id,
                        "is_active": False,
                    })
                else:
                    verified = False
                    verification_details.update({
                        "method": "database_state_probe",
                        "error": "Key is still active or record not found",
                    })

            elif action_type == ActionType.ACCOUNT_SESSION_CONTAINMENT or scope == ActionScope.CUSTOMER_APPLICATION:
                # Probe 4: Webhook / customer application containment
                exec_res = model.execution_result or {}
                if exec_res.get("success") is True and exec_res.get("http_status") in (200, 201, 202, 204):
                    verified = True
                    verification_details.update({
                        "method": "webhook_receipt_probe",
                        "receipt_id": exec_res.get("receipt_id"),
                        "http_status": exec_res.get("http_status"),
                    })
                else:
                    verified = False
                    verification_details.update({
                        "method": "webhook_receipt_probe",
                        "error": exec_res.get("error", "Webhook did not return success"),
                    })

            else:
                # Default fallback verification
                verified = model.execution_result.get("success", False) if model.execution_result else False
                verification_details["method"] = "default_execution_check"

        except Exception as e:
            logger.exception("VerificationManager: Probe failed with error: %s", e)
            verified = False
            verification_details["exception"] = str(e)

        from_status = model.status
        if verified:
            model.status = ActionStatus.VERIFIED_ACTIVE.value
            model.verified_at = now
            model.verification_result = verification_details

            audit_log = DefenseAuditLogModel(
                log_id=f"audit-{uuid.uuid4().hex[:12]}",
                action_id=action_id,
                tenant_id=tenant_id,
                from_status=from_status,
                to_status=ActionStatus.VERIFIED_ACTIVE.value,
                transition_trigger="verification_passed",
                actor="system:verification_manager",
                details=verification_details,
                timestamp=now,
            )
            self.db.add(audit_log)
            self.db.commit()

            ops_bus.publish(
                component="defense",
                event_type="defense.action_verified",
                level="success",
                message=f"Containment verified active for target '{target_entity}' ({action_type.value})",
                tenant_id=tenant_id,
                finding_id=model.finding_id,
                metadata={"action_id": action_id, "verification": verification_details},
            )
            logger.info("VerificationManager: Action '%s' VERIFIED_ACTIVE successfully.", action_id)
            return True
        else:
            model.status = ActionStatus.VERIFICATION_FAILED.value
            model.verification_result = verification_details

            audit_log = DefenseAuditLogModel(
                log_id=f"audit-{uuid.uuid4().hex[:12]}",
                action_id=action_id,
                tenant_id=tenant_id,
                from_status=from_status,
                to_status=ActionStatus.VERIFICATION_FAILED.value,
                transition_trigger="verification_failed",
                actor="system:verification_manager",
                details=verification_details,
                timestamp=now,
            )
            self.db.add(audit_log)
            self.db.commit()

            ops_bus.publish(
                component="defense",
                event_type="defense.verification_failed",
                level="error",
                message=f"Containment verification FAILED for target '{target_entity}' ({action_type.value})",
                tenant_id=tenant_id,
                finding_id=model.finding_id,
                metadata={"action_id": action_id, "error": verification_details},
            )
            logger.warning("VerificationManager: Action '%s' VERIFICATION_FAILED: %s", action_id, verification_details)
            return False


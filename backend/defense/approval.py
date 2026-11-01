"""
Approval Manager with Strict Dual-Custody Enforcement for Ternline Phase 1: Active Defense.

Responsibilities:
1. Enforces dual-custody authorization: requesters cannot self-approve.
2. Rejects service accounts, system keys, and API keys from acting as human approvers.
3. Strictly isolates approvals by tenant boundary (cross-tenant approvals blocked).
4. Prevents replayed or out-of-order state transitions.
5. Emits audited transition events to PostgreSQL and the live SSE ops bus.
"""

import datetime
import logging
import threading
import uuid
from typing import Optional
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
from backend.ops.bus import ops_bus

logger = logging.getLogger("cyber_engine.defense.approval")


class DefenseApprovalError(Exception):
    """Base exception for active defense approval failures."""
    pass


class ActionNotFoundError(DefenseApprovalError):
    pass


class ForbiddenTenantApprovalError(DefenseApprovalError):
    pass


class InvalidActionStatusError(DefenseApprovalError):
    pass


class SelfApprovalForbiddenError(DefenseApprovalError):
    pass


class ServiceAccountApprovalForbiddenError(DefenseApprovalError):
    pass


class ApprovalManager:
    """
    Coordinates human-in-the-loop authorization and dual-custody approval gating.
    """
    _lock = threading.RLock()

    def __init__(self, db: Session):
        self.db = db

    def approve_action(
        self,
        action_id: str,
        tenant_id: str,
        approver_identity: str,
        rationale: str,
    ) -> PlannedResponseAction:
        """
        Approves a pending containment action under strict dual-custody rules.
        """
        with self._lock:
            # Expire session cache to ensure latest state is read from DB
            self.db.expire_all()
            action = (
                self.db.query(DefenseActionModel)
                .filter(DefenseActionModel.action_id == action_id)
                .with_for_update()
                .first()
            )
            if not action:
                raise ActionNotFoundError(f"Defense action '{action_id}' not found")

            # 1. Enforce strict tenant isolation
            if action.tenant_id != tenant_id:
                logger.warning(
                    "Cross-tenant approval attempt rejected: action_tenant=%s caller_tenant=%s action_id=%s",
                    action.tenant_id, tenant_id, action_id
                )
                raise ForbiddenTenantApprovalError(
                    f"Action '{action_id}' does not belong to authenticated tenant '{tenant_id}'"
                )

            # 2. Enforce valid state for approval (reject replayed approvals)
            if action.status not in (ActionStatus.PROPOSED.value, ActionStatus.AWAITING_APPROVAL.value):
                raise InvalidActionStatusError(
                    f"Action '{action_id}' cannot be approved: current status is '{action.status}'"
                )

            # 3. Dual-Custody: Approver must be an authenticated human user
            approver_clean = (approver_identity or "").strip()
            approver_lower = approver_clean.lower()
            if not approver_clean or approver_lower.startswith(("service:", "key:", "system:")):
                raise ServiceAccountApprovalForbiddenError(
                    "Dual-custody violation: Service accounts, API keys, and system actors cannot act as human approvers"
                )

            # 4. Dual-Custody: Requester cannot self-approve
            requester_clean = (action.requested_by or "").strip()
            if approver_clean.lower() == requester_clean.lower():
                raise SelfApprovalForbiddenError(
                    f"Dual-custody violation: Requester '{requester_clean}' cannot approve their own defense action"
                )

            # 5. Apply state transition
            now = datetime.datetime.now(datetime.timezone.utc)
            old_status = action.status
            action.status = ActionStatus.APPROVED.value
            action.approved_by = approver_clean
            action.approval_rationale = rationale

            # 6. Record immutable audit log
            audit_log = DefenseAuditLogModel(
                log_id=f"log-{uuid.uuid4().hex[:12]}",
                action_id=action.action_id,
                tenant_id=action.tenant_id,
                from_status=old_status,
                to_status=ActionStatus.APPROVED.value,
                transition_trigger="approval_manager.approve",
                actor=approver_clean,
                details={
                    "requester": requester_clean,
                    "approver": approver_clean,
                    "action_type": action.action_type,
                    "target_entity": action.target_entity_id,
                    "fingerprint": action.deduplication_fingerprint,
                    "rationale": rationale,
                },
                timestamp=now,
            )
            self.db.add(audit_log)
            self.db.commit()
            self.db.refresh(action)

            # 7. Publish to live SSE bus
            ops_bus.publish(
                component="defense",
                event_type="defense.action_approved",
                level="info",
                message=f"Defense action '{action.action_id}' ({action.action_type}) approved by {approver_clean}",
                tenant_id=action.tenant_id,
                metadata={
                    "action_id": action.action_id,
                    "action_type": action.action_type,
                    "approver": approver_clean,
                    "target": action.target_entity_id,
                },
            )

            logger.info(
                "Defense action approved: action_id=%s tenant=%s approver=%s requester=%s",
                action.action_id, action.tenant_id, approver_clean, requester_clean
            )

            return self._model_to_planned(action)

    def reject_action(
        self,
        action_id: str,
        tenant_id: str,
        rejector_identity: str,
        rationale: str,
    ) -> PlannedResponseAction:
        """
        Rejects a proposed containment action and records rationale.
        """
        with self._lock:
            self.db.expire_all()
            action = (
                self.db.query(DefenseActionModel)
                .filter(DefenseActionModel.action_id == action_id)
                .with_for_update()
                .first()
            )
            if not action:
                raise ActionNotFoundError(f"Defense action '{action_id}' not found")

            if action.tenant_id != tenant_id:
                raise ForbiddenTenantApprovalError(
                    f"Action '{action_id}' does not belong to authenticated tenant '{tenant_id}'"
                )

            if action.status not in (ActionStatus.PROPOSED.value, ActionStatus.AWAITING_APPROVAL.value):
                raise InvalidActionStatusError(
                    f"Action '{action_id}' cannot be rejected: current status is '{action.status}'"
                )

            now = datetime.datetime.now(datetime.timezone.utc)
            old_status = action.status
            action.status = ActionStatus.REJECTED.value
            action.approved_by = rejector_identity
            action.approval_rationale = f"REJECTED: {rationale}"

            audit_log = DefenseAuditLogModel(
                log_id=f"log-{uuid.uuid4().hex[:12]}",
                action_id=action.action_id,
                tenant_id=action.tenant_id,
                from_status=old_status,
                to_status=ActionStatus.REJECTED.value,
                transition_trigger="approval_manager.reject",
                actor=rejector_identity,
                details={
                    "rejector": rejector_identity,
                    "action_type": action.action_type,
                    "target_entity": action.target_entity_id,
                    "rationale": rationale,
                },
                timestamp=now,
            )
            self.db.add(audit_log)
            self.db.commit()
            self.db.refresh(action)

            ops_bus.publish(
                component="defense",
                event_type="defense.action_rejected",
                level="warn",
                message=f"Defense action '{action.action_id}' rejected by {rejector_identity}",
                tenant_id=action.tenant_id,
                metadata={"action_id": action.action_id, "rejector": rejector_identity},
            )

            return self._model_to_planned(action)

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

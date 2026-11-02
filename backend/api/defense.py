"""
Active Defense REST API Endpoints.

Provides endpoints for:
- Listing and inspecting defense actions.
- Approving and rejecting containment actions under strict dual-custody enforcement.
- Querying and updating tenant defense policy.

Enforces:
- Scope-based RBAC permissions on all endpoints.
- Cryptographically verified human operator sessions for sensitive approval/rejection operations.
- Prevention of caller-supplied approver identity spoofing / impersonation.
- Immutable audit logging for policy modifications.
"""

import datetime
import logging
import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.core.auth import (
    AuthContext,
    Permission,
    get_current_auth,
    require_human_operator,
    require_permission,
)
from backend.models import (
    DefenseActionModel,
    DefenseAuditLogModel,
    SecurityFinding,
    TenantDefensePolicyModel,
)
from backend.schemas.defense import (
    ActionApprovalRequest,
    ActionRejectRequest,
    ActionRollbackRequest,
    ActionStatus,
    ActionType,
    DefenseAuditLogEntry,
    PlannedResponseAction,
    ProtectionMode,
    TenantDefensePolicy,
    TenantDefensePolicyUpdate,
    canonicalize_principal_id,
)
from backend.defense.approval import (
    ApprovalManager,
    ActionNotFoundError,
    ActionExpiredError,
    ForbiddenTenantApprovalError,
    InvalidActionStatusError,
    SelfApprovalForbiddenError,
    ServiceAccountApprovalForbiddenError,
)
from backend.ops.bus import ops_bus

logger = logging.getLogger("cyber_engine.api.defense")

router = APIRouter(prefix="/api/v1/defense", tags=["active-defense"])


@router.get("/actions", response_model=List[PlannedResponseAction])
async def list_defense_actions(
    status_filter: Optional[ActionStatus] = Query(None, alias="status", description="Filter by action status"),
    action_type: Optional[ActionType] = Query(None, description="Filter by action type"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    auth: AuthContext = Depends(require_permission(Permission.DEFENSE_ACTIONS_READ)),
    db: Session = Depends(get_db),
):
    """
    Lists defense actions for the authenticated tenant with optional status and type filters.
    Strictly tenant-isolated.
    Requires permission: defense:actions:read
    """
    query = (
        db.query(DefenseActionModel)
        .filter(DefenseActionModel.tenant_id == auth.tenant_id)
    )
    if status_filter:
        query = query.filter(DefenseActionModel.status == status_filter.value)
    if action_type:
        query = query.filter(DefenseActionModel.action_type == action_type.value)

    actions = (
        query.order_by(DefenseActionModel.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    manager = ApprovalManager(db)
    return [manager._model_to_planned(a) for a in actions]


@router.get("/actions/{action_id}", response_model=PlannedResponseAction)
async def get_defense_action(
    action_id: str,
    auth: AuthContext = Depends(require_permission(Permission.DEFENSE_ACTIONS_READ)),
    db: Session = Depends(get_db),
):
    """
    Retrieves detailed state and metadata for a specific defense action.
    Requires permission: defense:actions:read
    """
    action = (
        db.query(DefenseActionModel)
        .filter(
            DefenseActionModel.action_id == action_id,
            DefenseActionModel.tenant_id == auth.tenant_id,
        )
        .first()
    )
    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Defense action '{action_id}' not found",
        )

    manager = ApprovalManager(db)
    return manager._model_to_planned(action)


@router.post("/actions/plan/{finding_id}", response_model=List[PlannedResponseAction])
async def plan_defense_action_for_finding(
    finding_id: str,
    auth: AuthContext = Depends(require_permission(Permission.DEFENSE_ACTIONS_PROPOSE)),
    db: Session = Depends(get_db),
):
    """
    Synthesizes and durably plans candidate defense actions for a specific SecurityFinding.
    Applies deduplication, policy resolution, target validation, and audit recording.
    Requires permission: defense:actions:propose
    """
    finding = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.finding_id == finding_id,
            SecurityFinding.tenant_id == auth.tenant_id,
        )
        .first()
    )
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security finding '{finding_id}' not found",
        )

    from backend.defense.planner import ResponsePlanner
    planner = ResponsePlanner(db)
    actions = planner.plan_from_finding(finding)
    return actions


@router.post("/actions/{action_id}/approve", response_model=PlannedResponseAction)
async def approve_defense_action(
    action_id: str,
    payload: ActionApprovalRequest,
    auth: AuthContext = Depends(require_human_operator),
    db: Session = Depends(get_db),
):
    """
    Approves a pending defense action.
    Enforces strict server-side dual-custody authorization:
    - Requesters cannot approve their own actions.
    - Approver identity is derived strictly from verified cryptographic operator credentials.
    - Caller-supplied assertions in the body that mismatch authenticated identity are rejected (403).
    - Requires permission: defense:actions:approve
    """
    if not auth.has_permission(Permission.DEFENSE_ACTIONS_APPROVE):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Forbidden: missing required permission '{Permission.DEFENSE_ACTIONS_APPROVE}'",
        )

    # Validate caller assertion if present (reject impersonation attempts)
    if payload.approver_identity:
        caller_canon = canonicalize_principal_id(payload.approver_identity)
        auth_canon = canonicalize_principal_id(auth.operator_principal)
        if caller_canon != auth_canon:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Dual-custody impersonation rejected (identity mismatch): caller supplied identity '{payload.approver_identity}' does not match authenticated operator '{auth.operator_principal}'",
            )

    # Canonical verified approver identity from auth context
    verified_approver = auth.operator_principal

    manager = ApprovalManager(db)
    try:
        updated = manager.approve_action(
            action_id=action_id,
            tenant_id=auth.tenant_id,
            approver_identity=verified_approver,
            rationale=payload.rationale,
        )
        return updated
    except ActionNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Action '{action_id}' not found")
    except ActionExpiredError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except ForbiddenTenantApprovalError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except InvalidActionStatusError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except SelfApprovalForbiddenError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ServiceAccountApprovalForbiddenError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))


@router.post("/actions/{action_id}/reject", response_model=PlannedResponseAction)
async def reject_defense_action(
    action_id: str,
    payload: ActionRejectRequest,
    auth: AuthContext = Depends(require_human_operator),
    db: Session = Depends(get_db),
):
    """
    Rejects a pending defense action and records rejection rationale in the immutable audit log.
    Requires permission: defense:actions:reject
    """
    if not auth.has_permission(Permission.DEFENSE_ACTIONS_REJECT):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Forbidden: missing required permission '{Permission.DEFENSE_ACTIONS_REJECT}'",
        )

    if payload.rejector_identity:
        caller_canon = canonicalize_principal_id(payload.rejector_identity)
        auth_canon = canonicalize_principal_id(auth.operator_principal)
        if caller_canon != auth_canon:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Rejector identity mismatch: caller supplied identity '{payload.rejector_identity}' does not match authenticated operator '{auth.operator_principal}'",
            )

    verified_rejector = auth.operator_principal

    manager = ApprovalManager(db)
    try:
        updated = manager.reject_action(
            action_id=action_id,
            tenant_id=auth.tenant_id,
            rejector_identity=verified_rejector,
            rationale=payload.rationale,
        )
        return updated
    except ActionNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Action '{action_id}' not found")
    except ActionExpiredError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except ForbiddenTenantApprovalError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except InvalidActionStatusError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))


@router.post("/actions/{action_id}/execute", response_model=PlannedResponseAction)
async def execute_defense_action(
    action_id: str,
    auth: AuthContext = Depends(require_permission(Permission.DEFENSE_ACTIONS_EXECUTE)),
    db: Session = Depends(get_db),
):
    """
    Executes an approved or autonomous containment action.
    Acquires tenant lock, records EXECUTING status in DB, dispatches to provider adapter,
    runs out-of-band verification, and registers TTL expiration.
    Requires permission: defense:actions:execute
    """
    from backend.defense.executor import ResponseExecutor
    executor = ResponseExecutor(db)
    try:
        actor_id = auth.operator_principal or f"key:{auth.app_id}"
        executed = executor.execute_action(action_id=action_id, tenant_id=auth.tenant_id, actor=actor_id)
        return executed
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/actions/{action_id}/rollback", response_model=PlannedResponseAction)
async def rollback_defense_action(
    action_id: str,
    payload: ActionRollbackRequest,
    auth: AuthContext = Depends(require_permission(Permission.DEFENSE_ACTIONS_ROLLBACK)),
    db: Session = Depends(get_db),
):
    """
    Reverts an active or executing containment action.
    Restores normal operational state, invokes provider adapter rollback,
    records immutable audit log, and publishes SSE notification.
    Requires permission: defense:actions:rollback
    """
    from backend.defense.rollback import RollbackManager
    manager = RollbackManager(db)
    try:
        actor_id = payload.actor or auth.operator_principal or f"key:{auth.app_id}"
        rolled_back = manager.rollback_action(
            action_id=action_id,
            tenant_id=auth.tenant_id,
            actor=actor_id,
            rationale=payload.rationale,
        )
        return rolled_back
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/actions/reconcile-expirations", response_model=List[str])
async def reconcile_action_expirations(
    auth: AuthContext = Depends(require_permission(Permission.DEFENSE_ACTIONS_READ)),
    db: Session = Depends(get_db),
):
    """
    Scans for verified active actions whose Time-to-Live (TTL) has expired and automatically rolls them back.
    Requires permission: defense:actions:read
    """
    from backend.defense.rollback import RollbackManager
    manager = RollbackManager(db)
    expired = manager.check_and_expire_due_actions(tenant_id=auth.tenant_id)
    return expired



@router.get("/policy", response_model=TenantDefensePolicy)
async def get_tenant_defense_policy(
    auth: AuthContext = Depends(require_permission(Permission.DEFENSE_POLICY_READ)),
    db: Session = Depends(get_db),
):
    """
    Retrieves the tenant's Active Defense protection policy.
    Mandatory default mode is OBSERVE.
    Requires permission: defense:policy:read
    """
    row = (
        db.query(TenantDefensePolicyModel)
        .filter(TenantDefensePolicyModel.tenant_id == auth.tenant_id)
        .first()
    )
    if not row:
        return TenantDefensePolicy(
            tenant_id=auth.tenant_id,
            default_mode=ProtectionMode.OBSERVE,
            is_active=True,
        )

    config = row.configuration or {}
    return TenantDefensePolicy(
        tenant_id=auth.tenant_id,
        default_mode=ProtectionMode(row.default_mode.lower()),
        is_active=row.is_active,
        allowed_autonomous_actions=[ActionType(a) for a in config.get("allowed_autonomous_actions", []) if a in [e.value for e in ActionType]],
        max_autonomous_ttl_seconds=int(config.get("max_autonomous_ttl_seconds", 3600)),
        max_autonomous_actions_per_hour=int(config.get("max_autonomous_actions_per_hour", 10)),
        action_overrides=config.get("action_overrides", {}),
    )


@router.put("/policy", response_model=TenantDefensePolicy)
async def update_tenant_defense_policy(
    payload: TenantDefensePolicyUpdate,
    auth: AuthContext = Depends(require_permission(Permission.DEFENSE_POLICY_WRITE)),
    db: Session = Depends(get_db),
):
    """
    Updates the tenant's Active Defense policy and records an immutable audit log entry.
    Guaranteed safety invariants:
    - Sensitive actions (API key revocation, session containment) can never be set to autonomous.
    Requires permission: defense:policy:write
    """
    row = (
        db.query(TenantDefensePolicyModel)
        .filter(TenantDefensePolicyModel.tenant_id == auth.tenant_id)
        .first()
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    old_mode = row.default_mode if row else "observe"
    old_config = dict(row.configuration or {}) if row else {}

    if not row:
        row = TenantDefensePolicyModel(
            id=f"pol-{auth.tenant_id[:12]}",
            tenant_id=auth.tenant_id,
            default_mode=(payload.default_mode or ProtectionMode.OBSERVE).value,
            is_active=True,
            configuration={},
            created_at=now,
            updated_at=now,
        )
        db.add(row)

    if payload.default_mode:
        row.default_mode = payload.default_mode.value

    config = dict(row.configuration or {})
    if payload.allowed_autonomous_actions is not None:
        config["allowed_autonomous_actions"] = [a.value for a in payload.allowed_autonomous_actions]
    if payload.max_autonomous_ttl_seconds is not None:
        config["max_autonomous_ttl_seconds"] = payload.max_autonomous_ttl_seconds
    if payload.max_autonomous_actions_per_hour is not None:
        config["max_autonomous_actions_per_hour"] = payload.max_autonomous_actions_per_hour
    if payload.action_overrides is not None:
        config["action_overrides"] = payload.action_overrides

    row.configuration = config
    row.updated_at = now

    # Record immutable audit entry
    actor = auth.operator_principal or f"key:{auth.key_id}"
    audit_entry = DefenseAuditLogModel(
        log_id=f"log-{uuid.uuid4().hex[:12]}",
        action_id=None,
        tenant_id=auth.tenant_id,
        from_status=old_mode,
        to_status=row.default_mode,
        transition_trigger="defense.policy_updated",
        actor=actor,
        details={
            "old_mode": old_mode,
            "new_mode": row.default_mode,
            "reason": payload.reason or "Active Defense policy update",
            "old_configuration": old_config,
            "new_configuration": config,
        },
        timestamp=now,
    )
    db.add(audit_entry)

    db.commit()
    db.refresh(row)

    ops_bus.publish(
        component="defense",
        event_type="defense.policy_updated",
        level="info",
        message=f"Tenant '{auth.tenant_id}' Active Defense policy updated to mode '{row.default_mode}'",
        tenant_id=auth.tenant_id,
        metadata={"default_mode": row.default_mode},
    )

    return await get_tenant_defense_policy(auth=auth, db=db)


@router.get("/audit", response_model=List[DefenseAuditLogEntry])
async def list_defense_audit_logs(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    action_id: Optional[str] = Query(None, description="Filter by specific action ID"),
    auth: AuthContext = Depends(require_permission(Permission.DEFENSE_ACTIONS_READ)),
    db: Session = Depends(get_db),
):
    """
    Retrieves the immutable Active Defense audit log for the authenticated tenant.
    Chronologically ordered (newest first).
    Requires permission: defense:actions:read
    """
    query = (
        db.query(DefenseAuditLogModel)
        .filter(DefenseAuditLogModel.tenant_id == auth.tenant_id)
    )
    if action_id:
        query = query.filter(DefenseAuditLogModel.action_id == action_id)

    rows = (
        query.order_by(DefenseAuditLogModel.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return [
        DefenseAuditLogEntry(
            log_id=r.log_id,
            action_id=r.action_id,
            tenant_id=r.tenant_id,
            from_status=r.from_status,
            to_status=r.to_status,
            transition_trigger=r.transition_trigger,
            actor=r.actor,
            details=r.details or {},
            timestamp=r.timestamp,
        )
        for r in rows
    ]

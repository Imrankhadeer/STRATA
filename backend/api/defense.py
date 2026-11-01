"""
Active Defense REST API Endpoints.

Provides endpoints for:
- Listing and inspecting defense actions.
- Approving and rejecting containment actions under strict dual-custody enforcement.
- Querying and updating tenant defense policy.
"""

import datetime
import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.core.auth import AuthContext, get_current_auth
from backend.models import (
    DefenseActionModel,
    DefenseAuditLogModel,
    TenantDefensePolicyModel,
)
from backend.schemas.defense import (
    ActionApprovalRequest,
    ActionRejectRequest,
    ActionStatus,
    ActionType,
    PlannedResponseAction,
    ProtectionMode,
    TenantDefensePolicy,
    TenantDefensePolicyUpdate,
)
from backend.defense.approval import (
    ApprovalManager,
    ActionNotFoundError,
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
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    """
    Lists defense actions for the authenticated tenant with optional status and type filters.
    Strictly tenant-isolated.
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
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    """
    Retrieves detailed state and metadata for a specific defense action.
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


@router.post("/actions/{action_id}/approve", response_model=PlannedResponseAction)
async def approve_defense_action(
    action_id: str,
    payload: ActionApprovalRequest,
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    """
    Approves a pending defense action.
    Enforces strict server-side dual-custody authorization:
    - Requesters cannot approve their own actions.
    - Approvers must be authenticated human identities (API keys/service accounts rejected).
    """
    manager = ApprovalManager(db)
    try:
        updated = manager.approve_action(
            action_id=action_id,
            tenant_id=auth.tenant_id,
            approver_identity=payload.approver_identity,
            rationale=payload.rationale,
        )
        return updated
    except ActionNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Action '{action_id}' not found")
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
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    """
    Rejects a pending defense action and records rejection rationale in the immutable audit log.
    """
    manager = ApprovalManager(db)
    try:
        updated = manager.reject_action(
            action_id=action_id,
            tenant_id=auth.tenant_id,
            rejector_identity=payload.rejector_identity,
            rationale=payload.rationale,
        )
        return updated
    except ActionNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Action '{action_id}' not found")
    except ForbiddenTenantApprovalError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except InvalidActionStatusError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))


@router.get("/policy", response_model=TenantDefensePolicy)
async def get_tenant_defense_policy(
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    """
    Retrieves the tenant's Active Defense protection policy.
    Mandatory default mode is OBSERVE.
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
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    """
    Updates the tenant's Active Defense policy.
    Guaranteed safety invariants:
    - Sensitive actions (API key revocation, session containment) can never be set to autonomous.
    """
    row = (
        db.query(TenantDefensePolicyModel)
        .filter(TenantDefensePolicyModel.tenant_id == auth.tenant_id)
        .first()
    )

    now = datetime.datetime.now(datetime.timezone.utc)
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

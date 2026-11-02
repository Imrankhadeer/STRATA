import datetime
import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.db.session import get_db
from backend.models import Tenant, UserModel, WorkspaceMemberModel
from backend.core.auth import (
    AuthContext,
    Permission,
    Role,
    create_operator_token,
    get_current_auth,
    get_role_permissions,
    require_permission,
)
from backend.schemas.auth import TokenResponse, UserResponse
from backend.schemas.workspaces import (
    WorkspaceInfo,
    CreateWorkspaceRequest,
    SwitchWorkspaceRequest,
    WorkspaceMemberInfo,
    AddWorkspaceMemberRequest,
    UpdateWorkspaceMemberRoleRequest,
    UpdateWorkspaceRequest,
)
from backend.ops.bus import ops_bus

router = APIRouter(prefix="/api/v1/workspaces", tags=["Workspace & Multi-Tenancy Management"])


def _ensure_user_membership(user: UserModel, db: Session):
    """Ensures user has at least one WorkspaceMemberModel record for their primary tenant."""
    membership = (
        db.query(WorkspaceMemberModel)
        .filter(
            WorkspaceMemberModel.user_id == user.id,
            WorkspaceMemberModel.tenant_id == user.tenant_id,
        )
        .first()
    )
    if not membership and user.tenant_id:
        membership = WorkspaceMemberModel(
            id=f"wm-{uuid.uuid4().hex[:10]}",
            tenant_id=user.tenant_id,
            user_id=user.id,
            role=user.role if user.role in ["owner", "admin", "developer", "analyst", "viewer"] else "owner",
            created_at=datetime.datetime.now(datetime.timezone.utc),
        )
        db.add(membership)
        db.commit()


@router.get("", response_model=List[WorkspaceInfo])
def list_user_workspaces(
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    """Lists all workspaces that the authenticated operator belongs to."""
    if not auth.operator_principal:
        # Machine API key: return current workspace only
        tenant = db.query(Tenant).filter(Tenant.id == auth.tenant_id).first()
        t_name = tenant.name if tenant else "Primary Workspace"
        return [
            WorkspaceInfo(
                id=auth.tenant_id,
                name=t_name,
                role="machine_key",
                is_current=True,
                member_count=1,
                created_at=tenant.created_at if tenant else datetime.datetime.now(datetime.timezone.utc),
            )
        ]

    user = db.query(UserModel).filter(UserModel.email == auth.operator_principal).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User account not found.")

    _ensure_user_membership(user, db)

    memberships = (
        db.query(WorkspaceMemberModel, Tenant)
        .join(Tenant, WorkspaceMemberModel.tenant_id == Tenant.id)
        .filter(WorkspaceMemberModel.user_id == user.id, Tenant.is_active == True)
        .all()
    )

    result = []
    for mem, t in memberships:
        count = (
            db.query(func.count(WorkspaceMemberModel.id))
            .filter(WorkspaceMemberModel.tenant_id == t.id)
            .scalar()
            or 1
        )
        result.append(
            WorkspaceInfo(
                id=t.id,
                name=t.name,
                role=mem.role,
                is_current=(t.id == auth.tenant_id),
                member_count=count,
                created_at=t.created_at,
            )
        )
    return result


@router.post("", response_model=WorkspaceInfo, status_code=status.HTTP_201_CREATED)
def create_workspace(
    req: CreateWorkspaceRequest,
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    """Provisions a new independent workspace and assigns caller as owner."""
    if not auth.operator_principal:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Creating new workspaces requires an authenticated human operator session.",
        )

    user = db.query(UserModel).filter(UserModel.email == auth.operator_principal).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User account not found.")

    now = datetime.datetime.now(datetime.timezone.utc)
    new_tenant_id = f"ws-{uuid.uuid4().hex[:10]}"
    tenant = Tenant(
        id=new_tenant_id,
        name=req.name.strip(),
        is_active=True,
        created_at=now,
    )
    db.add(tenant)

    member = WorkspaceMemberModel(
        id=f"wm-{uuid.uuid4().hex[:10]}",
        tenant_id=new_tenant_id,
        user_id=user.id,
        role=Role.OWNER,
        created_at=now,
    )
    db.add(member)
    db.commit()

    ops_bus.publish(
        component="workspaces",
        event_type="workspace.created",
        level="info",
        message=f"New workspace '{req.name}' provisioned by {user.email}",
    )

    return WorkspaceInfo(
        id=new_tenant_id,
        name=tenant.name,
        role=Role.OWNER,
        is_current=False,
        member_count=1,
        created_at=now,
    )


@router.post("/switch", response_model=TokenResponse)
def switch_workspace(
    req: SwitchWorkspaceRequest,
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    """
    Switches active workspace context.
    Verifies that caller is an authorized member of the target workspace in PostgreSQL,
    then issues a newly scoped JWT with permissions bound to their role in that workspace.
    """
    if not auth.operator_principal:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Workspace context switching requires an active operator session.",
        )

    user = db.query(UserModel).filter(UserModel.email == auth.operator_principal).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User account not found.")

    target_tenant_id = req.tenant_id.strip()

    # Verify target tenant exists and is active
    tenant = db.query(Tenant).filter(Tenant.id == target_tenant_id, Tenant.is_active == True).first()
    if not tenant:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target workspace does not exist or is inactive.")

    # Verify user's membership in target workspace
    membership = (
        db.query(WorkspaceMemberModel)
        .filter(
            WorkspaceMemberModel.user_id == user.id,
            WorkspaceMemberModel.tenant_id == target_tenant_id,
        )
        .first()
    )

    # Legacy fallback: If user.tenant_id matches target but no membership row yet, seed it
    if not membership and user.tenant_id == target_tenant_id:
        membership = WorkspaceMemberModel(
            id=f"wm-{uuid.uuid4().hex[:10]}",
            tenant_id=target_tenant_id,
            user_id=user.id,
            role=user.role if user.role in ["owner", "admin", "developer", "analyst", "viewer"] else Role.OWNER,
            created_at=datetime.datetime.now(datetime.timezone.utc),
        )
        db.add(membership)
        db.commit()

    if not membership:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authorization denied: You are not a member of the requested workspace.",
        )

    # Update active workspace pointer on user record
    user.tenant_id = target_tenant_id
    user.role = membership.role
    db.commit()

    # Issue fresh JWT token scoped strictly to target tenant with their specific role permissions
    scopes = get_role_permissions(membership.role)
    new_token = create_operator_token(
        principal=user.email,
        tenant_id=target_tenant_id,
        scopes=scopes,
        is_human=True,
        role=membership.role,
    )

    ops_bus.publish(
        component="workspaces",
        event_type="workspace.switched",
        level="info",
        message=f"Operator {user.email} switched context to workspace {tenant.name} ({target_tenant_id})",
    )

    return TokenResponse(
        access_token=new_token,
        token_type="bearer",
        expires_in=3600,
        user=UserResponse.model_validate(user),
    )


@router.get("/members", response_model=List[WorkspaceMemberInfo])
def list_workspace_members(
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    """Lists members belonging to current workspace."""
    memberships = (
        db.query(WorkspaceMemberModel, UserModel)
        .join(UserModel, WorkspaceMemberModel.user_id == UserModel.id)
        .filter(WorkspaceMemberModel.tenant_id == auth.tenant_id)
        .all()
    )

    result = []
    for mem, u in memberships:
        result.append(
            WorkspaceMemberInfo(
                user_id=u.id,
                email=u.email,
                full_name=u.full_name,
                role=mem.role,
                is_active=u.is_active,
                joined_at=mem.created_at,
            )
        )
    return result


@router.post("/members", response_model=WorkspaceMemberInfo, status_code=status.HTTP_201_CREATED)
def add_workspace_member(
    req: AddWorkspaceMemberRequest,
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    """Adds or invites an operator to current workspace. Requires owner or admin role."""
    if auth.role not in [Role.OWNER, Role.ADMIN] and not auth.has_permission(Permission.ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Managing workspace members requires Owner or Admin permissions.",
        )

    email = req.email.strip().lower()
    user = db.query(UserModel).filter(UserModel.email == email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No registered user found with this email address. The operator must register first.",
        )

    existing_mem = (
        db.query(WorkspaceMemberModel)
        .filter(
            WorkspaceMemberModel.tenant_id == auth.tenant_id,
            WorkspaceMemberModel.user_id == user.id,
        )
        .first()
    )
    if existing_mem:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User is already a member of this workspace.",
        )

    mem = WorkspaceMemberModel(
        id=f"wm-{uuid.uuid4().hex[:10]}",
        tenant_id=auth.tenant_id,
        user_id=user.id,
        role=req.role,
        created_at=datetime.datetime.now(datetime.timezone.utc),
    )
    db.add(mem)
    db.commit()

    return WorkspaceMemberInfo(
        user_id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=mem.role,
        is_active=user.is_active,
        joined_at=mem.created_at,
    )


@router.delete("/members/{user_id}")
def remove_workspace_member(
    user_id: str,
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    """Removes a member from the workspace. Prevents removing the last owner."""
    if auth.role not in [Role.OWNER, Role.ADMIN] and not auth.has_permission(Permission.ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Removing workspace members requires Owner or Admin permissions.",
        )

    mem = (
        db.query(WorkspaceMemberModel)
        .filter(
            WorkspaceMemberModel.tenant_id == auth.tenant_id,
            WorkspaceMemberModel.user_id == user_id,
        )
        .first()
    )
    if not mem:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found in this workspace.")

    # Guard: Do not allow removing the last owner
    if mem.role == Role.OWNER:
        owner_count = (
            db.query(func.count(WorkspaceMemberModel.id))
            .filter(
                WorkspaceMemberModel.tenant_id == auth.tenant_id,
                WorkspaceMemberModel.role == Role.OWNER,
            )
            .scalar()
            or 0
        )
        if owner_count <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot remove the last Owner of the workspace. Promote another member first.",
            )

    db.delete(mem)
    db.commit()
    return {"success": True, "message": "Member removed from workspace."}


@router.patch("/members/{user_id}", response_model=WorkspaceMemberInfo)
def update_member_role(
    user_id: str,
    req: UpdateWorkspaceMemberRoleRequest,
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    """Updates a member's role within current workspace."""
    if auth.role not in [Role.OWNER, Role.ADMIN] and not auth.has_permission(Permission.ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Modifying member roles requires Owner or Admin permissions.",
        )

    mem = (
        db.query(WorkspaceMemberModel)
        .filter(
            WorkspaceMemberModel.tenant_id == auth.tenant_id,
            WorkspaceMemberModel.user_id == user_id,
        )
        .first()
    )
    if not mem:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Member not found in this workspace.")

    user = db.query(UserModel).filter(UserModel.id == user_id).first()

    mem.role = req.role
    db.commit()

    return WorkspaceMemberInfo(
        user_id=user.id if user else user_id,
        email=user.email if user else "",
        full_name=user.full_name if user else None,
        role=mem.role,
        is_active=user.is_active if user else True,
        joined_at=mem.created_at,
    )


@router.put("/current")
def update_current_workspace_name(
    req: UpdateWorkspaceRequest,
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    """Updates current workspace display name. Requires Owner or Admin."""
    if auth.role not in [Role.OWNER, Role.ADMIN] and not auth.has_permission(Permission.ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Updating workspace settings requires Owner or Admin permissions.",
        )

    tenant = db.query(Tenant).filter(Tenant.id == auth.tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workspace not found.")

    tenant.name = req.name.strip()
    db.commit()
    return {"success": True, "name": tenant.name}

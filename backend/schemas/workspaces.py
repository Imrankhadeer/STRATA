import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, EmailStr


class WorkspaceInfo(BaseModel):
    id: str
    name: str
    role: str
    is_current: bool
    member_count: int = 1
    created_at: datetime.datetime


class CreateWorkspaceRequest(BaseModel):
    name: str = Field(min_length=2, max_length=128, description="Workspace / Organization name")


class SwitchWorkspaceRequest(BaseModel):
    tenant_id: str = Field(description="Target workspace tenant ID to switch context to")


class WorkspaceMemberInfo(BaseModel):
    user_id: str
    email: str
    full_name: Optional[str] = None
    role: str
    is_active: bool
    joined_at: datetime.datetime


class AddWorkspaceMemberRequest(BaseModel):
    email: EmailStr
    role: str = Field(default="viewer", pattern="^(owner|admin|developer|analyst|viewer)$")


class UpdateWorkspaceMemberRoleRequest(BaseModel):
    role: str = Field(pattern="^(owner|admin|developer|analyst|viewer)$")


class UpdateWorkspaceRequest(BaseModel):
    name: str = Field(min_length=2, max_length=128)

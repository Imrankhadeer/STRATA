"""
FastAPI Router for Ternline API Key Lifecycle Management.

Endpoints:
- POST /api/v1/keys          — Issue a new cryptographically random API key for an application
- GET  /api/v1/keys          — List active and revoked API keys for authenticated tenant (hashes/secrets never exposed)
- POST /api/v1/keys/{key_id}/revoke — Immediately revoke an API key
- POST /api/v1/keys/{key_id}/rotate — Rotate an API key (issues new key, revokes previous)
"""

import datetime
import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.models import ApiKey
from backend.core.auth import get_current_auth, AuthContext, generate_api_key
from backend.ops.bus import ops_bus

router = APIRouter(prefix="/api/v1/keys", tags=["API Key Lifecycle"])


# --- Schemas ---

class CreateApiKeyRequest(BaseModel):
    app_id: str = Field(
        ...,
        min_length=1,
        max_length=64,
        pattern=r"^[a-zA-Z0-9_\-\.]+$",
        description="Application identifier for which the key is issued",
    )
    expires_in_days: Optional[int] = Field(
        default=None,
        ge=1,
        le=365,
        description="Optional expiration in days (1 to 365)",
    )


class CreateApiKeyResponse(BaseModel):
    key_id: str
    tenant_id: str
    app_id: str
    api_key: str  # Raw secret, only exposed once upon creation
    key_prefix: str
    created_at: str
    expires_at: Optional[str]
    message: str = "Store this API key securely. It will not be shown again."


class ApiKeyInfoResponse(BaseModel):
    key_id: str
    tenant_id: str
    app_id: str
    key_prefix: str
    is_active: bool
    created_at: str
    expires_at: Optional[str]


class RevokeApiKeyResponse(BaseModel):
    key_id: str
    tenant_id: str
    is_active: bool
    status: str
    message: str


class RotateApiKeyResponse(BaseModel):
    old_key_id: str
    new_key_id: str
    tenant_id: str
    app_id: str
    new_api_key: str  # Raw secret, only exposed once upon rotation
    key_prefix: str
    created_at: str
    expires_at: Optional[str]
    message: str = "Old key revoked. Store this new API key securely. It will not be shown again."


# --- Endpoints ---

@router.post("", response_model=CreateApiKeyResponse, status_code=status.HTTP_201_CREATED)
def create_api_key(
    payload: CreateApiKeyRequest,
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    """
    Issues a new cryptographically random API key for the authenticated tenant.
    The raw secret key is returned strictly in this response and never stored in plaintext.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    raw_key, key_hash = generate_api_key(tenant_id=auth.tenant_id, app_id=payload.app_id)
    key_prefix = raw_key[:12]  # e.g., 'ce_live_...'

    expires_at = None
    if payload.expires_in_days:
        expires_at = now + datetime.timedelta(days=payload.expires_in_days)

    key_id = f"key-{uuid.uuid4().hex[:12]}"
    api_key_rec = ApiKey(
        id=key_id,
        tenant_id=auth.tenant_id,
        app_id=payload.app_id,
        key_hash=key_hash,
        key_prefix=key_prefix,
        is_active=True,
        created_at=now.replace(tzinfo=None),
        expires_at=expires_at.replace(tzinfo=None) if expires_at else None,
    )

    db.add(api_key_rec)
    db.commit()

    ops_bus.publish(
        component="auth",
        event_type="auth.key_created",
        level="info",
        message=f"API key created for app '{payload.app_id}' with prefix '{key_prefix}'",
        tenant_id=auth.tenant_id,
        metadata={"key_id": key_id, "app_id": payload.app_id, "key_prefix": key_prefix},
    )

    return CreateApiKeyResponse(
        key_id=key_id,
        tenant_id=auth.tenant_id,
        app_id=payload.app_id,
        api_key=raw_key,
        key_prefix=key_prefix,
        created_at=now.isoformat(),
        expires_at=expires_at.isoformat() if expires_at else None,
    )


@router.get("", response_model=List[ApiKeyInfoResponse])
def list_api_keys(
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    """
    Lists all API keys for the authenticated tenant.
    Strict tenant isolation is enforced: keys belonging to other tenants are never returned.
    Secrets and hashes are never exposed.
    """
    keys = (
        db.query(ApiKey)
        .filter(ApiKey.tenant_id == auth.tenant_id)
        .order_by(ApiKey.created_at.desc())
        .all()
    )

    return [
        ApiKeyInfoResponse(
            key_id=k.id,
            tenant_id=k.tenant_id,
            app_id=k.app_id,
            key_prefix=k.key_prefix,
            is_active=k.is_active,
            created_at=k.created_at.isoformat() if k.created_at else "",
            expires_at=k.expires_at.isoformat() if k.expires_at else None,
        )
        for k in keys
    ]


@router.post("/{key_id}/revoke", response_model=RevokeApiKeyResponse)
def revoke_api_key(
    key_id: str,
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    """
    Immediately deactivates an API key.
    Enforces tenant boundaries: an authenticated tenant can only revoke keys they own.
    """
    key_rec = (
        db.query(ApiKey)
        .filter(ApiKey.id == key_id, ApiKey.tenant_id == auth.tenant_id)
        .first()
    )

    if not key_rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API key '{key_id}' not found for this tenant.",
        )

    key_rec.is_active = False
    db.commit()

    ops_bus.publish(
        component="auth",
        event_type="auth.key_revoked",
        level="warn",
        message=f"API key '{key_id}' was revoked for app '{key_rec.app_id}'",
        tenant_id=auth.tenant_id,
        metadata={"key_id": key_id, "app_id": key_rec.app_id},
    )

    return RevokeApiKeyResponse(
        key_id=key_id,
        tenant_id=auth.tenant_id,
        is_active=False,
        status="revoked",
        message="API key has been successfully revoked and can no longer authenticate requests.",
    )


@router.post("/{key_id}/rotate", response_model=RotateApiKeyResponse)
def rotate_api_key(
    key_id: str,
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    """
    Rotates an API key: revokes the existing key and generates a new active key for the same app_id.
    Returns the new raw secret key strictly once.
    """
    old_key = (
        db.query(ApiKey)
        .filter(ApiKey.id == key_id, ApiKey.tenant_id == auth.tenant_id)
        .first()
    )

    if not old_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API key '{key_id}' not found for this tenant.",
        )

    # 1. Revoke the existing key
    old_key.is_active = False

    # 2. Generate a new key for the same application
    now = datetime.datetime.now(datetime.timezone.utc)
    raw_key, key_hash = generate_api_key(tenant_id=auth.tenant_id, app_id=old_key.app_id)
    key_prefix = raw_key[:12]
    new_key_id = f"key-{uuid.uuid4().hex[:12]}"

    new_key_rec = ApiKey(
        id=new_key_id,
        tenant_id=auth.tenant_id,
        app_id=old_key.app_id,
        key_hash=key_hash,
        key_prefix=key_prefix,
        is_active=True,
        created_at=now.replace(tzinfo=None),
        expires_at=None,
    )

    db.add(new_key_rec)
    db.commit()

    ops_bus.publish(
        component="auth",
        event_type="auth.key_rotated",
        level="info",
        message=f"API key '{key_id}' rotated to '{new_key_id}' for app '{old_key.app_id}'",
        tenant_id=auth.tenant_id,
        metadata={"old_key_id": key_id, "new_key_id": new_key_id, "app_id": old_key.app_id},
    )

    return RotateApiKeyResponse(
        old_key_id=key_id,
        new_key_id=new_key_id,
        tenant_id=auth.tenant_id,
        app_id=old_key.app_id,
        new_api_key=raw_key,
        key_prefix=key_prefix,
        created_at=now.isoformat(),
        expires_at=None,
    )


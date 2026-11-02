import datetime
import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.db.session import get_db
from backend.models import ApplicationModel, ApiKey, EventModel, Tenant
from backend.core.auth import (
    AuthContext,
    Permission,
    Role,
    generate_api_key,
    get_current_auth,
    require_permission,
)
from backend.schemas.apps import (
    CreateAppRequest,
    AppResponse,
    CreateAppResponse,
)
from backend.ops.bus import ops_bus

router = APIRouter(prefix="/api/v1/apps", tags=["Application Lifecycle & Registration"])


def _backfill_legacy_applications(tenant_id: str, db: Session):
    """Backfills legacy app_ids present in api_keys or events into applications table."""
    existing_app_ids = {
        row[0]
        for row in db.query(ApplicationModel.id)
        .filter(ApplicationModel.tenant_id == tenant_id)
        .all()
    }

    # Discover from api_keys
    key_app_ids = (
        db.query(ApiKey.app_id)
        .filter(ApiKey.tenant_id == tenant_id, ApiKey.is_active == True)
        .distinct()
        .all()
    )
    for (aid,) in key_app_ids:
        if aid and aid not in existing_app_ids:
            now = datetime.datetime.now(datetime.timezone.utc)
            app = ApplicationModel(
                id=aid,
                tenant_id=tenant_id,
                name=aid.replace("-", " ").replace("_", " ").title(),
                description="Automatically discovered from active ingestion API key.",
                environment="production",
                is_active=True,
                created_at=now,
                updated_at=now,
            )
            db.add(app)
            existing_app_ids.add(aid)
    db.commit()


@router.get("", response_model=List[AppResponse])
def list_applications(
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    """Lists all registered applications in current workspace with live telemetry stats."""
    _backfill_legacy_applications(auth.tenant_id, db)

    apps = (
        db.query(ApplicationModel)
        .filter(ApplicationModel.tenant_id == auth.tenant_id, ApplicationModel.is_active == True)
        .order_by(ApplicationModel.created_at.desc())
        .all()
    )

    result = []
    now = datetime.datetime.now(datetime.timezone.utc)
    one_week_ago = now - datetime.timedelta(days=7)

    for app in apps:
        # Compute event telemetry stats
        event_stats = (
            db.query(
                func.count(EventModel.event_id),
                func.max(EventModel.timestamp),
            )
            .filter(EventModel.tenant_id == auth.tenant_id, EventModel.app_id == app.id)
            .first()
        )
        count = event_stats[0] or 0
        last_event = event_stats[1]

        # Fetch active key prefix
        active_key = (
            db.query(ApiKey)
            .filter(
                ApiKey.tenant_id == auth.tenant_id,
                ApiKey.app_id == app.id,
                ApiKey.is_active == True,
            )
            .order_by(ApiKey.created_at.desc())
            .first()
        )

        status_str = "awaiting_telemetry"
        if last_event:
            ts = last_event.replace(tzinfo=datetime.timezone.utc) if last_event.tzinfo is None else last_event
            if ts >= one_week_ago:
                status_str = "live_ingesting"
            else:
                status_str = "idle"

        result.append(
            AppResponse(
                app_id=app.id,
                name=app.name,
                description=app.description,
                environment=app.environment,
                is_active=app.is_active,
                created_at=app.created_at,
                updated_at=app.updated_at,
                event_count=count,
                last_event_at=last_event,
                active_key_prefix=active_key.key_prefix if active_key else None,
                status=status_str,
            )
        )
    return result


@router.post("", response_model=CreateAppResponse, status_code=status.HTTP_201_CREATED)
def register_application(
    req: CreateAppRequest,
    auth: AuthContext = Depends(require_permission(Permission.KEYS_WRITE)),
    db: Session = Depends(get_db),
):
    """
    Registers a new application within the current workspace and immediately
    issues a dedicated, cryptographically hashed ingestion API key.
    """
    app_id = req.app_id.strip()

    # Check for existing application with same ID in this workspace
    existing = (
        db.query(ApplicationModel)
        .filter(ApplicationModel.tenant_id == auth.tenant_id, ApplicationModel.id == app_id)
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"An application with identifier '{app_id}' already exists in this workspace.",
        )

    now = datetime.datetime.now(datetime.timezone.utc)
    app = ApplicationModel(
        id=app_id,
        tenant_id=auth.tenant_id,
        name=req.name.strip(),
        description=req.description.strip() if req.description else None,
        environment=req.environment,
        is_active=True,
        created_at=now,
        updated_at=now,
    )
    db.add(app)

    # Automatically provision scoped ingestion API key
    raw_key, key_hash = generate_api_key(tenant_id=auth.tenant_id, app_id=app_id)
    key_prefix = raw_key[:12] + "..."
    key_model = ApiKey(
        id=f"key-{uuid.uuid4().hex[:12]}",
        tenant_id=auth.tenant_id,
        app_id=app_id,
        key_hash=key_hash,
        key_prefix=key_prefix,
        is_active=True,
        scopes=["events:ingest"],
        created_at=now,
    )
    db.add(key_model)
    db.commit()

    ops_bus.publish(
        component="apps",
        event_type="app.registered",
        level="info",
        message=f"Application '{app.name}' ({app.id}) registered in workspace {auth.tenant_id}",
    )

    app_resp = AppResponse(
        app_id=app.id,
        name=app.name,
        description=app.description,
        environment=app.environment,
        is_active=app.is_active,
        created_at=app.created_at,
        updated_at=app.updated_at,
        event_count=0,
        last_event_at=None,
        active_key_prefix=key_prefix,
        status="awaiting_telemetry",
    )

    return CreateAppResponse(
        app=app_resp,
        api_key=raw_key,
        key_prefix=key_prefix,
        message=f"Application '{app.name}' registered successfully. Copy the ingestion key now; it will not be displayed again.",
    )


@router.get("/{app_id}", response_model=AppResponse)
def get_application(
    app_id: str,
    auth: AuthContext = Depends(get_current_auth),
    db: Session = Depends(get_db),
):
    """Retrieves application metadata and telemetry statistics."""
    app = (
        db.query(ApplicationModel)
        .filter(ApplicationModel.tenant_id == auth.tenant_id, ApplicationModel.id == app_id)
        .first()
    )
    if not app:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Application not found.")

    event_stats = (
        db.query(
            func.count(EventModel.event_id),
            func.max(EventModel.timestamp),
        )
        .filter(EventModel.tenant_id == auth.tenant_id, EventModel.app_id == app.id)
        .first()
    )

    active_key = (
        db.query(ApiKey)
        .filter(
            ApiKey.tenant_id == auth.tenant_id,
            ApiKey.app_id == app.id,
            ApiKey.is_active == True,
        )
        .order_by(ApiKey.created_at.desc())
        .first()
    )

    return AppResponse(
        app_id=app.id,
        name=app.name,
        description=app.description,
        environment=app.environment,
        is_active=app.is_active,
        created_at=app.created_at,
        updated_at=app.updated_at,
        event_count=event_stats[0] or 0,
        last_event_at=event_stats[1],
        active_key_prefix=active_key.key_prefix if active_key else None,
        status="live_ingesting" if event_stats[0] else "awaiting_telemetry",
    )


@router.delete("/{app_id}")
def delete_application(
    app_id: str,
    auth: AuthContext = Depends(require_permission(Permission.KEYS_WRITE)),
    db: Session = Depends(get_db),
):
    """Deactivates an application and revokes all its active API keys."""
    app = (
        db.query(ApplicationModel)
        .filter(ApplicationModel.tenant_id == auth.tenant_id, ApplicationModel.id == app_id)
        .first()
    )
    if not app:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Application not found.")

    app.is_active = False
    app.updated_at = datetime.datetime.now(datetime.timezone.utc)

    # Invalidate all keys for this application
    keys = (
        db.query(ApiKey)
        .filter(ApiKey.tenant_id == auth.tenant_id, ApiKey.app_id == app_id)
        .all()
    )
    for k in keys:
        k.is_active = False

    db.commit()

    ops_bus.publish(
        component="apps",
        event_type="app.deactivated",
        level="warn",
        message=f"Application '{app_id}' deactivated and {len(keys)} keys revoked in workspace {auth.tenant_id}",
    )

    return {"success": True, "message": f"Application '{app_id}' deactivated and API keys revoked."}


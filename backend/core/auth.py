import hashlib
import secrets
from fastapi import Security, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from backend.db.session import get_db
from backend.models import ApiKey, Tenant
from backend.ops.bus import ops_bus


security_bearer = HTTPBearer(auto_error=False)


def hash_api_key(raw_key: str) -> str:
    """Computes SHA-256 hash of the provided API key."""
    return hashlib.sha256(raw_key.strip().encode("utf-8")).hexdigest()


def generate_api_key(tenant_id: str, app_id: str, prefix: str = "ce_live_") -> tuple[str, str]:
    """
    Generates a secure cryptographically random API key.
    Returns (raw_key, key_hash).
    """
    random_secret = secrets.token_urlsafe(32)
    raw_key = f"{prefix}{random_secret}"
    key_hash = hash_api_key(raw_key)
    return raw_key, key_hash


class AuthContext:
    def __init__(self, tenant_id: str, app_id: str, key_id: str):
        self.tenant_id = tenant_id
        self.app_id = app_id
        self.key_id = key_id


def get_current_auth(
    credentials: HTTPAuthorizationCredentials = Security(security_bearer),
    db: Session = Depends(get_db)
) -> AuthContext:
    """
    Validates API key from Authorization: Bearer <key> header.
    Enforces tenant isolation server-side.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header with valid Bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    raw_key = credentials.credentials
    key_hash = hash_api_key(raw_key)

    api_key_record = (
        db.query(ApiKey)
        .filter(ApiKey.key_hash == key_hash, ApiKey.is_active == True)
        .first()
    )

    if not api_key_record:
        ops_bus.publish(
            component="auth",
            event_type="auth.rejected",
            level="warn",
            message="API request rejected: invalid or inactive API key",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Enforce key expiration if configured
    if api_key_record.expires_at:
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc)
        exp = api_key_record.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=datetime.timezone.utc)
        if exp < now:
            ops_bus.publish(
                component="auth",
                event_type="auth.rejected",
                level="warn",
                message="API request rejected: expired API key",
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # Verify active tenant
    tenant = db.query(Tenant).filter(Tenant.id == api_key_record.tenant_id, Tenant.is_active == True).first()
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tenant is inactive or does not exist"
        )

    return AuthContext(
        tenant_id=api_key_record.tenant_id,
        app_id=api_key_record.app_id,
        key_id=api_key_record.id,
    )

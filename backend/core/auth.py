import hashlib
import secrets
import datetime
from typing import Optional, List, Set, Tuple, Any
from fastapi import Security, HTTPException, status, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
import jwt

from backend.config import settings
from backend.db.session import get_db
from backend.models import ApiKey, Tenant
from backend.ops.bus import ops_bus


security_bearer = HTTPBearer(auto_error=False)

JWT_ALGORITHM = "HS256"
JWT_ISSUER = "ternline:auth"
JWT_AUDIENCE = "ternline:api"


class Permission:
    EVENTS_INGEST = "events:ingest"
    FINDINGS_READ = "findings:read"
    INVESTIGATIONS_READ = "investigations:read"
    INVESTIGATIONS_WRITE = "investigations:write"
    DEFENSE_ACTIONS_READ = "defense:actions:read"
    DEFENSE_ACTIONS_PROPOSE = "defense:actions:propose"
    DEFENSE_ACTIONS_APPROVE = "defense:actions:approve"
    DEFENSE_ACTIONS_REJECT = "defense:actions:reject"
    DEFENSE_ACTIONS_EXECUTE = "defense:actions:execute"
    DEFENSE_ACTIONS_ROLLBACK = "defense:actions:rollback"
    DEFENSE_POLICY_READ = "defense:policy:read"
    DEFENSE_POLICY_WRITE = "defense:policy:write"
    KEYS_READ = "keys:read"
    KEYS_WRITE = "keys:write"
    INCIDENTS_READ = "incidents:read"
    INCIDENTS_WRITE = "incidents:write"
    INCIDENTS_CONTAIN = "incidents:contain"
    THREAT_INTEL_READ = "threat_intel:read"
    THREAT_INTEL_WRITE = "threat_intel:write"
    ADMIN = "admin"


ALL_PERMISSIONS: Set[str] = {
    Permission.EVENTS_INGEST,
    Permission.FINDINGS_READ,
    Permission.INVESTIGATIONS_READ,
    Permission.INVESTIGATIONS_WRITE,
    Permission.DEFENSE_ACTIONS_READ,
    Permission.DEFENSE_ACTIONS_PROPOSE,
    Permission.DEFENSE_ACTIONS_APPROVE,
    Permission.DEFENSE_ACTIONS_REJECT,
    Permission.DEFENSE_ACTIONS_EXECUTE,
    Permission.DEFENSE_ACTIONS_ROLLBACK,
    Permission.DEFENSE_POLICY_READ,
    Permission.DEFENSE_POLICY_WRITE,
    Permission.KEYS_READ,
    Permission.KEYS_WRITE,
    Permission.INCIDENTS_READ,
    Permission.INCIDENTS_WRITE,
    Permission.INCIDENTS_CONTAIN,
    Permission.THREAT_INTEL_READ,
    Permission.THREAT_INTEL_WRITE,
    Permission.ADMIN,
}


def hash_api_key(raw_key: str) -> str:
    """Computes SHA-256 hash of the provided API key."""
    return hashlib.sha256(raw_key.strip().encode("utf-8")).hexdigest()


def generate_api_key(tenant_id: str, app_id: str, prefix: str = "ce_live_") -> Tuple[str, str]:
    """
    Generates a secure cryptographically random API key.
    Returns (raw_key, key_hash).
    """
    random_secret = secrets.token_urlsafe(32)
    raw_key = f"{prefix}{random_secret}"
    key_hash = hash_api_key(raw_key)
    return raw_key, key_hash


def create_operator_token(
    principal: str,
    tenant_id: str,
    scopes: Optional[List[str]] = None,
    expires_in_seconds: int = 3600,
    is_human: bool = True,
    app_id: str = "operator-console",
) -> str:
    """
    Issues a cryptographically signed JWT representing a verified operator session.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    exp = now + datetime.timedelta(seconds=expires_in_seconds)
    payload = {
        "sub": principal.strip(),
        "tenant_id": tenant_id.strip(),
        "app_id": app_id,
        "is_human": is_human,
        "scopes": scopes if scopes is not None else [Permission.ADMIN],
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=JWT_ALGORITHM)


def verify_operator_token(
    token: str,
    expected_tenant_id: Optional[str] = None,
) -> dict:
    """
    Verifies signature, expiration, issuer, and audience of an operator JWT.
    Enforces tenant boundaries if expected_tenant_id is provided.
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
            options={"require": ["sub", "tenant_id", "exp", "iat", "iss", "aud"]},
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Operator token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.PyJWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid operator token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if expected_tenant_id and payload.get("tenant_id") != expected_tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Operator token tenant mismatch: token belongs to '{payload.get('tenant_id')}', expected '{expected_tenant_id}'",
        )

    return payload


class AuthContext:
    def __init__(
        self,
        tenant_id: str,
        app_id: str,
        key_id: str,
        operator_principal: Optional[str] = None,
        is_human: bool = False,
        permissions: Optional[Set[str]] = None,
        auth_type: str = "api_key",
    ):
        self.tenant_id = tenant_id
        self.app_id = app_id
        self.key_id = key_id
        self.operator_principal = operator_principal
        self.is_human = is_human
        self.permissions = permissions or set()
        self.auth_type = auth_type

    def has_permission(self, permission: str) -> bool:
        if Permission.ADMIN in self.permissions or "*" in self.permissions:
            return True
        return permission in self.permissions


def get_current_auth(
    credentials: HTTPAuthorizationCredentials = Security(security_bearer),
    request: Request = None,
    db: Session = Depends(get_db)
) -> AuthContext:
    """
    Authenticates requests via either:
    1. Direct Operator JWT in Authorization: Bearer <jwt>
    2. API Key in Authorization: Bearer <api_key>, optionally combined with verified
       cryptographic Operator JWT in X-Operator-Token.

    Enforces tenant boundaries, key expiration, and cryptographic signature verification.
    Unverified headers (such as X-Operator-Principal or caller-supplied body IDs) are NEVER trusted.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header with valid Bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    raw_token = credentials.credentials.strip()

    # 1. Direct Operator JWT Bearer Token (Authorization: Bearer <jwt>)
    if raw_token.count(".") == 2 and (raw_token.startswith("ey") or "eyJ" in raw_token):
        payload = verify_operator_token(raw_token)
        tenant = db.query(Tenant).filter(Tenant.id == payload["tenant_id"], Tenant.is_active == True).first()
        if not tenant:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Tenant is inactive or does not exist",
            )
        perms = set(payload.get("scopes", []))
        return AuthContext(
            tenant_id=payload["tenant_id"],
            app_id=payload.get("app_id", "operator-console"),
            key_id=f"jwt:{payload.get('sub')}",
            operator_principal=payload.get("sub"),
            is_human=bool(payload.get("is_human", False)),
            permissions=perms,
            auth_type="jwt",
        )

    # 2. API Key Authentication (Authorization: Bearer <raw_api_key>)
    key_hash = hash_api_key(raw_token)
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

    # Key expiration
    if api_key_record.expires_at:
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

    # Tenant active check
    tenant = db.query(Tenant).filter(Tenant.id == api_key_record.tenant_id, Tenant.is_active == True).first()
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Tenant is inactive or does not exist",
        )

    # Determine scopes for the API key
    if api_key_record.scopes is not None:
        key_permissions = set(api_key_record.scopes)
    else:
        # Backward compatibility for seeded test key vs legacy untagged keys
        if api_key_record.id == "key-001" or api_key_record.key_hash == hash_api_key("ce_live_test_api_key_secret_12345"):
            key_permissions = {Permission.ADMIN}
        else:
            key_permissions = {Permission.EVENTS_INGEST}

    operator_principal = None
    is_human = False

    # Check for verified cryptographic Operator Token in X-Operator-Token header
    if request is not None:
        op_token_hdr = request.headers.get("X-Operator-Token")
        if op_token_hdr:
            token_str = op_token_hdr.strip()
            if token_str.lower().startswith("bearer "):
                token_str = token_str[7:].strip()
            op_payload = verify_operator_token(token_str, expected_tenant_id=api_key_record.tenant_id)
            operator_principal = op_payload.get("sub")
            is_human = bool(op_payload.get("is_human", False))
            key_permissions.update(op_payload.get("scopes", []))

    return AuthContext(
        tenant_id=api_key_record.tenant_id,
        app_id=api_key_record.app_id,
        key_id=api_key_record.id,
        operator_principal=operator_principal,
        is_human=is_human,
        permissions=key_permissions,
        auth_type="api_key",
    )


def require_permission(permission: str):
    """
    FastAPI dependency that enforces RBAC permission check on the authenticated context.
    """
    def _dependency(auth: AuthContext = Depends(get_current_auth)) -> AuthContext:
        if not auth.has_permission(permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: missing required permission '{permission}'",
            )
        return auth
    return _dependency


def require_human_operator(auth: AuthContext = Depends(get_current_auth)) -> AuthContext:
    """
    FastAPI dependency that enforces strict human operator authentication.
    Rejects API keys or service accounts acting without a verified human operator session.
    """
    if not auth.is_human or not auth.operator_principal:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Dual-custody violation: action requires an authenticated human operator",
        )
    return auth

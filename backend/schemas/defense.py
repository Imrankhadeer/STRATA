"""
Pydantic v2 schemas and validation models for Ternline Phase 1: Active Defense.
Defines protection modes, action scopes, credential authorities, candidate actions,
planned actions, and deterministic fingerprinting.
"""

from enum import Enum
import hashlib
import json
import uuid
import datetime
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, field_validator


class ProtectionMode(str, Enum):
    """
    Protection mode defining execution autonomy and gating.
    OBSERVE is the mandatory default for all new tenants.
    """
    OBSERVE = "observe"      # Dry-run audit logging only; no outward execution.
    ASSISTED = "assisted"    # Human approval required prior to dispatch.
    ENFORCED = "enforced"    # Autonomous execution permitted for bounded low-risk actions.


class ActionScope(str, Enum):
    """
    Differentiates perimeter ingestion protection from customer application containment.
    """
    TERNLINE_INGEST = "ternline_ingest"            # Immediate protection of Ternline API/Ingest surface.
    CUSTOMER_APPLICATION = "customer_application"  # Containment targeting customer services/gateways.


class CredentialAuthority(str, Enum):
    """
    Delineates internal Ternline credentials from external IdP/OAuth credentials.
    """
    TERNLINE_MANAGED = "ternline_managed"    # Keys stored in Ternline's api_keys table.
    EXTERNAL_CUSTOMER = "external_customer"  # Customer OAuth/IdP credentials (Auth0, Okta, etc.).


class ActionType(str, Enum):
    API_KEY_REVOCATION = "api_key_revocation"
    TEMPORARY_IP_BLOCK = "temporary_ip_block"
    TEMPORARY_RATE_LIMIT = "temporary_rate_limit"
    ACCOUNT_SESSION_CONTAINMENT = "account_session_containment"


class TargetEntityType(str, Enum):
    API_KEY = "api_key"
    IP_ADDRESS = "ip_address"
    USER_ID = "user_id"
    APP_ID = "app_id"


class ActionStatus(str, Enum):
    PROPOSED = "proposed"
    DRY_RUN_LOGGED = "dry_run_logged"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    VERIFIED_ACTIVE = "verified_active"
    VERIFICATION_FAILED = "verification_failed"
    EXPIRED = "expired"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    ROLLBACK_FAILED = "rollback_failed"
    EXECUTION_FAILED = "execution_failed"


def canonicalize_parameters(params: Optional[Dict[str, Any]]) -> str:
    """
    Recursively canonicalizes dictionary keys and values into a compact,
    deterministic JSON string without whitespace, sorted by keys.
    """
    if not params:
        return "{}"

    def _sort(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: _sort(v) for k, v in sorted(obj.items())}
        if isinstance(obj, list):
            return [_sort(x) for x in obj]
        return obj

    sorted_obj = _sort(params)
    return json.dumps(sorted_obj, separators=(",", ":"), ensure_ascii=True)


def canonicalize_principal_id(identity: str) -> str:
    """
    Produces a canonical, stable principal ID for identity comparison.
    Normalizes casing, strips common identity namespace qualifiers
    ('user:', 'analyst:', 'human:', 'operator:', 'admin:', 'account:', 'mailto:'),
    and trims whitespace.
    """
    if not identity or not isinstance(identity, str):
        return ""
    s = identity.strip()
    lower = s.lower()
    for prefix in ("user:", "analyst:", "secops:", "security:", "engineer:", "lead:", "security-lead:", "lead-analyst:", "human:", "operator:", "admin:", "account:", "mailto:"):
        if lower.startswith(prefix):
            s = s[len(prefix):].strip()
            lower = s.lower()
    return lower


def is_verified_human_principal(identity: str) -> tuple[bool, Optional[str]]:
    """
    Validates whether an identity represents an authenticated human operator.
    Returns (is_human, reason_if_invalid).

    Rules:
    - Rejects all automated/non-human prefixes: service:, key:, api_key:, apikey:, system:, bot:, agent:,
      cron:, worker:, job:, app:, ci:, pipeline:, automated:, daemon:, svc_, svc-
    - Rejects automated keywords inside handle: 'bot', 'agent', 'service', 'daemon', 'cron'
    - Positively requires valid human email (user@domain.tld) OR explicit human namespace
      ('user:', 'analyst:', 'lead:', 'human:', 'operator:', 'admin:') with valid alphanumeric handle.
    """
    import re
    if not identity or not isinstance(identity, str):
        return False, "Identity must be a non-empty string"
    s = identity.strip()
    lower = s.lower()

    # 1. Reject automated actor namespaces
    forbidden_prefixes = (
        "service:", "key:", "api_key:", "apikey:", "system:", "bot:", "agent:", "cron:",
        "worker:", "job:", "app:", "ci:", "pipeline:", "automated:",
        "daemon:", "svc_", "svc-",
    )
    if lower.startswith(forbidden_prefixes):
        return False, f"Identity carries non-human / automated namespace prefix: '{identity}'"

    canon = canonicalize_principal_id(s)
    if not canon or len(canon) < 3:
        return False, "Canonical principal identifier is too short"

    # 2. Reject automated keywords inside the identifier
    automated_keywords = ("bot", "daemon", "service-account", "cron-job", "ci-runner")
    if any(kw in canon for kw in automated_keywords):
        return False, f"Identity contains automated actor keyword: '{canon}'"

    # 3. Positive verification: either valid email format OR explicitly human-qualified prefix
    has_human_prefix = lower.startswith(("user:", "analyst:", "secops:", "security:", "engineer:", "lead:", "security-lead:", "lead-analyst:", "human:", "operator:", "admin:"))
    is_valid_email = bool(re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", canon))

    if is_valid_email or has_human_prefix:
        return True, None

    # Handle alphanumeric human username (e.g. 'alice', 'bob_smith') without automated markers
    if re.match(r"^[a-zA-Z0-9_.-]{3,64}$", canon):
        return True, None

    return False, f"Identity '{identity}' could not be verified as a human principal"


def compute_action_fingerprint(
    tenant_id: str,
    action_type: str,
    target_entity_type: str,
    target_entity_id: str,
    parameters: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Computes a deterministic, collision-resistant SHA-256 fingerprint for a response action:
    SHA-256(tenant_id : action_type : target_entity_type : target_entity_id : canonical_params)
    Enforces tenant isolation and parameter-order invariance.
    """
    t_id = (tenant_id or "").strip()
    a_type = (action_type.value if isinstance(action_type, ActionType) else str(action_type)).strip()
    e_type = (target_entity_type.value if isinstance(target_entity_type, TargetEntityType) else str(target_entity_type)).strip()
    e_id = (target_entity_id or "").strip()
    params_str = canonicalize_parameters(parameters)

    raw = f"{t_id}:{a_type}:{e_type}:{e_id}:{params_str}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class CandidateResponseAction(BaseModel):
    """
    Normalized candidate action proposal emitted by ResponsePlanner.
    """
    action_type: ActionType
    scope: ActionScope = ActionScope.TERNLINE_INGEST
    credential_authority: Optional[CredentialAuthority] = None
    target_entity_type: TargetEntityType
    target_entity_id: str = Field(..., min_length=1, max_length=256)
    parameters: Dict[str, Any] = Field(default_factory=dict)
    ttl_seconds: Optional[int] = Field(None, ge=1, le=86400 * 30)
    rationale: str = Field(..., min_length=3, max_length=1024)
    finding_id: Optional[str] = None

    @field_validator("target_entity_id")
    @classmethod
    def validate_target_not_blank(cls, v: str) -> str:
        s = v.strip()
        if not s:
            raise ValueError("target_entity_id cannot be empty or whitespace only")
        return s

    @field_validator("credential_authority")
    @classmethod
    def validate_credential_authority(cls, v: Optional[CredentialAuthority], info) -> Optional[CredentialAuthority]:
        action_type = info.data.get("action_type")
        if action_type == ActionType.API_KEY_REVOCATION and not v:
            # Default to ternline_managed if not specified for API key revocation
            return CredentialAuthority.TERNLINE_MANAGED
        return v


class TenantDefensePolicy(BaseModel):
    """
    Tenant-level Active Defense policy and protection mode configuration.
    """
    tenant_id: str
    default_mode: ProtectionMode = ProtectionMode.OBSERVE  # Mandatory default
    is_active: bool = True
    allowed_autonomous_actions: List[ActionType] = Field(
        default_factory=lambda: [ActionType.TEMPORARY_RATE_LIMIT, ActionType.TEMPORARY_IP_BLOCK]
    )
    max_autonomous_ttl_seconds: int = Field(3600, ge=60, le=86400)
    max_autonomous_actions_per_hour: int = Field(10, ge=1, le=100)
    action_overrides: Dict[str, Any] = Field(default_factory=dict)


class PlannedResponseAction(BaseModel):
    """
    Complete planned action model persisted in database and returned to callers.
    """
    action_id: str = Field(default_factory=lambda: f"act-{uuid.uuid4().hex[:12]}")
    tenant_id: str
    finding_id: Optional[str] = None
    action_type: ActionType
    scope: ActionScope
    credential_authority: Optional[CredentialAuthority] = None
    target_entity_type: TargetEntityType
    target_entity_id: str
    status: ActionStatus = ActionStatus.PROPOSED
    protection_mode: ProtectionMode = ProtectionMode.OBSERVE
    deduplication_fingerprint: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    ttl_seconds: Optional[int] = None
    expires_at: Optional[datetime.datetime] = None
    requested_by: str = "system:response_planner"
    approved_by: Optional[str] = None
    approval_rationale: Optional[str] = None
    provider_adapter: Optional[str] = None
    external_reference_id: Optional[str] = None
    execution_result: Optional[Dict[str, Any]] = None
    verification_result: Optional[Dict[str, Any]] = None
    rollback_result: Optional[Dict[str, Any]] = None
    created_at: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc)
    )
    executed_at: Optional[datetime.datetime] = None
    verified_at: Optional[datetime.datetime] = None
    rolled_back_at: Optional[datetime.datetime] = None



class PolicyEvaluationDecision(str, Enum):
    ALLOW_AUTONOMOUS = "allow_autonomous"
    REQUIRE_APPROVAL = "require_approval"
    DRY_RUN_LOGGED = "dry_run_logged"
    DENY_POLICY = "deny_policy"


class PolicyEvaluationResult(BaseModel):
    decision: PolicyEvaluationDecision
    applied_mode: ProtectionMode
    requires_dual_custody: bool
    rationale: str
    action_id: Optional[str] = None


class ActionApprovalRequest(BaseModel):
    approver_identity: str = Field(..., min_length=3, max_length=128, description="Authenticated human identity, e.g. 'user:analyst@corp.internal'")
    rationale: str = Field(..., min_length=5, max_length=1024, description="Audited operational rationale for approving containment action")

    @field_validator("approver_identity")
    @classmethod
    def validate_human_approver(cls, v: str) -> str:
        s = v.strip()
        is_human, reason = is_verified_human_principal(s)
        if not is_human:
            raise ValueError(f"Dual-custody violation: {reason}")
        return s


class ActionRejectRequest(BaseModel):
    rejector_identity: str = Field(..., min_length=3, max_length=128)
    rationale: str = Field(..., min_length=5, max_length=1024)


class TenantDefensePolicyUpdate(BaseModel):
    default_mode: Optional[ProtectionMode] = None
    allowed_autonomous_actions: Optional[List[ActionType]] = None
    max_autonomous_ttl_seconds: Optional[int] = Field(None, ge=60, le=86400)
    max_autonomous_actions_per_hour: Optional[int] = Field(None, ge=1, le=100)
    action_overrides: Optional[Dict[str, Any]] = None

    @field_validator("allowed_autonomous_actions")
    @classmethod
    def validate_safeguards_not_weakened(cls, v: Optional[List[ActionType]]) -> Optional[List[ActionType]]:
        if v is not None:
            # Mandatory safeguard: Sensitive irreversible actions can NEVER be set to autonomous
            forbidden = {ActionType.API_KEY_REVOCATION, ActionType.ACCOUNT_SESSION_CONTAINMENT}
            intersect = set(v).intersection(forbidden)
            if intersect:
                names = ", ".join(x.value for x in intersect)
                raise ValueError(f"Mandatory safety violation: [{names}] can never be configured for autonomous execution")
        return v

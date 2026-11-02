import datetime
from sqlalchemy import (
    Column,
    String,
    DateTime,
    Boolean,
    ForeignKey,
    JSON,
    Index,
    UniqueConstraint,
    Text,
    Integer,
    text,
)
from sqlalchemy.orm import relationship
from backend.db.session import Base


class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(String(64), primary_key=True)
    name = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    api_keys = relationship("ApiKey", back_populates="tenant", cascade="all, delete-orphan")
    events = relationship("EventModel", back_populates="tenant", cascade="all, delete-orphan")
    users = relationship("UserModel", back_populates="tenant", cascade="all, delete-orphan")
    applications = relationship("ApplicationModel", back_populates="tenant", cascade="all, delete-orphan")
    members = relationship("WorkspaceMemberModel", back_populates="tenant", cascade="all, delete-orphan")


class UserModel(Base):
    """
    User accounts for human operators, tenant administrators, and security analysts.
    Includes verification token and timestamp for self-securing email verification.
    """
    __tablename__ = "users"

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    email = Column(String(255), nullable=False, unique=True, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(128), nullable=True)
    role = Column(String(32), default="operator", nullable=False)  # admin, operator, analyst, viewer
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    verification_token = Column(String(128), nullable=True, unique=True, index=True)
    verification_token_expires_at = Column(DateTime, nullable=True)
    reset_token = Column(String(128), nullable=True, unique=True, index=True)
    reset_token_expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)

    tenant = relationship("Tenant", back_populates="users")
    workspace_memberships = relationship("WorkspaceMemberModel", back_populates="user", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_users_lookup", "email", "is_active", "is_verified"),
    )




class WorkspaceMemberModel(Base):
    """
    Explicit membership linking users to workspaces (tenants) with assigned RBAC roles.
    Allows a single human user to belong to multiple independent workspaces.
    """
    __tablename__ = "workspace_members"

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String(64), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(String(32), default="viewer", nullable=False)  # owner, admin, developer, analyst, viewer
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)

    tenant = relationship("Tenant", back_populates="members")
    user = relationship("UserModel", back_populates="workspace_memberships")

    __table_args__ = (
        UniqueConstraint("tenant_id", "user_id", name="uq_tenant_user_member"),
        Index("ix_workspace_members_user", "user_id"),
        Index("ix_workspace_members_tenant", "tenant_id"),
    )


class ApplicationModel(Base):
    """
    Registered client application within a workspace (tenant).
    Tracks application metadata, environment, active status, and binds to telemetry streams.
    """
    __tablename__ = "applications"

    id = Column(String(64), primary_key=True)  # unique app_id (e.g., payments-api)
    tenant_id = Column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(128), nullable=False)
    description = Column(String(512), nullable=True)
    environment = Column(String(32), default="production", nullable=False)  # production, staging, development
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)

    tenant = relationship("Tenant", back_populates="applications")

    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_tenant_app_id"),
        Index("ix_applications_tenant_active", "tenant_id", "is_active"),
    )

class ApiKey(Base):
    """
    API keys scoped to a tenant and application.
    Stored hashed with SHA-256 (not raw) for security.
    """
    __tablename__ = "api_keys"

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    app_id = Column(String(64), nullable=False, index=True)
    key_hash = Column(String(128), nullable=False, unique=True, index=True)
    key_prefix = Column(String(16), nullable=False)  # e.g., 'ce_live_...'
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)
    expires_at = Column(DateTime, nullable=True)
    scopes = Column(JSON, nullable=True, default=None)

    tenant = relationship("Tenant", back_populates="api_keys")

    __table_args__ = (
        Index("ix_api_keys_lookup", "key_hash", "is_active"),
    )


class EventModel(Base):
    """
    Canonical Event Model stored in database.
    Compatible with PostgreSQL JSONB and portable JSON.
    """
    __tablename__ = "events"

    event_id = Column(String(64), primary_key=True)
    schema_version = Column(String(16), nullable=False, default="1.0.0")
    timestamp = Column(DateTime, nullable=False, index=True)
    ingested_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)
    tenant_id = Column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    app_id = Column(String(64), nullable=False, index=True)
    service_id = Column(String(64), nullable=False, index=True)
    event_type = Column(String(128), nullable=False, index=True)
    severity = Column(String(32), nullable=False, default="info", index=True)
    
    source_resource = Column(String(256), nullable=True)
    target_resource = Column(String(256), nullable=True)
    trace_id = Column(String(128), nullable=True, index=True)
    request_id = Column(String(128), nullable=True)
    
    attributes = Column(JSON, nullable=False, default=dict)
    provenance = Column(JSON, nullable=False, default=dict)

    tenant = relationship("Tenant", back_populates="events")

    __table_args__ = (
        Index("ix_events_tenant_time", "tenant_id", "timestamp"),
        Index("ix_events_tenant_type", "tenant_id", "event_type"),
        Index("ix_events_tenant_trace", "tenant_id", "trace_id"),
    )


class SecurityFinding(Base):
    """
    Records detection results/findings with full provenance.
    Separate from policy authorization or response actions.
    """
    __tablename__ = "security_findings"

    finding_id = Column(String(64), primary_key=True)
    tenant_id = Column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    detector_id = Column(String(64), nullable=False, index=True)
    detector_version = Column(String(32), nullable=False)
    title = Column(String(256), nullable=False)
    severity = Column(String(32), nullable=False, index=True)
    confidence = Column(String(32), nullable=False, default="medium")
    description = Column(Text, nullable=False)
    
    event_id = Column(String(64), ForeignKey("events.event_id", ondelete="SET NULL"), nullable=True, index=True)
    evidence = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)
    status = Column(String(32), default="open", nullable=False)  # open, resolved, false_positive

    investigations = relationship("InvestigationReport", back_populates="finding", cascade="all, delete-orphan")


class InvestigationReport(Base):
    """
    Stores structured outputs from the Deep-Investigation Path.
    Contains grounded hypotheses, precise evidence citations, and candidate detector proposals.
    Candidate detectors are PROPOSALS only — never automatically promoted without deterministic validation.
    """
    __tablename__ = "investigation_reports"

    investigation_id = Column(String(64), primary_key=True)
    finding_id = Column(String(64), ForeignKey("security_findings.finding_id", ondelete="CASCADE"), nullable=False, index=True)
    tenant_id = Column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    verdict = Column(String(32), nullable=False)  # confirmed_threat, likely_benign, inconclusive
    summary = Column(Text, nullable=False)
    
    hypotheses = Column(JSON, nullable=False, default=list)
    candidate_rules = Column(JSON, nullable=False, default=list)
    recommended_mitigations = Column(JSON, nullable=False, default=list)

    investigator_provider = Column(String(64), nullable=False)
    investigator_model = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)

    finding = relationship("SecurityFinding", back_populates="investigations")


class DeclarativeRuleModel(Base):
    """
    Versioned rule registry for candidate, validated, and approved declarative detection rules.
    Acts as the approval-gated configuration store for the Fast Track detectors.
    """
    __tablename__ = "declarative_rules"

    rule_id = Column(String(64), primary_key=True)
    tenant_id = Column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    version = Column(Integer, default=1, nullable=False)
    target_detector = Column(String(64), nullable=False)
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=False)
    parameters = Column(JSON, nullable=False, default=dict)
    status = Column(String(32), default="proposed", nullable=False, index=True)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)
    validation_metrics = Column(JSON, nullable=True)
    approval_metadata = Column(JSON, nullable=True)

    __table_args__ = (
        Index("ix_rules_tenant_status", "tenant_id", "status"),
    )


class TenantDefensePolicyModel(Base):
    """
    Per-tenant Active Defense configuration, protection modes, and rate-limits.
    Mandatory default mode is 'observe' for every newly provisioned tenant.
    """
    __tablename__ = "tenant_defense_policies"

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    default_mode = Column(String(32), default="observe", nullable=False)  # observe, assisted, enforced
    is_active = Column(Boolean, default=True, nullable=False)
    configuration = Column(JSON, nullable=False, default=dict)
    
    updated_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)

    __table_args__ = (
        Index("ix_tenant_defense_policies_tenant", "tenant_id"),
    )


class DefenseActionModel(Base):
    """
    Authoritative state record for planned, approved, and executed defense actions.
    Enforces tenant isolation, idempotency fingerprints, and TTL tracking.
    """
    __tablename__ = "defense_actions"

    action_id = Column(String(64), primary_key=True)
    tenant_id = Column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = Column(String(64), ForeignKey("security_findings.finding_id", ondelete="SET NULL"), nullable=True, index=True)
    
    action_type = Column(String(64), nullable=False, index=True)  # api_key_revocation, temporary_ip_block, etc.
    scope = Column(String(32), nullable=False, default="ternline_ingest")  # ternline_ingest, customer_application
    credential_authority = Column(String(32), nullable=True)  # ternline_managed, external_customer
    target_entity_type = Column(String(64), nullable=False)  # ip_address, api_key, user_id, app_id
    target_entity_id = Column(String(256), nullable=False, index=True)
    
    status = Column(String(32), default="proposed", nullable=False, index=True)
    protection_mode = Column(String(32), default="observe", nullable=False)  # observe, assisted, enforced
    
    deduplication_fingerprint = Column(String(64), nullable=False, index=True)
    parameters = Column(JSON, nullable=False, default=dict)
    
    ttl_seconds = Column(Integer, nullable=True)
    expires_at = Column(DateTime, nullable=True, index=True)
    
    requested_by = Column(String(128), nullable=False)
    approved_by = Column(String(128), nullable=True)
    approval_rationale = Column(Text, nullable=True)
    
    provider_adapter = Column(String(64), nullable=True)
    external_reference_id = Column(String(256), nullable=True)
    
    execution_result = Column(JSON, nullable=True)
    verification_result = Column(JSON, nullable=True)
    rollback_result = Column(JSON, nullable=True)
    
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False, index=True)
    executed_at = Column(DateTime, nullable=True)
    verified_at = Column(DateTime, nullable=True)
    rolled_back_at = Column(DateTime, nullable=True)

    __table_args__ = (
        Index("ix_defense_actions_tenant_status", "tenant_id", "status"),
        Index("ix_defense_actions_dedup", "tenant_id", "deduplication_fingerprint", "status"),
        Index("ix_defense_actions_expirations", "status", "expires_at"),
        Index(
            "uq_active_defense_actions_dedup",
            "tenant_id",
            "deduplication_fingerprint",
            unique=True,
            postgresql_where=text("status IN ('proposed', 'awaiting_approval', 'approved', 'executing', 'verifying', 'verified_active')"),
        ),
    )


class DefenseAuditLogModel(Base):
    """
    Append-only immutable audit trail of all state transitions and policy decisions.
    Uses ON DELETE SET NULL on action_id to ensure audit logs survive parent action pruning.
    """
    __tablename__ = "defense_audit_log"

    log_id = Column(String(64), primary_key=True)
    action_id = Column(String(64), ForeignKey("defense_actions.action_id", ondelete="SET NULL"), nullable=True, index=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    
    from_status = Column(String(32), nullable=True)
    to_status = Column(String(32), nullable=False)
    transition_trigger = Column(String(64), nullable=False)
    
    actor = Column(String(128), nullable=False)
    details = Column(JSON, nullable=False, default=dict)
    timestamp = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False, index=True)

    __table_args__ = (
        Index("ix_defense_audit_log_tenant_time", "tenant_id", "timestamp"),
    )


class IncidentModel(Base):
    """
    Phase 2: Aggregated incident case correlating multiple SecurityFinding records.
    """
    __tablename__ = "incidents"

    incident_id = Column(String(64), primary_key=True)
    tenant_id = Column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    summary = Column(Text, nullable=True)
    severity = Column(String(32), default="medium", nullable=False)      # critical, high, medium, low
    status = Column(String(32), default="open", nullable=False)          # open, investigating, contained, resolved, false_positive
    lead_detector_id = Column(String(128), nullable=True)
    primary_entity_type = Column(String(64), nullable=True)              # ip, user, service, api_key
    primary_entity_id = Column(String(255), nullable=True)
    trace_ids = Column(JSON, default=list, nullable=False)
    affected_services = Column(JSON, default=list, nullable=False)
    mitre_tactics = Column(JSON, default=list, nullable=False)
    mitre_techniques = Column(JSON, default=list, nullable=False)
    finding_count = Column(Integer, default=1, nullable=False)
    assigned_to = Column(String(128), nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)

    __table_args__ = (
        Index("ix_incidents_tenant_status", "tenant_id", "status"),
        Index("ix_incidents_tenant_severity", "tenant_id", "severity"),
        Index("ix_incidents_tenant_created", "tenant_id", "created_at"),
    )


class IncidentFindingModel(Base):
    """
    Phase 2: Junction table linking incidents to their constituent SecurityFindings.
    """
    __tablename__ = "incident_findings"

    incident_id = Column(String(64), ForeignKey("incidents.incident_id", ondelete="CASCADE"), primary_key=True)
    finding_id = Column(String(64), ForeignKey("security_findings.finding_id", ondelete="CASCADE"), primary_key=True)
    tenant_id = Column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    added_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)

    __table_args__ = (
        Index("ix_incident_findings_tenant", "tenant_id"),
        Index("ix_incident_findings_finding", "finding_id"),
    )


class ThreatIntelIocModel(Base):
    """
    Phase 2: Tenant-isolated Indicators of Compromise (IOC) registry.
    """
    __tablename__ = "threat_intel_iocs"

    ioc_id = Column(String(64), primary_key=True)
    tenant_id = Column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    ioc_type = Column(String(64), nullable=False)                       # ip, domain, sha256, user_agent, query_pattern
    value = Column(String(512), nullable=False)
    threat_actor = Column(String(128), nullable=True)
    description = Column(Text, nullable=True)
    severity = Column(String(32), default="high", nullable=False)        # critical, high, medium, low
    confidence = Column(String(32), default="high", nullable=False)      # high, medium, low
    mitre_tactics = Column(JSON, default=list, nullable=False)
    mitre_techniques = Column(JSON, default=list, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    source = Column(String(128), default="manual", nullable=False)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)

    __table_args__ = (
        Index("ix_threat_intel_tenant_type_val", "tenant_id", "ioc_type", "value"),
        Index("ix_threat_intel_tenant_active", "tenant_id", "is_active"),
    )



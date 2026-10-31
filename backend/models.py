import datetime
from sqlalchemy import (
    Column,
    String,
    DateTime,
    Boolean,
    ForeignKey,
    JSON,
    Index,
    Text,
    Integer,
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


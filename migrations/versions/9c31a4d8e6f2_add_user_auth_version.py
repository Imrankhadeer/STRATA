"""Add platform users, workspace members, applications, incidents, threat intel, and user auth_version.

Revision ID: 9c31a4d8e6f2
Revises: 7b8c9d0e1f2a
Create Date: 2026-11-04 02:00:00.000000

"""
from typing import Sequence, Union

from alembic import op, context
import sqlalchemy as sa


revision: str = "9c31a4d8e6f2"
down_revision: Union[str, Sequence[str], None] = "7b8c9d0e1f2a"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    is_offline = context.is_offline_mode()
    inspector = None if is_offline else sa.inspect(bind)
    existing_tables = set(inspector.get_table_names()) if inspector else set()

    # 1. Users Table
    if "users" not in existing_tables:
        op.create_table(
            "users",
            sa.Column("id", sa.String(length=64), nullable=False),
            sa.Column("tenant_id", sa.String(length=64), nullable=False),
            sa.Column("email", sa.String(length=255), nullable=False),
            sa.Column("hashed_password", sa.String(length=255), nullable=False),
            sa.Column("full_name", sa.String(length=128), nullable=True),
            sa.Column("role", sa.String(length=32), nullable=False, server_default="operator"),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("is_verified", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("verification_token", sa.String(length=128), nullable=True),
            sa.Column("verification_token_expires_at", sa.DateTime(), nullable=True),
            sa.Column("reset_token", sa.String(length=128), nullable=True),
            sa.Column("reset_token_expires_at", sa.DateTime(), nullable=True),
            sa.Column("auth_version", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("email"),
            sa.UniqueConstraint("verification_token"),
            sa.UniqueConstraint("reset_token"),
        )
        op.create_index("ix_users_lookup", "users", ["email", "is_active", "is_verified"], unique=False)
        op.create_index(op.f("ix_users_tenant_id"), "users", ["tenant_id"], unique=False)
        op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)
        op.create_index(op.f("ix_users_verification_token"), "users", ["verification_token"], unique=True)
        op.create_index(op.f("ix_users_reset_token"), "users", ["reset_token"], unique=True)
    else:
        # Existing users table: ensure auth_version column exists
        columns = [c["name"] for c in inspector.get_columns("users")]
        if "auth_version" not in columns:
            op.add_column(
                "users",
                sa.Column("auth_version", sa.Integer(), nullable=False, server_default="0"),
            )

    # 2. Workspace Members Table
    if "workspace_members" not in existing_tables:
        op.create_table(
            "workspace_members",
            sa.Column("id", sa.String(length=64), nullable=False),
            sa.Column("tenant_id", sa.String(length=64), nullable=False),
            sa.Column("user_id", sa.String(length=64), nullable=False),
            sa.Column("role", sa.String(length=32), nullable=False, server_default="viewer"),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("tenant_id", "user_id", name="uq_tenant_user_member"),
        )
        op.create_index(op.f("ix_workspace_members_tenant_id"), "workspace_members", ["tenant_id"], unique=False)
        op.create_index(op.f("ix_workspace_members_user_id"), "workspace_members", ["user_id"], unique=False)
        op.create_index("ix_workspace_members_user", "workspace_members", ["user_id"], unique=False)
        op.create_index("ix_workspace_members_tenant", "workspace_members", ["tenant_id"], unique=False)

    # 3. Applications Table
    if "applications" not in existing_tables:
        op.create_table(
            "applications",
            sa.Column("id", sa.String(length=64), nullable=False),
            sa.Column("tenant_id", sa.String(length=64), nullable=False),
            sa.Column("name", sa.String(length=128), nullable=False),
            sa.Column("description", sa.String(length=512), nullable=True),
            sa.Column("environment", sa.String(length=32), nullable=False, server_default="production"),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("tenant_id", "id", name="uq_tenant_app_id"),
        )
        op.create_index(op.f("ix_applications_tenant_id"), "applications", ["tenant_id"], unique=False)
        op.create_index("ix_applications_tenant_active", "applications", ["tenant_id", "is_active"], unique=False)

    # 4. Incidents Table
    if "incidents" not in existing_tables:
        op.create_table(
            "incidents",
            sa.Column("incident_id", sa.String(length=64), nullable=False),
            sa.Column("tenant_id", sa.String(length=64), nullable=False),
            sa.Column("title", sa.String(length=255), nullable=False),
            sa.Column("summary", sa.Text(), nullable=True),
            sa.Column("severity", sa.String(length=32), nullable=False, server_default="medium"),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="open"),
            sa.Column("lead_detector_id", sa.String(length=128), nullable=True),
            sa.Column("primary_entity_type", sa.String(length=64), nullable=True),
            sa.Column("primary_entity_id", sa.String(length=255), nullable=True),
            sa.Column("trace_ids", sa.JSON(), nullable=False),
            sa.Column("affected_services", sa.JSON(), nullable=False),
            sa.Column("mitre_tactics", sa.JSON(), nullable=False),
            sa.Column("mitre_techniques", sa.JSON(), nullable=False),
            sa.Column("finding_count", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("assigned_to", sa.String(length=128), nullable=True),
            sa.Column("resolved_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("incident_id"),
        )
        op.create_index(op.f("ix_incidents_tenant_id"), "incidents", ["tenant_id"], unique=False)
        op.create_index("ix_incidents_tenant_status", "incidents", ["tenant_id", "status"], unique=False)
        op.create_index("ix_incidents_tenant_severity", "incidents", ["tenant_id", "severity"], unique=False)
        op.create_index("ix_incidents_tenant_created", "incidents", ["tenant_id", "created_at"], unique=False)

    # 5. Incident Findings Junction Table
    if "incident_findings" not in existing_tables:
        op.create_table(
            "incident_findings",
            sa.Column("incident_id", sa.String(length=64), nullable=False),
            sa.Column("finding_id", sa.String(length=64), nullable=False),
            sa.Column("tenant_id", sa.String(length=64), nullable=False),
            sa.Column("added_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(["finding_id"], ["security_findings.finding_id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["incident_id"], ["incidents.incident_id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("incident_id", "finding_id"),
        )
        op.create_index(op.f("ix_incident_findings_tenant_id"), "incident_findings", ["tenant_id"], unique=False)
        op.create_index("ix_incident_findings_tenant", "incident_findings", ["tenant_id"], unique=False)
        op.create_index("ix_incident_findings_finding", "incident_findings", ["finding_id"], unique=False)

    # 6. Threat Intel IOCs Table
    if "threat_intel_iocs" not in existing_tables:
        op.create_table(
            "threat_intel_iocs",
            sa.Column("ioc_id", sa.String(length=64), nullable=False),
            sa.Column("tenant_id", sa.String(length=64), nullable=False),
            sa.Column("ioc_type", sa.String(length=64), nullable=False),
            sa.Column("value", sa.String(length=512), nullable=False),
            sa.Column("threat_actor", sa.String(length=128), nullable=True),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("severity", sa.String(length=32), nullable=False, server_default="high"),
            sa.Column("confidence", sa.String(length=32), nullable=False, server_default="high"),
            sa.Column("mitre_tactics", sa.JSON(), nullable=False),
            sa.Column("mitre_techniques", sa.JSON(), nullable=False),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("source", sa.String(length=128), nullable=False, server_default="manual"),
            sa.Column("expires_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("ioc_id"),
        )
        op.create_index(op.f("ix_threat_intel_iocs_tenant_id"), "threat_intel_iocs", ["tenant_id"], unique=False)
        op.create_index("ix_threat_intel_tenant_type_val", "threat_intel_iocs", ["tenant_id", "ioc_type", "value"], unique=False)
        op.create_index("ix_threat_intel_tenant_active", "threat_intel_iocs", ["tenant_id", "is_active"], unique=False)


def downgrade() -> None:
    op.drop_table("threat_intel_iocs")
    op.drop_table("incident_findings")
    op.drop_table("incidents")
    op.drop_table("applications")
    op.drop_table("workspace_members")
    op.drop_table("users")

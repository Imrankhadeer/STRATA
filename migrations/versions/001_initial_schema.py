"""Initial migration for tenants, api_keys, events, and security_findings

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-10-28 01:25:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Tenants Table
    op.create_table(
        'tenants',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )

    # 2. API Keys Table
    op.create_table(
        'api_keys',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('tenant_id', sa.String(length=64), nullable=False),
        sa.Column('app_id', sa.String(length=64), nullable=False),
        sa.Column('key_hash', sa.String(length=128), nullable=False),
        sa.Column('key_prefix', sa.String(length=16), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_api_keys_app_id'), 'api_keys', ['app_id'], unique=False)
    op.create_index(op.f('ix_api_keys_key_hash'), 'api_keys', ['key_hash'], unique=True)
    op.create_index(op.f('ix_api_keys_tenant_id'), 'api_keys', ['tenant_id'], unique=False)
    op.create_index('ix_api_keys_lookup', 'api_keys', ['key_hash', 'is_active'], unique=False)

    # 3. Events Table
    op.create_table(
        'events',
        sa.Column('event_id', sa.String(length=64), nullable=False),
        sa.Column('schema_version', sa.String(length=16), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('ingested_at', sa.DateTime(), nullable=False),
        sa.Column('tenant_id', sa.String(length=64), nullable=False),
        sa.Column('app_id', sa.String(length=64), nullable=False),
        sa.Column('service_id', sa.String(length=64), nullable=False),
        sa.Column('event_type', sa.String(length=128), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('source_resource', sa.String(length=256), nullable=True),
        sa.Column('target_resource', sa.String(length=256), nullable=True),
        sa.Column('trace_id', sa.String(length=128), nullable=True),
        sa.Column('request_id', sa.String(length=128), nullable=True),
        sa.Column('attributes', sa.JSON(), nullable=False),
        sa.Column('provenance', sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('event_id')
    )
    op.create_index(op.f('ix_events_app_id'), 'events', ['app_id'], unique=False)
    op.create_index(op.f('ix_events_event_type'), 'events', ['event_type'], unique=False)
    op.create_index(op.f('ix_events_service_id'), 'events', ['service_id'], unique=False)
    op.create_index(op.f('ix_events_severity'), 'events', ['severity'], unique=False)
    op.create_index(op.f('ix_events_tenant_id'), 'events', ['tenant_id'], unique=False)
    op.create_index(op.f('ix_events_timestamp'), 'events', ['timestamp'], unique=False)
    op.create_index(op.f('ix_events_trace_id'), 'events', ['trace_id'], unique=False)
    op.create_index('ix_events_tenant_time', 'events', ['tenant_id', 'timestamp'], unique=False)
    op.create_index('ix_events_tenant_trace', 'events', ['tenant_id', 'trace_id'], unique=False)
    op.create_index('ix_events_tenant_type', 'events', ['tenant_id', 'event_type'], unique=False)

    # 4. Security Findings Table
    op.create_table(
        'security_findings',
        sa.Column('finding_id', sa.String(length=64), nullable=False),
        sa.Column('tenant_id', sa.String(length=64), nullable=False),
        sa.Column('detector_id', sa.String(length=64), nullable=False),
        sa.Column('detector_version', sa.String(length=32), nullable=False),
        sa.Column('title', sa.String(length=256), nullable=False),
        sa.Column('severity', sa.String(length=32), nullable=False),
        sa.Column('confidence', sa.String(length=32), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('event_id', sa.String(length=64), nullable=True),
        sa.Column('evidence', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.ForeignKeyConstraint(['event_id'], ['events.event_id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('finding_id')
    )
    op.create_index(op.f('ix_security_findings_detector_id'), 'security_findings', ['detector_id'], unique=False)
    op.create_index(op.f('ix_security_findings_event_id'), 'security_findings', ['event_id'], unique=False)
    op.create_index(op.f('ix_security_findings_severity'), 'security_findings', ['severity'], unique=False)
    op.create_index(op.f('ix_security_findings_tenant_id'), 'security_findings', ['tenant_id'], unique=False)


def downgrade() -> None:
    op.drop_table('security_findings')
    op.drop_table('events')
    op.drop_table('api_keys')
    op.drop_table('tenants')

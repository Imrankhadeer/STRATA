"""Add active defense tables

Revision ID: 5f8e12a49b01
Revises: 38a2b18135c4
Create Date: 2026-11-01 15:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '5f8e12a49b01'
down_revision: Union[str, Sequence[str], None] = '38a2b18135c4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. tenant_defense_policies
    op.create_table(
        'tenant_defense_policies',
        sa.Column('id', sa.String(length=64), primary_key=True),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('default_mode', sa.String(length=32), nullable=False, server_default='observe'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('configuration', sa.JSON(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_tenant_defense_policies_tenant', 'tenant_defense_policies', ['tenant_id'], unique=True)

    # 2. defense_actions
    op.create_table(
        'defense_actions',
        sa.Column('action_id', sa.String(length=64), primary_key=True),
        sa.Column('tenant_id', sa.String(length=64), sa.ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        sa.Column('finding_id', sa.String(length=64), sa.ForeignKey('security_findings.finding_id', ondelete='SET NULL'), nullable=True),
        sa.Column('action_type', sa.String(length=64), nullable=False),
        sa.Column('scope', sa.String(length=32), nullable=False, server_default='ternline_ingest'),
        sa.Column('credential_authority', sa.String(length=32), nullable=True),
        sa.Column('target_entity_type', sa.String(length=64), nullable=False),
        sa.Column('target_entity_id', sa.String(length=256), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False, server_default='proposed'),
        sa.Column('protection_mode', sa.String(length=32), nullable=False, server_default='observe'),
        sa.Column('deduplication_fingerprint', sa.String(length=64), nullable=False),
        sa.Column('parameters', sa.JSON(), nullable=False),
        sa.Column('ttl_seconds', sa.Integer(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('requested_by', sa.String(length=128), nullable=False),
        sa.Column('approved_by', sa.String(length=128), nullable=True),
        sa.Column('approval_rationale', sa.Text(), nullable=True),
        sa.Column('provider_adapter', sa.String(length=64), nullable=True),
        sa.Column('external_reference_id', sa.String(length=256), nullable=True),
        sa.Column('execution_result', sa.JSON(), nullable=True),
        sa.Column('verification_result', sa.JSON(), nullable=True),
        sa.Column('rollback_result', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('executed_at', sa.DateTime(), nullable=True),
        sa.Column('verified_at', sa.DateTime(), nullable=True),
        sa.Column('rolled_back_at', sa.DateTime(), nullable=True),
    )
    op.create_index('ix_defense_actions_tenant_status', 'defense_actions', ['tenant_id', 'status'])
    op.create_index('ix_defense_actions_dedup', 'defense_actions', ['tenant_id', 'deduplication_fingerprint', 'status'])
    op.create_index('ix_defense_actions_expirations', 'defense_actions', ['status', 'expires_at'])

    # 3. defense_audit_log (Uses SET NULL on action_id for audit immutability)
    op.create_table(
        'defense_audit_log',
        sa.Column('log_id', sa.String(length=64), primary_key=True),
        sa.Column('action_id', sa.String(length=64), sa.ForeignKey('defense_actions.action_id', ondelete='SET NULL'), nullable=True),
        sa.Column('tenant_id', sa.String(length=64), nullable=False),
        sa.Column('from_status', sa.String(length=32), nullable=True),
        sa.Column('to_status', sa.String(length=32), nullable=False),
        sa.Column('transition_trigger', sa.String(length=64), nullable=False),
        sa.Column('actor', sa.String(length=128), nullable=False),
        sa.Column('details', sa.JSON(), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
    )
    op.create_index('ix_defense_audit_log_action', 'defense_audit_log', ['action_id'])
    op.create_index('ix_defense_audit_log_tenant_time', 'defense_audit_log', ['tenant_id', 'timestamp'])


def downgrade() -> None:
    op.drop_table('defense_audit_log')
    op.drop_table('defense_actions')
    op.drop_table('tenant_defense_policies')


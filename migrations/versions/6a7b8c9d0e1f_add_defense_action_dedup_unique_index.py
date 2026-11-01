"""Add partial unique index for active defense action deduplication

Revision ID: 6a7b8c9d0e1f
Revises: 5f8e12a49b01
Create Date: 2026-11-01 15:45:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '6a7b8c9d0e1f'
down_revision: Union[str, Sequence[str], None] = '5f8e12a49b01'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index(
        'uq_active_defense_actions_dedup',
        'defense_actions',
        ['tenant_id', 'deduplication_fingerprint'],
        unique=True,
        postgresql_where=sa.text("status IN ('proposed', 'awaiting_approval', 'approved', 'executing', 'verifying', 'verified_active')"),
    )


def downgrade() -> None:
    op.drop_index('uq_active_defense_actions_dedup', table_name='defense_actions')


"""shield_active remote gate on device_app_policies

Revision ID: 0028
Revises: 0027
Create Date: 2026-11-17
"""
import sqlalchemy as sa
from alembic import op

revision = '0028'
down_revision = '0027'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "device_app_policies",
        sa.Column("shield_active", sa.Boolean(), nullable=False,
                  server_default=sa.false()))


def downgrade() -> None:
    op.drop_column("device_app_policies", "shield_active")

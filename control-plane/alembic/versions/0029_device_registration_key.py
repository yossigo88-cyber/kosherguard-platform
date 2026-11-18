"""devices.registration_key for idempotent personal self-registration

Revision ID: 0029
Revises: 0028
Create Date: 2026-11-17
"""
import sqlalchemy as sa
from alembic import op

revision = '0029'
down_revision = '0028'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "devices",
        sa.Column("registration_key", sa.String(length=64), nullable=True))
    # Partial unique index: MDM-enrolled devices carry no key and must
    # not collide with each other (NULLs are distinct in PostgreSQL
    # unique indexes anyway, the WHERE clause makes the intent explicit
    # and keeps the index small).
    op.create_index(
        "ix_devices_tenant_registration_key", "devices",
        ["tenant_id", "registration_key"], unique=True,
        postgresql_where=sa.text("registration_key IS NOT NULL"))


def downgrade() -> None:
    op.drop_index("ix_devices_tenant_registration_key", "devices")
    op.drop_column("devices", "registration_key")

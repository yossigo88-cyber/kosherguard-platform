"""MDM enrollments and command ledger

Milestone 4: device enrollment records and the per-command lifecycle
ledger (queued -> delivered -> acknowledged|error|not_now, applied only
on positive device confirmation).
"""

from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"


def upgrade() -> None:
    op.create_table(
        "mdm_enrollments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(),
                  sa.ForeignKey("tenants.id"), nullable=False, index=True),
        sa.Column("device_id", sa.Integer(),
                  sa.ForeignKey("devices.id"), nullable=False, index=True),
        sa.Column("enrollment_id", sa.String(length=120), nullable=False),
        sa.Column("state", sa.String(length=20), nullable=False,
                  server_default="pending"),
        sa.Column("supervised", sa.Boolean(), nullable=False,
                  server_default=sa.false()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "enrollment_id"),
    )
    op.create_table(
        "mdm_commands",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(),
                  sa.ForeignKey("tenants.id"), nullable=False, index=True),
        sa.Column("enrollment_pk", sa.Integer(),
                  sa.ForeignKey("mdm_enrollments.id"), nullable=False,
                  index=True),
        sa.Column("command", sa.String(length=60), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("status", sa.String(length=20), nullable=False,
                  server_default="queued"),
        sa.Column("applied", sa.Boolean(), nullable=False,
                  server_default=sa.false()),
        sa.Column("result_detail", sa.Text(), nullable=False,
                  server_default=""),
        sa.Column("actor_user_id", sa.Integer(),
                  sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("mdm_commands")
    op.drop_table("mdm_enrollments")

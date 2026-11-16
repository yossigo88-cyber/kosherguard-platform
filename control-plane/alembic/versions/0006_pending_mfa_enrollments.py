"""Pending MFA enrollments: server-bound, expiring, single-use secrets.

Revision: 0006
"""

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"


def upgrade() -> None:
    op.create_table(
        "pending_mfa_enrollments",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(),
                  sa.ForeignKey("users.id"), nullable=False),
        sa.Column("secret", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_pending_mfa_enrollments_user_id",
                    "pending_mfa_enrollments", ["user_id"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_pending_mfa_enrollments_user_id",
                  table_name="pending_mfa_enrollments")
    op.drop_table("pending_mfa_enrollments")

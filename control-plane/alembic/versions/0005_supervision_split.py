"""Split enrollment supervision into requested vs verified

A guardian's checkbox records a REQUEST. Device-reported supervision is
a different fact and only device check-in data may set it.
"""

from alembic import op
import sqlalchemy as sa

revision = "0005"
down_revision = "0004"


def upgrade() -> None:
    op.add_column(
        "mdm_enrollments",
        sa.Column("supervision_requested", sa.Boolean(), nullable=False,
                  server_default=sa.false()))
    op.add_column(
        "mdm_enrollments",
        sa.Column("supervision_verified", sa.Boolean(), nullable=False,
                  server_default=sa.false()))
    op.execute("UPDATE mdm_enrollments SET supervision_requested = supervised")
    op.drop_column("mdm_enrollments", "supervised")


def downgrade() -> None:
    op.add_column(
        "mdm_enrollments",
        sa.Column("supervised", sa.Boolean(), nullable=False,
                  server_default=sa.false()))
    op.execute("UPDATE mdm_enrollments SET supervised = supervision_requested")
    op.drop_column("mdm_enrollments", "supervision_verified")
    op.drop_column("mdm_enrollments", "supervision_requested")

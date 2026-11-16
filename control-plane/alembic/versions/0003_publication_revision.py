"""publication revision counter

Revision counter on publication_states so concurrent publishes
serialize in the database and every generation number is used once.
"""

from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"


def upgrade() -> None:
    op.add_column(
        "publication_states",
        sa.Column("revision", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("publication_states", "revision")

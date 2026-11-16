"""Parity fixes found by schema comparison (test_migrations):

- users.is_platform_admin (added to the model without a migration)
- auth_sessions.ix_auth_sessions_token_hash must be UNIQUE (the model
  declares unique=True; 0001 had a table-level UniqueConstraint but a
  non-unique named index).

Revision: 0009
"""

import sqlalchemy as sa
from alembic import op

revision = "0009"
down_revision = "0008"


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("is_platform_admin", sa.Boolean(), nullable=False,
                  server_default=sa.false()))
    op.drop_index("ix_auth_sessions_token_hash",
                  table_name="auth_sessions")
    op.create_index("ix_auth_sessions_token_hash", "auth_sessions",
                    ["token_hash"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_auth_sessions_token_hash",
                  table_name="auth_sessions")
    op.create_index("ix_auth_sessions_token_hash", "auth_sessions",
                    ["token_hash"])
    op.drop_column("users", "is_platform_admin")

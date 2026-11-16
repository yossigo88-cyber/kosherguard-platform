"""Policies, policy versions, devices, assignments, publication state.

Revision: 0002
"""

from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "policies",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_id", sa.Integer, sa.ForeignKey("tenants.id"),
                  nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False),
        sa.Column("engine_doc", sa.Text, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "name"),
    )
    op.create_index("ix_policies_tenant_id", "policies", ["tenant_id"])
    op.create_table(
        "policy_versions",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("policy_id", sa.Integer, sa.ForeignKey("policies.id"),
                  nullable=False),
        sa.Column("version", sa.Integer, nullable=False),
        sa.Column("engine_doc", sa.Text, nullable=False),
        sa.Column("actor_user_id", sa.Integer, sa.ForeignKey("users.id"),
                  nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("policy_id", "version"),
    )
    op.create_index("ix_policy_versions_policy_id", "policy_versions",
                    ["policy_id"])
    op.create_table(
        "devices",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_id", sa.Integer, sa.ForeignKey("tenants.id"),
                  nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("state", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "name"),
    )
    op.create_index("ix_devices_tenant_id", "devices", ["tenant_id"])
    op.create_table(
        "device_assignments",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_id", sa.Integer, sa.ForeignKey("tenants.id"),
                  nullable=False),
        sa.Column("device_id", sa.Integer, sa.ForeignKey("devices.id"),
                  nullable=False),
        sa.Column("policy_id", sa.Integer, sa.ForeignKey("policies.id"),
                  nullable=False),
        sa.Column("active", sa.Boolean, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_device_assignments_tenant_id", "device_assignments",
                    ["tenant_id"])
    op.create_table(
        "publication_states",
        sa.Column("tenant_id", sa.Integer, sa.ForeignKey("tenants.id"),
                  primary_key=True),
        sa.Column("selected_policy_id", sa.Integer,
                  sa.ForeignKey("policies.id"), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("publication_states")
    op.drop_table("device_assignments")
    op.drop_table("devices")
    op.drop_table("policy_versions")
    op.drop_table("policies")

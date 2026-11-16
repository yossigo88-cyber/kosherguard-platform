"""Complete migration coverage: the tables previously created only by
metadata.create_all.

device_app_policies, ddm_status_reports, filter_decisions,
category_rules, invite_tokens, credential_artifacts,
issued_credentials - definitions mirror app.models exactly (columns,
constraints, indexes). Boolean/datetime defaults are ORM-side in
models, so they are applied on insert here as plain columns.

Revision: 0008
"""

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"


def upgrade() -> None:
    op.create_table(
        "device_app_policies",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(),
                  sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("device_id", sa.Integer(),
                  sa.ForeignKey("devices.id"), nullable=False),
        sa.Column("mode", sa.String(length=20), nullable=False),
        sa.Column("bundle_ids", sa.Text(), nullable=False),
        sa.Column("actor_user_id", sa.Integer(),
                  sa.ForeignKey("users.id"), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  nullable=False),
        sa.UniqueConstraint("tenant_id", "device_id"),
    )
    op.create_index("ix_device_app_policies_tenant_id",
                    "device_app_policies", ["tenant_id"])

    op.create_table(
        "ddm_status_reports",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(),
                  sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("enrollment_id", sa.String(length=120),
                  nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("declaration_states", sa.Text(), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True),
                  nullable=False),
    )
    op.create_index("ix_ddm_status_reports_tenant_id",
                    "ddm_status_reports", ["tenant_id"])
    op.create_index("ix_ddm_status_reports_enrollment_id",
                    "ddm_status_reports", ["enrollment_id"])

    op.create_table(
        "filter_decisions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(),
                  sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("device_id", sa.Integer(),
                  sa.ForeignKey("devices.id"), nullable=True),
        sa.Column("source", sa.String(length=20), nullable=False),
        sa.Column("domain", sa.String(length=255), nullable=False),
        sa.Column("action", sa.String(length=10), nullable=False),
        sa.Column("rule", sa.String(length=120), nullable=False),
        sa.Column("reason", sa.String(length=300), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True),
                  nullable=False),
    )
    op.create_index("ix_filter_decisions_tenant_id",
                    "filter_decisions", ["tenant_id"])

    op.create_table(
        "category_rules",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("domain", sa.String(length=253), nullable=False),
        sa.Column("category", sa.String(length=120), nullable=False),
        sa.Column("verdict", sa.String(length=16), nullable=False),
        sa.Column("source", sa.String(length=400), nullable=False),
        sa.Column("added_by_user_id", sa.Integer(),
                  sa.ForeignKey("users.id"), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  nullable=False),
        sa.Column("deactivated_at", sa.DateTime(timezone=True),
                  nullable=True),
        sa.UniqueConstraint("domain"),
    )

    op.create_table(
        "invite_tokens",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(),
                  sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("role", sa.Enum("owner", "guardian", "viewer",
                                  name="role"), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("invited_by_user_id", sa.Integer(),
                  sa.ForeignKey("users.id"), nullable=True),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True),
                  nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  nullable=False),
    )
    op.create_index("ix_invite_tokens_tenant_id",
                    "invite_tokens", ["tenant_id"])
    op.create_index("ix_invite_tokens_token_hash",
                    "invite_tokens", ["token_hash"], unique=True)

    op.create_table(
        "credential_artifacts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(),
                  sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("kind", sa.String(length=40), nullable=False),
        sa.Column("label", sa.String(length=200), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("byte_size", sa.Integer(), nullable=False),
        sa.Column("storage_path", sa.String(length=500),
                  nullable=False),
        sa.Column("environment", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("uploaded_by_user_id", sa.Integer(),
                  sa.ForeignKey("users.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  nullable=False),
        sa.Column("rotated_at", sa.DateTime(timezone=True),
                  nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True),
                  nullable=True),
    )
    op.create_index("ix_credential_artifacts_tenant_id",
                    "credential_artifacts", ["tenant_id"])

    op.create_table(
        "issued_credentials",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("tenant_id", sa.Integer(),
                  sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("device_id", sa.Integer(),
                  sa.ForeignKey("devices.id"), nullable=False),
        sa.Column("jti", sa.String(length=64), nullable=False),
        sa.Column("scope", sa.String(length=24), nullable=False),
        sa.Column("policy_id", sa.Integer(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True),
                  nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True),
                  nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  nullable=False),
    )
    op.create_index("ix_issued_credentials_tenant_id",
                    "issued_credentials", ["tenant_id"])
    op.create_index("ix_issued_credentials_device_id",
                    "issued_credentials", ["device_id"])
    op.create_index("ix_issued_credentials_jti",
                    "issued_credentials", ["jti"], unique=True)


def downgrade() -> None:
    op.drop_table("issued_credentials")
    op.drop_table("credential_artifacts")
    op.drop_table("invite_tokens")
    op.drop_table("category_rules")
    op.drop_table("filter_decisions")
    op.drop_table("ddm_status_reports")
    op.drop_table("device_app_policies")

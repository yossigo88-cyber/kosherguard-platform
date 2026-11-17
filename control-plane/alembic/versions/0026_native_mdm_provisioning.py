"""Native MDM enrollment provisioning, persistent lifecycle and identity pinning."""
from alembic import op
import sqlalchemy as sa

revision = '0026'
down_revision = '0025'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('mdm_provisions',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('tenant_id', sa.Integer, sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('enrollment_pk', sa.Integer, sa.ForeignKey('mdm_enrollments.id'), nullable=False, unique=True),
        sa.Column('udid', sa.String(120), nullable=False),
        sa.Column('serial', sa.String(120), nullable=False),
        sa.Column('mode', sa.String(30), nullable=False),
        sa.Column('topic', sa.String(200), nullable=False),
        sa.Column('stage', sa.String(30), nullable=False, server_default='issued'),
        sa.Column('declaration_json', sa.Text, nullable=False, server_default='{}'),
        sa.Column('ticket_hash', sa.String(64), nullable=False, unique=True),
        sa.Column('ticket_expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('served_at', sa.DateTime(timezone=True)),
        sa.Column('machineinfo_sha256', sa.String(64), unique=True),
        sa.Column('cert_der', sa.LargeBinary),
        sa.Column('cert_sha256', sa.String(64), unique=True),
        sa.Column('cert_expires_at', sa.DateTime(timezone=True)),
        sa.Column('pending_cert_der', sa.LargeBinary),
        sa.Column('pending_cert_sha256', sa.String(64), unique=True),
        sa.Column('pending_cert_expires_at', sa.DateTime(timezone=True)),
        sa.Column('push_state', sa.String(30), nullable=False, server_default='idle'),
        sa.Column('push_attempts', sa.Integer, nullable=False, server_default='0'),
        sa.Column('push_next_at', sa.DateTime(timezone=True)),
        sa.Column('identity_health', sa.String(30), nullable=False, server_default='not_issued'),
        sa.Column('push_ciphertext', sa.Text),
        sa.Column('revoked_at', sa.DateTime(timezone=True)),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False))
    op.create_index('ix_mdm_provisions_tenant_id', 'mdm_provisions', ['tenant_id'])
    op.create_index('uq_mdm_provision_current_udid', 'mdm_provisions', ['udid'], unique=True,
                    postgresql_where=sa.text('revoked_at IS NULL'),
                    sqlite_where=sa.text('revoked_at IS NULL'))

    op.create_table('mdm_apple_inventory',
        sa.Column('id',sa.Integer,primary_key=True),
        sa.Column('tenant_id',sa.Integer,sa.ForeignKey('tenants.id'),nullable=False),
        sa.Column('device_id',sa.Integer,sa.ForeignKey('devices.id'),nullable=False,unique=True),
        sa.Column('serial',sa.String(120),nullable=False,unique=True),
        sa.Column('udid',sa.String(120),nullable=False,unique=True),
        sa.Column('approved_by',sa.Integer,sa.ForeignKey('users.id'),nullable=False),
        sa.Column('created_at',sa.DateTime(timezone=True),nullable=False))
    op.create_index('ix_mdm_apple_inventory_tenant_id','mdm_apple_inventory',['tenant_id'])
    op.create_table('mdm_web_ceremonies',
        sa.Column('id',sa.Integer,primary_key=True),
        sa.Column('token_hash',sa.String(64),nullable=False,unique=True),
        sa.Column('encrypted_state',sa.Text,nullable=False),
        sa.Column('expires_at',sa.DateTime(timezone=True),nullable=False))
    op.create_table('mdm_web_activations',
        sa.Column('id',sa.Integer,primary_key=True),
        sa.Column('tenant_id',sa.Integer,sa.ForeignKey('tenants.id'),nullable=False),
        sa.Column('enrollment_pk',sa.Integer,sa.ForeignKey('mdm_enrollments.id'),nullable=False,unique=True),
        sa.Column('nonce_hash',sa.String(64),nullable=False,unique=True),
        sa.Column('session_hash',sa.String(64),nullable=False),
        sa.Column('ceremony_hash',sa.String(64),nullable=False),
        sa.Column('encrypted_attempt',sa.Text,nullable=False),
        sa.Column('expires_at',sa.DateTime(timezone=True),nullable=False),
        sa.Column('used_at',sa.DateTime(timezone=True)))
    op.create_index('ix_mdm_web_activations_tenant_id','mdm_web_activations',['tenant_id'])


def downgrade():
    op.drop_table('mdm_web_activations')
    op.drop_table('mdm_web_ceremonies')
    op.drop_table('mdm_apple_inventory')
    op.drop_table('mdm_provisions')

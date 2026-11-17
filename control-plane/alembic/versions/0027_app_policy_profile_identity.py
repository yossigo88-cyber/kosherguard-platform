"""Track the applied applicationaccess profile identifier per device policy.

Review finding A1: applying a policy used to queue an InstallProfile
whose PayloadIdentifier embed the mode and whose UUID was fresh every
time, so a blocklist<->allowlist switch stacked a second profile and
left the first one's restrictions installed with no removal path. The
identifier is now stable (mdm.app_management.PROFILE_IDENTIFIER) and
this column records what was last queued so apply can clean up a
legacy per-mode profile and unapply can queue RemoveProfile against
the exact identifier.
"""
from alembic import op
import sqlalchemy as sa

revision = '0027'
down_revision = '0026'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('device_app_policies',
                  sa.Column('profile_identifier', sa.String(255),
                            nullable=True))


def downgrade():
    op.drop_column('device_app_policies', 'profile_identifier')

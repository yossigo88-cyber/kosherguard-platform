"""System-action marker for publication jobs.

Server-set only (never accepted from the jobs API): marks a job as a
narrow, server-initiated cleanup publication such as an exception
revocation, so the worker can run it without re-checking the initiating
user's current publish delegation - while API-enqueued jobs keep the
full actor re-check.
"""
from alembic import op
import sqlalchemy as sa
revision='0016'
down_revision='0015'
branch_labels=None
depends_on=None


def upgrade():
    op.add_column('publication_jobs',
                  sa.Column('system_action', sa.String(40), nullable=True))


def downgrade():
    op.drop_column('publication_jobs', 'system_action')

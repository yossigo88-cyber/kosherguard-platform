"""Enrollment device_udid: the pre-association identity key.

Security fix round 3 (user-approved 2026-11-16): the UDID expected at
enrollment, recorded when the enrollment is created (from the device
record / operator input, never from a later caller claim). The first
authenticated DDM contact binds a pending record whose recorded UDID
uniquely matches the real NanoMDM enrollment ID.

Revision: 0007
"""

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"


def upgrade() -> None:
    op.add_column(
        "mdm_enrollments",
        sa.Column("device_udid", sa.String(length=120), nullable=True))


def downgrade() -> None:
    op.drop_column("mdm_enrollments", "device_udid")

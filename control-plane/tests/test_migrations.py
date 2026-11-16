"""Schema migration tests: alembic upgrade from the preserved prior
schema (0006) to head adds mdm_enrollments.device_udid and preserves
existing rows - not just metadata.create_all."""

import os
import sqlite3
import sys
from datetime import datetime, timezone

import pytest
from alembic import command
from alembic.config import Config

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _cfg(db_path, rev=None):
    cfg = Config(os.path.join(os.path.dirname(__file__), "..",
                              "alembic.ini"))
    cfg.set_main_option(
        "script_location",
        os.path.join(os.path.dirname(__file__), "..", "alembic"))
    os.environ["KG_DATABASE_URL"] = f"sqlite:///{db_path}"
    return cfg


def test_upgrade_from_prior_schema_preserves_rows(tmp_path):
    db = tmp_path / "mig.db"
    cfg = _cfg(str(db))
    # Build the preserved prior schema (0006) and insert a row as the
    # old code would have.
    command.upgrade(cfg, "0006")
    con = sqlite3.connect(str(db))
    con.execute(
        "INSERT INTO tenants (id, name, created_at) VALUES (1, 't1', ?)",
        (datetime.now(timezone.utc).isoformat(),))
    dev_cols = [r[1] for r in con.execute(
        "PRAGMA table_info(devices)").fetchall()]
    vals = {"id": 1, "tenant_id": 1, "name": "d1",
            "state": "active",
            "created_at": datetime.now(timezone.utc).isoformat()}
    cols = [c for c in dev_cols if c in vals]
    con.execute(
        f"INSERT INTO devices ({', '.join(cols)}) "
        f"VALUES ({', '.join('?' for _ in cols)})",
        tuple(vals[c] for c in cols))
    con.execute(
        "INSERT INTO mdm_enrollments (id, tenant_id, device_id, "
        "enrollment_id, state, supervision_requested, "
        "supervision_verified, created_at) "
        "VALUES (1, 1, 1, 'pending-x', 'pending', 0, 0, ?)",
        (datetime.now(timezone.utc).isoformat(),))
    con.commit()
    # Upgrade to head: the column arrives, the row survives.
    command.upgrade(cfg, "head")
    cols = [r[1] for r in con.execute(
        "PRAGMA table_info(mdm_enrollments)").fetchall()]
    assert "device_udid" in cols
    row = con.execute(
        "SELECT enrollment_id, state, device_udid FROM mdm_enrollments"
        ).fetchone()
    assert row == ("pending-x", "pending", None)
    con.close()
    # And the new column is writable through the ORM path.
    from app.db import make_engine, session_scope
    from app.models import MDMEnrollment
    from sqlalchemy import select
    engine = make_engine(f"sqlite:///{db}")
    with session_scope(engine) as session:
        enr = session.scalar(select(MDMEnrollment).where(
            MDMEnrollment.enrollment_id == "pending-x"))
        enr.device_udid = "UDID-123"
    with session_scope(engine) as session:
        enr = session.scalar(select(MDMEnrollment).where(
            MDMEnrollment.enrollment_id == "pending-x"))
        assert enr.device_udid == "UDID-123"

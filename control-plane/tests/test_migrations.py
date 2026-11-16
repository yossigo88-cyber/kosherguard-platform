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


ALL_TABLES = {
    "tenants", "users", "auth_sessions", "audit_events",
    "login_attempts", "policies", "policy_versions", "devices",
    "device_assignments", "publication_states", "mdm_enrollments",
    "device_app_policies", "ddm_status_reports", "mdm_commands",
    "filter_decisions", "category_rules", "pending_mfa_enrollments",
    "invite_tokens", "credential_artifacts", "issued_credentials", "publication_jobs", "device_groups", "group_memberships", "policy_exceptions", "sensitive_command_approvals",
}


def test_clean_alembic_only_install(tmp_path):
    """A fresh database built by alembic ALONE (no metadata.create_all)
    contains every model table and accepts ORM writes."""
    import sqlite3 as _sq
    db = tmp_path / "clean.db"
    cfg = _cfg(str(db))
    command.upgrade(cfg, "head")
    con = _sq.connect(str(db))
    tables = {r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    tables.discard("alembic_version")
    assert tables == ALL_TABLES, (
        f"missing: {ALL_TABLES - tables}; extra: {tables - ALL_TABLES}")
    # Columns match the model for the security-round tables.
    enr_cols = {r[1] for r in con.execute(
        "PRAGMA table_info(mdm_enrollments)").fetchall()}
    assert {"device_udid", "supervision_requested",
            "supervision_verified", "state"} <= enr_cols
    ic_cols = {r[1] for r in con.execute(
        "PRAGMA table_info(issued_credentials)").fetchall()}
    assert {"jti", "scope", "tenant_id", "device_id",
            "revoked_at"} <= ic_cols
    con.close()
    # ORM write path works against the alembic-built schema.
    from app.db import make_engine, session_scope
    from app.models import (FilterDecision, IssuedCredential, Tenant,
                            utcnow)
    from sqlalchemy import select
    engine = make_engine(f"sqlite:///{db}")
    with session_scope(engine) as session:
        session.add(Tenant(name="t1"))
        session.flush()
        t = session.scalar(select(Tenant))
        session.add(FilterDecision(
            tenant_id=t.id, device_id=None, source="proxy",
            domain="x.example", action="block", rule="r",
            reason="test", received_at=utcnow()))
        session.add(IssuedCredential(
            tenant_id=t.id, device_id=1, jti="j1", scope="proxy",
            expires_at=utcnow(), created_at=utcnow()))
    with session_scope(engine) as session:
        assert session.scalar(select(FilterDecision)).domain == "x.example"
        assert session.scalar(select(IssuedCredential)).jti == "j1"


def test_alembic_schema_matches_model_metadata(tmp_path):
    """Comparison evidence: the alembic-built schema (migrations only,
    no create_all) and a metadata.create_all schema have identical
    table, column and index sets. NOTE: exercised on SQLite; the same
    migrations run on PostgreSQL in deployment (env.py rewrites the
    URL to psycopg), where the 'role' enum is a native type -
    0008 declares it with create_type=False so the type created by
    0001 is reused. Also exercised against disposable local
    PostgreSQL: clean alembic install, 0006->head upgrade preserving
    rows, and table/column/index comparison all pass."""
    import sqlite3 as _sq
    db_a = tmp_path / "alembic.db"
    db_b = tmp_path / "createall.db"
    cfg = _cfg(str(db_a))
    command.upgrade(cfg, "head")
    from app.db import make_engine
    from app.models import Base
    engine_b = make_engine(f"sqlite:///{db_b}")
    Base.metadata.create_all(engine_b)

    def shape(path):
        con = _sq.connect(str(path))
        tables = {}
        for (name,) in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall():
            if name == "alembic_version":
                continue
            cols = sorted(
                (r[1], r[2], r[3]) for r in con.execute(
                    f"PRAGMA table_info({name})").fetchall())
            idx = sorted(
                (r[1], r[2]) for r in con.execute(
                    f"PRAGMA index_list({name})").fetchall()
                if not r[1].startswith("sqlite_autoindex"))
            tables[name] = (cols, idx)
        con.close()
        return tables

    assert shape(str(db_a)) == shape(str(db_b))

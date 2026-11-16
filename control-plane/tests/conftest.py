import os
import sys
import uuid

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))  # mfa_support et al.

import pgserver  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402

from app import db as db_module  # noqa: E402


@pytest.fixture(scope="session")
def pg_uri():
    server = pgserver.get_server(f"/tmp/kg-pg-{uuid.uuid4().hex[:8]}")
    yield server.get_uri()


@pytest.fixture()
def engine(pg_uri):
    # pgserver's URI is driver-neutral; SQLAlchemy uses psycopg v3.
    url = pg_uri.replace("postgresql://", "postgresql+psycopg://", 1)
    eng = create_engine(url)
    db_module.create_schema(eng)
    yield eng
    with eng.begin() as conn:
        for table in ("sensitive_command_approvals", "category_rules", "invite_tokens", "mdm_commands", "mdm_enrollments", "login_attempts", "audit_events", "auth_sessions", "users", "tenants"):
            conn.execute(text(f"TRUNCATE {table} CASCADE"))
    eng.dispose()

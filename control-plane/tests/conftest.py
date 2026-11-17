import os
import sys
import uuid

# Tests run with a lowered (but still bounded) PBKDF2 cost so the
# suite stays fast; production default is 600k (app/security.py).
os.environ.setdefault("KG_PBKDF2_ITERATIONS", "50000")

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
    try:
        yield eng
    finally:
        # All model tables, not a hand-maintained subset. Keep sequences
        # advancing so tests cannot accidentally rely on hardcoded IDs.
        names = ", ".join('"' + t.name + '"'
                          for t in db_module.Base.metadata.sorted_tables)
        with eng.begin() as conn:
            conn.execute(text(f"TRUNCATE {names} CASCADE"))
        eng.dispose()

import os
import sys

from alembic import context

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.models import Base  # noqa: E402

target_metadata = Base.metadata


def run_migrations_online() -> None:
    from sqlalchemy import create_engine

    url = os.environ.get("KG_DATABASE_URL", "").strip()
    if not url:
        raise RuntimeError("KG_DATABASE_URL is required to run migrations")
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+psycopg://", 1)
    engine = create_engine(url)
    with engine.connect() as connection:
        context.configure(connection=connection,
                          target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()

"""Database engine and scoped data access.

session_scope yields a SQLAlchemy session. ScopedSession wraps it with a
tenant id and refuses any query or write that names a different tenant -
the tenant-isolation guard, with negative tests proving tenant A cannot
read or mutate tenant B.
"""

from __future__ import annotations

from contextlib import contextmanager

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from .models import AuditEvent, Base, Tenant, User


class TenantIsolationError(RuntimeError):
    pass


def make_engine(database_url: str):
    return create_engine(database_url, pool_pre_ping=True)


def create_schema(engine) -> None:
    Base.metadata.create_all(engine)


@contextmanager
def session_scope(engine):
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


class ScopedSession:
    """Tenant-scoped access; every read and write is pinned to tenant_id."""

    def __init__(self, session: Session, tenant_id: int) -> None:
        self._session = session
        self.tenant_id = tenant_id

    def _check(self, row_tenant_id: int) -> None:
        if row_tenant_id != self.tenant_id:
            raise TenantIsolationError(
                f"row belongs to tenant {row_tenant_id}, "
                f"not tenant {self.tenant_id}")

    def users(self) -> list[User]:
        return list(
            self._session.scalars(
                select(User).where(User.tenant_id == self.tenant_id)))

    def get_user(self, user_id: int) -> User | None:
        user = self._session.get(User, user_id)
        if user is None:
            return None
        self._check(user.tenant_id)
        return user

    def add_user(self, email: str, password_hash: str, role) -> User:
        user = User(tenant_id=self.tenant_id, email=email,
                    password_hash=password_hash, role=role)
        self._session.add(user)
        self._session.flush()
        return user

    def audit(self, action: str, detail: str = "",
              actor_user_id: int | None = None) -> AuditEvent:
        event = AuditEvent(tenant_id=self.tenant_id, action=action,
                           detail=detail, actor_user_id=actor_user_id)
        self._session.add(event)
        self._session.flush()
        return event

    def audit_events(self) -> list[AuditEvent]:
        return list(
            self._session.scalars(
                select(AuditEvent)
                .where(AuditEvent.tenant_id == self.tenant_id)
                .order_by(AuditEvent.id)))

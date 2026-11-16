"""Control-plane data model.

The family is the tenant. Every scoped table carries tenant_id and the
data layer refuses cross-tenant access. Users are guardians of a tenant
with a role. Sessions store only token hashes. Audit events are
append-only.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    DateTime, Enum, ForeignKey, Integer, String, Text, UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Role(str, enum.Enum):
    owner = "owner"        # full control, manages other guardians
    guardian = "guardian"  # manages policies and devices
    viewer = "viewer"      # read-only


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False)


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("tenant_id", "email"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id"), nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[Role] = mapped_column(Enum(Role), nullable=False)
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tenant: Mapped[Tenant] = relationship()
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False)


class AuthSession(Base):
    __tablename__ = "auth_sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    tenant_id: Mapped[int] = mapped_column(
        ForeignKey("tenants.id"), nullable=False, index=True)
    actor_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False)


class LoginAttempt(Base):
    """Persisted login-rate-limit state; restarts do not reset lockouts."""
    __tablename__ = "login_attempts"
    key: Mapped[str] = mapped_column(String(400), primary_key=True)
    failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    first_failure_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow)

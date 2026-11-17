"""Guardian account lifecycle routes: guardian list, invites,
invite acceptance, MFA reset. Extracted from main.py."""
import json
from datetime import timedelta

from fastapi import Depends, Response  # noqa: F401
from sqlalchemy import select
from sqlalchemy.orm import Session  # noqa: F401

from pydantic import BaseModel

from . import security
from .db import ScopedSession, lock_tenant
from .models import (AuthSession, InviteToken, LoginAttempt,  # noqa: F401
                     PendingMfaEnrollment, Role, User, utcnow)
from .staff_routes import fresh_check as _fresh_check


def _aware(value):
    from datetime import timezone
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


class DelegationBody(BaseModel):
    capabilities: list[str]
class RoleBody(BaseModel):
    role: str
class AcceptInviteBody(BaseModel):
    token: str
    password: str
class InviteBody(BaseModel):
    email: str
    role: str = "guardian"
class MfaResetBody(BaseModel):
    password: str
    totp_code: str | None = None
    confirm: str | None = None

GUARDIAN_CAPABILITIES = {"policies", "schedules", "devices", "groups", "apps", "publish", "exceptions"}

def register_guardian_routes(app, *, error, current_user, db_session,
                             require_csrf_header, require_owner, user_json,
                             settings):

    # -- Guardian account lifecycle (M6) ------------------------------

    # Approved requirement: multiple authorized parent/guardian
    # accounts per family tenant. Owners invite; invite tokens are
    # single-use, expiring, and stored hashed.
    from .models import InviteToken

    @app.put("/api/guardians/{user_id}/delegation", dependencies=[Depends(require_csrf_header)])
    def set_delegation(user_id: int, body: DelegationBody, user: User = Depends(current_user), session: Session = Depends(db_session)):
        denied=require_owner(user)
        if denied is not None:return denied
        target=session.get(User,user_id)
        if target is None or target.tenant_id!=user.tenant_id:return error(404,"guardian not found")
        if target.role != Role.guardian:return error(400,"delegation is for guardian accounts only")
        if not set(body.capabilities) <= GUARDIAN_CAPABILITIES:return error(400,"unsupported delegated capability")
        target.delegated_settings=json.dumps(sorted(set(body.capabilities)))
        ScopedSession(session,user.tenant_id).audit("guardian.delegation",f"user {user_id}: {target.delegated_settings}",actor_user_id=user.id)
        return {"id":target.id,"delegated_settings":json.loads(target.delegated_settings)}

    @app.get("/api/guardians")
    def list_guardians(user: User = Depends(current_user),
                       session: Session = Depends(db_session)):
        rows = ScopedSession(session, user.tenant_id).query(
            User, User.id).all() if hasattr(ScopedSession, "query") else             session.execute(select(User).where(
                User.tenant_id == user.tenant_id)).scalars().all()
        return {"guardians": [user_json(u) for u in rows]}

    @app.post("/api/guardians/invite",
              dependencies=[Depends(require_csrf_header)])
    def invite_guardian(body: InviteBody,
                        user: User = Depends(current_user),
                        session: Session = Depends(db_session)):
        denied = require_owner(user)
        if denied is not None:
            return denied
        email = body.email.strip().lower()
        if "@" not in email:
            return error(400, "invalid email")
        if body.role not in ("guardian", "viewer", "owner"):
            return error(400, "invalid role")
        existing = session.execute(select(User).where(
            User.tenant_id == user.tenant_id,
            User.email == email)).scalar_one_or_none()
        if existing is not None:
            return error(409, "email already has an account")
        # One live invite per email: a second invite would hand out a
        # second valid path to the same account. The partial unique
        # index (used_at IS NULL) enforces this under concurrency.
        active = session.execute(select(InviteToken).where(
            InviteToken.tenant_id == user.tenant_id,
            InviteToken.email == email,
            InviteToken.used_at.is_(None))).scalars().all()
        if any(_aware(i.expires_at) > utcnow() for i in active):
            return error(409, "an active invite already exists for this email")
        # The partial unique index includes expired-but-unused rows.
        # Retire them explicitly before issuing the replacement.
        for old_invite in active:
            old_invite.used_at = utcnow()
        session.flush()
        raw = security.new_session_token()
        invite = InviteToken(
            tenant_id=user.tenant_id, email=email, role=Role(body.role),
            token_hash=security.hash_session_token(raw),
            invited_by_user_id=user.id,
            expires_at=utcnow() + timedelta(hours=72))
        session.add(invite)
        try:
            session.flush()
        except Exception as exc:
            from sqlalchemy.exc import IntegrityError
            session.rollback()
            if isinstance(exc, IntegrityError):
                return error(409, "an active invite already exists for this email")
            raise
        ScopedSession(session, user.tenant_id).audit(
            "guardian.invite", email, actor_user_id=user.id)
        session.commit()
        # The raw token is returned once; delivery to the invitee is
        # out of band. It is never stored or logged.
        return {"invited": email, "role": body.role,
                "invite_token": raw,
                "expires_at": invite.expires_at.isoformat()}

    @app.post("/api/invites/accept",
              dependencies=[Depends(require_csrf_header)])
    def accept_invite(body: AcceptInviteBody,
                      session: Session = Depends(db_session)):
        # Row lock: two concurrent accepts of the same token
        # serialize; the second sees used_at set and is refused.
        invite = session.execute(select(InviteToken).where(
            InviteToken.token_hash == security.hash_session_token(
                body.token)).with_for_update()).scalar_one_or_none()
        if invite is None or invite.used_at is not None:
            return error(400, "invalid or used invite")
        if _aware(invite.expires_at) <= utcnow():
            return error(400, "invite expired")
        if len(body.password) < 12:
            return error(400, "password too short")
        existing = session.execute(select(User).where(
            User.tenant_id == invite.tenant_id,
            User.email == invite.email)).scalar_one_or_none()
        if existing is not None:
            return error(409, "email already has an account")
        new_user = User(
            tenant_id=invite.tenant_id, email=invite.email,
            password_hash=security.hash_password(body.password),
            role=invite.role)
        session.add(new_user)
        invite.used_at = utcnow()
        try:
            session.flush()
        except Exception as exc:
            from sqlalchemy.exc import IntegrityError
            session.rollback()
            if isinstance(exc, IntegrityError):
                return error(409, "email already has an account")
            raise
        ScopedSession(session, invite.tenant_id).audit(
            "guardian.accept_invite", invite.email,
            actor_user_id=new_user.id)
        session.commit()
        return {"accepted": invite.email, "role": invite.role.value}

    @app.put("/api/guardians/{user_id}/role",
             dependencies=[Depends(require_csrf_header)])
    def change_role(user_id: int, body: RoleBody,
                    user: User = Depends(current_user),
                    session: Session = Depends(db_session)):
        denied = require_owner(user)
        if denied is not None:
            return denied
        if body.role not in ("guardian", "viewer", "owner"):
            return error(400, "invalid role")
        # Lock the tenant row first: concurrent owner demotions
        # serialize, so the last-owner check below can never be
        # satisfied by two racing requests at once.
        lock_tenant(session, user.tenant_id)
        target = session.get(User, user_id)
        if target is None or target.tenant_id != user.tenant_id:
            return error(404, "guardian not found")
        if target.id == user.id:
            return error(400, "cannot change your own role")
        if target.role == Role.owner and body.role != "owner":
            owners = session.scalars(select(User).where(
                User.tenant_id == user.tenant_id,
                User.role == Role.owner)).all()
            if len(owners) <= 1:
                return error(409, "cannot demote the last owner of the "
                                  "tenant")
        target.role = Role(body.role)
        ScopedSession(session, user.tenant_id).audit(
            "guardian.role_change",
            f"{target.email} -> {body.role}", actor_user_id=user.id)
        session.commit()
        return user_json(target)

    @app.post("/api/guardians/{user_id}/mfa-reset",
              dependencies=[Depends(require_csrf_header)])
    def mfa_reset(user_id: int, body: MfaResetBody,
                  user: User = Depends(current_user),
                  session: Session = Depends(db_session)):
        denied = require_owner(user)
        if denied is not None:
            return denied
        # Fresh authentication: an unattended session must not be
        # enough to strip a guardian's MFA. Password AND a current MFA
        # code with explicit confirmation.
        if not security.verify_password(body.password,
                                        user.password_hash):
            return error(403, "fresh authentication failed")
        bad = _fresh_check(error, user, body.totp_code, body.confirm,
                           "mfa-reset")
        if bad is not None:
            return bad
        target = session.get(User, user_id)
        if target is None or target.tenant_id != user.tenant_id:
            return error(404, "guardian not found")
        if target.id == user.id:
            return error(400, "cannot remove your own MFA; use another verified owner")
        target.totp_secret = None
        for old in session.scalars(select(AuthSession).where(AuthSession.user_id == target.id)):
            session.delete(old)
        pending = session.scalar(select(PendingMfaEnrollment).where(PendingMfaEnrollment.user_id == target.id))
        if pending is not None:
            session.delete(pending)
        ScopedSession(session, user.tenant_id).audit(
            "guardian.mfa_reset", target.email, actor_user_id=user.id)
        session.commit()
        return user_json(target)

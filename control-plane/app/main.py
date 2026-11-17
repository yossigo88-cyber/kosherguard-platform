"""KosherGuard control-plane API (Milestone 1 slice).

Endpoints: health, login (password + optional TOTP MFA), logout, me.
Sessions are random tokens stored hashed server-side; the browser gets
an HttpOnly SameSite=Strict cookie. State-changing endpoints require the
X-KosherGuard-Request header, which a cross-site form cannot set (CSRF
defense adapted from the reviewed dashboard). Login attempts are rate
limited with state persisted in the login_attempts table so restarts do
not reset lockouts. All errors are JSON {"error": ...}; no internals
leak to clients.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from . import app_ops
from . import ddm_ops, filter_log_ops
from . import mdm_ops
from .ddm_routes import register_ddm_routes
from .enrollment_routes import register_enrollment_routes
from .restore_routes import register_restore_routes
from .support_routes import register_support_routes
from .observability import register_observability
from .category_source_routes import register_category_source_routes
from .offboarding_routes import register_offboarding_routes
from .guardian_routes import register_guardian_routes
from .staff_routes import (ALL_STAFF, fresh_check,
                           register_staff_routes, require_staff)
from . import schedule_ops, security
from mdm.adapter import DESTRUCTIVE_COMMANDS
from .config import Settings
from .db import ScopedSession, make_engine
from .models import (StaffRole, SensitiveCommandApproval, AuthSession, LoginAttempt,
                     PendingMfaEnrollment, Role, User, Tenant)




class GroupBody(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    policy_id: int | None = None


class PolicyPreviewBody(BaseModel):
    domain: str
    at: datetime | None = None


class PublicationJobBody(BaseModel):
    request_key: str


class CategoryRuleBody(BaseModel):
    domain: str
    category: str
    verdict: str = "block"
    source: str = "manual-review"






class PolicyBody(BaseModel):
    name: str
    description: str = ""
    default_policy: str
    allowlist: list[str] = []
    blocklist: list[str] = []
    category_allow: list[str] = []
    category_block: list[str] = []
    enabled: bool = True
    schedules: list[dict] | None = None


class DeviceBody(BaseModel):
    name: str


class AssignmentBody(BaseModel):
    policy_id: int


class SchedulesBody(BaseModel):
    schedules: list[dict]


class EnrollmentBody(BaseModel):
    device_id: int
    supervision_requested: bool = False
    device_udid: str | None = None


class MDMCommandBody(BaseModel):
    command: str
    payload: dict = {}
    # Required only for destructive commands (Answer 25): fresh TOTP
    # verification and an explicit confirmation equal to the command.
    totp_code: str | None = None
    confirm: str | None = None
    reason: str | None = None
class RetentionBody(BaseModel):
    days: int = Field(strict=True, ge=1, le=30)


class FilterLogBody(BaseModel):
    decisions: list[dict]


class AppPolicyBody(BaseModel):
    mode: str
    bundle_ids: list[str] = []


class AppCommandBody(BaseModel):
    action: str
    itunes_store_id: int | None = None
    bundle_id: str | None = None
    configuration: dict | None = None




class CredentialBody(BaseModel):
    kind: str
    label: str
    content_base64: str


class MintBody(BaseModel):
    scope: str = "dataset"


class LoginBody(BaseModel):
    email: str
    password: str
    tenant_name: str | None = None
    totp_code: str | None = None


class PasswordChangeBody(BaseModel):
    current_password: str
    new_password: str


class MfaConfirmBody(BaseModel):
    code: str
    password: str


SESSION_COOKIE = "kg_session"
CSRF_HEADER = "x-kosherguard-request"
MAX_FAILURES = 5
LOCKOUT_SECONDS = 60

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def error(status: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": message})


def _load_device_auth():
    """Load the shared device_auth by file path - the control plane's
    own package is also named "app", so a plain import would resolve
    to the wrong package."""
    import importlib.util as _ilu
    _da_path = os.path.abspath(os.path.join(
        os.path.dirname(__file__), "..", "..",
        "url-filter-server", "app", "device_auth.py"))
    _spec = _ilu.spec_from_file_location("kg_device_auth", _da_path)
    _da = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_da)
    return _da


def create_app(settings: Settings, engine=None) -> FastAPI:
    app = FastAPI(title="KosherGuard Control Plane", docs_url=None,
                  redoc_url=None)
    engine = engine or make_engine(settings.database_url)
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    def db_session():
        session = factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def limiter_key(email: str, request: Request) -> str:
        client = request.client.host if request.client else "unknown"
        return f"{email.strip().lower()}|{client}"

    def is_locked(session: Session, key: str) -> bool:
        row = session.get(LoginAttempt, key)
        if row is None:
            return False
        first = row.first_failure_at
        if first.tzinfo is None:
            first = first.replace(tzinfo=timezone.utc)
        if (utcnow() - first).total_seconds() >= LOCKOUT_SECONDS:
            session.delete(row)
            session.flush()
            return False
        return row.failures >= MAX_FAILURES

    def record_failure(session: Session, key: str) -> None:
        row = session.get(LoginAttempt, key)
        if row is None:
            session.add(LoginAttempt(key=key, failures=1,
                                     first_failure_at=utcnow()))
        else:
            row.failures += 1
        session.flush()

    def require_csrf_header(request: Request) -> None:
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            if request.headers.get(CSRF_HEADER) != "1":
                from fastapi import HTTPException
                raise HTTPException(status_code=403,
                                    detail="missing request header")

    def current_user(request: Request,
                     session: Session = Depends(db_session)) -> User:
        token = request.cookies.get(SESSION_COOKIE)
        if not token:
            from fastapi import HTTPException
            raise HTTPException(status_code=401, detail="not signed in")
        token_hash = security.hash_session_token(token)
        row = session.scalar(
            select(AuthSession).where(
                AuthSession.token_hash == token_hash))
        if row is None:
            from fastapi import HTTPException
            raise HTTPException(status_code=401, detail="invalid session")
        expires = row.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires <= utcnow():
            session.delete(row)
            session.commit()
            from fastapi import HTTPException
            raise HTTPException(status_code=401, detail="session expired")
        user = session.get(User, row.user_id)
        if user is None:
            from fastapi import HTTPException
            raise HTTPException(status_code=401, detail="invalid session")
        request.state.mfa_verified = bool(row.mfa_verified)
        # A password-only login is a restricted enrollment session, not
        # permission to operate the tenant. Read checks also cover existing
        # sessions, role promotion and accounts whose MFA was reset.
        if (user.role in (Role.owner, Role.guardian) or user.is_platform_admin
                or user.staff_role is not None):
            enrollment_paths = {"/api/auth/me", "/api/auth/logout",
                "/api/auth/mfa/enroll-start", "/api/auth/mfa/enroll-confirm",
                "/api/auth/password-change"}
            if request.url.path not in enrollment_paths and (
                    not user.totp_secret or not row.mfa_verified):
                from fastapi import HTTPException
                raise HTTPException(status_code=403,
                    detail="verified MFA required; enroll then sign in with a code")
        # Answer 29: read_only staff may VIEW authorized information
        # only. Block every mutating call outside account self-service
        # (/api/auth/*), even when the account also holds a tenant owner
        # role - the same precedence as the destructive-command limit.
        if (user.staff_role == StaffRole.read_only.value
                and request.method not in ("GET", "HEAD", "OPTIONS")
                and not request.url.path.startswith("/api/auth/")):
            from fastapi import HTTPException
            raise HTTPException(status_code=403,
                detail="read-only staff role: viewing authorized information only")
        # Serialize tenant configuration writes with publication/default
        # changes. The lock lives through the same request DB transaction.
        if request.method in {"POST", "PUT", "DELETE", "PATCH"} and request.url.path.startswith(("/api/policies", "/api/devices", "/api/groups", "/api/publications")):
            from .models import PublicationState
            session.scalar(select(PublicationState).where(
                PublicationState.tenant_id == user.tenant_id).with_for_update())
        return user

    @app.middleware("http")
    async def private_responses(request: Request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store, private"
            response.headers["Pragma"] = "no-cache"
        return response

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/api/auth/login", dependencies=[Depends(require_csrf_header)])
    def login(body: LoginBody, request: Request, response: Response,
              session: Session = Depends(db_session)):
        key = limiter_key(body.email, request)
        if is_locked(session, key):
            return error(429, "too many failed attempts; try again later")
        users = list(session.scalars(
            select(User).where(User.email == body.email.strip().lower())))
        if body.tenant_name:
            users = [u for u in users if u.tenant.name == body.tenant_name]
        user = users[0] if len(users) == 1 else None
        if (user is None
                or not security.verify_password(body.password,
                                                user.password_hash)):
            record_failure(session, key)
            session.commit()
            return error(401, "invalid credentials")
        if user.totp_secret:
            if not body.totp_code or not security.verify_totp(
                    user.totp_secret, body.totp_code):
                record_failure(session, key)
                session.commit()
                return error(401, "invalid credentials")
        row = session.get(LoginAttempt, key)
        if row is not None:
            session.delete(row)
        token = security.new_session_token()
        lifetime = timedelta(seconds=settings.session_lifetime_seconds)
        session.add(AuthSession(
            user_id=user.id,
            token_hash=security.hash_session_token(token),
            expires_at=utcnow() + lifetime,
            mfa_verified=bool(user.totp_secret)))
        session.commit()
        response.set_cookie(
            SESSION_COOKIE, token, httponly=True, samesite="strict",
            secure=settings.secure_cookies, max_age=int(lifetime.total_seconds()))
        return {"status": "signed_in", "role": user.role.value,
                "mfa_required": bool((user.role != Role.viewer or user.is_platform_admin or user.staff_role is not None) and not user.totp_secret)}

    @app.post("/api/auth/logout", dependencies=[Depends(require_csrf_header)])
    def logout(request: Request, response: Response,
               session: Session = Depends(db_session)):
        token = request.cookies.get(SESSION_COOKIE)
        if token:
            row = session.scalar(
                select(AuthSession).where(
                    AuthSession.token_hash
                    == security.hash_session_token(token)))
            if row is not None:
                session.delete(row)
                session.commit()
        response.delete_cookie(SESSION_COOKIE)
        return {"status": "signed_out"}

    @app.get("/api/auth/me")
    def me(request: Request, user: User = Depends(current_user)):
        return {"email": user.email, "role": user.role.value,
                "tenant_id": user.tenant_id,
                "mfa_enabled": user.totp_secret is not None,
                "privileged": user.role != Role.viewer or user.is_platform_admin,
                "staff_role": user.staff_role,
                "mfa_verified": request.state.mfa_verified,
                "delegated_settings": json.loads(user.delegated_settings)}

    # -- Tenant audit log viewer (spec Part 10: Settings > logs) --------
    # Append-only audit events, tenant-scoped, newest first. Any
    # authenticated tenant user may read (viewers included: read-only
    # visibility of who changed what); writes remain role-gated.
    @app.get("/api/audit-logs")
    def audit_logs(user: User = Depends(current_user),
                   session: Session = Depends(db_session)):
        rows = session.execute(
            select(AuditEvent)
            .where(AuditEvent.tenant_id == user.tenant_id)
            .order_by(AuditEvent.id.desc())
            .limit(200)).scalars().all()
        emails = {u.id: u.email for u in session.execute(
            select(User).where(User.tenant_id == user.tenant_id))
            .scalars().all()}
        return {"events": [
            {"id": e.id, "action": e.action, "detail": e.detail,
             "actor": emails.get(e.actor_user_id, "system"),
             "created_at": e.created_at.isoformat()} for e in rows]}

    # -- Account self-service (M6 follow-up, hardened) ------------------
    # Password change requires the current password (fresh auth) and
    # invalidates the account's OTHER sessions: changing the password
    # is the remediation step after suspected compromise, so it must
    # actually kick other sessions out. MFA enrollment is server-bound:
    # enroll-start generates and stores the secret server-side (one
    # pending row per user, replaced on restart, 10-minute expiry);
    # enroll-confirm requires the account password and a valid code
    # against THAT stored secret, then promotes and deletes it. The
    # client never supplies the secret, so it cannot substitute a
    # known/weak one, bind another user's pending secret, or replay an
    # old URI after expiry.
    @app.post("/api/auth/password-change",
              dependencies=[Depends(require_csrf_header)])
    def password_change(body: PasswordChangeBody, request: Request,
                        user: User = Depends(current_user),
                        session: Session = Depends(db_session)):
        if not security.verify_password(body.current_password,
                                        user.password_hash):
            return error(403, "current password incorrect")
        if len(body.new_password) < 12:
            return error(400, "password too short")
        user.password_hash = security.hash_password(body.new_password)
        current_token = request.cookies.get(SESSION_COOKIE)
        current_hash = (security.hash_session_token(current_token)
                        if current_token else None)
        others = session.execute(select(AuthSession).where(
            AuthSession.user_id == user.id,
            AuthSession.token_hash != current_hash)).scalars().all()
        for row in others:
            session.delete(row)
        ScopedSession(session, user.tenant_id).audit(
            "auth.password_change",
            f"{user.email} other_sessions_invalidated={len(others)}",
            actor_user_id=user.id)
        session.commit()
        return {"changed": True,
                "other_sessions_invalidated": len(others)}

    @app.post("/api/auth/mfa/enroll-start",
              dependencies=[Depends(require_csrf_header)])
    def mfa_enroll_start(user: User = Depends(current_user),
                         session: Session = Depends(db_session)):
        if user.totp_secret:
            return error(409, "MFA already enrolled")
        secret = security.new_totp_secret()
        pending = session.execute(select(PendingMfaEnrollment).where(
            PendingMfaEnrollment.user_id == user.id)).scalar_one_or_none()
        if pending is None:
            pending = PendingMfaEnrollment(user_id=user.id, secret=secret,
                                           expires_at=utcnow())
            session.add(pending)
        pending.secret = secret
        pending.expires_at = utcnow() + timedelta(minutes=10)
        session.commit()
        import pyotp
        uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user.email, issuer_name="KosherGuard")
        return {"secret": secret, "provisioning_uri": uri,
                "expires_in_seconds": 600}

    @app.post("/api/auth/mfa/enroll-confirm",
              dependencies=[Depends(require_csrf_header)])
    def mfa_enroll_confirm(body: MfaConfirmBody,
                           user: User = Depends(current_user),
                           session: Session = Depends(db_session)):
        if user.totp_secret:
            return error(409, "MFA already enrolled")
        confirm_key = f"mfa-confirm:{user.id}"
        if is_locked(session, confirm_key):
            return error(429, "too many confirmation attempts; try again later")
        if not security.verify_password(body.password,
                                        user.password_hash):
            record_failure(session, confirm_key)
            return error(403, "fresh authentication failed")
        pending = session.execute(select(PendingMfaEnrollment).where(
            PendingMfaEnrollment.user_id == user.id)).scalar_one_or_none()
        if pending is None:
            return error(400, "no enrollment started")
        expires = pending.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires < utcnow():
            session.delete(pending)
            session.commit()
            return error(400, "enrollment expired; start again")
        if not security.verify_totp(pending.secret, body.code):
            record_failure(session, confirm_key)
            return error(400, "invalid code")
        user.totp_secret = pending.secret
        session.delete(pending)
        ScopedSession(session, user.tenant_id).audit(
            "auth.mfa_enroll", user.email, actor_user_id=user.id)
        session.commit()
        return {"mfa_enabled": True}

    # -- Milestone 2: policies, devices, tighten-only enforcement ------

    from . import policy_ops, publication_ops
    from .models import (AuditEvent, Device, DeviceAssignment,
                         IssuedCredential, MDMEnrollment, Policy,
                         PolicyVersion, PublicationState)


    def require_guardian(user: User, capability="devices") -> JSONResponse | None:
        if user.role == Role.owner:
            return None
        if user.role != Role.guardian:
            return error(403, "viewers cannot change configuration")
        try:grants = json.loads(user.delegated_settings)
        except (ValueError, TypeError):grants = []
        if capability not in grants:
            return error(403, "owner has not delegated this setting")
        return None

    def guard_baseline(user, session, policy, proposed=None):
        if user.role == Role.owner:return None
        baseline = policy_ops.selected_default(session, user.tenant_id)
        if baseline is None:return error(409, "owner must select a protected baseline first")
        if policy is not None and policy.id == baseline.id:
            return error(403, "protected baseline is owner-controlled")
        if proposed is not None:
            try:policy_ops.prove_tighten_only(proposed, baseline)
            except policy_ops.PolicyError as exc:return error(exc.status,str(exc))
        return None

    def policy_json(policy, session):
        import json as _json
        versions = len(session.scalars(
            select(PolicyVersion).where(
                PolicyVersion.policy_id == policy.id)).all())
        doc = _json.loads(policy.engine_doc)
        return {"id": policy.id, "name": policy.name,
                "description": policy.description,
                "enabled": policy.enabled, "versions": versions,
                "protected_baseline": bool(policy_ops.selected_default(session,policy.tenant_id) and policy_ops.selected_default(session,policy.tenant_id).id==policy.id),
                "default_policy": doc["default_policy"],
                "allowlist": doc["allowlist"], "blocklist": doc["blocklist"],
                "category_allow": doc["category_rules"]["allow"],
                "category_block": doc["category_rules"]["block"],
                "schedules": schedule_ops.doc_schedules(doc)}

    def get_tenant_policy(session, tenant_id, policy_id):
        policy = session.get(Policy, policy_id)
        if policy is None or policy.tenant_id != tenant_id:
            return None
        return policy

    @app.post("/api/policies", dependencies=[Depends(require_csrf_header)])
    def create_policy(body: PolicyBody,
                      user: User = Depends(current_user),
                      session: Session = Depends(db_session)):
        denied = require_guardian(user, "policies")
        if denied is not None:
            return denied
        import json as _json
        try:
            doc = policy_ops.normalize_engine_doc(body.model_dump())
            denied = guard_baseline(user, session, None, doc)
            if denied is not None:return denied
        except policy_ops.PolicyError as exc:
            return error(exc.status, str(exc))
        existing = session.scalar(select(Policy).where(
            Policy.tenant_id == user.tenant_id, Policy.name == body.name))
        if existing is not None:
            return error(409, f"policy named {body.name!r} already exists")
        policy = Policy(tenant_id=user.tenant_id, name=body.name,
                        description=body.description, enabled=body.enabled,
                        engine_doc=_json.dumps(doc))
        session.add(policy)
        session.flush()
        version = policy_ops.snapshot_version(session, policy, user.id)
        ScopedSession(session, user.tenant_id).audit("policy.create",
                     f"created policy {body.name!r} (version {version})",
                     actor_user_id=user.id)
        session.commit()
        return policy_json(policy, session)

    @app.get("/api/policies")
    def list_policies(user: User = Depends(current_user),
                      session: Session = Depends(db_session)):
        rows = session.scalars(select(Policy).where(
            Policy.tenant_id == user.tenant_id).order_by(Policy.id))
        return {"policies": [policy_json(p, session) for p in rows]}

    @app.put("/api/policies/{policy_id}",
             dependencies=[Depends(require_csrf_header)])
    def update_policy(policy_id: int, body: PolicyBody,
                      user: User = Depends(current_user),
                      session: Session = Depends(db_session)):
        denied = require_guardian(user, "policies")
        if denied is not None:
            return denied
        import json as _json
        policy = get_tenant_policy(session, user.tenant_id, policy_id)
        if policy is None:
            return error(404, "policy not found")
        denied = guard_baseline(user, session, policy)
        if denied is not None:return denied
        try:
            doc = policy_ops.normalize_engine_doc(body.model_dump())
            # A general policy update must not silently drop the
            # policy's filtering schedules (that would loosen filtering
            # without anyone asking). Carry them over unchanged unless
            # this request itself supplies a replacement list.
            if body.schedules is None:
                existing = schedule_ops.doc_schedules(
                    _json.loads(policy.engine_doc))
                if existing:
                    doc = schedule_ops.with_schedules(doc, existing)
            denied = guard_baseline(user, session, policy, doc)
            if denied is not None:return denied
            policy_ops.enforce_on_content_mutation(
                session, user.tenant_id, policy, doc)
            if not body.enabled:
                default = policy_ops.selected_default(session,
                                                      user.tenant_id)
                if default is not None and default.id == policy.id:
                    raise policy_ops.PolicyError(
                        "cannot disable the selected default policy; "
                        "select another default first", 409)
        except policy_ops.PolicyError as exc:
            return error(exc.status, str(exc))
        policy.name = body.name
        policy.description = body.description
        policy.enabled = body.enabled
        policy.engine_doc = _json.dumps(doc)
        version = policy_ops.snapshot_version(session, policy, user.id)
        ScopedSession(session, user.tenant_id).audit(
            "policy.update", f"updated policy {body.name!r} "
            f"(version {version})", actor_user_id=user.id)
        session.commit()
        return policy_json(policy, session)

    @app.put("/api/policies/{policy_id}/schedules",
             dependencies=[Depends(require_csrf_header)])
    def replace_schedules(policy_id: int, body: SchedulesBody,
                          user: User = Depends(current_user),
                          session: Session = Depends(db_session)):
        """Replace a policy's filtering schedules wholesale.

        Wholesale replacement (rather than per-schedule CRUD) means the
        change goes through the exact same versioned, audited,
        tighten-only-checked mutation path as every other policy
        content change."""
        denied = require_guardian(user, "schedules")
        if denied is not None:
            return denied
        import json as _json
        policy = get_tenant_policy(session, user.tenant_id, policy_id)
        if policy is None:
            return error(404, "policy not found")
        denied = guard_baseline(user, session, policy)
        if denied is not None:return denied
        doc = _json.loads(policy.engine_doc)
        try:
            normalized = schedule_ops.validate_schedules(body.schedules)
            candidate = schedule_ops.with_schedules(doc, normalized)
            denied = guard_baseline(user, session, policy, candidate)
            if denied is not None:return denied
            policy_ops.enforce_on_content_mutation(
                session, user.tenant_id, policy, candidate)
        except schedule_ops.ScheduleError as exc:
            return error(400, f"invalid schedules: {exc}")
        except policy_ops.PolicyError as exc:
            return error(exc.status, str(exc))
        policy.engine_doc = _json.dumps(candidate)
        version = policy_ops.snapshot_version(session, policy, user.id)
        ScopedSession(session, user.tenant_id).audit(
            "policy.schedules",
            f"replaced schedules of {policy.name!r} "
            f"({len(normalized)} schedule(s), version {version})",
            actor_user_id=user.id)
        session.commit()
        return policy_json(policy, session)

    @app.post("/api/policies/{policy_id}/select",
              dependencies=[Depends(require_csrf_header)])
    def select_default_policy(policy_id: int,
                              user: User = Depends(current_user),
                              session: Session = Depends(db_session)):
        denied = require_owner(user)
        if denied is not None:
            return denied
        policy = get_tenant_policy(session, user.tenant_id, policy_id)
        if policy is None:
            return error(404, "policy not found")
        if not policy.enabled:
            return error(409, "a disabled policy cannot be the default")
        try:
            policy_ops.enforce_on_default_selection(
                session, user.tenant_id, policy)
        except policy_ops.PolicyError as exc:
            return error(exc.status, str(exc))
        state = session.get(PublicationState, user.tenant_id)
        if state is None:
            state = PublicationState(tenant_id=user.tenant_id)
            session.add(state)
        state.selected_policy_id = policy.id
        ScopedSession(session, user.tenant_id).audit(
            "policy.select_default", f"selected policy {policy.name!r} "
            "as the tenant default", actor_user_id=user.id)
        session.commit()
        return {"status": "selected", "policy_id": policy.id}

    from .models import DeviceGroup, GroupMembership
    from . import group_ops

    @app.get("/api/groups")
    def list_groups(user: User = Depends(current_user), session: Session = Depends(db_session)):
        return {"groups": [group_ops.group_json(session,row) for row in session.scalars(
            select(DeviceGroup).where(DeviceGroup.tenant_id==user.tenant_id).order_by(DeviceGroup.id))]}

    @app.post("/api/groups", dependencies=[Depends(require_csrf_header)])
    def create_group(body: GroupBody, user: User = Depends(current_user), session: Session = Depends(db_session)):
        denied=require_guardian(user, "groups")
        if denied is not None:return denied
        if not body.name.strip():return error(400,"group name required")
        if session.scalar(select(DeviceGroup).where(DeviceGroup.tenant_id==user.tenant_id,DeviceGroup.name==body.name.strip())):
            return error(409,"group name already exists")
        try:group_ops.checked_policy(session,user.tenant_id,body.policy_id)
        except policy_ops.PolicyError as exc:return error(exc.status,str(exc))
        row=DeviceGroup(tenant_id=user.tenant_id,name=body.name.strip(),policy_id=body.policy_id)
        session.add(row);session.flush()
        ScopedSession(session,user.tenant_id).audit("group.create",f"group {row.id}",actor_user_id=user.id)
        return group_ops.group_json(session,row)

    @app.put("/api/groups/{group_id}", dependencies=[Depends(require_csrf_header)])
    def update_group(group_id: int, body: GroupBody, user: User = Depends(current_user), session: Session = Depends(db_session)):
        denied=require_guardian(user, "groups")
        if denied is not None:return denied
        try:
            row=group_ops.scoped_group(session,user.tenant_id,group_id)
            group_ops.checked_policy(session,user.tenant_id,body.policy_id)
        except policy_ops.PolicyError as exc:return error(exc.status,str(exc))
        name=body.name.strip()
        if not name:return error(400,"group name required")
        other=session.scalar(select(DeviceGroup).where(DeviceGroup.tenant_id==user.tenant_id,DeviceGroup.name==name,DeviceGroup.id!=group_id))
        if other:return error(409,"group name already exists")
        row.name=name;row.policy_id=body.policy_id
        ScopedSession(session,user.tenant_id).audit("group.update",f"group {row.id} policy {body.policy_id}",actor_user_id=user.id)
        return group_ops.group_json(session,row)

    @app.put("/api/groups/{group_id}/devices/{device_id}", dependencies=[Depends(require_csrf_header)])
    def join_group(group_id: int, device_id: int, user: User = Depends(current_user), session: Session = Depends(db_session)):
        denied=require_guardian(user, "groups")
        if denied is not None:return denied
        try:
            row=group_ops.scoped_group(session,user.tenant_id,group_id)
            group_ops.checked_policy(session,user.tenant_id,row.policy_id)
        except policy_ops.PolicyError as exc:return error(exc.status,str(exc))
        device=session.get(Device,device_id)
        if device is None or device.tenant_id!=user.tenant_id:return error(404,"device not found")
        member=session.scalar(select(GroupMembership).where(GroupMembership.device_id==device_id))
        if member is not None and member.tenant_id!=user.tenant_id:return error(409,"invalid membership")
        if member is None:session.add(GroupMembership(tenant_id=user.tenant_id,group_id=group_id,device_id=device_id))
        else:member.group_id=group_id
        session.flush()
        ScopedSession(session,user.tenant_id).audit("group.join",f"device {device_id} group {group_id}",actor_user_id=user.id)
        return group_ops.group_json(session,row)

    @app.delete("/api/groups/{group_id}/devices/{device_id}", dependencies=[Depends(require_csrf_header)])
    def leave_group(group_id: int, device_id: int, user: User = Depends(current_user), session: Session = Depends(db_session)):
        denied=require_guardian(user, "groups")
        if denied is not None:return denied
        try:row=group_ops.scoped_group(session,user.tenant_id,group_id)
        except policy_ops.PolicyError as exc:return error(exc.status,str(exc))
        member=session.scalar(select(GroupMembership).where(GroupMembership.tenant_id==user.tenant_id,GroupMembership.group_id==group_id,GroupMembership.device_id==device_id))
        if member is None:return error(404,"membership not found")
        session.delete(member);session.flush()
        ScopedSession(session,user.tenant_id).audit("group.leave",f"device {device_id} group {group_id}",actor_user_id=user.id)
        return group_ops.group_json(session,row)

    @app.post("/api/devices", dependencies=[Depends(require_csrf_header)])
    def create_device(body: DeviceBody,
                      user: User = Depends(current_user),
                      session: Session = Depends(db_session)):
        denied = require_guardian(user)
        if denied is not None:
            return denied
        existing = session.scalar(select(Device).where(
            Device.tenant_id == user.tenant_id, Device.name == body.name))
        if existing is not None:
            return error(409, f"device named {body.name!r} already exists")
        device = Device(tenant_id=user.tenant_id, name=body.name)
        session.add(device)
        session.flush()
        ScopedSession(session, user.tenant_id).audit(
            "device.create", f"registered device {body.name!r}",
            actor_user_id=user.id)
        session.commit()
        return {"id": device.id, "name": device.name,
                "state": device.state}

    def _connectivity_class(last_seen):
        """Receipt-based classification, NOT live presence: the server
        only knows when a device last reported. recently_reporting <
        1h; stale 1-24h; offline > 24h; never_reported when the
        enrollment has never contacted us."""
        if last_seen is None:
            return "never_reported"
        seen = last_seen
        if seen.tzinfo is None:
            seen = seen.replace(tzinfo=timezone.utc)
        age = utcnow() - seen
        if age < timedelta(hours=1):
            return "recently_reporting"
        if age < timedelta(hours=24):
            return "stale"
        return "offline"

    @app.get("/api/devices")
    def list_devices(user: User = Depends(current_user),
                     session: Session = Depends(db_session)):
        """Devices with the Answer-23 update-state chain, honestly
        layered: desired state (assignments/publication) is server
        intent; command ledger states (queued/delivered/acknowledged)
        are server push records; last_seen/DDM reports are STORED
        DEVICE RECEIPTS. None of these proves actual on-device
        enforcement - the response says so per device."""
        from sqlalchemy import func
        from .models import (DDMStatusReport, DeviceAssignment,
                             MDMCommand, PublicationState)
        rows = session.scalars(select(Device).where(
            Device.tenant_id == user.tenant_id).order_by(Device.id))
        pub = session.get(PublicationState, user.tenant_id)
        published_revision = pub.revision if pub else 0
        devices = []
        for d in rows:
            enrollment = session.scalars(select(MDMEnrollment).where(
                MDMEnrollment.device_id == d.id).order_by(
                    MDMEnrollment.id.desc())).first()
            last_seen = enrollment.last_seen_at if enrollment else None
            ack = session.scalar(select(func.max(MDMCommand.updated_at))
                .where(MDMCommand.tenant_id == user.tenant_id,
                       MDMCommand.status == "acknowledged")
                .join(MDMEnrollment,
                      MDMCommand.enrollment_pk == MDMEnrollment.id)
                .where(MDMEnrollment.device_id == d.id))
            receipt = (session.scalar(select(func.max(
                DDMStatusReport.received_at)).where(
                    DDMStatusReport.tenant_id == user.tenant_id,
                    DDMStatusReport.enrollment_id ==
                    enrollment.enrollment_id))
                if enrollment else None)
            confirmed = [t for t in (ack, receipt) if t is not None]
            pending = session.scalar(select(func.count())
                .select_from(MDMCommand)
                .where(MDMCommand.tenant_id == user.tenant_id,
                       MDMCommand.status.in_(
                           ("queued", "delivered", "not_now")))
                .join(MDMEnrollment,
                      MDMCommand.enrollment_pk == MDMEnrollment.id)
                .where(MDMEnrollment.device_id == d.id))
            assignment = session.scalars(select(DeviceAssignment).where(
                DeviceAssignment.device_id == d.id,
                DeviceAssignment.active.is_(True))).first()
            devices.append({
                "id": d.id, "name": d.name, "state": d.state,
                "assigned_policy_id":
                    assignment.policy_id if assignment else None,
                "published_revision": published_revision,
                "enrollment": ({
                    "state": enrollment.state,
                    "supervision_requested":
                        enrollment.supervision_requested,
                    "supervision_verified":
                        enrollment.supervision_verified,
                    "last_seen_at": (enrollment.last_seen_at.isoformat()
                                     if enrollment.last_seen_at else None),
                } if enrollment else None),
                "connectivity": _connectivity_class(last_seen),
                "connectivity_basis":
                    "device check-in receipts only; not live presence",
                "pending_commands": pending,
                "last_confirmed_update": (max(confirmed).isoformat()
                                          if confirmed else None),
                "last_confirmed_update_basis":
                    "latest stored device receipt (acknowledged command "
                    "or DDM status report)",
                "enforcement_note":
                    "server state and stored receipts only; actual "
                    "on-device enforcement is not verified by this "
                    "server"})
        return {"devices": devices}

    @app.post("/api/devices/{device_id}/assignment",
              dependencies=[Depends(require_csrf_header)])
    def assign_policy(device_id: int, body: AssignmentBody,
                      user: User = Depends(current_user),
                      session: Session = Depends(db_session)):
        denied = require_guardian(user)
        if denied is not None:
            return denied
        device = session.get(Device, device_id)
        if device is None or device.tenant_id != user.tenant_id:
            return error(404, "device not found")
        policy = get_tenant_policy(session, user.tenant_id, body.policy_id)
        if policy is None:
            return error(404, "policy not found")
        if not policy.enabled:
            return error(409, "a disabled policy cannot be assigned")
        if user.role != Role.owner and policy_ops.selected_default(session,user.tenant_id) is None:
            return error(409,"owner must select a protected baseline first")
        try:
            policy_ops.enforce_on_new_assignment(
                session, user.tenant_id, policy)
        except policy_ops.PolicyError as exc:
            return error(exc.status, str(exc))
        for old in session.scalars(select(DeviceAssignment).where(
                DeviceAssignment.device_id == device.id,
                DeviceAssignment.active.is_(True))):
            old.active = False
        session.add(DeviceAssignment(tenant_id=user.tenant_id,
                                     device_id=device.id,
                                     policy_id=policy.id))
        ScopedSession(session, user.tenant_id).audit(
            "device.assign", f"assigned policy {policy.name!r} to "
            f"device {device.name!r}", actor_user_id=user.id)
        session.commit()
        return {"status": "assigned", "device_id": device.id,
                "policy_id": policy.id}

    # -- MDM (Milestone 4) ---------------------------------------------------
    def make_adapter():
        if settings.nanomdm_url:
            import sys as _sys
            import os as _os
            repo = _os.path.dirname(_os.path.dirname(
                _os.path.dirname(_os.path.abspath(__file__))))
            if repo not in _sys.path:
                _sys.path.insert(0, repo)
            from mdm.adapter import NanoMDMAdapter
            return NanoMDMAdapter(settings.nanomdm_url,
                                  settings.nanomdm_api_key or "")
        return None

    def enrollment_json(row):
        return {"id": row.id, "device_id": row.device_id,
                "enrollment_id": row.enrollment_id,
                "device_udid": row.device_udid, "state": row.state,
                "supervision_requested": row.supervision_requested,
                "supervision_verified": row.supervision_verified,
                "last_seen_at": (row.last_seen_at.isoformat()
                                 if row.last_seen_at else None),
                "created_at": row.created_at.isoformat()}

    def command_json(row):
        import json as _json
        return {"id": row.id, "enrollment_pk": row.enrollment_pk,
                "command": row.command, "status": row.status,
                "applied": row.applied,
                "payload": _json.loads(row.payload or "{}"),
                "result_detail": row.result_detail,
                "created_at": row.created_at.isoformat()}

    @app.post("/api/mdm/enrollments",
              dependencies=[Depends(require_csrf_header)])
    def mdm_create_enrollment(body: EnrollmentBody,
                              user: User = Depends(current_user),
                              session: Session = Depends(db_session)):
        denied = require_guardian(user)
        if denied is not None:
            return denied
        try:
            row = mdm_ops.create_enrollment(
                session, user.tenant_id, body.device_id,
                body.supervision_requested,
                device_udid=body.device_udid)
        except mdm_ops.MDMError as exc:
            return error(exc.status, str(exc))
        session.commit()
        return enrollment_json(row)

    @app.get("/api/mdm/enrollments")
    def mdm_list_enrollments(user: User = Depends(current_user),
                             session: Session = Depends(db_session)):
        rows = mdm_ops.list_enrollments(session, user.tenant_id)
        return {"enrollments": [enrollment_json(r) for r in rows]}

    @app.post("/api/mdm/enrollments/{enrollment_pk}/commands",
              dependencies=[Depends(require_csrf_header)])
    def mdm_issue_command(enrollment_pk: int, body: MDMCommandBody,
                          user: User = Depends(current_user),
                          session: Session = Depends(db_session)):
        denied = require_guardian(user)
        if denied is not None:
            return denied
        if user.role != Role.owner and body.command not in {"DeviceInformation", "ProfileList", "InstalledApplicationList", "ManagedApplicationList"}:
            return error(403,"profile/application/system changes require owner approval")
        if body.command in DESTRUCTIVE_COMMANDS:
            # Answer 25: fresh verification + explicit confirmation, then
            # the request waits for a DIFFERENT privileged approver.
            # Nothing is queued to the device here.
            # A support/read-only staff account is limited to
            # troubleshooting even if it also holds a tenant owner role
            # (Answer 25: support gets no destructive commands).
            if user.staff_role in (StaffRole.support_admin.value,
                                   StaffRole.read_only.value):
                return error(403, "destructive commands are not available to this role")
            if user.role != Role.owner and user.staff_role not in (
                    StaffRole.owner.value, StaffRole.security_admin.value):
                return error(403, "destructive commands are not available to this role")
            bad = fresh_check(error, user, body.totp_code, body.confirm, body.command)
            if bad is not None:
                return bad
            if not (body.reason or "").strip():
                return error(400, "a reason is required for destructive commands")
            approval = SensitiveCommandApproval(
                tenant_id=user.tenant_id, enrollment_pk=enrollment_pk,
                operation=body.command, payload=json.dumps(body.payload or {}),
                reason=body.reason.strip(), status="pending",
                requested_by_user_id=user.id,
                expires_at=utcnow() + timedelta(hours=1))
            session.add(approval)
            session.flush()
            ScopedSession(session, user.tenant_id).audit(
                "mdm.sensitive.request",
                f"{body.command} on enrollment {enrollment_pk}: {body.reason.strip()}",
                actor_user_id=user.id)
            session.commit()
            return JSONResponse(status_code=202, content={
                "approval_id": approval.id, "status": "pending",
                "detail": "awaiting approval by a second privileged user; nothing sent to the device"})
        try:
            row = mdm_ops.issue_command(
                session, user.tenant_id, enrollment_pk, body.command,
                body.payload, user.id, adapter=make_adapter())
        except mdm_ops.MDMError as exc:
            return error(exc.status, str(exc))
        session.commit()
        return command_json(row)

    @app.get("/api/mdm/enrollments/{enrollment_pk}/commands")
    def mdm_list_commands(enrollment_pk: int,
                          user: User = Depends(current_user),
                          session: Session = Depends(db_session)):
        try:
            rows = mdm_ops.list_commands(session, user.tenant_id,
                                         enrollment_pk)
        except mdm_ops.MDMError as exc:
            return error(exc.status, str(exc))
        return {"commands": [command_json(r) for r in rows]}

    @app.get("/api/mdm/commands/{command_id}")
    def mdm_get_command(command_id: int,
                        user: User = Depends(current_user),
                        session: Session = Depends(db_session)):
        try:
            row = mdm_ops.get_command(session, user.tenant_id, command_id)
        except mdm_ops.MDMError as exc:
            return error(exc.status, str(exc))
        return command_json(row)

# -- Overview and customer (tenant) administration (M6) -----------
    @app.get("/api/overview")
    def overview(user: User = Depends(current_user),
                 session: Session = Depends(db_session)):
        """Guardian-facing overview: this tenant's own numbers only."""
        from sqlalchemy import func
        tid = user.tenant_id
        devices = session.execute(select(func.count()).select_from(
            Device).where(Device.tenant_id == tid)).scalar()
        policies = session.execute(select(func.count()).select_from(
            Policy).where(Policy.tenant_id == tid)).scalar()
        guardians = session.execute(select(func.count()).select_from(
            User).where(User.tenant_id == tid)).scalar()
        enrollments = session.execute(select(func.count()).select_from(
            MDMEnrollment).where(MDMEnrollment.tenant_id == tid)).scalar()
        recent = session.execute(
            select(AuditEvent).where(AuditEvent.tenant_id == tid)
            .order_by(AuditEvent.id.desc()).limit(10)).scalars().all()
        return {
            "devices": devices, "policies": policies,
            "guardians": guardians, "enrollments": enrollments,
            "recent_activity": [
                {"action": a.action, "detail": a.detail,
                 "at": a.created_at.isoformat()} for a in recent],
        }

    register_staff_routes(app, error=error,
        current_user=current_user, db_session=db_session,
        require_csrf_header=require_csrf_header, make_adapter=make_adapter,
        command_json=command_json, require_guardian=require_guardian,
        mdm_command_body=MDMCommandBody)

    @app.get("/api/admin/tenants")
    def admin_list_tenants(user: User = Depends(current_user),
                           session: Session = Depends(db_session)):
        """Platform-admin customer list: tenant names and counts only -
        never another tenant's policies, devices or user details."""
        denied = require_staff(error, user, *ALL_STAFF)
        if denied is not None:
            return denied
        from sqlalchemy import func
        from .models import Tenant
        rows = []
        for tenant in session.execute(select(Tenant)).scalars().all():
            rows.append({
                "id": tenant.id, "name": tenant.name,
                "created_at": tenant.created_at.isoformat(),
                "devices": session.execute(select(func.count())
                    .select_from(Device).where(
                        Device.tenant_id == tenant.id)).scalar(),
                "guardians": session.execute(select(func.count())
                    .select_from(User).where(
                        User.tenant_id == tenant.id)).scalar(),
            })
        return {"tenants": rows}

    # -- Application management (spec Part 10: Applications) -----------
    # Per-device allow/block policy plus install/remove/list actions,
    # all delivered through the standard MDM command lifecycle. Payload
    # structures follow Apple's documented formats but are
    # BUILT-UNVERIFIED on device until the spec Part 17 device-testing
    # phase (see mdm/app_management.py).
    @app.get("/api/devices/{device_id}/app-policy")
    def get_app_policy(device_id: int,
                       user: User = Depends(current_user),
                       session: Session = Depends(db_session)):
        try:
            return app_ops.get_policy(session, user.tenant_id, device_id)
        except app_ops.AppOpsError as exc:
            return error(exc.status, str(exc))

    @app.put("/api/devices/{device_id}/app-policy",
             dependencies=[Depends(require_csrf_header)])
    def put_app_policy(device_id: int, body: AppPolicyBody,
                       user: User = Depends(current_user),
                       session: Session = Depends(db_session)):
        denied = require_guardian(user, "apps")
        if denied is not None:
            return denied
        if user.role != Role.owner:
            return error(403,"app baseline changes are owner-only until a tightening proof exists")
        try:
            result = app_ops.put_policy(session, user.tenant_id, device_id,
                                        body.mode, body.bundle_ids, user.id)
        except app_ops.AppOpsError as exc:
            return error(exc.status, str(exc))
        session.commit()
        return result

    @app.post("/api/devices/{device_id}/app-policy/apply",
              dependencies=[Depends(require_csrf_header)])
    def apply_app_policy(device_id: int,
                         user: User = Depends(current_user),
                         session: Session = Depends(db_session)):
        denied = require_guardian(user, "apps")
        if denied is not None:
            return denied
        if user.role != Role.owner:
            return error(403,"app baseline changes are owner-only until a tightening proof exists")
        try:
            row = app_ops.apply_policy(session, user.tenant_id, device_id,
                                       user.id, adapter=make_adapter())
        except app_ops.AppOpsError as exc:
            return error(exc.status, str(exc))
        session.commit()
        return command_json(row)

    @app.post("/api/devices/{device_id}/app-commands",
              dependencies=[Depends(require_csrf_header)])
    def queue_app_command(device_id: int, body: AppCommandBody,
                          user: User = Depends(current_user),
                          session: Session = Depends(db_session)):
        denied = require_guardian(user, "apps")
        if denied is not None:
            return denied
        if user.role != Role.owner and body.action not in {"list", "managed-list"}:
            return error(403,"app installation/removal/configuration is owner-only")
        try:
            row = app_ops.queue_app_command(
                session, user.tenant_id, device_id, body.action, user.id,
                itunes_store_id=body.itunes_store_id,
                bundle_id=body.bundle_id, configuration=body.configuration,
                adapter=make_adapter())
        except app_ops.AppOpsError as exc:
            return error(exc.status, str(exc))
        session.commit()
        return command_json(row)

    # -- Filtering decision logs (spec Part 10: Filtering logs) --------
    # Ingestion is edge-to-control-plane: bearer-authenticated with the
    # device's scoped credential (scope "proxy"), so the browser CSRF
    # header does not apply (no cookies involved). Tenant/device binding
    # comes from the verified token, never the body.
    @app.post("/api/filter-logs")
    def post_filter_logs(request: Request, body: FilterLogBody,
                         session: Session = Depends(db_session)):
        try:
            claims = filter_log_ops.verify_edge_token(
                settings, request.headers.get("authorization"))
            with session.begin_nested():
                accepted = filter_log_ops.record_decisions(
                    session, claims, body.decisions)
        except filter_log_ops.FilterLogError as exc:
            return error(exc.status, str(exc))
        session.commit()
        return {"accepted": accepted}

    @app.get("/api/privacy/retention")
    def get_retention(user: User = Depends(current_user),
                      session: Session = Depends(db_session)):
        return {"blocked_days": session.get(Tenant, user.tenant_id).blocked_log_retention_days,
                "allowed_history": False, "min_days": 1, "max_days": 30}

    @app.put("/api/privacy/retention", dependencies=[Depends(require_csrf_header)])
    def set_retention(body: RetentionBody, user: User = Depends(current_user),
                      session: Session = Depends(db_session)):
        denied = require_owner(user)
        if denied is not None:
            return denied
        if not 1 <= body.days <= 30:
            return error(400, "retention must be 1-30 days")
        tenant = session.get(Tenant, user.tenant_id)
        tenant.blocked_log_retention_days = body.days
        session.flush()
        deleted = filter_log_ops.purge_expired(session, tenant_id=user.tenant_id)
        return {"blocked_days": body.days, "deleted": deleted, "allowed_history": False}

    @app.get("/api/filter-logs")
    def get_filter_logs(user: User = Depends(current_user),
                        session: Session = Depends(db_session)):
        rows = filter_log_ops.recent_decisions(session, user.tenant_id)
        devices = {d.id: d.name for d in session.execute(
            select(Device).where(Device.tenant_id == user.tenant_id))
            .scalars().all()}
        return {"decisions": [
            {"id": r.id, "device": devices.get(r.device_id),
             "source": r.source, "domain": r.domain, "action": r.action,
             "rule": r.rule, "reason": r.reason,
             "received_at": r.received_at.isoformat()} for r in rows]}


    @app.get("/api/filter-status")
    def get_filter_status(user: User = Depends(current_user),
                          session: Session = Depends(db_session)):
        # Evidenced configured/published/reported state only; health is
        # explicitly "unknown" (see filter_log_ops.edge_status).
        return filter_log_ops.edge_status(session, user.tenant_id)


    register_ddm_routes(app, error=error, db_session=db_session,
                        settings=settings)

    register_enrollment_routes(app, error=error, current_user=current_user,
        db_session=db_session, require_csrf_header=require_csrf_header,
        require_guardian=require_guardian, settings=settings)

    # -- Device scoped-credential issuance (M6, extended for 8B) -------

    # Mints the short-lived scoped tokens url-filter-server (scope
    # "dataset") and proxy-edge (scope "proxy") verify. The raw token is
    # returned once to the guardian and never stored or logged;
    # revocation is by short expiry (+ jti list server-side).
    # A proxy-scoped token is bound to the device's EFFECTIVE policy:
    # its active assignment, else the tenant default. This is a
    # shared-secret scoped identity for issuance and routing only; it
    # does not by itself prove real on-device protection, which
    # requires the end-to-end device validation that remains gated.
    @app.post("/api/devices/{device_id}/dataset-credential",
              dependencies=[Depends(require_csrf_header)])
    def mint_dataset_credential(device_id: int,
                                body: MintBody | None = None,
                                user: User = Depends(current_user),
                                session: Session = Depends(db_session)):
        denied = require_guardian(user)
        if denied is not None:
            return denied
        if not settings.device_token_key:
            return error(503, "device credential issuance not configured")
        row = session.get(Device, device_id)
        if row is None or row.tenant_id != user.tenant_id:
            return error(404, "device not found")
        device = row
        scope = (body.scope if body else "dataset").strip()
        if scope not in ("dataset", "proxy", "doh"):
            return error(400, "scope must be 'dataset', 'proxy' or 'doh'")
        policy_id = None
        if scope == "proxy":
            try:
                policy_id = group_ops.effective_assignments(session,user.tenant_id).get(device.id)
            except policy_ops.PolicyError as exc:
                return error(exc.status,str(exc))
            if policy_id is None:
                pub = session.get(PublicationState, user.tenant_id)
                if pub is not None and pub.selected_policy_id is not None:
                    policy_id = pub.selected_policy_id
            if policy_id is None:
                return error(409, "device has no effective policy to bind")
        # Load the shared device_auth by file path - the control
        # plane's own package is also named "app", so a plain import
        # would resolve to the wrong package.
        import importlib.util as _ilu
        _da_path = os.path.abspath(os.path.join(
            os.path.dirname(__file__), "..", "..",
            "url-filter-server", "app", "device_auth.py"))
        _spec = _ilu.spec_from_file_location("kg_device_auth", _da_path)
        _da = _ilu.module_from_spec(_spec)
        _spec.loader.exec_module(_da)
        issue_token = _da.issue_token
        token = issue_token(
            settings.device_token_key.encode(),
            device_id=str(device.id),
            tenant_id=str(user.tenant_id),
            scope=scope,
            lifetime_seconds=min(
                settings.session_lifetime_seconds, 86400),
            policy_id=policy_id)
        payload = _da.verify_token(
            settings.device_token_key.encode(), token, scope)
        session.add(IssuedCredential(
            tenant_id=user.tenant_id, device_id=device.id,
            jti=payload["jti"], scope=scope, policy_id=policy_id,
            expires_at=datetime.fromtimestamp(payload["exp"], timezone.utc)))
        ScopedSession(session, user.tenant_id).audit(
            "device.credential_mint",
            f"{device.name} scope={scope}"
            + (f" policy_id={policy_id}" if policy_id is not None else ""),
            actor_user_id=user.id)
        session.commit()
        return {"device_id": device.id, "credential": token, "scope": scope,
                "policy_id": policy_id}

    @app.post("/api/devices/{device_id}/credentials/revoke",
              dependencies=[Depends(require_csrf_header)])
    def revoke_device_credentials(device_id: int,
                                  user: User = Depends(current_user),
                                  session: Session = Depends(db_session)):
        """Revoke every outstanding token for one device (all scopes).

        Marks the issuance-registry rows; edge verifiers refuse listed
        jtis once they receive the revocation set (distribution lands
        with the devices.json/publication work - until then the feed
        below is the export path). Natural short expiry still applies.
        """
        denied = require_guardian(user)
        if denied is not None:
            return denied
        row = session.get(Device, device_id)
        if row is None or row.tenant_id != user.tenant_id:
            return error(404, "device not found")
        now = utcnow()
        outstanding = session.execute(select(IssuedCredential).where(
            IssuedCredential.device_id == row.id,
            IssuedCredential.tenant_id == user.tenant_id,
            IssuedCredential.revoked_at.is_(None),
            IssuedCredential.expires_at > now)).scalars().all()
        for cred in outstanding:
            cred.revoked_at = now
        ScopedSession(session, user.tenant_id).audit(
            "device.credential_revoke",
            f"{row.name}: {len(outstanding)} outstanding token(s) revoked",
            actor_user_id=user.id)
        session.commit()
        return {"device_id": row.id, "revoked": len(outstanding)}

    @app.get("/api/credential-revocations")
    def credential_revocations(request: Request,
                               session: Session = Depends(db_session)):
        """Revoked, not-yet-expired jtis for one tenant (the set edge
        verifiers refuse). Two authenticated readers: a guardian
        session, or an edge presenting a scoped device token (dataset,
        proxy or doh) - the token's tenant scopes the feed, so an edge
        can never read another tenant's revocations."""
        tenant_id = None
        header = request.headers.get("authorization", "")
        if header.lower().startswith("bearer "):
            payload = None
            _da = _load_device_auth()
            for scope in ("dataset", "proxy", "doh"):
                try:
                    payload = _da.verify_token(
                        settings.device_token_key.encode(),
                        header[7:].strip(), scope)
                    break
                except Exception:
                    continue
            if payload is None:
                return error(401, "unauthorized")
            try:
                tenant_id = int(payload.get("tenant_id"))
            except (TypeError, ValueError):
                return error(401, "unauthorized")
        else:
            cookie = request.cookies.get(SESSION_COOKIE)
            auth_row = (session.scalar(select(AuthSession).where(
                AuthSession.token_hash ==
                security.hash_session_token(cookie))) if cookie else None)
            user = None
            if auth_row is not None:
                expires = auth_row.expires_at
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)
                if expires > utcnow():
                    user = session.get(User, auth_row.user_id)
            if user is None:
                return error(401, "authentication required")
            denied = require_guardian(user)
            if denied is not None:
                return denied
            tenant_id = user.tenant_id
        now = utcnow()
        rows = session.execute(select(IssuedCredential).where(
            IssuedCredential.tenant_id == tenant_id,
            IssuedCredential.revoked_at.is_not(None),
            IssuedCredential.expires_at > now)).scalars().all()
        return {"revoked_jtis": [r.jti for r in rows]}

    # -- Credential artifacts (Part 16 upload screens) ------------------

    # Full lifecycle (upload/list/rotate/revoke) with the secret bytes
    # on the server filesystem only. Fixture-only during this build:
    # artifacts are stamped with settings.environment and the screen
    # warns on any non-production build. Content is never returned.
    from .credential_ops import (KINDS, CredentialError, artifact_json,
                                 decode_content, delete_secret,
                                 fingerprint, write_secret)
    from .models import CredentialArtifact

    def credential_routes():
        @app.get("/api/credentials")
        def list_credentials(user: User = Depends(current_user),
                             session: Session = Depends(db_session)):
            rows = session.execute(select(CredentialArtifact).where(
                CredentialArtifact.tenant_id == user.tenant_id
            ).order_by(CredentialArtifact.id)).scalars().all()
            return {"environment": settings.environment,
                    "fixture_only": settings.environment != "production",
                    "credentials": [artifact_json(r) for r in rows]}

        @app.post("/api/credentials",
                  dependencies=[Depends(require_csrf_header)])
        def upload_credential(body: CredentialBody,
                              user: User = Depends(current_user),
                              session: Session = Depends(db_session)):
            denied = require_owner(user)
            if denied is not None:
                return denied
            if body.kind not in KINDS:
                return error(400, f"kind must be one of {', '.join(KINDS)}")
            label = body.label.strip()
            if not label:
                return error(400, "label is required")
            try:
                raw = decode_content(body.content_base64)
            except CredentialError as exc:
                return error(400, str(exc))
            try:
                rel = write_secret(settings.credentials_root,
                                   user.tenant_id, raw)
            except CredentialError as exc:
                return error(503, str(exc))
            row = CredentialArtifact(
                tenant_id=user.tenant_id, kind=body.kind, label=label,
                sha256=fingerprint(raw), byte_size=len(raw),
                storage_path=rel, environment=settings.environment,
                uploaded_by_user_id=user.id)
            session.add(row)
            session.flush()
            ScopedSession(session, user.tenant_id).audit(
                "credential.upload", f"{row.kind} '{row.label}' "
                f"(sha256 {row.sha256[:12]}..., {row.byte_size} bytes, "
                f"env={row.environment})", actor_user_id=user.id)
            session.commit()
            return artifact_json(row)

        @app.post("/api/credentials/{credential_id}/rotate",
                  dependencies=[Depends(require_csrf_header)])
        def rotate_credential(credential_id: int, body: CredentialBody,
                              user: User = Depends(current_user),
                              session: Session = Depends(db_session)):
            denied = require_owner(user)
            if denied is not None:
                return denied
            row = session.get(CredentialArtifact, credential_id)
            if row is None or row.tenant_id != user.tenant_id:
                return error(404, "credential not found")
            if row.status != "active":
                return error(409, "credential is revoked")
            try:
                raw = decode_content(body.content_base64)
            except CredentialError as exc:
                return error(400, str(exc))
            rel = write_secret(settings.credentials_root,
                               user.tenant_id, raw)
            delete_secret(settings.credentials_root, row.storage_path)
            row.storage_path = rel
            row.sha256 = fingerprint(raw)
            row.byte_size = len(raw)
            row.version += 1
            row.rotated_at = utcnow()
            ScopedSession(session, user.tenant_id).audit(
                "credential.rotate", f"{row.kind} '{row.label}' "
                f"-> version {row.version}", actor_user_id=user.id)
            session.commit()
            return artifact_json(row)

        @app.delete("/api/credentials/{credential_id}",
                    dependencies=[Depends(require_csrf_header)])
        def revoke_credential(credential_id: int,
                              user: User = Depends(current_user),
                              session: Session = Depends(db_session)):
            denied = require_owner(user)
            if denied is not None:
                return denied
            row = session.get(CredentialArtifact, credential_id)
            if row is None or row.tenant_id != user.tenant_id:
                return error(404, "credential not found")
            if row.status != "active":
                return error(409, "credential already revoked")
            delete_secret(settings.credentials_root, row.storage_path)
            row.status = "revoked"
            row.revoked_at = utcnow()
            ScopedSession(session, user.tenant_id).audit(
                "credential.revoke", f"{row.kind} '{row.label}' "
                f"(secret bytes deleted)", actor_user_id=user.id)
            session.commit()
            return artifact_json(row)

    credential_routes()

    def require_owner(user: User) -> JSONResponse | None:
        if user.role != Role.owner:
            return error(403, "owner role required")
        return None

    def user_json(row):
        return {"id": row.id, "email": row.email, "role": row.role.value,
                "mfa_enrolled": row.totp_secret is not None,
                "delegated_settings": json.loads(row.delegated_settings),
                "created_at": row.created_at.isoformat()}

    from .exception_request_routes import register_exception_request_routes
    register_exception_request_routes(app, error=error,
        current_user=current_user, db_session=db_session,
        require_csrf_header=require_csrf_header,
        require_guardian=require_guardian)
    register_guardian_routes(app, error=error,
        current_user=current_user, db_session=db_session,
        require_csrf_header=require_csrf_header, require_owner=require_owner,
        user_json=user_json, settings=settings)

    register_offboarding_routes(app, error=error, current_user=current_user,
        db_session=db_session, require_csrf_header=require_csrf_header,
        require_guardian=require_guardian, require_owner=require_owner,
        fresh_check=fresh_check)

    register_category_source_routes(app, error=error,
        current_user=current_user, db_session=db_session,
        require_csrf_header=require_csrf_header, require_staff=require_staff,
        fresh_check=fresh_check, settings=settings)

    register_restore_routes(app, error=error, current_user=current_user,
        db_session=db_session, require_csrf_header=require_csrf_header,
        require_guardian=require_guardian)
    register_support_routes(app, error=error, current_user=current_user,
        db_session=db_session, require_csrf_header=require_csrf_header,
        require_staff=require_staff)
    register_observability(app, error=error, current_user=current_user,
                           db_session=db_session)

    # -- Platform category dataset administration (M6) -----------------

    # Approved fallback for the commercial category feed: a
    # human-reviewed seed dataset managed through these routes.
    # Staff endpoints are gated by staff_role (Answer 29 five roles).
    # Legacy is_platform_admin rows are staff owner via alembic 0017;
    # staff_role itself is set out of band or by a staff owner, never
    # self-assigned. Guardians get 403.
    from .models import CategoryRule

    def rule_json(row):
        return {
            "id": row.id, "domain": row.domain, "category": row.category,
            "verdict": row.verdict, "source": row.source,
            "active": row.active,
            "added_by_user_id": row.added_by_user_id,
            "created_at": row.created_at.isoformat(),
            "deactivated_at": (
                row.deactivated_at.isoformat()
                if row.deactivated_at else None),
        }

    @app.get("/api/admin/categories")
    def admin_list_categories(user: User = Depends(current_user),
                              session: Session = Depends(db_session)):
        denied = require_staff(error, user, StaffRole.owner, StaffRole.security_admin)
        if denied is not None:
            return denied
        rows = session.execute(
            select(CategoryRule).order_by(CategoryRule.domain)).scalars().all()
        return {"rules": [rule_json(r) for r in rows]}

    @app.post("/api/admin/categories",
              dependencies=[Depends(require_csrf_header)])
    def admin_add_category(body: CategoryRuleBody,
                           user: User = Depends(current_user),
                           session: Session = Depends(db_session)):
        denied = require_staff(error, user, StaffRole.owner, StaffRole.security_admin)
        if denied is not None:
            return denied
        domain = body.domain.strip().lower().rstrip(".")
        if not domain or "/" in domain or " " in domain:
            return error(400, "invalid domain")
        if body.verdict not in ("block", "allow"):
            return error(400, "verdict must be block or allow")
        existing = session.execute(
            select(CategoryRule).where(
                CategoryRule.domain == domain)).scalar_one_or_none()
        if existing is not None and existing.active:
            return error(409, "domain already has an active rule")
        if existing is not None:
            # Reactivate with the new assignment; provenance updates.
            existing.category = body.category
            existing.verdict = body.verdict
            existing.source = body.source
            existing.added_by_user_id = user.id
            existing.active = True
            existing.deactivated_at = None
            row = existing
        else:
            row = CategoryRule(
                domain=domain, category=body.category,
                verdict=body.verdict, source=body.source,
                added_by_user_id=user.id)
            session.add(row)
        session.flush()
        ScopedSession(session, user.tenant_id).audit(
            "admin.category.upsert",
            f"{domain} -> {row.verdict}:{row.category} ({row.source})",
            actor_user_id=user.id)
        session.commit()
        return rule_json(row)

    @app.delete("/api/admin/categories/{rule_id}",
                dependencies=[Depends(require_csrf_header)])
    def admin_deactivate_category(rule_id: int,
                                  user: User = Depends(current_user),
                                  session: Session = Depends(db_session)):
        denied = require_staff(error, user, StaffRole.owner, StaffRole.security_admin)
        if denied is not None:
            return denied
        row = session.get(CategoryRule, rule_id)
        if row is None or not row.active:
            return error(404, "rule not found")
        row.active = False
        row.deactivated_at = utcnow()
        ScopedSession(session, user.tenant_id).audit(
            "admin.category.deactivate", row.domain, actor_user_id=user.id)
        session.commit()
        return rule_json(row)

    @app.get("/api/admin/categories/export")
    def admin_export_categories(user: User = Depends(current_user),
                                session: Session = Depends(db_session)):
        """Active rules in the exact shape the publication pipeline's
        categories file (KG_CATEGORIES_FILE) carries, so the DB can
        become the dataset source of truth."""
        denied = require_staff(error, user, StaffRole.owner, StaffRole.security_admin)
        if denied is not None:
            return denied
        rows = session.execute(
            select(CategoryRule).where(
                CategoryRule.active.is_(True))).scalars().all()
        import json as _json
        return JSONResponse(content=_json.loads(_json.dumps({
            "version": 1,
            "rules": [
                {"domain": r.domain, "category": r.category,
                 "verdict": r.verdict, "source": r.source}
                for r in rows
            ],
        })))

    # -- Front ends (Milestone 2) --------------------------------------
    from fastapi.staticfiles import StaticFiles
    control_plane_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    repo_root = os.path.dirname(control_plane_dir)
    @app.post("/api/publications", dependencies=[Depends(require_csrf_header)])
    def publish(user: User = Depends(current_user),
                session: Session = Depends(db_session)):
        denied = require_guardian(user, "publish")
        if denied is not None:
            return denied
        try:
            result = publication_ops.publish_selected(
                session, user.tenant_id, settings.publications_root,
                user.email, categories_path=settings.categories_file)
        except publication_ops.PolicyError as exc:
            session.rollback()
            return error(exc.status, str(exc))
        ScopedSession(session, user.tenant_id).audit(
            "publication.publish",
            f"published generation {result['revision']}",
            actor_user_id=user.id)
        session.commit()
        return result

    def publication_job_json(job):
        import json
        return {"id": job.id, "status": job.status,
                "attempts": job.attempts,
                "created_at": job.created_at.isoformat(),
                "finished_at": job.finished_at.isoformat() if job.finished_at else None,
                "result": json.loads(job.result) if job.result else None,
                "error": job.last_error,
                "semantics": "publishes the selected policy at worker execution time"}

    @app.get("/api/policy-templates")
    def policy_templates(user: User = Depends(current_user)):
        from .policy_preview import TEMPLATES
        return {"templates": TEMPLATES,
                "notice": "Examples only; categories require owner approval"}

    @app.post("/api/policies/{policy_id}/preview",
              dependencies=[Depends(require_csrf_header)])
    def preview_policy(policy_id: int, body: PolicyPreviewBody,
                       user: User = Depends(current_user),
                       session: Session = Depends(db_session)):
        from .models import Policy
        from .policy_preview import preview
        import json
        row = session.get(Policy, policy_id)
        if row is None or row.tenant_id != user.tenant_id:
            return error(404, "policy not found")
        try:
            return preview(json.loads(row.engine_doc), body.domain,
                           settings.categories_file, body.at)
        except (ValueError, OSError) as exc:
            return error(400, str(exc))

    @app.get("/api/exceptions")
    def list_exceptions(user: User = Depends(current_user),
                        session: Session = Depends(db_session)):
        from . import exception_ops
        from .models import PolicyException
        rows = session.scalars(select(PolicyException).where(
            PolicyException.tenant_id == user.tenant_id).order_by(
                PolicyException.id.desc())).all()
        return {"exceptions": [exception_ops.exception_json(r) for r in rows]}

    @app.post("/api/exceptions", dependencies=[Depends(require_csrf_header)])
    def create_exception(body: dict,
                         user: User = Depends(current_user),
                         session: Session = Depends(db_session)):
        denied = require_guardian(user, "exceptions")
        if denied is not None:
            return denied
        from . import exception_ops
        from .models import PolicyException
        try:
            (kind, scope_type, device_id, group_id, domains, reason,
             starts, expires) = exception_ops.validate_new(
                session, user.tenant_id, user, body)
        except Exception as exc:
            from .policy_ops import PolicyError
            if isinstance(exc, PolicyError):
                return error(exc.status, str(exc))
            raise
        row = PolicyException(
            tenant_id=user.tenant_id, kind=kind, scope_type=scope_type,
            device_id=device_id, group_id=group_id,
            domains=json.dumps(domains), reason=reason,
            approver_user_id=user.id, starts_at=starts, expires_at=expires)
        session.add(row)
        session.flush()
        ScopedSession(session, user.tenant_id).audit(
            "exception.create",
            f"{kind} for {scope_type} {device_id or group_id} "
            f"until {expires.isoformat()}: {reason}",
            actor_user_id=user.id)
        session.commit()
        return exception_ops.exception_json(row)

    @app.delete("/api/exceptions/{exception_id}",
                dependencies=[Depends(require_csrf_header)])
    def revoke_exception(exception_id: int,
                         user: User = Depends(current_user),
                         session: Session = Depends(db_session)):
        denied = require_guardian(user, "exceptions")
        if denied is not None:
            return denied
        from .models import PolicyException
        row = session.get(PolicyException, exception_id)
        if row is None or row.tenant_id != user.tenant_id:
            return error(404, "exception not found")
        if row.revoked_at is None:
            row.revoked_at = utcnow()
            row.revoked_by = user.id
            ScopedSession(session, user.tenant_id).audit(
                "exception.revoke",
                f"exception {row.id} ({row.kind} for {row.scope_type} "
                f"{row.device_id or row.group_id}): {row.reason}",
                actor_user_id=user.id)
            session.flush()
            # A revoked exception keeps filtering-open at the edge until a
            # new generation ships, so revocation enqueues its own
            # publication instead of waiting for a manual publish. The job
            # keeps the real revoker as its actor and carries the
            # server-set "exception-revoke" system marker: a narrow
            # cleanup authority that lets the worker run it without
            # re-checking the revoker's publish delegation or the owner's
            # availability. It fabricates no owner/MFA approval - the
            # manifest records actor "system:exception-revoke job <id>"
            # and the audit keeps the initiating user - and it grants no
            # general publish capability (the jobs API cannot set the
            # marker; ordinary jobs keep the full actor re-check). Like
            # any publish it ships the tenant's current saved state under
            # the usual invariants (assigned policies proven tighten-only
            # against the owner-controlled baseline at publish time).
            from .worker import enqueue
            from sqlalchemy.exc import IntegrityError
            try:
                enqueue(session, user.tenant_id, user.id, user.email,
                        f"exception-revoke-{row.id}-{int(utcnow().timestamp())}",
                        system_action="exception-revoke")
                session.commit()
            except (ValueError, IntegrityError):
                session.rollback()
                return error(500, "revoked, but republication could not be queued")
        from . import exception_ops
        return exception_ops.exception_json(row)

    @app.post("/api/publications/jobs", dependencies=[Depends(require_csrf_header)])
    def enqueue_publication(body: PublicationJobBody,
                            user: User = Depends(current_user),
                            session: Session = Depends(db_session)):
        denied = require_guardian(user, "publish")
        if denied is not None:
            return denied
        from .worker import enqueue
        from sqlalchemy.exc import IntegrityError
        try:
            row = enqueue(session, user.tenant_id, user.id, user.email,
                          body.request_key)
            session.commit()
        except ValueError as exc:
            session.rollback()
            return error(400, str(exc))
        except IntegrityError:
            session.rollback()
            from .models import PublicationJob
            row = session.scalar(select(PublicationJob).where(
                PublicationJob.tenant_id == user.tenant_id,
                PublicationJob.request_key == body.request_key))
            if row is None:
                raise
        return publication_job_json(row)

    @app.get("/api/publications/jobs/{job_id}")
    def publication_job_status(job_id: int, user: User = Depends(current_user),
                               session: Session = Depends(db_session)):
        from .models import PublicationJob
        row = session.get(PublicationJob, job_id)
        if row is None or row.tenant_id != user.tenant_id:
            return error(404, "publication job not found")
        return publication_job_json(row)

    @app.get("/api/publications/current")
    def publication_current(user: User = Depends(current_user)):
        from .publisher import Publisher
        try:
            manifest = Publisher(publication_ops.tenant_root(
                settings.publications_root, user.tenant_id)).current()
        except Exception as exc:
            return error(500, f"could not read current generation: {exc}")
        if manifest is None:
            return {"published": False}
        return {"published": True, "manifest": manifest}

    app.mount("/web", StaticFiles(
        directory=os.path.join(control_plane_dir, "web"), html=True),
        name="admin-web")
    app.mount("/portal", StaticFiles(
        directory=os.path.join(repo_root, "portal"), html=True),
        name="portal")
    app.mount("/", StaticFiles(
        directory=os.path.join(repo_root, "website"), html=True),
        name="website")

    @app.exception_handler(Exception)
    def unhandled(request: Request, exc: Exception):
        return error(500, "internal error")

    return app

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

import os
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from . import mdm_ops, schedule_ops, security
from .config import Settings
from .db import ScopedSession, make_engine
from .models import AuthSession, LoginAttempt, Role, User


class CategoryRuleBody(BaseModel):
    domain: str
    category: str
    verdict: str = "block"
    source: str = "manual-review"


class InviteBody(BaseModel):
    email: str
    role: str = "guardian"


class RoleBody(BaseModel):
    role: str


class AcceptInviteBody(BaseModel):
    token: str
    password: str


class MfaResetBody(BaseModel):
    password: str

SESSION_COOKIE = "kg_session"
CSRF_HEADER = "x-kosherguard-request"
MAX_FAILURES = 5
LOCKOUT_SECONDS = 60


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


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


class MDMCommandBody(BaseModel):
    command: str
    payload: dict = {}


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
    secret: str
    code: str
    password: str


def error(status: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": message})


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
        return user

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
            expires_at=utcnow() + lifetime))
        session.commit()
        response.set_cookie(
            SESSION_COOKIE, token, httponly=True, samesite="strict",
            secure=settings.secure_cookies, max_age=int(lifetime.total_seconds()))
        return {"status": "signed_in", "role": user.role.value}

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
    def me(user: User = Depends(current_user)):
        return {"email": user.email, "role": user.role.value,
                "tenant_id": user.tenant_id,
                "mfa_enabled": user.totp_secret is not None}

    # -- Account self-service (M6 follow-up) ---------------------------
    # Password change requires the current password (fresh auth). MFA
    # enrollment is two-step: start returns a new secret + provisioning
    # URI to the authenticated session only; confirm requires the
    # account password AND a valid code against that secret before the
    # secret is stored. The pending secret is never persisted, so an
    # abandoned enrollment leaves no half-state.
    @app.post("/api/auth/password-change",
              dependencies=[Depends(require_csrf_header)])
    def password_change(body: PasswordChangeBody,
                        user: User = Depends(current_user),
                        session: Session = Depends(db_session)):
        if not security.verify_password(body.current_password,
                                        user.password_hash):
            return error(403, "current password incorrect")
        if len(body.new_password) < 12:
            return error(400, "password too short")
        user.password_hash = security.hash_password(body.new_password)
        ScopedSession(session, user.tenant_id).audit(
            "auth.password_change", user.email, actor_user_id=user.id)
        session.commit()
        return {"changed": True}

    @app.post("/api/auth/mfa/enroll-start",
              dependencies=[Depends(require_csrf_header)])
    def mfa_enroll_start(user: User = Depends(current_user)):
        if user.totp_secret:
            return error(409, "MFA already enrolled")
        secret = security.new_totp_secret()
        import pyotp
        uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user.email, issuer_name="KosherGuard")
        return {"secret": secret, "provisioning_uri": uri}

    @app.post("/api/auth/mfa/enroll-confirm",
              dependencies=[Depends(require_csrf_header)])
    def mfa_enroll_confirm(body: MfaConfirmBody,
                           user: User = Depends(current_user),
                           session: Session = Depends(db_session)):
        if user.totp_secret:
            return error(409, "MFA already enrolled")
        if not security.verify_password(body.password,
                                        user.password_hash):
            return error(403, "fresh authentication failed")
        if not security.verify_totp(body.secret, body.code):
            return error(400, "invalid code")
        user.totp_secret = body.secret
        ScopedSession(session, user.tenant_id).audit(
            "auth.mfa_enroll", user.email, actor_user_id=user.id)
        session.commit()
        return {"mfa_enabled": True}

    # -- Milestone 2: policies, devices, tighten-only enforcement ------

    from . import policy_ops, publication_ops
    from .models import (AuditEvent, Device, DeviceAssignment,
                         MDMEnrollment, Policy, PolicyVersion,
                         PublicationState)

    def require_guardian(user: User) -> JSONResponse | None:
        if user.role.value not in ("owner", "guardian"):
            return error(403, "viewers cannot change configuration")
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
        import json as _json
        try:
            doc = policy_ops.normalize_engine_doc(body.model_dump())
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
        import json as _json
        policy = get_tenant_policy(session, user.tenant_id, policy_id)
        if policy is None:
            return error(404, "policy not found")
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
            policy_ops.enforce_on_content_mutation(
                session, user.tenant_id, policy, doc)
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
        import json as _json
        policy = get_tenant_policy(session, user.tenant_id, policy_id)
        if policy is None:
            return error(404, "policy not found")
        doc = _json.loads(policy.engine_doc)
        try:
            normalized = schedule_ops.validate_schedules(body.schedules)
            candidate = schedule_ops.with_schedules(doc, normalized)
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

    @app.post("/api/devices", dependencies=[Depends(require_csrf_header)])
    def create_device(body: DeviceBody,
                      user: User = Depends(current_user),
                      session: Session = Depends(db_session)):
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

    @app.get("/api/devices")
    def list_devices(user: User = Depends(current_user),
                     session: Session = Depends(db_session)):
        rows = session.scalars(select(Device).where(
            Device.tenant_id == user.tenant_id).order_by(Device.id))
        return {"devices": [{"id": d.id, "name": d.name, "state": d.state}
                            for d in rows]}

    @app.post("/api/devices/{device_id}/assignment",
              dependencies=[Depends(require_csrf_header)])
    def assign_policy(device_id: int, body: AssignmentBody,
                      user: User = Depends(current_user),
                      session: Session = Depends(db_session)):
        device = session.get(Device, device_id)
        if device is None or device.tenant_id != user.tenant_id:
            return error(404, "device not found")
        policy = get_tenant_policy(session, user.tenant_id, body.policy_id)
        if policy is None:
            return error(404, "policy not found")
        if not policy.enabled:
            return error(409, "a disabled policy cannot be assigned")
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
                "enrollment_id": row.enrollment_id, "state": row.state,
                "supervision_requested": row.supervision_requested,
                "supervision_verified": row.supervision_verified,
                "last_seen_at": (row.last_seen_at.isoformat()
                                 if row.last_seen_at else None),
                "created_at": row.created_at.isoformat()}

    def command_json(row):
        return {"id": row.id, "enrollment_pk": row.enrollment_pk,
                "command": row.command, "status": row.status,
                "applied": row.applied,
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
                body.supervision_requested)
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

    @app.get("/api/admin/tenants")
    def admin_list_tenants(user: User = Depends(current_user),
                           session: Session = Depends(db_session)):
        """Platform-admin customer list: tenant names and counts only -
        never another tenant's policies, devices or user details."""
        denied = require_platform_admin(user)
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
        if scope not in ("dataset", "proxy"):
            return error(400, "scope must be 'dataset' or 'proxy'")
        policy_id = None
        if scope == "proxy":
            assignment = session.execute(select(DeviceAssignment).where(
                DeviceAssignment.device_id == device.id,
                DeviceAssignment.active.is_(True))).scalar_one_or_none()
            if assignment is not None:
                policy_id = assignment.policy_id
            else:
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
        ScopedSession(session, user.tenant_id).audit(
            "device.credential_mint",
            f"{device.name} scope={scope}"
            + (f" policy_id={policy_id}" if policy_id is not None else ""),
            actor_user_id=user.id)
        session.commit()
        return {"device_id": device.id, "credential": token, "scope": scope,
                "policy_id": policy_id}

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

    # -- Guardian account lifecycle (M6) ------------------------------

    # Approved requirement: multiple authorized parent/guardian
    # accounts per family tenant. Owners invite; invite tokens are
    # single-use, expiring, and stored hashed.
    from .models import InviteToken

    def require_owner(user: User) -> JSONResponse | None:
        if user.role != Role.owner:
            return error(403, "owner role required")
        return None

    def user_json(row):
        return {"id": row.id, "email": row.email, "role": row.role.value,
                "mfa_enrolled": row.totp_secret is not None,
                "created_at": row.created_at.isoformat()}

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
        raw = security.new_session_token()
        invite = InviteToken(
            tenant_id=user.tenant_id, email=email, role=Role(body.role),
            token_hash=security.hash_session_token(raw),
            invited_by_user_id=user.id,
            expires_at=utcnow() + timedelta(hours=72))
        session.add(invite)
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
        invite = session.execute(select(InviteToken).where(
            InviteToken.token_hash == security.hash_session_token(
                body.token))).scalar_one_or_none()
        if invite is None or invite.used_at is not None:
            return error(400, "invalid or used invite")
        if invite.expires_at < utcnow():
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
        session.flush()
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
        target = session.get(User, user_id)
        if target is None or target.tenant_id != user.tenant_id:
            return error(404, "guardian not found")
        if target.id == user.id:
            return error(400, "cannot change your own role")
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
        # enough to strip a guardian's MFA.
        if not security.verify_password(body.password,
                                        user.password_hash):
            return error(403, "fresh authentication failed")
        target = session.get(User, user_id)
        if target is None or target.tenant_id != user.tenant_id:
            return error(404, "guardian not found")
        target.totp_secret = None
        ScopedSession(session, user.tenant_id).audit(
            "guardian.mfa_reset", target.email, actor_user_id=user.id)
        session.commit()
        return user_json(target)

    # -- Platform category dataset administration (M6) -----------------

    # Approved fallback for the commercial category feed: a
    # human-reviewed seed dataset managed through these routes.
    # Platform-admin only (is_platform_admin is set out of band, never
    # via the API); guardians get 403.
    from .models import CategoryRule

    def require_platform_admin(user: User) -> JSONResponse | None:
        if not getattr(user, "is_platform_admin", False):
            return error(403, "platform admin required")
        return None

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
        denied = require_platform_admin(user)
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
        denied = require_platform_admin(user)
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
        denied = require_platform_admin(user)
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
        denied = require_platform_admin(user)
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
        denied = require_guardian(user)
        if denied is not None:
            return denied
        try:
            result = publication_ops.publish_selected(
                session, user.tenant_id, settings.publications_root,
                user.email)
        except publication_ops.PolicyError as exc:
            session.rollback()
            return error(exc.status, str(exc))
        ScopedSession(session, user.tenant_id).audit(
            "publication.publish",
            f"published generation {result['revision']}",
            actor_user_id=user.id)
        session.commit()
        return result

    @app.get("/api/publications/current")
    def publication_current(user: User = Depends(current_user)):
        from .publisher import Publisher
        try:
            manifest = Publisher(settings.publications_root).current()
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

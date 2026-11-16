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

from . import mdm_ops, security
from .config import Settings
from .db import ScopedSession, make_engine
from .models import AuthSession, LoginAttempt, User

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


class DeviceBody(BaseModel):
    name: str


class AssignmentBody(BaseModel):
    policy_id: int


class EnrollmentBody(BaseModel):
    device_id: int
    supervised: bool = False


class MDMCommandBody(BaseModel):
    command: str
    payload: dict = {}


class LoginBody(BaseModel):
    email: str
    password: str
    tenant_name: str | None = None
    totp_code: str | None = None


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

    # -- Milestone 2: policies, devices, tighten-only enforcement ------

    from . import policy_ops, publication_ops
    from .models import (Device, DeviceAssignment, Policy, PolicyVersion,
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
                "category_block": doc["category_rules"]["block"]}

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
                "supervised": row.supervised,
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
                session, user.tenant_id, body.device_id, body.supervised)
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

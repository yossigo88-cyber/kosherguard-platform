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

from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from . import security
from .config import Settings
from .db import make_engine
from .models import AuthSession, LoginAttempt, User

SESSION_COOKIE = "kg_session"
CSRF_HEADER = "x-kosherguard-request"
MAX_FAILURES = 5
LOCKOUT_SECONDS = 60


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


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

    @app.exception_handler(Exception)
    def unhandled(request: Request, exc: Exception):
        return error(500, "internal error")

    return app

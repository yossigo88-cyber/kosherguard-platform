"""Category source registry routes (Answer 22): provenance (license +
attribution), versioned imports with SHA-256, category mapping and
validation results on record, manual review before activation, and
rollback. Staff-only (owner / security_admin), mirroring the category
dataset admin gate. A repository's open-source license is NOT assumed
to make its dataset commercially usable - license and attribution are
required fields and review is explicit. No paid classification feed is
introduced here; that needs separate approval."""
import json
import re

from fastapi import Depends
from pydantic import BaseModel, Field
from sqlalchemy import select

from .models import CategorySource, CategorySourceUpdate, StaffRole, utcnow

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
UPDATE_STATUSES = ("pending_review", "active", "rejected",
                   "superseded", "rolled_back")


class SourceCreateBody(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    license_name: str = Field(min_length=1, max_length=300)
    attribution: str = Field(min_length=1)
    notes: str = ""


class ImportBody(BaseModel):
    version: str = Field(min_length=1, max_length=120)
    sha256: str
    category_mapping: dict = {}
    validation_results: dict = {}


class ReviewBody(BaseModel):
    update_id: int
    totp_code: str | None = None
    confirm: str | None = None
    review_notes: str = ""


def _source_json(s: CategorySource) -> dict:
    return {"id": s.id, "name": s.name, "license_name": s.license_name,
            "attribution": s.attribution, "status": s.status,
            "notes": s.notes, "created_at": s.created_at.isoformat()}


def _update_json(u: CategorySourceUpdate) -> dict:
    return {
        "id": u.id, "source_id": u.source_id, "version": u.version,
        "sha256": u.sha256,
        "category_mapping": json.loads(u.category_mapping),
        "validation_results": json.loads(u.validation_results),
        "status": u.status,
        "imported_by_user_id": u.imported_by_user_id,
        "imported_at": u.imported_at.isoformat(),
        "reviewed_by_user_id": u.reviewed_by_user_id,
        "reviewed_at": u.reviewed_at.isoformat() if u.reviewed_at else None,
        "review_notes": u.review_notes,
    }


def register_category_source_routes(app, *, error, current_user,
                                    db_session, require_csrf_header,
                                    require_staff, fresh_check):
    def _staff(user):
        return require_staff(error, user, StaffRole.owner,
                             StaffRole.security_admin)

    @app.post("/api/admin/category-sources",
              dependencies=[Depends(require_csrf_header)])
    def create_source(body: SourceCreateBody, user=Depends(current_user),
                      session=Depends(db_session)):
        denied = _staff(user)
        if denied is not None:
            return denied
        existing = session.scalar(select(CategorySource).where(
            CategorySource.name == body.name.strip()))
        if existing is not None:
            return error(409, "source name already registered")
        source = CategorySource(
            name=body.name.strip(), license_name=body.license_name.strip(),
            attribution=body.attribution, notes=body.notes,
            created_by_user_id=user.id)
        session.add(source)
        session.flush()
        from .db import ScopedSession
        ScopedSession(session, user.tenant_id).audit(
            "category_source.create",
            f"source {source.id} {source.name!r} "
            f"license={source.license_name!r}", actor_user_id=user.id)
        session.commit()
        return _source_json(source)

    @app.get("/api/admin/category-sources")
    def list_sources(user=Depends(current_user),
                     session=Depends(db_session)):
        denied = _staff(user)
        if denied is not None:
            return denied
        rows = session.scalars(select(CategorySource).order_by(
            CategorySource.name)).all()
        return {"sources": [_source_json(s) for s in rows]}

    @app.post("/api/admin/category-sources/{source_id}/imports",
              dependencies=[Depends(require_csrf_header)])
    def import_update(source_id: int, body: ImportBody,
                      user=Depends(current_user),
                      session=Depends(db_session)):
        denied = _staff(user)
        if denied is not None:
            return denied
        source = session.get(CategorySource, source_id)
        if source is None:
            return error(404, "source not found")
        if not SHA256_RE.match(body.sha256):
            return error(400, "sha256 must be 64 lowercase hex chars")
        for key, value in body.category_mapping.items():
            if not isinstance(key, str) or not isinstance(value, str):
                return error(400, "category_mapping must map string to string")
        update = CategorySourceUpdate(
            source_id=source.id, version=body.version,
            sha256=body.sha256,
            category_mapping=json.dumps(body.category_mapping),
            validation_results=json.dumps(body.validation_results),
            imported_by_user_id=user.id)
        session.add(update)
        session.flush()
        from .db import ScopedSession
        ScopedSession(session, user.tenant_id).audit(
            "category_source.import",
            f"source {source.id} update {update.id} "
            f"version={update.version!r}", actor_user_id=user.id)
        session.commit()
        return _update_json(update)

    @app.get("/api/admin/category-sources/{source_id}/history")
    def history(source_id: int, user=Depends(current_user),
                session=Depends(db_session)):
        denied = _staff(user)
        if denied is not None:
            return denied
        source = session.get(CategorySource, source_id)
        if source is None:
            return error(404, "source not found")
        rows = session.scalars(select(CategorySourceUpdate).where(
            CategorySourceUpdate.source_id == source.id)
            .order_by(CategorySourceUpdate.id.desc())).all()
        return {"updates": [_update_json(u) for u in rows]}

    def _review(user, session, source_id, body, from_status, to_status,
                confirm_word, action):
        denied = _staff(user)
        if denied is not None:
            return denied, None
        source = session.get(CategorySource, source_id)
        if source is None:
            return error(404, "source not found"), None
        update = session.get(CategorySourceUpdate, body.update_id)
        if update is None or update.source_id != source.id:
            return error(404, "update not found"), None
        if update.status != from_status:
            return error(409, f"update is {update.status}; "
                              f"only {from_status} can be {action}"), None
        denied = fresh_check(error, user, body.totp_code, body.confirm,
                             confirm_word)
        if denied is not None:
            return denied, None
        return None, (source, update)

    @app.post("/api/admin/category-sources/{source_id}/activate",
              dependencies=[Depends(require_csrf_header)])
    def activate_update(source_id: int, body: ReviewBody,
                        user=Depends(current_user),
                        session=Depends(db_session)):
        """Manual review gate: activate a pending_review update with a
        fresh staff MFA code and explicit confirmation. The previously
        active update is superseded (one active per source)."""
        from .db import ScopedSession
        denied, found = _review(user, session, source_id, body,
                                "pending_review", "active",
                                "activate-category-update", "activated")
        if denied is not None:
            return denied
        source, update = found
        current = session.scalars(select(CategorySourceUpdate).where(
            CategorySourceUpdate.source_id == source.id,
            CategorySourceUpdate.status == "active")).all()
        for row in current:
            row.status = "superseded"
        update.status = "active"
        update.reviewed_by_user_id = user.id
        update.reviewed_at = utcnow()
        update.review_notes = body.review_notes
        ScopedSession(session, user.tenant_id).audit(
            "category_source.activate",
            f"source {source.id} update {update.id} "
            f"version={update.version!r}", actor_user_id=user.id)
        session.commit()
        return _update_json(update)

    @app.post("/api/admin/category-sources/{source_id}/rollback",
              dependencies=[Depends(require_csrf_header)])
    def rollback_update(source_id: int, body: ReviewBody,
                        user=Depends(current_user),
                        session=Depends(db_session)):
        """Roll back to a previously superseded update with a fresh
        staff MFA code. The currently active update is marked
        rolled_back, keeping the full audit trail."""
        from .db import ScopedSession
        denied, found = _review(user, session, source_id, body,
                                "superseded", "active",
                                "rollback-category-update", "rolled back")
        if denied is not None:
            return denied
        source, update = found
        current = session.scalars(select(CategorySourceUpdate).where(
            CategorySourceUpdate.source_id == source.id,
            CategorySourceUpdate.status == "active")).all()
        for row in current:
            row.status = "rolled_back"
        update.status = "active"
        update.reviewed_by_user_id = user.id
        update.reviewed_at = utcnow()
        update.review_notes = body.review_notes
        ScopedSession(session, user.tenant_id).audit(
            "category_source.rollback",
            f"source {source.id} update {update.id} "
            f"version={update.version!r}", actor_user_id=user.id)
        session.commit()
        return _update_json(update)

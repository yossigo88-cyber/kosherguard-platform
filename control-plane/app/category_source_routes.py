"""Category source registry routes (Answer 22): provenance (license +
attribution), versioned imports whose SHA-256 is VERIFIED against the
canonical dataset bytes (canonical JSON of the validated rows: sorted
keys, 2-space indent, trailing newline - app.publisher.canonical_json),
category mapping and validation results on record, manual review before
activation, and rollback. Staff-only (owner / security_admin), mirroring
the category dataset admin gate. A repository's open-source license is
NOT assumed to make its dataset commercially usable - license and
attribution are required fields and review is explicit. No paid
classification feed is introduced here; that needs separate approval.

Activation/rollback commit the rule changes first, then re-sync the
categories file AFTER the commit with an atomic replace (tempfile +
os.replace) and a post-write digest check, so the on-disk document
can never be ahead of the committed rules and a failed sync leaves
the last-known-good file untouched (audited). Concurrent activations
serialize on the source row (FOR UPDATE). The publish flow re-verifies
the file against the committed rules before shipping, so effective
categories cannot diverge from the database."""
import hashlib
import json
import os
import re
import tempfile

from fastapi import Depends
from pydantic import BaseModel, Field
from sqlalchemy import select

from .models import (CategoryRule, CategorySource, CategorySourceUpdate,
                     StaffRole, utcnow)
from .publication_ops import build_categories_doc, canonical_json

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
    rules: list[dict] = []

DOMAIN_RE = re.compile(r"^[a-z0-9][a-z0-9.-]*[a-z0-9]$")
VERDICTS = ("allow", "block")


def _validate_rules(raw_rules):
    """Validate imported dataset rows. Any malformed row rejects the
    whole import - a partially valid dataset must never become
    effective. Returns (rules, rejected_count)."""
    rules = []
    for item in raw_rules:
        if not isinstance(item, dict):
            raise ValueError("each rule must be an object")
        domain = str(item.get("domain", "")).strip().lower().rstrip(".")
        category = str(item.get("category", "")).strip()
        verdict = str(item.get("verdict", "block")).strip()
        if not domain or not DOMAIN_RE.match(domain) or len(domain) > 253:
            raise ValueError(f"invalid domain: {item.get('domain')!r}")
        if not category:
            raise ValueError(f"rule for {domain!r} has no category")
        if verdict not in VERDICTS:
            raise ValueError(f"rule for {domain!r}: verdict must be "
                             f"one of {VERDICTS}")
        rules.append({"domain": domain, "category": category,
                      "verdict": verdict})
    return rules


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
        "rules_count": len(json.loads(u.rules_json)),
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
                                    require_staff, fresh_check, settings):
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
        try:
            rules = _validate_rules(body.rules)
        except ValueError as exc:
            return error(400, f"invalid rules: {exc}")
        # Payload integrity: the declared hash must match the canonical
        # bytes of the validated dataset, so a tampered or truncated
        # import can never be activated under a format-valid hash.
        digest = hashlib.sha256(canonical_json(rules)).hexdigest()
        if digest != body.sha256:
            return error(
                400, "sha256 does not match the canonical dataset bytes "
                     "(sha256 over canonical JSON of the validated rules: "
                     "sorted keys, 2-space indent, trailing newline)")
        update = CategorySourceUpdate(
            source_id=source.id, version=body.version,
            sha256=body.sha256,
            category_mapping=json.dumps(body.category_mapping),
            validation_results=json.dumps(
                {"rows": len(rules), "rejected": 0}),
            rules_json=json.dumps(rules),
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
        # Lock the source row so concurrent activations/rollbacks of
        # the same source serialize: the loser sees the winner's
        # committed state instead of interleaving rule writes.
        source = session.get(CategorySource, source_id,
                             with_for_update=True)
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

    def _apply_rules(session, user, source, update, now):
        """Make an update's rows effective: deactivate the rows of the
        update(s) it replaces, upsert its own rows with provenance, and
        rebuild the categories file the publisher ships. Rules of a
        non-active update are never effective."""
        replaced = session.scalars(select(CategorySourceUpdate).where(
            CategorySourceUpdate.source_id == source.id,
            CategorySourceUpdate.status == "active")).all()
        for old in replaced:
            old.status = "superseded" if old.id != update.id else old.status
            for rule in session.scalars(select(CategoryRule).where(
                    CategoryRule.source_update_id == old.id,
                    CategoryRule.active.is_(True))).all():
                rule.active = False
                rule.deactivated_at = now
        rules = json.loads(update.rules_json)
        for item in rules:
            row = session.scalar(select(CategoryRule).where(
                CategoryRule.domain == item["domain"]))
            if row is None:
                row = CategoryRule(domain=item["domain"])
                session.add(row)
            row.category = item["category"]
            row.verdict = item["verdict"]
            row.source = f"{source.name}@{update.version}"
            row.source_update_id = update.id
            row.active = True
            row.deactivated_at = None
            row.added_by_user_id = user.id
        session.flush()
        update.status = "active"
        update.reviewed_by_user_id = user.id
        update.reviewed_at = now
        return len(rules)

    def _sync_categories_file(session, user):
        """Re-sync the categories file (KG_CATEGORIES_FILE) from the
        COMMITTED active rules. Runs after the database commit so the
        file can never be ahead of the database: the document is built
        and validated with the engine's own loader, written to a
        tempfile and atomically os.replace'd into place (a failed sync
        leaves the last-known-good file untouched), then re-read and
        digest-checked. A failure is audited and reported; the
        committed rules stay the source of truth and the publish flow
        refuses to ship a diverged file."""
        if not settings.categories_file:
            return None
        from .db import ScopedSession
        try:
            doc = build_categories_doc(session)
            payload = canonical_json(doc)
            path = settings.categories_file
            directory = os.path.dirname(os.path.abspath(path)) or "."
            fd, tmp = tempfile.mkstemp(dir=directory,
                                       prefix=".categories-",
                                       suffix=".tmp")
            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(payload)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, path)
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
            with open(path, "rb") as fh:
                if hashlib.sha256(fh.read()).hexdigest() != \
                        hashlib.sha256(payload).hexdigest():
                    raise OSError("post-write digest mismatch")
        except Exception as exc:
            ScopedSession(session, user.tenant_id).audit(
                "category_source.file_sync_failed",
                f"categories file sync failed after commit: {exc}",
                actor_user_id=user.id)
            session.commit()
            return error(
                500, "category rules committed, but syncing the "
                     "categories file failed; the previous file is "
                     "untouched (last-known-good) and publication "
                     "refuses diverged data. Re-run category-source "
                     "resync once the filesystem is writable.")
        ScopedSession(session, user.tenant_id).audit(
            "category_source.file_synced",
            f"categories file synced: {len(doc['domains'])} domains",
            actor_user_id=user.id)
        session.commit()
        return None

    @app.post("/api/admin/category-sources/{source_id}/activate",
              dependencies=[Depends(require_csrf_header)])
    def activate_update(source_id: int, body: ReviewBody,
                        user=Depends(current_user),
                        session=Depends(db_session)):
        """Manual review gate + real activation: fresh staff MFA, then
        the update's rows REPLACE the previously active update's rows
        in category_rules (source/version/hash bound) and the
        categories document is rebuilt. A pending update's rows are
        never effective before this."""
        from .db import ScopedSession
        denied, found = _review(user, session, source_id, body,
                                "pending_review", "active",
                                "activate-category-update", "activated")
        if denied is not None:
            return denied
        source, update = found
        if not json.loads(update.rules_json):
            return error(400, "update carries no rules; import the "
                              "dataset rows before activation")
        applied = _apply_rules(session, user, source, update, utcnow())
        update.review_notes = body.review_notes
        ScopedSession(session, user.tenant_id).audit(
            "category_source.activate",
            f"source {source.id} update {update.id} "
            f"version={update.version!r} rules={applied}",
            actor_user_id=user.id)
        session.commit()
        sync_error = _sync_categories_file(session, user)
        if sync_error is not None:
            return sync_error
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
            for rule in session.scalars(select(CategoryRule).where(
                    CategoryRule.source_update_id == row.id,
                    CategoryRule.active.is_(True))).all():
                rule.active = False
                rule.deactivated_at = utcnow()
        # Reactivate the rollback target's rows (real data rollback,
        # not just a status flip).
        for item in json.loads(update.rules_json):
            row = session.scalar(select(CategoryRule).where(
                CategoryRule.domain == item["domain"]))
            if row is None:
                row = CategoryRule(domain=item["domain"])
                session.add(row)
            row.category = item["category"]
            row.verdict = item["verdict"]
            row.source = f"{source.name}@{update.version}"
            row.source_update_id = update.id
            row.active = True
            row.deactivated_at = None
            row.added_by_user_id = user.id
        session.flush()
        update.status = "active"
        update.reviewed_by_user_id = user.id
        update.reviewed_at = utcnow()
        update.review_notes = body.review_notes
        ScopedSession(session, user.tenant_id).audit(
            "category_source.rollback",
            f"source {source.id} update {update.id} "
            f"version={update.version!r}", actor_user_id=user.id)
        session.commit()
        sync_error = _sync_categories_file(session, user)
        if sync_error is not None:
            return sync_error
        return _update_json(update)

    @app.post("/api/admin/category-sources/resync",
              dependencies=[Depends(require_csrf_header)])
    def resync_categories_file(user=Depends(current_user),
                               session=Depends(db_session)):
        """Rebuild the categories file from the committed active rules.
        Staff-only repair path for a failed sync; it cannot change the
        effective rules, only re-materialize them."""
        denied = _staff(user)
        if denied is not None:
            return denied
        sync_error = _sync_categories_file(session, user)
        if sync_error is not None:
            return sync_error
        if not settings.categories_file:
            return {"synced": False,
                    "detail": "no categories file configured"}
        return {"synced": True}

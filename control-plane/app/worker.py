"""Durable publication outbox. Run with python -m app.worker.

A database transaction claims each job, including a row lock (SKIP LOCKED
on PostgreSQL), through completion. A killed worker releases its lock and
leaves the job queued. No Apple calls or device commands are performed.
"""
from __future__ import annotations

import argparse
import json
import signal
import threading
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from .models import AuditEvent, PublicationJob, PublicationState, User, Role
from .publication_ops import publish_selected, tenant_root
from .publisher import Publisher


def enqueue(session: Session, tenant_id: int, actor_id: int,
            actor_email: str, request_key: str) -> PublicationJob:
    if not request_key or len(request_key) > 100:
        raise ValueError("request_key must contain 1-100 characters")
    old = session.scalar(select(PublicationJob).where(
        PublicationJob.tenant_id == tenant_id,
        PublicationJob.request_key == request_key))
    if old is not None:
        return old
    row = PublicationJob(tenant_id=tenant_id, actor_user_id=actor_id,
                         actor_email=actor_email, request_key=request_key)
    session.add(row)
    session.flush()
    session.add(AuditEvent(tenant_id=tenant_id, actor_user_id=actor_id,
                          action="publication.queued", detail=f"job {row.id}"))
    return row


def run_once(engine, settings, now=None) -> bool:
    """Process one due job. Returns False when there is no due work.

    Retries are bounded and use exponential backoff. The publisher records
    a durable job identifier in its manifest before activation. If the
    worker dies after file activation but before DB commit, the retry
    verifies that manifest, repairs the DB revision, and does not publish
    twice. The publication-state lock also serializes synchronous callers
    which acquire the same lock in publish_selected.
    """
    now = now or datetime.now(timezone.utc)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory.begin() as session:
        job = session.scalar(select(PublicationJob).where(
            PublicationJob.status == "queued",
            PublicationJob.available_at <= now).order_by(
                PublicationJob.id).with_for_update(skip_locked=True).limit(1))
        if job is None:
            return False
        job.attempts += 1
        try:
            with session.begin_nested():
                actor = session.get(User, job.actor_user_id)
                if (actor is None or actor.tenant_id != job.tenant_id or
                        actor.role not in (Role.owner, Role.guardian) or
                        not actor.totp_secret):
                    raise PermissionError("publication actor no longer authorized")
                state = session.scalar(select(PublicationState).where(
                    PublicationState.tenant_id == job.tenant_id
                ).with_for_update())
                manifest = Publisher(tenant_root(
                    settings.publications_root, job.tenant_id)).current()
                if manifest and state is not None:
                    # A prior crashed transaction may have activated a
                    # generation belonging to another completed request.
                    state.revision = max(state.revision, manifest["revision"])
                if manifest and manifest.get("publication_job_id") == job.id:
                    if state is None:
                        raise RuntimeError("publication state missing")
                    state.revision = max(state.revision, manifest["revision"])
                    result = {"revision": manifest["revision"],
                              "generation": manifest["generation"],
                              "recovered": True}
                else:
                    result = publish_selected(
                        session, job.tenant_id, settings.publications_root,
                        job.actor_email, settings.categories_file,
                        publication_job_id=job.id)
                job.result = json.dumps(result, sort_keys=True)
                job.status = "completed"
                job.finished_at = now
                job.last_error = None
                session.add(AuditEvent(
                    tenant_id=job.tenant_id, actor_user_id=job.actor_user_id,
                    action="publication.completed", detail=f"job {job.id}"))
        except Exception:
            # Errors may contain paths or private payloads. Only a fixed
            # classification is retained, not arbitrary exception text.
            job.last_error = "publication failed; inspect local worker diagnostics"
            job.status = "failed" if job.attempts >= 5 else "queued"
            job.available_at = now + timedelta(seconds=min(300, 2 ** job.attempts))
            if job.status == "failed":
                job.finished_at = now
        session.flush()
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description="KosherGuard publication worker")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=float, default=5)
    args = parser.parse_args(argv)
    if args.interval <= 0:
        parser.error("interval must be positive")
    from .config import Settings
    from .db import make_engine
    settings = Settings()
    engine = make_engine(settings.database_url)
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    try:
        while not stop.is_set():
            from .filter_log_ops import purge_expired
            with sessionmaker(bind=engine).begin() as maintenance:
                purge_expired(maintenance)
            worked = run_once(engine, settings)
            if args.once:
                break
            if not worked:
                stop.wait(args.interval)
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()

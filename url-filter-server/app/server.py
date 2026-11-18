"""URL-filter dataset service (FastAPI).

Serves the versioned dataset to the iOS extension's prefilter updater
and verdict lookups. Per the privacy model (investigation 5.4), the
query path has no per-device logging: verdict queries are answered
from the dataset without recording which URL was asked about.

Deployment note: in the Apple URL Filter architecture the off-device
lookup reaches this data through Apple's PIR container tooling behind
an OHTTP gateway/relay, so the service never sees the device or its
query. The plain endpoints here are the dataset-distribution surface
(manifest, prefilter, shards); the PIR/OHTTP wrapping is the
deployment layer and depends on Apple's tooling and approvals.
"""

from __future__ import annotations

import hashlib

import os

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from .device_auth import TokenError, verify_token
from .revocations import RevocationFeed
from fastapi.responses import JSONResponse, Response

from .dataset import Dataset


class DatasetRef:
    """Atomically swappable dataset holder. Endpoints read .current
    per request; a reload builds the replacement FULLY (outside this
    lock) and swaps the reference only on success, so a failed reload
    always leaves the last good dataset serving."""

    def __init__(self, dataset: Dataset):
        import threading
        self._lock = threading.Lock()
        self._dataset = dataset

    @property
    def current(self) -> Dataset:
        with self._lock:
            return self._dataset

    def swap(self, dataset: Dataset) -> None:
        with self._lock:
            self._dataset = dataset


def create_app(dataset: Dataset,
               device_token_key: bytes | None = None,
               revoked_jtis: set | None = None,
               revocation_feed=None,
               dataset_ref: DatasetRef | None = None,
               reload_callback=None,
               reload_token: str | None = None,
               status_provider=None) -> FastAPI:
    if device_token_key is None:
        raw = os.environ.get("KG_DEVICE_TOKEN_KEY", "")
        device_token_key = raw.encode() if raw else None

    def require_device(request: Request):
        """Per-device credential check. When no key is configured the
        service runs in local-development mode and lets requests
        through; production must set KG_DEVICE_TOKEN_KEY. revoked_jtis,
        when supplied (see app.revocations.RevocationFeed), refuses
        listed tokens immediately."""
        if device_token_key is None:
            return {"device_id": "dev-mode", "tenant_id": "dev-mode"}
        effective = (revocation_feed.shared_set
                     if revocation_feed is not None else revoked_jtis)
        header = request.headers.get("authorization", "")
        token = (header[7:] if header.lower().startswith("bearer ")
                 else "")
        try:
            return verify_token(device_token_key, token, "dataset",
                                revoked_jtis=effective)
        except TokenError:
            # Deliberately generic: no oracle about which check failed.
            # The TokenError message distinguishes expired/bad-signature/
            # revoked; it is never sent to the client.
            raise HTTPException(status_code=401, detail="unauthorized")

    app = FastAPI(title="KosherGuard URL Filter Server", docs_url=None,
                  redoc_url=None)
    ref = dataset_ref if dataset_ref is not None else DatasetRef(dataset)

    if reload_callback is not None:
        # Admin reload: registered ONLY with an explicit admin token -
        # an unauthenticated reload trigger would let anyone force
        # dataset rebuilds. The callback returns a fully built Dataset
        # or raises; a raise never disturbs the serving dataset.
        if not reload_token:
            raw = os.environ.get("KG_RELOAD_TOKEN", "")
            reload_token = raw if raw else None
        if reload_token is None:
            raise ValueError("reload_callback requires a reload token "
                             "(argument or KG_RELOAD_TOKEN)")

        @app.post("/v1/admin/reload")
        def reload_dataset(request: Request):
            header = request.headers.get("authorization", "")
            token = (header[7:] if header.lower().startswith("bearer ")
                     else "")
            import hmac as _hmac
            if not _hmac.compare_digest(token, reload_token):
                raise HTTPException(status_code=401,
                                    detail="unauthorized")
            try:
                rebuilt = reload_callback()
            except Exception:
                # Deliberately generic: rebuild errors can carry
                # policy/source detail that is not the caller's.
                raise HTTPException(
                    status_code=502,
                    detail="dataset rebuild failed; previous dataset "
                           "kept") from None
            if not isinstance(rebuilt, Dataset):
                raise HTTPException(status_code=502,
                                    detail="rebuild returned no "
                                           "dataset; previous kept")
            ref.swap(rebuilt)
            return {"version": rebuilt.manifest.get("version"),
                    "prefilter_sha256":
                        rebuilt.manifest.get("prefilter", {})
                        .get("sha256")}

    @app.get("/v1/dataset/status",
             dependencies=[Depends(require_device)])
    def dataset_status():
        """Authenticated freshness/error readback for the app (and,
        via the app, the dashboard): which generation is served, which
        the publication root advertises, whether the service is behind,
        and the last activation error. Same device credential as the
        dataset itself - freshness is part of the filtering contract,
        not an operator-only signal."""
        body = {"served_generation": ref.current.version,
                "watcher": None}
        if status_provider is not None:
            # The provider must be the watcher's CREDENTIAL-SAFE view
            # (public_status): the detailed operator error can name
            # other devices' IDs, hosts or paths and must never cross
            # into a response any tenant device can read.
            body["watcher"] = status_provider()
        return body

    @app.get("/v1/dataset/manifest",
             dependencies=[Depends(require_device)])
    def manifest():
        return ref.current.manifest

    @app.get("/v1/dataset/prefilter",
             dependencies=[Depends(require_device)])
    def prefilter():
        current = ref.current
        data = current.prefilter.to_bytes()
        return Response(
            content=data, media_type="application/octet-stream",
            headers={"X-SHA256": hashlib.sha256(data).hexdigest(),
                     "X-Bloom-Bits": str(current.prefilter.bit_count),
                     "X-Bloom-Hashes": str(current.prefilter.hash_count),
                     "X-Bloom-Murmur-Seed": str(current.prefilter.murmur_seed),
                     "X-Bloom-Format": "apple-fnv1a-murmur3-doublehash-v1"})

    @app.get("/v1/dataset/shards/{index}",
             dependencies=[Depends(require_device)])
    def shard(index: int):
        current = ref.current
        if index < 0 or index >= len(current.shards):
            return JSONResponse(status_code=404,
                                content={"error": "no such shard"})
        data = current.shards[index]
        return Response(
            content=data, media_type="application/octet-stream",
            headers={"X-SHA256": hashlib.sha256(data).hexdigest()})

    return app


def build_runtime(dataset: Dataset,
                  device_token_key: bytes | None = None,
                  control_plane_url: str | None = None,
                  token_provider=None,
                  refresh_interval: float = 60.0,
                  publication_root: str | None = None,
                  watch_interval: float = 60.0):
    """Service entrypoint wiring: build the app WITH its revocation
    feed and refresh loop running. Returns (app, stop_event); set the
    event to stop the loop (the ASGI server's own lifecycle owns
    serving). When control_plane_url and token_provider are absent the
    app runs without revocation distribution (local development only -
    production configures both). The provider is the renewal source:
    it is consulted on every refresh and must return a current scoped
    credential (minted via POST /api/devices/{id}/dataset-credential
    with a guardian session); after the last successful pull, staleness
    is bounded by the credential's lifetime (at most 86400s) because
    expired tokens fail verification anyway.

    publication_root, when set, starts the automatic publish ->
    rebuild -> serve chain (PublicationWatcher on the tenant's
    publication root): every control-plane publish rebuilds and swaps
    the served dataset with no human POST and no restart. A failed
    poll keeps the last good dataset; watcher.status() exposes the
    loaded generation, last build time and last error."""
    feed = None
    stop = None
    if control_plane_url and token_provider is not None:
        feed = RevocationFeed(control_plane_url, token_provider)
        stop = feed.start_refresh_loop(interval=refresh_interval)
    ref = DatasetRef(dataset)
    watcher = None
    stops = [s for s in [stop] if s is not None]
    if publication_root is not None:
        from .publication_watch import PublicationWatcher
        watcher = PublicationWatcher(publication_root, ref)
        stops.append(watcher.start_refresh_loop(
            interval=watch_interval))
    app = create_app(dataset, device_token_key=device_token_key,
                     revocation_feed=feed, dataset_ref=ref,
                     status_provider=(watcher.public_status
                                      if watcher is not None else None))
    if not stops:
        return app, None
    if len(stops) == 1:
        return app, stops[0]
    import threading
    combined = threading.Event()

    def propagate():
        combined.wait()
        for s in stops:
            s.set()

    threading.Thread(target=propagate, name="runtime-stop",
                     daemon=True).start()
    return app, combined

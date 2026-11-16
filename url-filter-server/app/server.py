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


def create_app(dataset: Dataset,
               device_token_key: bytes | None = None,
               revoked_jtis: set | None = None,
               revocation_feed=None) -> FastAPI:
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
        except TokenError as exc:
            # Deliberately generic: no oracle about which check failed.
            raise HTTPException(status_code=401,
                                detail=f"unauthorized: {exc}")

    app = FastAPI(title="KosherGuard URL Filter Server", docs_url=None,
                  redoc_url=None)

    @app.get("/v1/dataset/manifest",
             dependencies=[Depends(require_device)])
    def manifest():
        return dataset.manifest

    @app.get("/v1/dataset/prefilter",
             dependencies=[Depends(require_device)])
    def prefilter():
        data = dataset.prefilter.to_bytes()
        return Response(
            content=data, media_type="application/octet-stream",
            headers={"X-SHA256": hashlib.sha256(data).hexdigest(),
                     "X-Bloom-Bits": str(dataset.prefilter.m),
                     "X-Bloom-Hashes": str(dataset.prefilter.k)})

    @app.get("/v1/dataset/shards/{index}",
             dependencies=[Depends(require_device)])
    def shard(index: int):
        if index < 0 or index >= len(dataset.shards):
            return JSONResponse(status_code=404,
                                content={"error": "no such shard"})
        data = dataset.shards[index]
        return Response(
            content=data, media_type="application/octet-stream",
            headers={"X-SHA256": hashlib.sha256(data).hexdigest()})

    return app


def build_runtime(dataset: Dataset,
                  device_token_key: bytes | None = None,
                  control_plane_url: str | None = None,
                  token_provider=None,
                  refresh_interval: float = 60.0):
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
    expired tokens fail verification anyway."""
    feed = None
    stop = None
    if control_plane_url and token_provider is not None:
        feed = RevocationFeed(control_plane_url, token_provider)
        stop = feed.start_refresh_loop(interval=refresh_interval)
    app = create_app(dataset, device_token_key=device_token_key,
                     revocation_feed=feed)
    return app, stop

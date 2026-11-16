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

from fastapi import FastAPI
from fastapi.responses import JSONResponse, Response

from .dataset import Dataset


def create_app(dataset: Dataset) -> FastAPI:
    app = FastAPI(title="KosherGuard URL Filter Server", docs_url=None,
                  redoc_url=None)

    @app.get("/v1/dataset/manifest")
    def manifest():
        return dataset.manifest

    @app.get("/v1/dataset/prefilter")
    def prefilter():
        data = dataset.prefilter.to_bytes()
        return Response(
            content=data, media_type="application/octet-stream",
            headers={"X-SHA256": hashlib.sha256(data).hexdigest(),
                     "X-Bloom-Bits": str(dataset.prefilter.m),
                     "X-Bloom-Hashes": str(dataset.prefilter.k)})

    @app.get("/v1/dataset/shards/{index}")
    def shard(index: int):
        if index < 0 or index >= len(dataset.shards):
            return JSONResponse(status_code=404,
                                content={"error": "no such shard"})
        data = dataset.shards[index]
        return Response(
            content=data, media_type="application/octet-stream",
            headers={"X-SHA256": hashlib.sha256(data).hexdigest()})

    return app

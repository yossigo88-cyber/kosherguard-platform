"""Real health depth, structured request logging and metrics (spec M6).

monitoring.md used to be configuration-only. This module implements the
environment-feasible parts inside the control-plane itself:

- /health        - cheap liveness (unchanged, always answers)
- /health/depth  - dependency check (database SELECT 1); 503 when degraded
- /metrics       - Prometheus text exposition, staff-only
- one JSON log line per API request on the "kosherguard.requests" logger

Hard privacy rules (user requirement: credentials never in logs):
- no request/response bodies, no headers, no cookies, no query strings
  (query strings can carry tokens), no email addresses
- route templates ("/api/devices/{id}") instead of concrete paths, so
  identifiers never land in logs or metric labels and cardinality stays
  bounded; unmatched routes collapse to "unmatched"
"""

import json
import logging
import threading
import time
from datetime import datetime, timezone

from fastapi import Depends, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import text

request_log = logging.getLogger("kosherguard.requests")


class Metrics:
    """Tiny in-process counter registry with Prometheus rendering."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[tuple, int] = {}

    def inc(self, name: str, amount: int = 1, **labels: str) -> None:
        key = (name, tuple(sorted(labels.items())))
        with self._lock:
            self._counters[key] = self._counters.get(key, 0) + amount

    def render(self) -> str:
        lines = []
        with self._lock:
            items = sorted(self._counters.items())
        for (name, labels), value in items:
            label_text = ""
            if labels:
                label_text = "{" + ",".join(
                    f'{k}="{v}"' for k, v in labels) + "}"
            lines.append(f"{name}{label_text} {value}")
        return "\n".join(lines) + "\n"


def _route_template(request: Request) -> str:
    route = request.scope.get("route")
    path = getattr(route, "path", None)
    if isinstance(path, str) and path:
        return path
    return "unmatched"


def register_observability(app, *, error, current_user, db_session,
                           metrics: Metrics | None = None) -> Metrics:
    metrics = metrics or Metrics()
    app.state.metrics = metrics

    @app.middleware("http")
    async def observe_requests(request: Request, call_next):
        started = time.monotonic()
        response = await call_next(request)
        elapsed_ms = int((time.monotonic() - started) * 1000)
        route = _route_template(request)
        metrics.inc("http_requests_total", route=route,
                    method=request.method,
                    status=str(response.status_code))
        if request.url.path.startswith("/api/"):
            request_log.info(json.dumps({
                "ts": datetime.now(timezone.utc).isoformat(),
                "method": request.method,
                "route": route,
                "status": response.status_code,
                "duration_ms": elapsed_ms,
            }, separators=(",", ":")))
        return response

    @app.get("/health/depth")
    def health_depth(session=Depends(db_session)):
        checks = {}
        try:
            session.execute(text("SELECT 1"))
            checks["database"] = "ok"
        except Exception:
            checks["database"] = "fail"
        ok = all(v == "ok" for v in checks.values())
        body = {"status": "ok" if ok else "degraded", "checks": checks}
        if not ok:
            from fastapi.responses import JSONResponse
            return JSONResponse(body, status_code=503)
        return body

    @app.get("/metrics")
    def metrics_endpoint(user=Depends(current_user)):
        # Staff-only operational surface: no tenant browsing data here,
        # but request shapes can still reveal usage, so keep it gated.
        if user.staff_role is None and not user.is_platform_admin:
            return error(403, "metrics are staff-only")
        return PlainTextResponse(metrics.render(),
                                 media_type="text/plain; version=0.0.4")

    return metrics

#!/usr/bin/env python3
"""Bounded, entirely local synthetic control-plane API benchmark.

python tools/benchmark_api.py --requests 600 --clients 8 --output /tmp/api.json

Measures the authenticated JSON read path and a small login sample against
a real HTTP server (uvicorn) on loopback with a disposable database and one
synthetic tenant/user. This is NOT production capacity, availability, or a
promised customer/device count (Answer 6): it documents what the small
internal test environment actually did, so capacity claims stay grounded.
"""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import platform
import statistics
import sys
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "control-plane"))

PASSWORD = "a long enough password"
READ_PATHS = ["/api/overview", "/api/policies", "/api/devices",
              "/api/groups", "/api/exceptions"]


def build_server(root):
    import pgserver
    from sqlalchemy import create_engine
    import pyotp

    from app import security
    from app.config import Settings
    from app.db import create_schema, session_scope
    from app.main import create_app
    from app.models import Role, Tenant, User

    pg = pgserver.get_server(f"/tmp/kg-bench-pg-{uuid.uuid4().hex[:8]}")
    url = pg.get_uri().replace("postgresql://", "postgresql+psycopg://", 1)
    engine = create_engine(url)
    create_schema(engine)
    secret = pyotp.random_base32()
    with session_scope(engine) as s:
        tenant = Tenant(name="bench-family")
        s.add(tenant)
        s.flush()
        s.add(User(tenant_id=tenant.id, email="bench@example.test",
                   password_hash=security.hash_password(PASSWORD),
                   role=Role.owner, staff_role=None,
                   totp_secret=secret))
    settings = Settings({"KG_DATABASE_URL": "postgresql://placeholder",
                         "KG_PUBLICATIONS_ROOT": str(root / "pubs")})
    app = create_app(settings, engine=engine)
    return app, secret


def percentile(sorted_values, p):
    return sorted_values[min(len(sorted_values) - 1,
                             int((len(sorted_values) - 1) * p))]


def summarize(name, samples):
    lat = sorted(s[0] for s in samples)
    ok = sum(1 for s in samples if s[1])
    return {
        "name": name,
        "requests": len(samples),
        "ok": ok,
        "errors": len(samples) - ok,
        "latency_ms": {"median": round(statistics.median(lat), 3),
                       "p95": round(percentile(lat, .95), 3),
                       "p99": round(percentile(lat, .99), 3)},
    }


def run(requests=600, clients=8):
    if not 1 <= requests <= 100000 or not 1 <= clients <= 64:
        raise ValueError("requests 1-100000; clients 1-64")
    import httpx
    import pyotp
    import uvicorn

    with tempfile.TemporaryDirectory(prefix="kg-api-load-") as root:
        app, secret = build_server(Path(root))
        config = uvicorn.Config(app, host="127.0.0.1", port=0,
                                log_level="error")
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        deadline = time.time() + 30
        while not server.started and time.time() < deadline:
            time.sleep(0.05)
        if not server.started:
            raise RuntimeError("uvicorn did not start")
        port = server.servers[0].sockets[0].getsockname()[1]
        base = f"http://127.0.0.1:{port}"
        hdr = {"X-KosherGuard-Request": "1"}
        try:
            # Login sample: distinct timing of the real bcrypt+TOTP path.
            login_samples = []
            for _ in range(min(10, requests)):
                started = time.perf_counter()
                r = httpx.post(base + "/api/auth/login", headers=hdr,
                               json={"email": "bench@example.test",
                                     "password": PASSWORD,
                                     "totp_code": pyotp.TOTP(secret).now()},
                               timeout=10)
                login_samples.append(
                    ((time.perf_counter() - started) * 1000,
                     r.status_code == 200))
            cookie = r.cookies

            def one(n):
                started = time.perf_counter()
                try:
                    r = httpx.get(base + READ_PATHS[n % len(READ_PATHS)],
                                  cookies=cookie, timeout=10)
                    good = r.status_code == 200
                except Exception:
                    good = False
                return (time.perf_counter() - started) * 1000, good

            started = time.perf_counter()
            with concurrent.futures.ThreadPoolExecutor(
                    max_workers=clients) as pool:
                values = list(pool.map(one, range(requests)))
            seconds = time.perf_counter() - started
        finally:
            server.should_exit = True
            thread.join(timeout=10)
        read_summary = summarize("authenticated GET mix " +
                                 str(READ_PATHS), values)
        read_summary["elapsed_seconds"] = round(seconds, 4)
        read_summary["throughput_requests_per_second"] = round(
            requests / seconds, 2)
        return {
            "scope": ("local loopback HTTP (uvicorn) against a disposable "
                      "database; one synthetic tenant/user; no Apple, APNs, "
                      "network or device traffic"),
            "requests": requests,
            "concurrent_clients": clients,
            "results": [summarize("POST /api/auth/login (bcrypt+TOTP)",
                                  login_samples), read_summary],
            "environment": {"python": platform.python_version(),
                            "platform": platform.system(),
                            "cpus": os.cpu_count()},
        }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--requests", type=int, default=600)
    parser.add_argument("--clients", type=int, default=8)
    parser.add_argument("--output")
    args = parser.parse_args()
    report = run(args.requests, args.clients)
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(text + "\n")
    print(text)


if __name__ == "__main__":
    main()

# Synthetic load testing and measured performance

Answer 6: do not invent a customer count or promise production capacity;
build a scalable architecture with configurable limits, use small internal
test environments and synthetic load testing, and document the tested
capacity and actual performance before accepting customers. Answer 23:
policy-update speed figures are provisional performance goals to measure,
not guaranteed service promises, and each delivery path is measured
separately. This document records exactly what was measured, where, and
what the numbers do NOT mean.

## Harness (committed, re-runnable)

| Tool | What it measures |
| --- | --- |
| `tools/benchmark_dns.py` | DNS edge verdict path: loopback UDP queries that all match the blocklist (sinkhole answer), no upstream forwarding |
| `tools/benchmark_api.py` | Control-plane API: real uvicorn HTTP server on loopback with a disposable PostgreSQL, one synthetic tenant/user; login path (bcrypt + TOTP verification) and an authenticated GET mix |
| `tools/benchmark_propagation.py` | Policy propagation: publishing a new generation (atomic `current` symlink flip) until the running DNS edge serves the new block verdict |

Smoke tests keep the harness runnable: `control-plane/tests/test_benchmark_smoke.py`
and `dns-edge/tests/test_benchmark_smoke.py` run tiny bounded passes in CI.

## Test environment

- One shared Linux container, 1 CPU, Python 3.10.12.
- Disposable PostgreSQL (pgserver) for the API benchmark; no external
  services of any kind: no Apple/APNs, no devices, no internet DNS, no
  network beyond loopback.

## Measured results (this environment, 2026-11-16)

### DNS verdict path (`--queries 800 --clients 8`)

- Throughput: **7,887 queries/second**, 800/800 correct sinkhole answers, 0 errors.
- Latency: median 0.94 ms, p95 1.58 ms, p99 3.65 ms.

### Control-plane API (`--requests 400 --clients 8`)

- `POST /api/auth/login` (bcrypt + TOTP): median 37.2 ms, p95/p99 38.9 ms, 10/10 ok.
  Login is deliberately CPU-expensive (password hashing) and is rate-limited
  and lockout-protected in the application; it is not a bulk path.
- Authenticated GET mix (`/api/overview`, `/api/policies`, `/api/devices`,
  `/api/groups`, `/api/exceptions`): **287.6 requests/second**, 400/400 ok,
  0 errors; latency median 25.7 ms, p95 37.6 ms, p99 90.3 ms.

### Policy propagation (`--rounds 10`, watch poll 0.1 s)

- Generation flip to new verdict served: median 139 ms, p95 212 ms,
  max 225 ms, 10/10 propagated.

## Answer 23 per-path status

| Update path | Status |
| --- | --- |
| DNS policy publication to running engine | Measured above (median 139 ms in-environment). |
| Category-source activation to categories file | Synchronous with the approval request (tested in `test_category_sources.py`); file sync runs strictly after commit. |
| APNs push delivery | No live APNs integration in this build (no Apple credentials); not measurable here. |
| MDM command queue to device acknowledgment | Commands are queued and attested locally; no real device enrollment is authorized, so device-side timing is not measurable here. |
| PAC/proxy refresh | Documented platform limit (managed Wi-Fi only); not measurable here. |
| Native iOS filter / URL-filter database updates | Blocked on Apple entitlement, signing and hardware (Answer 40); not measurable here. |

The provisional goals in Answer 23 (approximately 30 s for online block
changes, 2 minutes for allow changes) are end-to-end targets across every
segment above. Only the publication-to-engine segment is measurable in this
environment, so no end-to-end claim is made or implied.

## What these numbers do NOT mean

- They are not a production capacity estimate, SLA, or promised
  customer/device count.
- They exclude upstream DNS recursion, TLS/DoH termination, WAN latency,
  database growth, multi-tenant contention, MDM/APNs delivery, and iOS
  device behavior.
- The single-CPU container understates and overstates different things at
  once; numbers are reproducible here via the harness, not transferable
  to any deployment.

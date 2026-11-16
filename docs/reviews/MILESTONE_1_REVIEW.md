# Milestone 1 Review - Foundation

Scope: Stage 11C symlink security fix, dashboard security audit before
reuse, fresh-architecture design (per the owner's November 16, 2026
02:31 EST instruction, verified on the WhatsApp channel at 02:31:32),
requirements coverage tracking, and the control-plane foundation:
FastAPI + SQLAlchemy + Alembic on PostgreSQL, authentication with TOTP
MFA, hashed server-side sessions, roles with multi-guardian tenants,
tenant isolation with negative tests, audit log model, and persisted
rate limiting.

## Actual test results (all executed, none assumed)

| Suite | Result | How run |
| ----- | ------ | ------- |
| filtering-engine | 337 passed in ~70s | `python3 -m pytest tests/ -q` in filtering-engine/ (baseline before the fix was 316; the fix broke nothing) |
| dashboard (reference tree) | 276 passed | `python3 -m pytest tests/` split into batches due to sandbox time limits; 276 collected = 276 passed |
| control-plane | 18 passed | `python3 -m pytest tests/ -q` in control-plane/, against a real bundled PostgreSQL (pgserver + psycopg 3) |
| Alembic migration 0001 | upgrade, downgrade, re-upgrade all clean | run against a fresh bundled PostgreSQL; final table set: tenants, users, auth_sessions, audit_events, login_attempts, alembic_version |

## Changed files

Stage 11C symlink fix:
- filtering-engine/src/generation_io.py
- filtering-engine/src/engine_set.py
- filtering-engine/tests/test_generation_symlink.py (new, 21 tests)

Architecture and coverage:
- docs/FULL_BUILD_ARCHITECTURE.md
- docs/REQUIREMENTS_COVERAGE.md

Control plane (all new):
- control-plane/requirements.txt
- control-plane/app/__init__.py, config.py, security.py, models.py,
  db.py, main.py
- control-plane/alembic.ini, alembic/env.py,
  alembic/versions/0001_initial_schema.py
- control-plane/tests/conftest.py, test_foundation.py, test_api.py
- docs/reviews/MILESTONE_1_REVIEW.md (this file)

## What the symlink fix does

Any symlink in a parent-directory component of a generation path is
rejected outright. The final component may be a symlink only if its
target is a single relative path that stays inside its own parent
directory. Directory fds are pinned after validation and all reads
happen relative to them, with dev+inode identity checks, so a swapped
directory cannot redirect reads after validation. Linux raises ENOTDIR
or ELOOP depending on flags when a symlink is opened with O_NOFOLLOW;
both are detected and distinguished from honest ENOENT.

## Dashboard security audit (gate for reuse)

Reviewed: auth.py, server.py, store.py, db.py, publishing.py. Findings:
PBKDF2-HMAC-SHA256 at 200k iterations, HttpOnly SameSite=Strict cookies
plus a custom CSRF header, login limiting, request body caps and
timeouts, restrictive CSP, static-path traversal rejection, parameterized
SQL throughout (the single f-string SQL interpolates only the hardcoded
DEVICE_STATES constant tuple - verified), atomic publication via
temp+rename with only relative symlinks (compatible with the fixed
loader). Gaps vs the approved design (stdlib server, SQLite, no MFA, no
tenancy) are addressed by building the control plane fresh; the
dashboard is reference only and nothing imports from it.

## Adaptation ledger

| Reused | From | Changes | Gate |
| ------ | ---- | ------- | ---- |
| PBKDF2 parameters and session model | dashboard/src/auth.py | Sessions store only token hashes; TOTP MFA added | test_foundation.py, test_api.py |
| CSRF header + SameSite=Strict cookie pattern | dashboard/src/server.py | Carried into FastAPI dependencies | test_csrf_header_required |
| Login limiting | dashboard/src/auth.py | Persisted in login_attempts (survives restarts) | test_lockout_after_repeated_failures |
| Strict env boolean parsing | dashboard/src/server.py | None | TestConfig tests |
| Generation publication discipline | dashboard/src/publishing.py | Kept compatible with the fixed loader | engine suite |

## Unresolved issues

- None security-critical.

## Remaining work

- M2: control-plane API completion (policies, devices, publication
  triggers), portal, admin dashboard front end, public website tree.
- M3: policy compiler, DNS edge with per-device authenticated identity,
  proxy-PAC, category pipeline with seed dataset and provenance records.
- M4: NanoMDM/NanoDEP evaluation and MDM integration (no production
  Apple credentials, no real-device enrollment in this build).
- M5: iOS Swift sources (labeled uncompiled/unsigned/untested) and
  URL-filter servers.
- M6-M8: operations, full testing, final delivery.
- Publishing these commits to GitHub via the cloud-browser web editor
  with logical commit boundaries preserved (no flattening bulk upload).

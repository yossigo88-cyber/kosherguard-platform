# Stage 10.5: Private Online Staging Dashboard - Review and Evidence

Date: 2026-11-15. Branch: `stage-9b-deployment-preparation` only.
main remains untouched at
`5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a`.

Status: Phases 1-3 complete and verified locally. Phase 4 (Render
deployment) is BLOCKED on the owner's account approval - see "Steps
requiring the owner's approval" below. Phases 5-6 are therefore
partially pending: this document records the architecture, the
committed configuration, and the local security verification, and it
will be updated with live deployment evidence after the deployment
itself is authorized and verified. Stage 10.5 is NOT complete: the
live staging dashboard does not exist yet.

## Phase 1 - What was inspected (actual files, not assumptions)

- `dashboard/src/server.py`: the dashboard is a single-process Python
  web application built ONLY on the standard library
  (`http.server.ThreadingHTTPServer`); no Flask, no third-party
  packages, no requirements.txt. Entry point: `server.py:main()`,
  arguments `--host` (default 127.0.0.1), `--port` (default 8080),
  `--db`, `--publish-dir`.
- Static frontend: plain HTML/CSS/JS served from `dashboard/static/`
  by the same process, with path-traversal protection and a strict
  Content-Security-Policy (`default-src 'self'`, `frame-ancestors
  'none'`). Not a separate static site; one service serves both.
- Database: SQLite (`dashboard/src/db.py`), schema initialized and
  migrated automatically at startup; the data directory is created if
  missing. No external database server exists or is needed.
- Filtering engine: NOT required for the dashboard to run.
  `dashboard/src/engine_bridge.py` imports the engine's Python
  *validation code* from `filtering-engine/src` (same repository, so
  it deploys together), but no DNS engine process runs or is
  contacted. The dashboard itself reports `devices_connected: false`
  and `mdm_operational: false`.
- Environment variables: `KG_ADMIN_PASSWORD` (required to seed the
  first admin; the server REFUSES to start without it when no admin
  exists - no default credentials), `KG_ADMIN_USERNAME` (default
  `admin`), `KG_SECURE_COOKIES`, `KG_TRUSTED_PROXIES`,
  `KG_MAX_CONNECTIONS`, `KG_REQUEST_TIMEOUT`,
  `KG_TOTAL_REQUEST_TIMEOUT`, `KG_PUBLISH_DIR`. Security settings
  refuse ambiguous values at startup instead of falling back to
  insecure defaults.
- Localhost assumptions: the default bind is 127.0.0.1; deployment
  passes `--host 0.0.0.0 --port $PORT`. A non-loopback bind without
  `KG_SECURE_COOKIES=1` is a startup REFUSAL
  (`_require_cookie_safety`), so an internet-facing instance cannot
  accidentally run with insecure cookies.
- Render free-tier suitability: the app is dependency-free Python +
  SQLite on the local filesystem. Render's free web-service tier runs
  it directly. Precise free-tier storage behavior (per
  https://render.com/docs/free, read 2026-11-15): the filesystem is
  ephemeral and ANY local change - including a local SQLite database
  - is lost EVERY time the service redeploys, restarts, OR SPINS
  DOWN, and Render spins a free service down after 15 minutes without
  inbound traffic (spin-up on the next request takes about a minute,
  with a Render loading page shown meanwhile). Render may also
  restart a free service at any time. So in practice the staging
  database resets at least once per idle day. Acceptable for a
  synthetic-data staging dashboard (the admin is re-seeded from
  `KG_ADMIN_PASSWORD` on each boot); documented as a limitation, not
  hidden. Free Render Postgres exists but expires 30 days after
  creation, and the dashboard's storage layer is SQLite-only, so it
  is not used.

## Phase 2 - Staging architecture (committed as `render.yaml`)

- One Render free web service (`plan: free`), runtime `python`,
  deploying branch `stage-9b-deployment-preparation` ONLY, with
  `autoDeploy: true` so new commits to that branch redeploy
  automatically. main is never deployed.
- `buildCommand: "true"` - nothing to build (standard library only).
- `startCommand: python3 dashboard/src/server.py --host 0.0.0.0
  --port $PORT` - binds Render's assigned port.
- `healthCheckPath: /api/health` - the public minimal health check
  (process/database liveness only; reveals no configuration).
- Environment variables (names only; values never committed):
  `PYTHON_VERSION=3.13.7`, `KG_ADMIN_USERNAME=admin`,
  `KG_ADMIN_PASSWORD` (Render-generated random value on first deploy,
  never in the repository), `KG_SECURE_COOKIES=1` (mandatory for the
  non-loopback bind).
- Isolation: staging runs the dashboard alone with synthetic data
  only. No DNS engine, no Apple MDM/APNs, no customer devices, no
  production data. The publishing directory is local to the ephemeral
  container.
- Free-only: no paid plan, no paid disk, no paid database, no custom
  domain. SQLite-in-container was chosen over a free hosted database
  because the dashboard's storage layer is SQLite-only; adding a
  second free service would expose another component for zero staging
  benefit. Its cost is the ephemeral-data limitation above.

## Phase 3 - Authentication and security (verified LIVE locally, 2026-11-15)

Route-by-route reconciliation of "every dashboard page and API
endpoint requires authentication" with the actual code
(`server.py:_dispatch_api`): the ONLY public API routes are
`GET /api/health` (a minimal liveness probe that reveals only
process/database status - required by Render's health check) and
`POST /api/login` itself. Every other API endpoint passes through
`self._admin(conn)`, which rejects requests without a valid session
with 401. The static SPA shell (HTML/CSS/JS) is served without a
session - that shell IS the login page, verified below to carry no
dashboard data: every byte of dashboard data flows through the
authenticated API. There is no public registration route and no
public dashboard page.

Existing implementation (not added in this stage): pbkdf2 password
hashing (`auth.hash_password`), per-account-session tokens in an
HttpOnly + SameSite=Strict cookie (`Secure` added when
`KG_SECURE_COOKIES=1`), CSRF protection via a required
`X-KosherGuard-Request` header on every mutation (combined with
SameSite=Strict), a login rate limiter (5 failures -> 60s lockout),
no registration endpoint, no default credentials (startup refusal
without `KG_ADMIN_PASSWORD`), request body size caps, per-request and
total request timeouts, connection limits, and a strict CSP. Sessions
are server-side SQLite rows; logout destroys the session row.

Ran the real server locally
(`KG_ADMIN_PASSWORD=staging-test-password-123 python3
dashboard/src/server.py --host 127.0.0.1 --port 8091 ...`) and tested
from unauthenticated and authenticated curl sessions:

| # | Check | Result |
|---|-------|--------|
| 1 | GET / unauthenticated | 200, serves the login UI shell only - no dashboard data in it |
| 2 | GET /api/config/status unauthenticated | 401 "not signed in" |
| 3 | POST /api/login, wrong password | 401 |
| 4 | POST /api/login, correct password | 200 + `kg_session` cookie, HttpOnly + SameSite=Strict |
| 5 | Authenticated GET /api/config/status | 200 |
| 6 | Authenticated POST without the CSRF header | 403 |
| 7 | POST /api/logout | 200, session destroyed |
| 8 | Old session cookie after logout | 401 (logout really invalidates) |
| 9 | 6th consecutive wrong password | 429 (rate limiter active after 5) |
| 10 | GET /api/health | 200 `{"status": "ok"}`, no sensitive data |
| 11 | Path traversal `--path-as-is /../filtering-engine/...` | 404 |

Test-iteration notes (honest): POST /api/logout requires a JSON body;
`{}` succeeds while a bodyless POST is rejected 411/400 by the
request-body rules. The first local logout attempts used a bodyless
POST and were rejected before reaching the handler; retested with a
JSON body and logout + invalidation verified. This matches the API's
documented mutation rules; no code change was needed.

Full automated suites re-run on the final tree of this stage:
`python3 -m pytest filtering-engine/tests -q` -> 146 passed in
57.87s; `python3 -m pytest dashboard/tests -q` -> 165 passed in
104.72s. Both first runs, no failures (the suites cover the same
auth, CSRF, cookie, and rate-limit behaviors in-process).

## Phase 4 - Deployment: BLOCKED on owner approval

Render deployment requires the owner's own accounts and
authorizations. Per instructions, nothing was purchased, no account
was created, and no GitHub authorization was requested. Exact steps
that need the owner:

1. Sign in to https://render.com (GitHub sign-in is fine) - or create
   the free account.
2. Authorize the Render GitHub App to access the
   `yossigo88-cyber/kosherguard-platform` repository (Render prompts
   for this when connecting the repo). This is a NEW GitHub
   authorization only the owner can approve.
3. Create a new Blueprint instance: Dashboard -> New -> Blueprint,
   select the repository. Render reads `render.yaml` and creates the
   single free web service on branch
   `stage-9b-deployment-preparation` with auto-deploy enabled.
4. After the first deploy, open the service's Environment tab to view
   the Render-generated `KG_ADMIN_PASSWORD` (or replace it with a
   password of your choice, min 12 characters).

Alternative if the owner prefers not to grant Render GitHub access:
say so and this stage stays stopped; there is no free way to deploy
from a private workflow without connecting the repository.

## Phase 5 - Live verification (PENDING deployment)

The full checklist (URL loads, login page, unauthenticated rejection
from an unauthenticated session, valid sign-in, logout, navigation,
no secrets in responses/logs/repo, deployed commit matches the
branch HEAD, and a follow-up commit triggering auto-deploy) will be
run against the live URL and recorded here after deployment. The
dashboard will NOT be called private until unauthenticated rejection
is verified against the live URL.

## Phase 6 - Evidence

- Configuration committed: `render.yaml` (repo root, feature branch).
- This report: `docs/reviews/STAGE_10_5_STAGING_REVIEW.md`.
- Staging URL: pending deployment (Render assigns
  `<service>.onrender.com`).
- Deployed commit SHA: pending deployment.

## Known limitations

- Free-tier sleep: the service spins down after 15 minutes without
  traffic; the next request waits about a minute while Render shows
  its spin-up page.
- Ephemeral storage (verified against
  https://render.com/docs/free on 2026-11-15): local filesystem
  changes - including the SQLite database with policies, sessions and
  the audit log - are lost on EVERY redeploy, restart, or spin-down,
  and Render may restart a free service at any time. The admin
  account is re-seeded from `KG_ADMIN_PASSWORD` on each boot. Fine
  for synthetic staging data; NOT suitable for production.
- Legacy no-manifest engine loading is unavailable on platforms
  without O_NOFOLLOW (Stage 10, section 19); irrelevant to the
  dashboard-only staging service but recorded for completeness.

## Confirmations

- main remains untouched at
  `5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a`.
- No merge, no production deploy, no customer devices, no MDM/APNs,
  no Stage 11 work.
- No paid service was used or activated; no money was spent.
- No new GitHub permissions were requested by the agent.
- No functionality was removed.
- Stage 10.5 is NOT complete: deployment awaits the owner's approval
  above, and live security verification follows it.

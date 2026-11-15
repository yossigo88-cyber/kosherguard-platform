# KosherGuard Admin Dashboard (Stage 7, hardened in Stage 9A)

A development-stage admin interface for managing KosherGuard filtering
policies, categories, and domain records. It is a real, working
application: a Python backend API with persistent storage, session
authentication, and audit logging, plus a browser interface served by
the same process.

**This dashboard does not manage iPhones.** No devices are enrolled, no
Apple MDM connection exists, no remote policy push is available, and no
iPhone filtering is controlled here. Those capabilities require Apple
MDM authorization that does not exist; see
[../docs/MDM_ENROLLMENT_AND_PUSH.md](../docs/MDM_ENROLLMENT_AND_PUSH.md).

## Architecture

```
dashboard/
  src/
    engine_bridge.py  - imports the Stage 3 filtering engine (policy
                        validation, evaluation, domain/category syntax)
    util.py           - small shared helpers
    db.py             - SQLite schema + seed categories
    auth.py           - PBKDF2 password hashing, sessions, login limiter
    store.py          - validated policy/category/domain/audit operations,
                        policy versioning, publication, rollback
    publishing.py     - atomic generation-based engine configuration publication
    server.py         - stdlib HTTP server: JSON API + static files
  static/
    index.html        - interface shell (login view + app shell)
    styles.css        - design system
    app.js            - interface logic (vanilla JS, hash routing)
  tests/              - 157 pytest tests against a real running server
```

Technology choices, per the Stage 7 requirement to fit the existing
project without paid services: Python standard library only
(`http.server`, `sqlite3`, `hashlib`, `secrets`), no new dependencies,
no external services, no build step. The interface is hand-written
HTML/CSS/JS.

## Filtering-engine integration

Policy evaluation is performed by the Stage 3 `PolicyEngine` itself,
imported through `engine_bridge.py` - no decision logic is duplicated.
The dashboard converts a stored policy (default behavior, allowed and
blocked domains, allowed and blocked categories) into the engine's
policy structure and calls `PolicyEngine.decide()`. Domain and category
syntax validation is the engine's own (`validate_domain`,
`validate_category`), and the import path runs through the engine's
`CategoryDB.merge_records`, preserving its validated, all-or-nothing
import semantics.

Rule precedence (documented and enforced by the engine, shown in the
interface):

1. Explicit allowlist match - ALLOW
2. Explicit blocklist match - BLOCK
3. Category block rule - BLOCK
4. Category allow rule - ALLOW
5. Default policy - allow/block

A listed domain covers its subdomains. An explicit allow rule overrides
a category block rule; a blocked category overrides an allowed category.

Two stored flags are administrative state, honestly labeled as such:

- **Policy enabled/disabled**: shown and filterable; no policy is
  applied to live traffic from this dashboard, so the flag governs
  nothing operational yet.
- **Category enabled/disabled**: disabled categories are excluded from
  the category data used by the domain-test evaluator, so the flag has
  real, visible effect in simulation.

A domain record's **explicit allow/block rule** is stored administrative
intent only. It does not change any engine decision; to enforce it, add
the domain to a policy's allow or block list. The domain-test result
shows the record next to the engine's decision so the difference is
always visible.

## Security model

- The first administrator is seeded from the `KG_ADMIN_PASSWORD`
  environment variable (username `KG_ADMIN_USERNAME`, default `admin`).
  The server refuses to start with no password when no admin exists.
  Passwords are stored as PBKDF2-HMAC-SHA256 hashes (200,000 iterations,
  random salt) and compared with `secrets.compare_digest` equivalent
  (`hmac.compare_digest`). No secret appears in source, responses, or
  static files.
- Passwords must be at least 12 characters (first-admin seeding and
  password changes). Existing shorter passwords keep working; update
  one via Settings - the minimum applies only when a password is set.
- Sessions are 256-bit random tokens stored server-side with a 12-hour
  expiry, delivered in an `HttpOnly; SameSite=Strict` cookie. With
  `KG_SECURE_COOKIES=1` (required for HTTPS production) the cookie also
  gets the `Secure` attribute, on both creation and clearing. Localhost
  development may omit the setting; a deployment-shaped configuration
  (any `KG_TRUSTED_PROXIES` entry, or a non-loopback bind address)
  refuses to start unless `KG_SECURE_COOKIES=1` is set explicitly, so
  the Secure attribute can never be forgotten on a real deployment.
- Every `/api/*` endpoint except `/api/login` and `/api/health`
  requires a valid session.
- Every state-changing request requires the `X-KosherGuard-Request`
  header; with the SameSite=Strict cookie this defeats CSRF.
- Failed logins are limited: 5 failures for a username+address lock
  further attempts for 60 seconds. Behind a reverse proxy the real
  client address is taken from `X-Forwarded-For` only when the
  immediate peer is listed in `KG_TRUSTED_PROXIES` (see below), so a
  forged header cannot steer or bypass the limiter, and one attacker's
  lockout never applies to other clients.
- Failed login attempts are recorded in the audit log
  (`auth.login_failed`) with the attempted username (truncated to 64
  characters) and a generic detail; passwords and tokens are never
  recorded, and an audit failure never changes the login response.
- Request bodies are capped at 1 MB. The `Content-Length` header must
  be a plain non-negative decimal integer: malformed or negative values
  are rejected (400) before any body byte is read, oversized values are
  rejected (413), and in all of these cases (and when the header is
  missing) the connection is closed, so unread bytes cannot be parsed
  as the next request on it. All errors are JSON `{"error": ...}`;
  internals are never returned.
- Concurrent request handling is bounded (`KG_MAX_CONNECTIONS`, default
  32; excess connections are refused, not queued). Every connection has
  a per-read inactivity timeout (`KG_REQUEST_TIMEOUT`, default 30
  seconds) AND a total deadline for receiving one complete request
  (`KG_TOTAL_REQUEST_TIMEOUT`, default 60 seconds), so a slow-trickle
  client that sends one byte before each inactivity timeout expires
  still cannot hold a handler slot forever. The total deadline bounds
  receiving only; producing and sending the response is covered by the
  per-read timeout.
- Static files are served only from `static/`; path traversal is
  rejected, and the HTML carries a restrictive Content-Security-Policy
  (`default-src 'self'`), `X-Frame-Options: DENY`, and
  `X-Content-Type-Options: nosniff`.
- Every administrative mutation writes an audit record (admin, action,
  detail, UTC time), visible under Activity Logs.
- Expired sessions are rejected on use (and deleted then); remaining
  expired rows are removed at server startup. There is deliberately no
  background cleanup thread, so shutdown stays simple and clean.
- The DNS filtering service is not exposed by this server at all.

### Configuration (environment variables)

| Variable | Default | Meaning |
| --- | --- | --- |
| `KG_ADMIN_PASSWORD` | (required on first run) | Seeds the first administrator. |
| `KG_ADMIN_USERNAME` | `admin` | First administrator's username. |
| `KG_SECURE_COOKIES` | off | `1` adds the `Secure` attribute to session cookies. Set this ONLY when the dashboard is served over HTTPS (browsers drop Secure cookies over plain HTTP). Any value other than `1/0/true/false/yes/no` refuses startup - a typo can never silently weaken a production deployment. Deployment guard: with trusted proxies configured or a non-loopback bind address, startup is refused unless this is explicitly `1`. |
| `KG_TRUSTED_PROXIES` | (empty) | Comma-separated IP addresses of trusted reverse proxies. Only requests arriving from these peers may supply the client address via `X-Forwarded-For`; the last entry of the header is used and must parse as an IP address, otherwise the socket peer is used. With no trusted proxies the header is always ignored. |
| `KG_MAX_CONNECTIONS` | `32` | Maximum concurrent requests; extra connections are refused. |
| `KG_REQUEST_TIMEOUT` | `30` | Per-read inactivity timeout in seconds (also bounds idle keep-alive). |
| `KG_TOTAL_REQUEST_TIMEOUT` | `60` | Total seconds one complete request (headers + body) may take to arrive; defeats slow-trickle clients that keep each individual read under the inactivity timeout. Must be at least `KG_REQUEST_TIMEOUT`. |

Required proxy configuration: the proxy must terminate TLS, forward to
the dashboard bound on `127.0.0.1`, and set/append `X-Forwarded-For`
(Caddy's `reverse_proxy 127.0.0.1:8080` does this by default). Then set
`KG_TRUSTED_PROXIES` to the proxy's address (usually `127.0.0.1`) and
`KG_SECURE_COOKIES=1`.

### Health endpoint

`GET /api/health` is public and deliberately minimal: `200`
`{"status": "ok"}` when the process responds and the database answers a
real query, `503 {"status": "unavailable"}` otherwise. It reveals no
usernames, paths, configuration, or error details. It is public so an
unauthenticated uptime check can use it; it exposes nothing beyond
up/down.

## Running (development)

```bash
cd dashboard
KG_ADMIN_PASSWORD='choose-a-strong-password' \
  python3 src/server.py --host 127.0.0.1 --port 8080 --db data/dashboard.db
```

Then open http://127.0.0.1:8080 and sign in. The database file and
schema are created on first run, with the starting category catalogue
(11 categories, zero domains - a starting catalogue, not a complete
URL database).

## Publication API (Stage 10)

- `GET /api/config/status` - selected policy, active published revision,
  unpublished-changes flag, on-disk generation, and the engine's
  self-reported status (when the engine shares the publication directory).
- `POST /api/policies/<id>/select` - designate the policy to publish.
  The selected policy cannot be disabled or deleted until another is
  selected.
- `POST /api/config/publish` - validate and atomically publish the
  selected policy plus current domains/categories as a new immutable
  configuration generation (audited).
- `POST /api/config/rollback {"revision": N}` - republish a previous
  revision's complete content as a new revision (audited).
- `GET /api/config/revisions[/<n>]` - published configuration history,
  with content hashes and the exact stored JSON.
- `GET /api/policies/<id>/versions[/<n>]` - immutable per-policy version
  history; `POST /api/policies/<id>/rollback {"version": n}` rolls the
  draft back to a prior version by creating a new version.

## Testing

```bash
cd dashboard && python3 -m pytest tests/ -q
```

157 tests run the real server on an ephemeral localhost port with a
throwaway database: policy CRUD and validation, rule precedence and
conflicts, category management, domain validation and duplicates, the
import process (including atomic abort and line-numbered errors),
authentication and lockout, persistence across restarts, audit logging,
security behavior (CSRF, body limits, traversal, injection strings,
header checks), and the Stage 9A hardening (secure-cookie modes and
strict configuration parsing, proxy-aware login limiting including
spoofed and malformed forwarding headers, the 12-character password
minimum, failed-login auditing without secrets, expired-session
rejection and cleanup, health endpoint, connection bounds with
header timeouts, strict Content-Length validation (negative, malformed,
and oversized values, with connection-close behavior), the total
request deadline (slow-trickle clients in both the header and body
phases, killed and their slot released), and the cookie deployment
guard (localhost default, explicit deployment opt-in, refusal cases),
and the deployment scripts: `deploy/backup.sh` and `deploy/restore.sh`
run as real subprocesses - a full round trip (back up a live server,
mutate, restore, restart, and verify every kind of data through the
API), corrupt-backup refusal, overwrite refusal, the required
--service-stopped restore confirmation (refusal leaves the database
byte-for-byte unchanged), restore temporary-file cleanup on success
and on failure, failed-backup cleanup (no partial file is left looking
like a valid backup), genuinely concurrent backup processes (collision-
safe unique publication, nothing overwritten, every backup integrity-
checked), rotation including invalid-KEEP refusal, and file/directory
permission checks (backup dir 0700, backup files and restored database
0600), missing files, and valid rotation. No sleeps are used for synchronization; the server socket is
bound before the test client connects.

## Deployment (prepared, not done)

Nothing here is deployed. Stage 9B prepared the deployment assets:

- `docs/deployment/RUNBOOK.md` - prerequisites and step-by-step
  instructions for a single small server: the dashboard bound to
  `127.0.0.1:8080`, Caddy terminating HTTPS in front of it.
- `docs/deployment/PRELAUNCH_CHECKLIST.md` - security, configuration,
  backups, and operational readiness checks before going live.
- `deploy/Caddyfile.example` - reverse-proxy configuration matching
  `KG_TRUSTED_PROXIES` and `KG_SECURE_COOKIES=1` (the server refuses to
  start in this shape without it).
- `deploy/kosherguard-dashboard.service` - systemd unit (auto-restart,
  unprivileged user, sandboxing directives). Reviewed but NOT yet
  tested on a live system.
- `deploy/backup.sh` / `deploy/restore.sh` - consistent online SQLite
  backups written to a temporary file and published atomically without
  overwrite (hard-link publication with collision retry) only after an
  integrity check, validated rotation, and a verified atomic restore
  that requires an explicit --service-stopped confirmation and always
  cleans up its temporary file. Backup
  directories and files and restored databases are forced private
  (0700/0600); the systemd unit sets UMask=0077 and
  StateDirectoryMode=0700. Both scripts are exercised by automated
  tests, including failure cases, but have NOT run on a production
  server.

This is preparation, not a production-ready deployment: the unit,
proxy config, and backup schedule still need to be verified on a real
server against the checklist. The standard-library server must never
face the internet directly; keep it behind the proxy. The connection
bounds above reduce abuse impact; they do not replace a proxy.

## Known limitations

- Single-admin model (the schema supports more, but there is no user
  management interface yet), with no self-service password recovery: a
  lost password means editing the database directly.
- Backup and restore scripts exist (`deploy/backup.sh` and
  `deploy/restore.sh`; see `docs/deployment/RUNBOOK.md`), but
  automatic scheduling and off-site backup storage are not configured
  automatically - the operator sets those up (the runbook says how).
  Until then the single SQLite file remains a single point of
  failure.
- No device synchronization of any kind (requires Apple MDM
  authorization, which does not exist).
- The interface is English-only, desktop and mobile responsive.

# KosherGuard Admin Dashboard (Stage 7)

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
    store.py          - validated policy/category/domain/audit operations
    server.py         - stdlib HTTP server: JSON API + static files
  static/
    index.html        - interface shell (login view + app shell)
    styles.css        - design system
    app.js            - interface logic (vanilla JS, hash routing)
  tests/              - 84 pytest tests against a real running server
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
- Sessions are 256-bit random tokens stored server-side with a 12-hour
  expiry, delivered in an `HttpOnly; SameSite=Strict` cookie.
- Every `/api/*` endpoint except `/api/login` requires a valid session.
- Every state-changing request requires the `X-KosherGuard-Request`
  header; with the SameSite=Strict cookie this defeats CSRF.
- Failed logins are limited: 5 failures for a username+address lock
  further attempts for 60 seconds.
- Request bodies are capped at 1 MB (checked from Content-Length before
  reading). All errors are JSON `{"error": ...}`; internals are never
  returned.
- Static files are served only from `static/`; path traversal is
  rejected, and the HTML carries a restrictive Content-Security-Policy
  (`default-src 'self'`), `X-Frame-Options: DENY`, and
  `X-Content-Type-Options: nosniff`.
- Every administrative mutation writes an audit record (admin, action,
  detail, UTC time), visible under Activity Logs.
- The DNS filtering service is not exposed by this server at all.

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

## Testing

```bash
cd dashboard && python3 -m pytest tests/ -q
```

84 tests run the real server on an ephemeral localhost port with a
throwaway database: policy CRUD and validation, rule precedence and
conflicts, category management, domain validation and duplicates, the
import process (including atomic abort and line-numbered errors),
authentication and lockout, persistence across restarts, audit logging,
and security behavior (CSRF, body limits, traversal, injection strings,
header checks). No sleeps are used for synchronization; the server
socket is bound before the test client connects.

## Deployment (future, not done)

Nothing here is deployed. When the project is ready, a free deployment
path is any always-free tier that runs Python (for example a free VM or
container tier) behind its TLS termination; the app needs only
`python3` and write access to its database file. Before any real
deployment: put the server behind HTTPS (and add the `Secure` flag to
the session cookie), set a strong `KG_ADMIN_PASSWORD`, and keep the
bind address private until TLS exists.

## Known limitations

- Single-admin model (the schema supports more, but there is no user
  management interface yet).
- No device synchronization of any kind (requires Apple MDM
  authorization, which does not exist).
- The interface is English-only, desktop and mobile responsive.
- Session storage is the same SQLite file; a very busy deployment would
  want periodic cleanup of expired sessions.

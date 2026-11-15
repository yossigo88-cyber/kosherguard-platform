# Stage 10.5: Private Online Staging Dashboard - Review and Evidence

Date: 2026-11-15 (updated 2026-11-15 ~19:15 UTC after live Oracle
deployment). Branch: `stage-9b-deployment-preparation` only.
main remains untouched at
`5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a` (re-verified via the
GitHub API on 2026-11-15 ~19:05 UTC).

Status: DEPLOYED AND VERIFIED LIVE. The staging dashboard runs on a
dedicated Oracle Cloud Infrastructure (OCI) Always Free VM at
https://129-158-203-53.sslip.io/ - completely separate from the
production KosherGuard server, its network, its DNS, and the paid
hosting. The earlier Render plan (below) was superseded by the
owner's decision on 2026-11-15: deploy on a separate free Oracle
server, "nothing to do with my original kosher guard". No Render
service was ever created; `render.yaml` remains in the repo as an
unused alternative blueprint only.

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
- Loopback bind + fail-closed cookie safety: a non-loopback bind
  without `KG_SECURE_COOKIES=1` is a startup REFUSAL
  (`_require_cookie_safety`), so an internet-facing instance cannot
  accidentally run with insecure cookies. The Oracle deployment binds
  the app to 127.0.0.1:8080 behind a TLS-terminating reverse proxy
  and declares the proxy in `KG_TRUSTED_PROXIES`.

## Phase 2 - Actual staging architecture (Oracle Cloud, deployed 2026-11-15)

- Compute instance `kosherguard-platform-staging`, region us-ashburn-1,
  AD-1 (OCID
  `ocid1.instance.oc1.iad.anuwcljtlu6l33icvr73t2nhfbl7ctozhpvinfhojkukkfjv54m4ognncsda`):
  - Shape `VM.Standard.E2.1.Micro` (marked "Always Free-eligible" in
    the console), 1 OCPU / 1 GB RAM.
  - Image Canonical Ubuntu 22.04 Minimal (x86_64), build 2026.11.05-0.
  - Boot volume 46.6 GB (block storage, persistent across restarts).
  - Ephemeral public IPv4 129.158.203.53 (no charge). Ephemeral IPs
    survive reboots but a stop/start cycle can assign a new IP, which
    would change the sslip.io hostname below.
- Networking: NEW dedicated VCN `vcn-20261115-1351` (10.0.0.0/16) with
  its own subnet `subnet-20261115-1351` (10.0.0.0/24) and its own
  default security list. Added ingress rules: TCP 80 and TCP 443 from
  0.0.0.0/0 (verified in the console after creation). The original
  production VM's VCN and security lists were never modified.
- OS firewall (Ubuntu iptables): ACCEPT tcp 80 and 443, persisted in
  `/etc/iptables/rules.v4`; all other inbound rules unchanged
  (default image policy: SSH + established only).
- Application service: systemd unit `kg-dashboard.service` running
  `python3 dashboard/src/server.py --host 127.0.0.1 --port 8080` as
  the unprivileged `ubuntu` user (never root), `Restart=always`,
  `NoNewPrivileges=true`, environment from `/etc/kg-dashboard.env`
  (mode 600, owner ubuntu): `KG_ADMIN_USERNAME`, `KG_ADMIN_PASSWORD`
  (generated locally, stored only in the user's vault - never
  committed, never sent in chat), `KG_SECURE_COOKIES=true`,
  `KG_TRUSTED_PROXIES=127.0.0.1`. Unit is enabled (starts on boot).
- TLS edge: Caddy v2.11.9 (official Caddy apt repository), enabled
  and active, terminating HTTPS for `129-158-203-53.sslip.io` with an
  automatically managed Let's Encrypt certificate (issued 2026-11-15,
  expires 2027-02-13; Caddy renews automatically) and
  reverse-proxying to 127.0.0.1:8080. Port 80 answers only with a
  308 redirect to HTTPS (verified).
- Deployed code: cloned from GitHub on the server with
  `git clone --depth 1 --branch stage-9b-deployment-preparation`,
  deployed commit
  `02e8ecb54018cacb683a60107fca8b1e3a8dd0fb`
  ("Stage 10.5: precise free-tier storage behavior (Render docs) and
  public-route reconciliation") - the branch HEAD at deploy time.
  The working tree is clean (`git status` empty, verified 19:08 UTC).
  NOTE: this review document is itself committed to the branch after
  deployment, so the branch HEAD after that commit is a DOCS-ONLY
  descendant; the running code on the server remains exactly the
  deployed SHA above.
- Automatic GitHub deployments: NOT configured. There is no webhook,
  polling job, CI workflow, or any other mechanism deploying new
  commits to this server; updating is a manual, deliberate operation
  (git fetch/reset on the server by an operator). (Render's
  `autoDeploy: true` in `render.yaml` has no effect: no Render
  service was ever created from the blueprint.)
- Isolation: the staging VM runs the dashboard alone with
  synthetic/local data only. No DNS engine, no Apple MDM/APNs, no
  customer devices, no production data, no connection of any kind to
  the production KosherGuard server or the paid website.

## Always Free / $0 verification

- Tenancy limits read in the owner's OCI console (us-ashburn-1,
  read-only, 2026-11-15 ~18:39 UTC, before launch):
  - "Cores for Standard.E2.1.Micro VM Instances": limit 2, used 1,
    available 1.
  - "Free Tier Volume Quota (GB) in the Region": limit 200, used 47,
    available 153.
- Post-launch usage (computed from the console-verified pre-launch
  figures plus the resources actually created at ~18:51 UTC; not a
  second live console read):
  - Micro cores: 2 used of 2 (existing VM 1 + new VM 1) - at, not
    over, the limit.
  - Block storage: ~93.6 GB used of 200 (existing 47 + new 46.6).
- The "$2.00/month" figure shown on the create panel was the
  list-price estimator, labeled by Oracle "does not reflect any tier
  unit pricing"; the boot volume is covered by the 200 GB Free Tier
  volume quota.
- No paid options were selected, no billing upgrade, no card, no
  payment of any kind. The account remains on Free Trial; all created
  resources are Always Free-eligible, so they remain $0 after any
  trial transition as well. Ephemeral public IP carries no charge;
  outbound egress within the free allowance.
- Uptime honesty: Oracle may reclaim idle Always Free compute, so
  "always on" is not guaranteed; no sleep/spin-down mechanism like
  Render's exists, and the service is enabled to start on boot.

## Phase 3 - Authentication and security (verified LIVE locally, 2026-11-15)

Route-by-route reconciliation of "every dashboard page and API
endpoint requires authentication" with the actual code
(`server.py:_dispatch_api`): the ONLY public API routes are
`GET /api/health` (a minimal liveness probe that reveals only
process/database status) and `POST /api/login` itself. Every other
API endpoint passes through `self._admin(conn)`, which rejects
requests without a valid session with 401. The static SPA shell
(HTML/CSS/JS) is served without a session - that shell IS the login
page, verified below to carry no dashboard data: every byte of
dashboard data flows through the authenticated API. There is no
public registration route and no public dashboard page.

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

Local verification (before deployment): the real server was run
locally and exercised from unauthenticated and authenticated curl
sessions (login, logout, CSRF rejection, rate limiting, path
traversal, health probe; 11 checks). Full automated suites re-run on
the final tree of this stage: `python3 -m pytest
filtering-engine/tests -q` -> 146 passed in 57.87s; `python3 -m
pytest dashboard/tests -q` -> 165 passed in 104.72s. Both first runs,
no failures.

## Phase 4 - Live deployment and verification (Oracle, 2026-11-15 ~19:00-19:10 UTC)

All checks below ran against the real public URL
https://129-158-203-53.sslip.io/ (or the server's loopback where
noted), after deployment, with the deployed commit
`02e8ecb54018cacb683a60107fca8b1e3a8dd0fb`:

| # | Check | Result |
|---|-------|--------|
| 1 | HTTPS certificate | Valid Let's Encrypt (issuer YE1), CN 129-158-203-53.sslip.io, 2026-11-15 to 2027-02-13 |
| 2 | GET /api/health over HTTPS | 200 `{"status": "ok"}` |
| 3 | Plain HTTP port 80 | 308 redirect to HTTPS only |
| 4 | App port 8080 from the internet | Unreachable (loopback bind; connection refused/timeout) |
| 5 | GET / unauthenticated | 200 login UI shell only - no dashboard data |
| 6 | GET /api/overview unauthenticated | 401 "not signed in" |
| 7 | POST /api/login without X-KosherGuard-Request | 403 (CSRF header enforced) |
| 8 | POST /api/login wrong password | 401 generic message |
| 9 | 6 consecutive wrong passwords | 5 x 401 then 429 (60s lockout) |
| 10 | POST /api/login correct credentials | 200 + cookie `HttpOnly; Secure; SameSite=Strict; Max-Age=43200` |
| 11 | Authenticated GET /api/me | 200 `{"username": "admin"}` |
| 12 | Session across `systemctl restart kg-dashboard` | Pre-restart session still 200 (SQLite persistence) |
| 13 | POST /api/logout (JSON body) | 200; same cookie then = 401 "invalid session" |
| 14 | Synthetic policy create -> restart -> read | 201 created, survived restart (200, fields intact), then deleted 200; overview confirmed `policies: 0` |
| 15 | UI desktop (1920px) and mobile (390px) | Both render correctly; real form sign-in performed through the browser (screenshots captured) |
| 16 | Live admin audit trail | `audit_log` records real UI actions (category enable/disable by `admin`, 19:07 UTC) - authenticated writes + auditing work end to end |
| 17 | Listener inventory (`ss -tlnp`) | 22 sshd, 80/443 caddy, 8080 python on 127.0.0.1 only |
| 18 | Services enabled on boot | kg-dashboard and caddy both enabled + active |
| 19 | Database file persists | `dashboard/data/dashboard.db` on the boot volume; service restarts and policy test above confirm durability |
| 20 | Deployed SHA = branch SHA at deploy time | `02e8ecb54018cacb683a60107fca8b1e3a8dd0fb`, clean tree |

Test-iteration note (honest): DELETE /api/policies/<id> and
POST /api/logout require a JSON body (`{}`); a bodyless request is
rejected 411/400 before the handler. First attempts used a bodyless
request and were retried correctly. No code change was needed.

The original paid KosherGuard production website, its server
(129.213.65.159), its VCN, its DNS records at Porkbun, and all of its
data were inspected read-only at most and are completely untouched by
this deployment.

## Phase 5 - Evidence

- Staging URL: https://129-158-203-53.sslip.io/ (admin username
  `admin`; password stored only in the user's vault, generated
  locally for this deployment).
- Instance OCID:
  `ocid1.instance.oc1.iad.anuwcljtlu6l33icvr73t2nhfbl7ctozhpvinfhojkukkfjv54m4ognncsda`;
  security list OCID:
  `ocid1.securitylist.oc1.iad.aaaaaaaaxa2xzdstvsi5jj5ptzmapbdnfhojkxfake4kexdtueaazxg42nja`.
- Deployed commit SHA:
  `02e8ecb54018cacb683a60107fca8b1e3a8dd0fb` (branch
  `stage-9b-deployment-preparation`; the branch HEAD after this
  review commit is a docs-only descendant - no deployed-code change).
- main: `5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a` (untouched).
- This report: `docs/reviews/STAGE_10_5_STAGING_REVIEW.md`.

## Known limitations

- Automatic GitHub deployments are NOT configured (deliberate, per
  owner instruction 2026-11-15): new commits do not reach the server
  without a manual operator update.
- The public IP is ephemeral: a stop/start cycle could change it and
  therefore the sslip.io hostname. Reserving a static IP (also free)
  or using a controlled subdomain are future options.
- sslip.io is a shared wildcard-DNS service: the hostname encodes the
  IP and shares the sslip.io suffix with unrelated sites. Cookies are
  scoped to the exact hostname and are Secure + SameSite=Strict; the
  stored vault login is scoped to the sslip.io domain.
- The dashboard self-labels "Development environment"; it manages
  policies, categories and domain records only - no MDM enrollment,
  push notifications, or device management exist.
- Oracle may reclaim Always Free compute it considers idle; long-term
  guaranteed uptime is not claimed.
- Legacy no-manifest engine loading is unavailable on platforms
  without O_NOFOLLOW (Stage 10, section 19); irrelevant to the
  dashboard-only staging service but recorded for completeness.

## Confirmations

- Deployed on a separate free Oracle server, nothing to do with the
  original paid KosherGuard site - which remains completely
  untouched (item 6 verified).
- Oracle instance configuration recorded above and verified within
  the Always Free allowance (no charge possible on the selected
  shape/storage/IP; no billing change made).
- Persistent storage (SQLite on the boot volume), firewall (VCN
  security list + iptables), HTTPS (valid Let's Encrypt certificate,
  HTTP only redirects), and administrator authentication
  (vault-stored generated password, pbkdf2, rate limiting, CSRF,
  Secure+SameSite=Strict+HttpOnly sessions) all confirmed live.
- Unauthenticated visitors cannot access dashboard data or APIs
  (checks 5, 6, 7, 8 above; only the login shell and the minimal
  health probe are public).
- Deployed Git commit confirmed:
  `02e8ecb54018cacb683a60107fca8b1e3a8dd0fb` on the intended feature
  branch `stage-9b-deployment-preparation`.
- Automatic GitHub deployments are documented as NOT configured.
- This report was committed to the feature branch only.
- main remains untouched at
  `5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a`; no merge, no production
  deploy, no customer devices, no MDM/APNs, no Stage 11 work, no paid
  service used or activated, no money spent, no functionality
  removed.

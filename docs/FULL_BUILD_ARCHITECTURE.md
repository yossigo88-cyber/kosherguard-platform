# KosherGuard Full-Platform Architecture

Status: Milestone 1 design document. Defines the fresh, clean architecture
the full platform is built on, per the owner's November 16, 2026 02:31 EST
instruction to build from a fresh architecture rather than extending the old
project as-is. Reuse is selective: only what survives security and quality
review is adapted, never blindly copied. The existing filtering-engine and
dashboard trees are reference material; the old branches and history are
preserved untouched.

## 1. Goals and constraints

- One monorepo (`kosherguard-platform`) holding every component with clear
  top-level boundaries and explicit interfaces between them.
- Approved stack defaults: FastAPI + SQLAlchemy + Alembic on PostgreSQL for
  the control plane; no invented cryptography anywhere.
- The family is the tenant. Multiple guardians per tenant, role-based
  access, strict tenant isolation with negative tests.
- Authentication: hashed server-side sessions plus TOTP MFA. No long-lived
  bearer tokens in DoH URLs; per-device DNS identity uses client
  certificates or protected scoped credentials, redacted from logs.
- iOS 26 is the client target. Swift sources are written in this build but
  delivered labeled uncompiled, unsigned and untested.
- MDM/ADE uses NanoMDM/NanoDEP (evaluation first); no production Apple
  credentials, no customer-device enrollment or destructive MDM commands in
  this build.
- Code build only: no production deployment, no DNS changes, no live infra
  changes, no purchases.

## 2. Repository layout (new top-level trees)

```
control-plane/        FastAPI service: API, auth, tenancy, audit, policy
                      management, device registry, publication pipeline
control-plane/web/    Admin dashboard (new front end)
portal/               Family/guardian self-service portal
website/              Public marketing/docs site (separate from dashboard)
filtering-engine/     ADAPTED from the old tree after review (see 4)
dns-edge/             DoH/DoT endpoints, per-device identity, rate limits
proxy-pac/            PAC generation and proxy fallback service
policy-compiler/      Tenant policy -> engine bundle compiler and validator
category-pipeline/    Category dataset ingestion, provenance, updates
url-filter-server/    Server-side URL filtering (PIR / Privacy Pass / OHTTP)
mdm/                  MDM integration (NanoMDM/NanoDEP evaluation), commands
ios/                  Native iOS app (Swift, uncompiled/unsigned/untested)
ops/                  Observability, backup/restore, runbooks, CI config
docs/                 Architecture, requirements coverage, review reports
deploy/               Preserved from the old tree (not modified here)
```

The old `dashboard/` tree is left in place as reference and is superseded
by `control-plane/` + `portal/`. Nothing in the new trees imports from
`dashboard/`; shared concepts are re-implemented or adapted with review
notes in the milestone review reports.

## 3. Control plane design (Milestone 1 foundation)

- FastAPI application with an async request pipeline, structured JSON
  errors, and OpenAPI schema served from the app.
- SQLAlchemy 2.x models with Alembic migrations. PostgreSQL is the target
  database; the test suite runs against a real bundled PostgreSQL
  (pgserver) so SQL behavior matches production, not SQLite semantics.
- Entities: Tenant (family), User (guardian), Role, Device, Policy,
  PolicyVersion, Category, DomainRule, DeviceAssignment, AuditEvent,
  Publication, Session.
- Tenant isolation: every scoped table carries tenant_id; a row-level
  guard in the data layer refuses cross-tenant access, and negative tests
  prove tenant A cannot read or mutate tenant B.
- Auth: email+password (PBKDF2-HMAC-SHA256, per-user salt, constant-time
  compare - parameters adapted from the reviewed dashboard auth module),
  TOTP MFA enrollment and challenge, hashed session tokens stored
  server-side with expiry and rotation, HttpOnly SameSite=Strict cookies
  plus a custom header for state-changing requests (CSRF defense adapted
  from the reviewed dashboard design).
- Rate limiting on authentication and mutation endpoints; login lockout
  after repeated failures (adapted from the dashboard limiter, made
  per-tenant and persisted so restarts do not reset it).
- Audit log: append-only record of every administrative action with
  actor, tenant, action, payload summary and timestamp.

## 4. Adapted components and review gates

| Source (old tree)              | Disposition in new architecture |
| ------------------------------ | ------------------------------- |
| filtering-engine DNS/proxy core | Adapted into filtering-engine/ after the Stage 11C symlink fix (done, 337 tests pass) and a line-level security review |
| dashboard auth patterns        | Re-implemented in control-plane with MFA and tenancy added; parameters and CSRF model carried over with review notes |
| dashboard publishing pipeline  | Re-implemented as policy-compiler with atomic generation publication kept (temp file + rename, symlink switch, 0600 files) |
| dashboard domain/category model | Re-implemented with tenant scoping |
| dashboard UI (static app.js)   | Not reused; new front ends |

Every adaptation records: what was reused, what was changed and why, the
review that gated it, and the tests that prove it.

## 5. Data plane design (Milestones 3-5)

- dns-edge: DoH/DoT listeners terminate TLS, authenticate the device
  (client certificate or protected scoped credential - never a long-lived
  bearer token in the URL), resolve the device to a tenant+policy, and hand
  the query to the filtering engine. Device identity and policy id are
  redacted from request logs.
- policy-compiler: compiles a tenant's policy version, categories and
  domain rules into an immutable engine bundle (generation), validates it
  against the engine's loader contract, and publishes atomically.
- category-pipeline: ingests category datasets with provenance and license
  records; seed fallback dataset ships with recorded provenance.
- proxy-pac: generates per-tenant PAC files and serves the proxy fallback
  for traffic classes DNS cannot cover.
- url-filter-server: server-side URL filtering for full-URL decisions,
  designed around privacy-preserving retrieval (PIR, Privacy Pass tokens,
  OHTTP relay) so the filter service learns as little as possible about
  per-device browsing.

## 6. Device management (Milestone 4)

- mdm/ wraps a NanoMDM/NanoDEP deployment evaluated during the milestone;
  the evaluation result and rationale are recorded in the milestone review.
- The control plane owns the device registry and issues MDM commands
  through a queue with audit entries; enrollment profiles are generated
  per device. No real-device enrollment, no push to production devices,
  and no destructive commands (erase/wipe) in this build.

## 7. Operations (Milestone 6)

- Structured logging with redaction rules (no device identity, session
  tokens, credentials or DNS identity material in logs).
- Metrics and health endpoints per service; alert rule definitions.
- Backup/restore for the control-plane database with tested restore
  (adapted from the reviewed dashboard backup flow, moved to PostgreSQL).

## 8. Testing strategy (Milestone 7)

- Unit tests per component, integration tests against the bundled
  PostgreSQL and the real engine loader, and end-to-end tests that drive
  the control plane API the way the front ends do.
- Security negative tests are first-class: tenant isolation, auth bypass
  attempts, CSRF, symlink/path traversal, oversized and malformed bodies.
- Every milestone review report lists actual test output, changed files,
  unresolved issues and remaining work. Nothing is reported as tested
  that was not run.

## 9. What is explicitly out of scope for this build

Production deployment, DNS/hosting changes, live website changes, paid
services, production Apple credentials, customer-device enrollment or
erasure, merges into main, force-pushes, deletion of prior work.

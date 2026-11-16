# Milestone 6 Review - Operations, admin tooling, device identity

## Status: IMPLEMENTATION CHECKPOINT

## Built this milestone

### Platform category-dataset administration (control-plane)
- `CategoryRule` model: platform-wide domain -> category with full
  provenance (source, added_by, created/deactivated timestamps);
  soft-delete only, audit trail preserved.
- `User.is_platform_admin` flag, set out of band, never via API.
- Routes: GET/POST /api/admin/categories,
  DELETE /api/admin/categories/{id}, GET /api/admin/categories/export
  (emits the exact shape the publication categories file carries).
- Tests: 7 new (authz negatives, add/list/export, duplicate 409,
  deactivate/reactivate history, input validation, audit trail).
  Full control-plane suite: 61 passing locally (tree: local HEAD
  6f6599a + docs commits; published-tree verification in M7).

### Per-device dataset credentials (url-filter-server)
- `device_auth.py`: short-lived HMAC-signed scoped tokens
  (device_id, tenant_id, scope, exp; 1h default, 24h hard cap) in the
  Authorization header. URL-transported tokens are rejected by test.
  Applies the user's approved per-device-identity requirement
  (WhatsApp 2026-11-16 02:25 EST) to dataset distribution; DoH
  identity binding belongs to dns-edge.
- Dataset routes require a credential when KG_DEVICE_TOKEN_KEY is
  configured; without a key the service is in explicit dev mode.
- Tests: 8 new (roundtrip, tamper, expiry, wrong scope, wrong key,
  lifetime cap, endpoint authz incl. URL-token rejection, dev mode).
  url-filter-server suite: 24 passing locally.

### Operations (spec Parts 15-16)
- deploy/monitoring.md, deploy/prometheus.yml.example: health/metrics/
  alert config; log-redaction rules (no tokens, keys, hashes).
- docs/setup/APPLE_CREDENTIALS.md: ADE server token vs MDM push
  certificate kept distinct; full gate checklist; no credentials in
  repo, none hardcoded.
- deploy/COSTS.md: expected ongoing costs identified before any spend;
  nothing purchased, all spend requires separate user approval.

## Unresolved / remaining

- Credential issuance endpoint in the control plane (guardian-facing
  per-device token minting) is not yet wired; verification side is
  done, issuance is the remaining half.
- dns-edge per-device DoH identity binding itself (the DNS half of
  the approved requirement).
- M1-M5 published-tree re-verification folds into M7 fresh-clone.
- Held unpublished work still awaits user approval (per-tenant
  publication isolation fix + erratum + category wiring).

## Changed files

- control-plane/app/models.py, main.py, tests/conftest.py,
  tests/test_category_admin.py
- url-filter-server/app/device_auth.py, server.py,
  tests/test_url_filter.py
- deploy/{monitoring.md,prometheus.yml.example,COSTS.md},
  docs/setup/APPLE_CREDENTIALS.md

## Security hardening follow-up (2026-11-16, post-review)

Two weaknesses found in the account self-service code on inspection
AFTER its first publish; both fixed openly with before/after evidence.
These are new-account hardening issues, distinct in kind from the HELD
cross-tenant/policy findings: every sensitive operation here required
the account's own fresh password, so a stolen session alone could not
exploit either, and no other tenant's data was reachable.

1. Stateless MFA enrollment (BEFORE): enroll-start returned a
   server-generated secret, but enroll-confirm accepted ANY
   client-supplied secret + valid code + the account password. No
   expiry, no binding of the pending secret to the user or to a
   server-issued value; "not persisted" meant "not verified", not
   "safe". An attacker needed session AND password to abuse it
   (already full compromise), so severity: hardening weakness, not a
   stop-condition finding.
   AFTER: PendingMfaEnrollment table (model + alembic 0006). The
   secret is generated and stored server-side, one pending row per
   user, 10-minute expiry, replaced on restart, deleted on confirm
   (single-use) and on expiry. Confirm takes only {code, password}.
   Tests: substitution attack rejected, expiry rejected + row cleared,
   restart invalidates the old code, pending bound to the caller's
   user only, confirm-without-start 400.

2. Sessions surviving password change (BEFORE): changing the account
   password left every existing session valid, so the standard
   compromise-remediation step would not eject a stolen session.
   AFTER: password-change deletes the account's OTHER auth sessions
   and audits the count ("other_sessions_invalidated=N"). Test: a
   second logged-in client gets 401 afterwards while the changing
   session survives.

3. UI staleness (BEFORE): the guardians table showed the admin as MFA
   "not enrolled" immediately after successful enrollment while the
   account panel showed MFA ON. AFTER: the guardian list refreshes
   after enrollment; rendered evidence (guard-09 screenshot) shows
   both views agreeing.

Evidence: control-plane suite 116 -> 122 tests on head c781438;
rendered pipeline /tmp/evidence/run_guard.py re-run PASS (signed-out
invite acceptance in a cookie-less context, role change, password
change, MFA enrollment with a real TOTP code, network log captured).

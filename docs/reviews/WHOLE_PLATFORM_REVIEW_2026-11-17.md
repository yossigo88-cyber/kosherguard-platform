# Whole-platform review and correction - 2026-11-17

Branch: `full-platform-build`.
Review baseline: `2ec2ae548127107460364f0978d8e05d21768eb1`.
Scope: every component of the repository - control plane, dashboard,
filtering engine, dns-edge, proxy-edge, mdm, category-pipeline,
url-filter-server, portal, website, deploy scripts, iOS Swift sources,
docs. Ordinary defects were fixed with negative-control-first
regressions; suites were re-run with retained logs and JUnit.

This is a code-and-test review candidate. No merge to main, deployment,
DNS change, real Apple credential operation, real device operation,
purchase, force-push, or branch deletion was performed.

## 1. Defects found and fixed

### 1.1 Control plane: post-lock authorization refresh (TOCTOU)
`current_user` loaded the user/session, then acquired the tenant lock,
then authorized from the pre-lock snapshot. A concurrent demotion,
MFA enrollment, or session expiry during the lock wait was honored only
after the next request. Reproduced end-to-end on real PostgreSQL: an
HTTP-only owner demoted mid-request retained write authorization.
Fix: re-read the AuthSession/User rows after lock acquisition and
re-run MFA/expiry/read_only checks; stale ORM state maps to 401.
Regression: `control-plane/tests/test_current_user_lock_refresh_pg.py`
(7 real-PostgreSQL cases). Negative control (fix stashed): fails.
Evidence: /tmp/current-user.log, /tmp/current-user.xml,
/tmp/http-authz-neg.log.

### 1.2 Dashboard: session storage and token cost
`dashboard/src/auth.py` stored session tokens in plaintext and accepted
password hashes with unbounded KDF iteration counts. Fix: session
tokens are stored as SHA-256 digests (legacy plaintext sessions
invalidated) and PBKDF2 iteration counts are bounded to a sane range.
Regression: `dashboard/tests/test_auth_storage.py` (9 tests; 7 fail on
baseline). Evidence: /tmp/dashboard-auth.log/.xml,
/tmp/dashboard-storage-neg.log.

### 1.3 Dashboard: publication replay deletes a live generation
A replayed publication revision could delete the existing generation.
Fix: created-flag guard in `dashboard/src/publishing.py`.
Regression: `dashboard/tests/test_publisher_collision.py` (fails on
baseline, passes fixed). Evidence: /tmp/dashboard-publishing.log/.xml,
/tmp/publisher-neg.log.

### 1.4 Portal: schedule weekday labels off by one
`portal/app.js` DAYNAMES assumed Sunday-first while the backend uses
Monday=0; every saved schedule displayed the wrong days. Fix:
Monday-first labels. Regressions in `tools/test_review_ui.mjs`
(production-code VM tests; fail on baseline). Visual verification:
Chromium render inspected as pixels (schedule section readable, days
aligned). Evidence: /tmp/review-ui-neg.log, screenshot delivered with
review messages.

### 1.5 Control plane web: guardian MFA reset asked only for a password
The admin MFA-reset dialog requested only the guardian password while
the handler required fresh authentication; help copy matched the weaker
flow. Fix: `control-plane/web/app.js` now requires password + current
authenticator code + explicit confirmation and cancels without sending;
`control-plane/web/index.html` help copy updated to match. Regressions
in `tools/test_review_ui.mjs` (payload and cancel cases; fail on
baseline). Visual verification: real reset handler exercised through
three rendered dialogs with synthetic values, cancelled before any
request; screenshot delivered. Handler-driven synthetic tests and
rendered-fixture screenshots are distinct evidence classes.

### 1.6 url-filter-server: category loader accepted an unrelated schema
`app/dataset.py` `load_categories` did not consume the real
category-pipeline output (domains -> categories) and could silently
generate an empty dataset. Fix: consume and validate the pipeline
schema through the engine's CategoryDB, like category-pipeline/build.py.
Regression: `url-filter-server/tests/test_category_input.py` (7 tests;
fail on baseline). Evidence: /tmp/url-filter.log/.xml,
/tmp/category-input-neg.log.

### 1.7 url-filter-server: 401 body leaked the failure reason
`app/server.py` interpolated the TokenError message ("bad signature" vs
"token expired" vs "token revoked") into the 401 detail, contradicting
its own no-oracle comment. Fix: generic "unauthorized" body.
Regression: appended to `url-filter-server/tests/test_url_filter.py`
(identical bodies across missing/tampered/expired/wrong-scope tokens;
fails on baseline). Evidence: /tmp/url-filter.log/.xml,
/tmp/url-filter-401-neg.log.

### 1.8 Website: nav anchor pointed at the wrong section
`website/index.html` "How it works" linked `#how` (the hero) instead of
`#how-it-works` (the section). Fix applied; anchor-integrity check over
all six pages passes (3 fragment links resolve). Negative control:
baseline mismatch confirmed. Evidence: /tmp/website-anchors.log.

### 1.9 OHTTP interop script: two setup/teardown defects
`deploy/ohttp/interop/run-local-interop.sh` copied interop-client.mjs
via a relative `$(dirname "$0")` AFTER cd into the gateway tree (copy
always failed under relative invocation), and its EXIT trap ran
`kill ${GW_PID:-0} ${STUB_PID:-0}` - with unset PIDs that is `kill 0`,
which signals the caller's ENTIRE process group. Both proven in one
negative-control run of the original under setsid (cp failure + a
sibling marker process killed by the trap). Fix: absolute SCRIPT_DIR
captured before any cd; cleanup kills only explicitly set PIDs.
Positive stub harness (no network; fake curl/npm/node): full flow exit
0, zero surviving processes. Real-network interop (pinned gateway +
npm ci) remains untested. Evidence: /tmp/ohttp-script.log,
/tmp/ohttp-script-neg.log.

### 1.10 iOS Swift sources: ordinary source defects
Fixed within existing requirements (no invented functionality):
- Public access modifiers + initializers on AuthSessionClient,
  CredentialIssuanceClient, KeychainCredentialStore, AppConfiguration
  (cross-module usability).
- Conditional FoundationNetworking imports (Linux/portable builds).
- AppConfiguration reads the real managed App Configuration: standard
  UserDefaults dictionary forKey "com.apple.configuration.managed"
  (Apple forum 672938; apple/swift-configuration#107); HTTPS-only base
  URL (no plaintext/userinfo); positive deviceID only.
- AuthSessionClient parses Set-Cookie case-insensitively via HTTPCookie.
- Removed the client-side refusal of the doh credential scope: the
  published control plane mints doh (app/main.py), so the refusal
  contradicted the live server contract.
- KosherGuardApp: canImport(URLFilter) guard, fixed double-optional
  signOut binding, stored dataset credential deleted on 401.
- PrefilterUpdater rewritten: authenticated manifest + prefilter fetch,
  SHA-256 integrity against the manifest, monotonic version (no
  downgrade), atomic persist/restore, 45-minute cadence; corrupt bits
  are rejected without advancing the version or overwriting the file.
  Contract matches url-filter-server's real /v1/dataset/manifest and
  /v1/dataset/prefilter responses (section 3).

iOS verification status, precisely: Linux logic-level only. Direct
swiftc (Swift 6.1.3) compiled the four portable URLFilter sources
against a TEST-ONLY Crypto shim (hand-rolled SHA-256 matching 3 NIST
vectors - not a validated crypto library, not the production
swift-crypto dependency build), and the 6 portable test bodies in
tools/swift-portable-tests.swift ran verbatim with minimal XCTest
assertion shims (not full XCTest execution): 6/6 passed, exit 0.
Negative control: baseline PrefilterUpdater fails to compile.
The production SPM harness (tools/run-swift-portable-tests.sh, pinned
swift-crypto exact 3.12.3) is blocked in this environment: SPM never
completes the "Planning build" phase under the sandbox's time-boxed
shell and background processes cannot survive. NOT compiled for iOS,
NOT signed, NOT run on Apple hardware; Network Extension targets are
untouched and unverified. Evidence: /tmp/swift-portable.log.
ios/README.md updated to match this reality exactly.

### 1.11 iOS PrefilterUpdater: transient failure suppressed retries for 45 minutes
Found by the independent audit re-check (section 6): refresh() stamped
lastAttempt before fetching, so one transient failure (e.g. a dropped
connection or a 5xx) suppressed every retry for the full 45-minute
cadence. Fixed within the existing requirements: a completed check
(new bits applied, or a confirmed nothing-new staleVersion) starts the
45-minute cadence; a failed attempt gets a short 60-second backoff
(failureRetryInterval) so recovery is quick but the server is never
hammered. Two regressions added to tools/swift-portable-tests.swift:
testSuccessEnforcesFortyFiveMinuteCadence (cadence preserved after
success, verified by the staleVersion that proves the post-cadence
fetch really ran) and testTransientFailureRetriesAfterShortBackoff
(401, refused at +30s, retried and succeeding at +61s). Negative
control: against the pre-fix source the backoff regression fails with
tooSoon at the 61s retry (exit 1, /tmp/swift-portable-backoff-neg.log);
with the fix the portable suite is 8/8 (exit 0,
/tmp/swift-portable-fixed8.log). Same portability qualifications as
1.10 apply: Linux logic-level only, not compiled for iOS.

## 2. Suite results (all exit 0, logs + JUnit retained under /tmp)

Exact-head ledger: every suite below was re-run on a fresh
unauthenticated clone of the published full-platform-build head
7602c71d3b86cfe6e9fd41a26119facc9ae78ad8 (/tmp/head-*.log/.xml),
matching the earlier runs on the local candidate tree
(/tmp/<suite>.log/.xml). The one exception is the iOS portable suite,
whose post-fix 8/8 run accompanies the delivery note for the head
containing the 1.11 fix (it cannot precede the commit that publishes
the fix).

- control-plane: 458 passed (5 chunks, /tmp/head-cp-{0..4}.xml/.log)
- dashboard: 286 passed (3 chunks: 98 + 95 + 93,
  /tmp/head-db-0{0,1,2}.xml/.log). First chunk-01 attempt was
  interrupted by a shell time-box and its partial log showed a
  startup-timeout flake in test_dashboard_to_dns_end_to_end; the clean
  re-run passed 95/95.
- filtering-engine: 337 passed (/tmp/head-filtering-engine.{xml,log})
- dns-edge: 87 passed (/tmp/head-dns-edge.{xml,log})
- mdm: 64 passed (/tmp/head-mdm.{xml,log})
- proxy-edge: 38 passed (/tmp/head-proxy-edge.{xml,log})
- url-filter-server: 46 passed (/tmp/head-url-filter.{xml,log})
- category-pipeline: 6 passed (/tmp/head-category-pipeline.{xml,log})
- UI production-code VM regressions (tools/test_review_ui.mjs): 3 passed
  (/tmp/head-review-ui.log)
- iOS portable (qualified, sections 1.10/1.11): 6 passed at 7602c71;
  8 passed with the 1.11 fix

Every fix above also carries a negative control: the regression fails
when the fix is stashed, and the vulnerable-behavior reproductions are
kept out of the ordinary passing suites.

## 3. Contract cross-checks performed

- iOS PrefilterUpdater manifest/prefilter contract verified against
  url-filter-server's actual responses (keys version, prefilter.bytes,
  prefilter.sha256; raw octet-stream prefilter; Bearer dataset-scope
  credential).
- url-filter-server load_categories validated against the real
  category-pipeline output schema.
- Portal weekday convention verified against the control-plane backend
  (Monday=0).
- iOS managed App Configuration mechanism verified against Apple forum
  672938 and apple/swift-configuration#107.
- ios/README entitlement references verified to exist in
  docs/GENTECH_TECHNICAL_INVESTIGATION.md (sections 5.4, 10).

## 4. Docs ledger

- Corrected: ios/README.md (status lines, removed false doh-refusal and
  "server rejects 400" claims).
- Verified: docs/design/DOH_IOS_TRANSPORT.md and dns-edge/doh_identity.py
  attribute to the user a rule against bearer credentials in DoH URLs.
  The rule is genuine user evidence (WhatsApp 2026-11-16 02:25 EST,
  build authorization: no long-lived bearer credentials in DoH URLs or
  query strings; evaluate client certificates or appropriately
  protected scoped credentials). The implemented design complies:
  credentials are short-lived, scoped ("doh"), and attached as an
  Authorization header - never in the URL; dns-edge ignores
  URL-transported tokens by construction.
- website/privacy.html and website/terms.html remain DRAFTs pending
  professional legal review, as their banners state; no changes made.
- All other docs: no accuracy claims were re-verified in this pass;
  they were not relied upon for any fix.

## 5. Independent audit reconciliation

An independent audit followed publication of the head at 7602c71. Its
scope: it re-derived every fix and count in this report and re-ran the
principal negative controls, with high-risk spot-checks beyond that;
it was not another line-by-line audit of the platform. It found no
blocking defect. Its findings are reconciled here:

- PrefilterUpdater retry suppression: real source defect, fixed in
  1.11 with a bounded regression.
- Struct callers of refresh() lack synchronization: confirmed as a
  limit, not fixed. PrefilterUpdater is a struct; callers must
  serialize refresh() on a single owned value. Making it an actor or
  adding locking is a redesign outside this correction pass.
- App-group wiring for extension/app sharing: remains an undecided
  design item for the owner (unchanged, section 6).
- url-filter-server's dataset loader imports the sibling
  filtering-engine/src tree via sys.path: confirmed. This is a
  deployment requirement - url-filter-server must be deployed with
  filtering-engine/src importable - now documented here and already
  reflected in how the suite runs (PYTHONPATH=../filtering-engine/src).

## 6. Known remaining limits

- No iOS compile, signing, or device testing (no Apple SDK/credentials).
- No real-network OHTTP interop run (gateway fetch + npm ci).
- SPM production-dependency build of the portable Swift tests is
  blocked in this environment (see 1.10).
- PrefilterUpdater persistence URL is caller-supplied; app-group wiring
  for extension/app sharing is an undecided design item for the owner.
- PrefilterUpdater is a struct without internal synchronization;
  callers must serialize refresh() (see section 5).
- url-filter-server depends on the sibling filtering-engine/src tree
  being importable at deployment (see section 5).
- Alembic migrations were exercised through the suite but not
  individually audited line-by-line.

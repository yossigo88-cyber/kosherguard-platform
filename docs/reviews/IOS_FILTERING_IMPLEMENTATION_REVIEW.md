# iOS Filtering Implementation - Final Review

Branch `full-platform-build` (local only, not pushed). Implementation
head (tested): `4d6b202`. Base: `c216b8c`. The complete list of files
changed between base and the implementation head:

- control-plane/app/main.py
- control-plane/app/publication_ops.py
- control-plane/app/publisher.py
- control-plane/tests/test_filter_rules.py
- control-plane/tests/test_native_mdm.py
- docs/design/DOH_IOS_TRANSPORT.md
- docs/reviews/IOS_FILTERING_IMPLEMENTATION_REVIEW.md
- docs/setup/IOS_BUILD.md
- ios/Configuration/App.entitlements
- ios/Configuration/FilterControlExtension-Info.plist
- ios/Configuration/FilterControlExtension.entitlements
- ios/Configuration/FilterExtension.entitlements
- ios/KosherGuard.xcodeproj/project.pbxproj
- ios/Package.swift
- ios/README.md
- ios/Sources/FilterExtension/FilterControlProvider.swift
- ios/Sources/FilterExtension/FilterDataProvider.swift
- ios/Sources/KosherGuard/KosherGuardApp.swift
- ios/Sources/URLFilter/AppConfiguration.swift
- ios/Sources/URLFilter/CredentialIssuanceClient.swift
- ios/Sources/URLFilter/FilterRuleStore.swift
- ios/Sources/URLFilter/FilterRulesClient.swift
- ios/Sources/URLFilter/FilterSyncController.swift
- ios/Sources/URLFilter/FilterVerdictEngine.swift
- ios/Sources/URLFilter/KeychainCredentialStore.swift
- ios/Sources/URLFilter/PrefilterUpdater.swift
- ios/Sources/URLFilter/SignInCoordinator.swift (added)
- mdm/command_codec.py
- mdm/tests/test_command_codec.py
- tools/run-swift-portable-tests.sh
- tools/swift-portable-tests.swift

(plus this document, committed immediately after with these exact
identifiers).
This document is the single authoritative account of the current
state and supersedes all earlier drafts of this review. Claims that
could not be verified in this environment say so explicitly; nothing
here asserts Apple-SDK compilation, signed entitlements, or on-device
behavior.

## 1. Scope of the assignment

1. Complete `FilterDataProvider`/`FilterControlProvider` with real
   App Group persistence and rule loading.
2. Secure the iPhone connection to the KosherGuard DNS/filtering
   infrastructure.
3. Resolve the DoH authentication mismatch.
4. Complete managed-configuration delivery and validation.
5. Make the iOS project compile and establish a reproducible
   build/test process.

## 2. What existed before (verified against base c216b8c)

At base, `ios/` contained exactly: `Package.swift`, a hand-authored
`KosherGuard.xcodeproj`, `README.md`, three entitlement/plist pairs,
and these Swift sources:
- URLFilter module: `AppConfiguration`, `AuthSessionClient`,
  `CredentialIssuanceClient`, `DNSOverHTTPSClient`,
  `KeychainCredentialStore`, `MDMEnrollmentClient`,
  `PrefilterUpdater`, `URLFilterConfiguration`.
- `KosherGuardApp.swift` (SwiftUI shell + credential flow).
- `FilterDataProvider.swift` / `FilterControlProvider.swift` (NE
  provider stubs).

`FilterRuleStore`, `FilterVerdictEngine`, `FilterRulesClient` and
`FilterSyncController` did NOT exist at base; they were added by this
work, together with the control-plane `filter-rules` export route.
Elsewhere in the repo (pre-existing): the `url-filter-server`
Bloom+PIR dataset service, the FastAPI control plane, and `dns-edge`
(see 4.3).

## 3. What was broken (at base and in earlier review rounds)

- No on-device rule persistence at all: the providers had no store,
  no engine, no sync path.
- Trust/lifecycle (found in review rounds): unbound snapshots;
  last-known-good reuse across expiry and identity; corrupt-store
  dead end; inode change-detection used the wrong attribute
  (`.systemNumber`); a bootstrap infrastructure-host allow exception
  (removed - never approved); `synced` reported with nil
  persistence; 401/404/409 lumped into generic failure (stale rules
  lived on); sign-out left shared rules behind; managed
  configuration read once at startup; slow in-flight HTTP responses
  could reinstall an old identity after sign-out/config change (no
  cancellation/epoch); clear() was not a durable tombstone; a stale
  process could re-mirror an old configuration; the generation floor
  was best-effort, conflated absent with corrupt, compared within a
  single policy only, and was written after the envelope
  (interruption could lose the highest revision); stored credentials
  were not origin/device bound and the sign-in clients were not
  rebuilt on configuration change; an invalid managed configuration
  left the old policy live.
- Build/packaging: an unbuildable `FilterExtension` SPM target
  (removed); wrong entitlement key; no shared keychain access group;
  Xcode target source membership did not cover the actual dependency
  closure (control target referenced SyncController/RulesClient/
  Prefilter/Keychain/AppConfiguration with only 3 member sources;
  data target's store referenced AppConfiguration, absent from its
  membership).

## 4. What the current code does (authoritative)

### 4.1 Policy delivery (control plane)

`GET /api/devices/{device_id}/filter-rules` authenticates with the
GUARDIAN SESSION COOKIE (`current_user` + `require_guardian`) - the
same session the iOS app establishes by native sign-in; it is not a
separate device-credential channel. It returns the device's explicit
guardian allow/block domains with the tenant-wide published
`generation`, sourced only from the last published immutable
generation (manifest re-verified per read). Inactive devices: 409;
unknown/cross-tenant device: 404. Dedicated tests:
`control-plane/tests/test_filter_rules.py` (9 tests).

### 4.2 On-device filtering (iOS, added by this work)

- `FilterRuleStore`: App Group persistence of snapshots, an identity
  bootstrap (pure pin: configFingerprint + endpointFingerprint, hex
  validated, NO network exception), a durable generation floor, a
  durable session epoch, and the mirrored managed configuration.
  Exclusively-locked (flock) cross-process writes; atomic replace.
- Snapshot validation: mandatory positive tenant/device/policy ids,
  full 64-hex fingerprint, finite non-future fetchedAt, valid
  defaultPolicy; same-generation refresh must be content-identical
  apart from fetchedAt; change detection uses `.systemFileNumber`
  (inode) + size + mtime; unchanged stamps still revalidate the
  current configuration binding.
- Durable floor: generations are monotonic per identity ACROSS
  policies (the published revision is tenant-wide - a policy switch
  cannot roll back). The floor is written BEFORE the envelope, its
  write is not best-effort, and a corrupt floor file fails every
  write closed (it is never treated as "no floor"). clear() removes
  the floor with its identity.
- Single transactional lifecycle authority: `admit(configuration:)`
  is the only door to a sync - under ONE store lock it requires an
  EXACT valid mirror of the managed configuration (absent or
  different both refuse) and a non-tombstoned store, and returns the
  durable authority NONCE (a random UUID per rotation, never a
  counter, so no captured value can recur and a corrupt record fails
  closed; the empty fresh-install record is a valid authority for
  the first sync session and is replaced by a real rotation). A
  controller holding a superseded configuration is refused by
  syncNow itself before any network request, whatever its init-time
  label says.
  Every commit path (`commit`, `commitArtifact`,
  `invalidateIfCurrent`) re-checks the captured nonce UNDER THE SAME
  LOCK as the write; it is captured before the first request and
  NEVER refreshed. Every rotation is marker-FIRST with strict
  errors: a part-way failure leaves dead writers, never a usable old
  authority. The controller also re-reads the session cookie after
  each await; a changed cookie discards the response. Delayed error
  responses (401/404/409, dataset 401) invalidate only when the
  captured nonce is still current - they can never clear a newer
  synced identity. The prefilter download is staged to a scratch
  file and becomes durable only through the same-nonce atomic
  commit, so a stale fetch cannot recreate an old artifact.
- Configuration lifecycle: `adoptConfiguration` (epoch advance +
  identity clear + mirror write, atomically) is the only supported
  switch; `mirrorConfiguration` refuses to overwrite a different
  existing mirror (stale processes get `configurationSuperseded`);
  an invalid/removed managed configuration triggers
  `invalidateConfiguration` (rotates the authority, then writes a
  durable TOMBSTONE marker, then removes identity and mirror - the
  old policy cannot stay live). The tombstone durably separates
  FRESH INSTALL from INVALIDATED: a tombstoned store admits no one
  and no controller init re-mirrors it; only the app's atomic
  `adoptConfiguration` lifts it (tombstone removal is the LAST,
  strict step of adoption, so a failed adoption stays blocked). A
  controller holding an older configuration than the mirror refuses
  to start (`notConfigured: superseded`) and touches nothing.
- Credential origin binding: the sign-in flow stores
  `session.origin` / `credential.dataset.origin` (endpoint
  fingerprint of the minting configuration). The controller refuses
  unbound or mismatched credentials and never sends an old bearer
  token to a newly configured origin. The app's credential clients
  are rebuilt on `UserDefaults.didChangeNotification`, so the
  sign-in form can only target the currently configured origin.
- Session lifecycle (SignInCoordinator, portable + XCTested):
  SIGN-OUT DISCLOSURE GATE: the orchestrated sign-out captures the
  session cookie AND the bundle's session origin BEFORE any await,
  runs local teardown FIRST (bundle, store clear, in-lock prefilter
  removal, strict), and performs the server logout LAST - and only
  with a client the caller captured together with, and bound to, an
  origin equal to the bundle's session origin. A managed-config
  change replacing the client mid-await can therefore never leak
  the old cookie to a NEW server: the remote logout is omitted
  (portable-proven: bound client gets the cookie exactly once with
  local teardown already complete; origin-mismatched client gets
  ZERO calls while local teardown still completes; nil client is
  local-only).
  CAPTURED CONFIGURATIONS ARE NEVER AUTHORITATIVE: the coordinator
  holds a current-configuration source (the UserDefaults mirror) and
  re-reads it AT EXECUTION TIME. Observers enqueue
  `applyCurrentConfiguration()` with NO captured copy - rapid
  A -> B pushes coalesce to the latest source, so a queued older
  task can never re-adopt a stale configuration (portable-proven:
  the enqueued-apply test adopts only B; a second run is
  alreadyCurrent). The sync controller is built only AFTER the
  adoption settles, from the managed configuration re-read at that
  moment. Sign-in attempts are additionally gated against the
  current source at admission: a captured-and-superseded
  configuration is refused before it admits anything or sends a
  byte (zero auth calls, no mirror write), and a coordinator
  without an installed source fails closed.
  exactly ONE sign-in attempt is in flight (a concurrent attempt is
  refused, never queued, so two attempts can never interleave into
  a mixed session-A/dataset-B state). ADMISSION RUNS BEFORE ANY
  NETWORK: the store must be valid and untombstoned, the mirrored
  configuration must exactly match the attempt's configuration
  (`admit(configuration:)`), and the caller's live origin must
  still match - a queued sign-in for a superseded configuration is
  refused before its email/password/TOTP reach the network. The
  bundle write is a GATED LIFECYCLE TRANSACTION:
  `rotateAuthorityAndCommit` runs the conditional rotation AND the
  vault write under the same store lock, and the bundle carries the
  NEW authority nonce (`credentials.bundle`: session, session
  origin, dataset credential, dataset origin, authority). The sync
  controller requires the bundle's authority to equal the admitted
  nonce BEFORE ANY REQUEST, so a bundle written in the rotation
  gap (a sign-out/adoption interleaving the vault write) can never
  resurrect a session; the coordinator also re-checks after the
  transaction and removes exactly its own stale bundle on drift.
  Vault writes and teardowns are strict (errors surface; absent
  keys are not errors). Sign-in, sign-out and configuration
  adoption/invalidation + credential teardown are all serialized
  through the ONE shared lifecycle actor - the app's observers no
  longer independently adopt or delete. Sign-out invalidates LOCALLY FIRST
  (bundle + shared store clear + prefilter removal) and notifies
  the server LAST, best-effort. Controller invalidation is always
  conditional on the admitted nonce and STRICT: a failed marker
  write surfaces `persistenceUnavailable` instead of pretending
  `signedOut`, and rule-path invalidations (401/404/409, origin
  unbound, signed out) remove the prefilter artifact too, and the
  removal runs INSIDE the same locked lifecycle transaction as the
  authority rotation (registered artifacts + the canonical cache
  path) - an old catch can never delete a new identity's committed
  cache, and there are no manual out-of-lock deletes left in the
  controller or the app. Artifact install (same-directory
  rename(2)) and removal are now both in-lock.
- Managed-configuration lifecycle (ConfigurationApplier, portable +
  XCTested): invalid/absent push -> strict tombstone; valid push
  with a missing OR different mirror OR a present tombstone ->
  strict atomic adoption; valid + same mirror -> no-op. This closes
  the recovery deadlock: a valid configuration after an invalid one
  is adopted (tombstone lifted, mirror written) instead of leaving
  the controller permanently refused.
- Prefilter cache is identity-bound: the persisted snapshot records
  the endpoint fingerprint of the identity that downloaded it;
  restore rejects a foreign (or legacy, unbound) cache, so a
  version from a previous server can never suppress the first
  download from the current one.
- Cancellation: syncNow checks Task.isCancelled at the top (never
  fetches or commits once cancelled - deterministically tested),
  immediately after the rules fetch await BEFORE apply() can
  commit, and before the artifact commit
  (Apple-platform mid-flight behavior; corelibs URLSession hangs on
  in-flight cancellation, so those checks are source-reviewed, not
  portable-tested). The control provider cancels the sync task on
  stopFilter and generation-guards completion.
- Reader binding: every written envelope is stamped with the
  committing authority nonce, and `load()` rejects a snapshot whose
  stamped authority is not the store's CURRENT nonce - a rotated
  invalidation marker revokes the snapshot even when the identity-
  file deletions behind it failed or never ran. The epoch file
  participates in the engine's change detection, and the engine
  additionally PINS its in-memory policy to the committing nonce and
  re-checks that pin PER FLOW, so revocation is immediate, reload or
  not. A revocation/invalid load never falls back to
  last-known-good. (Cost: one small file read + decode per verdict;
  acceptable at this milestone, noted for later optimization.)
- Immutable published revisions: the durable floor now carries the
  content DIGEST of the highest published revision (canonical bytes
  excluding fetchedAt, so a freshness-only re-delivery digests
  identically). Same identity + same generation + ANY content change
  (policyID, rules, default policy) is `revisionConflict`, never a
  write - even when the snapshot file itself is corrupt, because the
  proof lives in the floor, not the corrupt file. Older floor files
  without a digest decode as corrupt and fail closed.
  `commitArtifact` installs the staged prefilter with a single
  same-directory `rename(2)` - an atomic REPLACE that preserves the
  previous artifact on failure (the earlier remove+move could lose
  it between steps).
- `FilterVerdictEngine`: `notReady` blocks EVERY flow (no host
  exception of any kind); missing bootstrap = no identity record =
  notReady; expiry enforced per flow; no last-known-good across
  expiry/identity/revocation.
- Corruption recovery: a corrupt rules file can be replaced under
  the write lock only by a fresh published snapshot matching the
  CURRENT bootstrap identity with generation >= the durable floor,
  and only when that floor EXISTS - a corrupt snapshot with an
  absent floor has no trustworthy monotonic history, so recovery is
  refused (fail closed; the path back is re-adoption/re-sign-in).
  A corrupt floor fails every write closed.
- `FilterSyncController` states include `invalidated(String)`:
  rules 401/403, 404, 409 and prefilter 401/403 each clear store +
  prefilter and surface a tombstone state; sign-out clears the same
  state; transient failures keep only the currently-valid,
  expiry-enforced snapshot.
- Rule sync runs from the filter CONTROL provider
  (`FilterControlProvider`), Apple's documented database-maintenance
  role, reading the mirrored configuration and shared-access-group
  keychain (placeholder team id). It syncs at startFilter, on
  not-ready flows, and on a bounded-rate maintenance schedule
  (`MaintenancePolicy`: routine hourly; exponential backoff from 5
  minutes capped at the routine interval, portable-tested) - it does
  NOT depend on `handleNewFlow` callbacks, which may never arrive
  because the data provider never returns `needRules`. The provider
  owns its sync Task: `stopFilter` cancels the in-flight task and
  bumps a generation counter; task completions and maintenance-timer
  fires check stop-state AND generation before any
  `notifyRulesChanged` or reschedule, so a pre-stop sync can never
  commit-notify or rearm a stopped (or restarted) provider, and
  `startFilter` resets `stopped` so a restarted instance resumes.
  CAVEAT - NOT A PROVEN STOP BARRIER: task creation and task
  assignment are separate transactions, so a stopFilter landing
  between them can miss cancelling the task; the generation guard
  then only suppresses that task's `notifyRulesChanged`/reschedule
  and does not interrupt its in-flight work. This is not a
  signed-out/credential bypass (the session guard still requires a
  bundle whose authority equals the admitted nonce before any
  request), but stopFilter is not proven to be a hard stop barrier
  and remains marked for Apple-SDK verification.
  The data provider is strictly read-only on the App Group.
  Apple-provider runtime behavior remains hardware-UNVERIFIED.

### 4.3 DNS / DoH - actual server state, and the still-blocked path

Server side (pre-existing source, inspected this round): `dns-edge`
(`doh_server.py`, `doh_identity.py`) implements authenticated
per-device DoH: every request must carry a short-lived HMAC-scoped
device token (scope "doh") in the Authorization header - never in
the URL - and the tenant is read only from the verified token
payload, making cross-tenant queries inexpressible. Verification
logic is shared with `url-filter-server/app/device_auth.py`
(header-transported, rotatable, redacted from logs). The user
requirement behind this design is verified in the user channel
(WhatsApp, 2026-11-16 02:25 EST: authenticated per-device DNS as the
intended identity mechanism; no long-lived bearer credentials in DoH
URLs or query strings; evaluate client certificates or protected
scoped credentials; verify actual iOS transport support; redact
credentials from logs).

iOS side: `DNSOverHTTPSClient` exists (base source) but has NO
runtime call site - nothing wires device DNS to it. The assignment's
"secure iPhone connection to the filtering DNS infrastructure" is
therefore NOT complete and is honestly STILL BLOCKED:

- App-mediated resolution via `DNSOverHTTPSClient` would cover only
  the app's own queries, not the device's DNS.
- The supported iOS routes to investigate (no claim that this list
  is exhaustive): an encrypted-DNS configuration profile
  (`com.apple.dnsSettings.managed`, supervised/managed devices),
  which carries a DoH server URL and server certificates but has no
  per-request Authorization-header mechanism - whether a
  client-certificate identity model can satisfy the user's
  requirements on this route is UNESTABLISHED and needs
  investigation, not assumed impossible; the `dns-proxy` value of
  the NetworkExtension entitlement with an `NEDNSProxyProvider` app
  extension (supervised or per-app managed deployment), which can
  attach headers but requires the entitlement grant, supervised
  hardware for validation, and an on-device short-lived-token
  issuance/rotation client that has not been built; and
  `NEDNSSettingsManager`/`DNEDNSOverHTTPSSettings` inside the app's
  own NetworkExtension configuration, whose scope (app-routed DNS
  vs device-wide) must be verified against Apple's current
  documentation on real hardware.
- Decision required before implementation: which route, and which
  per-device identity model it can carry. Neither weakening the
  header-token model nor shipping unauthenticated DoH satisfies the
  stated requirement.

No claim is made anywhere in this branch about a deployed resolver
fleet; the repository's dns-edge code is source, not deployment
evidence.

### 4.4 URL Filter (iOS 26) and categories - honest state

The Bloom+PIR prefilter is fetched, verified (manifest hash) and
persisted by the sync, but NO runtime verdict path consumes it: the
data provider evaluates only the explicit-domain snapshot, and no
`NEURLFilter`-based provider exists. Category enforcement on-device
is blocked on MISSING RUNTIME INTEGRATION (provider + call sites),
not merely on hardware. The `url-filter-provider` entitlement value
and ledger notes are preparation only.

### 4.5 Build system - what is and is not verified

- `ios/Package.swift` declares two library targets (KosherGuard -
  SwiftUI, and URLFilter). The package as a whole is NOT built
  anywhere: SwiftUI/NetworkExtension/Security are unavailable off
  macOS/Xcode.
- The Linux-verified artifact is a COPIED-SOURCE HARNESS
  (`tools/run-swift-portable-tests.sh`): it copies exactly the nine
  portable URLFilter sources (AuthSessionClient.swift,
  CredentialIssuanceClient.swift, AppConfiguration.swift,
  PrefilterUpdater.swift, FilterRuleStore.swift,
  FilterRulesClient.swift, FilterSyncController.swift,
  FilterVerdictEngine.swift, SignInCoordinator.swift) into a
  scratch SPM package with the
  pinned swift-crypto 3.12.3 dependency and runs the XCTest suite
  under the real Swift 6.0.3 toolchain. It proves nothing about NE,
  SwiftUI, signing, or the Xcode target graph.
- The Xcode project's target membership was completed to the actual
  dependency closure (app, data extension, control extension) and is
  now guarded by STATIC VALIDATION TESTS that run in the portable
  suite: (a) every type referenced by a target's member sources must
  be defined by a member of the same target (parsed from the
  pbxproj + sources); (b) the shared keychain access group literal
  in code must equal the keychain-access-groups entitlement of every
  target, and the app-group entitlement must equal the store's
  app-group identifier. These guards make membership drift a test
  failure, but they are static: "compiles under the Apple SDK"
  remains UNVERIFIED until an Xcode build runs.

## 5. Files changed in this delta

- `control-plane/app/main.py` - filter-rules export route
  (guardian-session authenticated, publication-bound).
- `control-plane/tests/test_filter_rules.py` - new (9 tests).
- `ios/Sources/URLFilter/`: `FilterRuleStore.swift`,
  `FilterVerdictEngine.swift`, `FilterRulesClient.swift`,
  `FilterSyncController.swift` (all new); `PrefilterUpdater.swift`
  (unauthorized vs transient, retry backoff);
  `KeychainCredentialStore.swift` (shared access group);
  `AppConfiguration.swift` (identity comparison support).
- `ios/Sources/FilterExtension/`: real provider wiring
  (control provider syncs on a bounded maintenance schedule; data
  provider read-only, fail-closed with no exceptions).
- `ios/Sources/KosherGuard/KosherGuardApp.swift`: origin-bound
  credentials, config-change rebuild, atomic adoption/invalidation,
  sign-out clears shared state, managed-config observer.
- `ios/Package.swift`: unbuildable FilterExtension target removed.
- `ios/KosherGuard.xcodeproj/project.pbxproj`: target source
  membership completed to the dependency closure.
- `ios/Configuration/*.entitlements`: corrected
  `com.apple.developer.networking.networkextension` array schema;
  `group.com.kosherguard.shared` app group; shared
  `keychain-access-groups` (placeholder team id).
- `tools/swift-portable-tests.swift`, `tools/run-swift-portable-tests.sh`.

## 6. Tests run and actual results

- Portable Swift suite (Swift 6.0.3 Linux toolchain, copied-source
  harness): **102 tests, 0 failures**. Round-11 additions: bound
  sign-out orchestration (cookie after local teardown; mismatched
  origin omits remote logout; nil client local-only). Round-10
  additions: queued
  lifecycle applies coalesce to the current source (stale captured
  configuration never re-adopted), sign-in captured against a
  superseded source refused with zero network and zero mirror
  writes, and current-source apply without an installed source
  fails closed. Round-9 additions: the
  independent reviewer's two EighthReviewRegressions proofs adapted
  (sign-out between rotation and bundle save cannot resurrect a
  session - sync makes zero HTTP requests; already-stale origin
  refused before any auth call), superseded-configuration
  admission refusal before network, bundle-authority binding
  (foreign-nonce bundle signed out with zero HTTP;
  current-authority bundle admits), locked artifact removal
  (invalidation removes the registered cache; a stale catch's
  invalidation is a no-op preserving the new identity's cache).
  Round-8 additions:
  SignInCoordinator exclusivity (concurrent A/B refused), stale
  attempts discarded on sign-out and config change mid-flight (no
  global writes), rejected mint leaves nothing global and rotates
  nothing, success rotates and stores the atomic bundle, tombstoned
  store refuses sign-in; ConfigurationApplier invalid -> valid ->
  adopt -> sync-ready orchestration proof and already-current
  no-op; identity-bound prefilter cache (foreign cache rejected,
  first download not suppressed); cancelled sync never fetches or
  commits. Round-7 additions: the
  independent reviewer's two SixthReviewRegressions proofs adapted
  (invalidated configuration cannot be re-admitted or re-mirrored;
  rotated authority marker revokes the reader even when identity-
  file deletion fails), fresh-install admission after init mirror,
  adoption lifts tombstone, conditional rotateAuthority, immutable-
  revision rejection (same identity+generation+changed policyID),
  freshness-only re-delivery allowed, corrupt-snapshot recovery
  retains the floor's immutable proof, and atomic artifact replace
  (stale nonce preserves the previous artifact). Two pre-existing
  same-generation conflict tests now expect `revisionConflict` (the
  durable floor digest is the authoritative immutable-revision
  gate; the in-memory `conflictingGeneration` check remains as
  defense in depth). New this round: session-epoch
  regressions (delayed-response-after-config-change, sign-out
  mid-flight, stale-instance refusal, stale-epoch commit rejection,
  credential origin mismatch/unbound), floor integrity (cross-policy
  rollback rejected, corrupt floor fails closed), maintenance-policy
  bounds, Xcode membership closure, entitlement consistency. Two of
  these adapt the independent reviewer's reproducing tests
  (`FourthReviewRegressions`, `FifthReviewRegressions`).
- Python control-plane route tests: **9/9 pass**. Full suite (MY
  OWN run, this environment - Python 3.10.12, pytest 9.2.0, Linux
  7.3.4): **496 passed, 3 failed**; the exact failures are
  `tests/test_dns_reporting_e2e.py::test_dns_query_lands_in_tenant_log`,
  `tests/test_policy_bundle.py::test_assigned_schedule_bundle_and_real_doh_wire`
  and
  `tests/test_policy_bundle.py::test_invalid_assigned_generation_reload_keeps_default_schedule`,
  and all 3 reproduce identically (same node IDs) at untouched base
  `c216b8c` via git worktree - pre-existing environment failures;
  no Python source changed in the review rounds. Attribution: the independent reviewer's broader
  control-plane run was killed ~70% through, so the 495/3 and
  base-reproduction evidence is THIS run's, not the reviewer's; the
  reviewer's independently verified scope is the 102-test portable
  Swift suite (reconstructed and passed) plus the 31 targeted
  filter-rules/native-codec Python tests.
- NOT run (blockers, not bypassed): Xcode/Apple-SDK compilation of
  the app and both extensions (needs macOS + Xcode); signed
  entitlement validation (needs an Apple Developer account);
  on-device NEFilter and maintenance-loop behavior (needs
  supervised/managed hardware); Family Controls / URL Filter
  approval; any DoH client behavior (no client is wired - see 4.3).

## 7. Resulting filtering coverage - honest verdict

The explicit-domain enforcement described in 4.2 is the IMPLEMENTED
INTENT, verified only at the portable-logic level (the verdict
engine and store under XCTest on Linux). Whether the profile
actually routes traffic through the extension and the extension
actually runs is NOT PROVEN: no Apple-SDK build, signed profile or
supervised device has executed any of it. Subject to that, the
intended behavior is fail-closed: rules that are unavailable,
expired, invalidated, unbound, stale-nonce or unverifiable all
block. Category blocklists are NOT enforced by the
app today (no runtime consumer of the prefilter - see 4.4). The
app-based filter is not system-wide on its own: it applies where
iOS routes traffic through the NEFilterManager configuration
(supervised device or per-app managed VPN mapping). Device DNS
filtering remains a server-side property; the authenticated
per-device DoH path is designed server-side and still blocked on
the client route decision in 4.3.

## 8. Reproducing the test evidence

    export PATH=<swift-6.0.3 toolchain>/usr/bin:$PATH
    KG_SWIFT_TEST_WORK=/tmp/kg-swift-work \
      bash tools/run-swift-portable-tests.sh
    cd control-plane && pytest tests/test_filter_rules.py -q
    pytest tests -q   # full suite; expect 496 passed / 3 pre-existing

## 9. Review history

Eleven independent-review rounds were incorporated; the reproducing
test attachments (`IndependentReviewRegressions`,
`SecondReviewRegressions`, `FourthReviewRegressions`,
`FifthReviewRegressions`, `SixthReviewRegressions`) were adapted
into the portable suite, some in stricter form. Round 7 added the
tombstone (durable fresh-vs-invalidated state), envelope authority
binding with a per-flow reader pin, the floor content digest
(immutable published revisions), atomic rename-based artifact
install, sign-in attempt-token + conditional session rotation +
attempt-conditioned cleanup, local-first sign-out, and an owned,
generation-guarded control-provider task/timer. Round 8 moved
sign-in and managed-configuration orchestration into portable,
XCTested types (SignInCoordinator: exclusive in-flight + atomic
credential bundle; ConfigurationApplier: the invalid -> valid
recovery path), made the prefilter cache identity-bound, removed
the prefilter on every rule-path invalidation, and added explicit
cancellation checks in syncNow. Round 9 bound the credential
bundle to the lifecycle authority (gated rotate-and-write
transaction, nonce checked before any request), moved sign-in
admission before the first network call, consolidated all
credential/config lifecycle through one shared actor, moved cache
removal into the locked lifecycle transactions, and corrected the
rules-commit cancellation check to fire before apply(). Round 10
made captured configurations non-authoritative: the lifecycle
owner re-reads the managed-configuration source at execution time
(coalescing rapid pushes), the sync controller is built from the
post-adoption re-read, and sign-in admission is gated against the
current source. Round 11 gated remote logout on a provably bound
client (origin captured before the await, compared against the
bundle's session origin by the coordinator). One reviewer probe
(inode-bypass via timestamp precision) was not reproducible as
written; the underlying wrong attribute (`.systemNumber`) was real,
was fixed to `.systemFileNumber`, and is covered by a
same-size/mtime atomic-replacement test. Round-4 wording findings
about this report (invented resolver-fleet claims, crediting added
files to base, guardian-cookie mislabel, whole-package build claims,
categories-blocker mischaracterization) are corrected in this
rewrite; sections 1-8 above are the current truth.

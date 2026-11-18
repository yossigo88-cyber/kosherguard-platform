# Stage 14 review: personal-iPhone lane (URL Filter + PIR + policy sync)

Date: 2026-11-18. Branch: `stage-12-free-ios-build`. All SHAs and run URLs
below were verified live (`git rev-parse` / `git ls-remote` / GitHub API) at
write time; nothing is reconstructed from abbreviations.

## What this stage built

A safe, code-side implementation of KosherGuard's personal (unsupervised)
iPhone lane on iOS 26+:

1. URL Filter website filtering wired to a real dataset pipeline (server-side
   export -> device fetch -> extension reload), not placeholder hosts.
2. Category rules + allow/block lists through a canonical policy parser
   (`filtering-engine/src/policy_engine.py`), with loud publish-time refusal
   of every policy shape the lane cannot express (see Limits).
3. Real Apple PIR round trip: `apple/pir-service-example` (pinned
   `bbb215355b87be40e081756d072f29cd8f9f000b`) serving the KosherGuard
   NEURLFilter export and answering actual PIR queries on free CI, base and
   update modes.
4. Backend auth + policy sync: device registration, session/device
   credentials, publication watch, revocation feed with atomic snapshots.
5. Dashboard changes reaching the iPhone: automatic
   publication -> dataset-serve chain (`80d28f5c...`), dataset hot-reload
   without restart (`55352975...`), freshness/error status surfaced in the
   app UI (`ca4159dc...`, `160ee90f...`, `b6c7faaf...`).
6. Consent-based Family Controls app shielding (`.child` authorization path,
   `b75c3f1f...`).
7. Enable/disable and failure handling: explicit URL Filter enable/disable
   with system readback (`15cd87c6...`); enable refuses undeployable
   placeholder PIR endpoints (`24c141cd...`); background refresh expiry fails
   to a safe state rather than pretending freshness (`17de1527...`).

## Commits (stage-14 range, oldest first)

- `fac70dc4bff2ce588a378ed476af61da18680ac7` batch 1: personal-lane configuration, discovery, idempotent device registration
- `08950f23f4268afae23a4654df961068d8b885e3` batch 1 review corrections (session cleanup, name-conflict recovery, host-only PIR URLs, parser regression tests)
- `5adbb194aa519000855754a0f024af263bcc6cae` connected personal-lane E2E (register -> publish -> assign -> rules -> mint -> real fetch -> republish -> offboard)
- `b92e932e60be2fd86541c7127cc379a6c8694514` E2E revocation re-spend refusal
- `ac1238abf3a92f7682093f714a595d7534486d94` revocation feed: atomic immutable snapshots
- `17de152732912d8594c0ec054fd36fb2e2f7b4b3` background policy refresh + use-time expiry
- `344fa8a94a2704acf9a1f183f3f08e8a0412cf13` PIR interop CI: pin ubuntu-24.04
- `c75887bfd502d1ef89c958c86296d1c33e71a397` deploy/pir: build Apple's tools from source, device-only export binding
- `24c141cdd226b08868d76c22388da133662782ab` enable refuses placeholder PIR endpoints
- `feced2a760189fb7596354d8aed2fa85eeb908c1` PIR interop CI corrections + www canonicalization
- `15cd87c6f2e767ab8a094370497fa8356e613992` explicit URL Filter enable/disable + system readback
- `612019f3a28fffe79945ca3637a5c9718cf47511` device key-set semantics: refuse unexpressible ancestor exceptions, unify Bloom + PIR keys
- `b75c3f1f2e45343eb46f435081b4fc41a82bb5db` consent-based Family Controls .child authorization
- `5535297513263e261eeec938954ae37285cd6c0b` dataset hot-reload without restart
- `8999d300619b40debdaec3cbd862ea0dc811d2b5` verify_pins workspace-state parsing fix
- `80d28f5cdaa6795c559970187e11de2b4b55bfc0` automatic publication -> dataset-serve chain with PIR export hook
- `dffb043d5ff1bee7ef7a77ec5e58b408b5609c2a` iOS compile fix (await hoisting)
- `bb1f7fa27e817971f17f56aeb70a72f2a5067644` canonical policy parser, staged activation, per-device divergence refusal
- `da524ad56e1767d07e6c575afa8691f370e4998a` interop install YAML fold fix
- `ca4159dcbd7367b93c18357a7a4a3f9ba4229055` dataset status endpoint + app model
- `55ba295d899ca374f6cc4b82929eef0b8272220e` timed-schedule refusal, canonical field inventory, partial-activation order test
- `d9a162b3a5c891f11474cf9d04ec1b9b91d5a93e` parser strictness, portable guard, silent-pass guards
- `160ee90f4ba50f2d0957f6bdd9a8ec34f35088dd` app-visible dataset status + portable suite in CI
- `b6c7faaf4cd43db57945636c766b1da690446f48` privacy: credential-safe status (public_status, no operator detail)
- `5495517ef2b4b3538c0ec6375cec7e8b482535da` interop chdir platform split (superseded)
- `2029730cbc58f2aae77c5426a2dd0077948b8db6` portable CI macOS 12 target (superseded)
- `10c7eeaeb8018e7f496a273c9c44b7cc156ef663` portable CI macOS 13 target
- `4fed85be6bfb848e3cfcc9b83ea13d25ed376b79` deterministic multi-definer guard + CWD postcondition
- `4b82b1ca621d973cb39e103975b19e69a0033258` try-#require root-cause fix + full evidence logging

Commit URLs: `https://github.com/yossigo88-cyber/kosherguard-platform/commit/<full-sha>`.

## Test evidence (exact counts, no hidden skips)

- url-filter-server: 95 passed / 0 failed (95 collected).
- control-plane: 558 passed / 0 failed (run in two halves, 275 + 283, due to
  the sandbox exec cap; both halves green).
- Portable Swift suite: 177 executed / 177 passed / 0 failed / 0 skipped, in
  enforced script mode (`tools/run-swift-portable-tests.sh`: KG_REPO_ROOT is
  set by the script itself and any skip is fatal, so the 161+16-skips
  silent-pass class cannot recur). CI evidence, all three jobs green on
  macOS: run 44240484150
  (https://github.com/yossigo88-cyber/kosherguard-platform/actions/runs/44240484150).
- Personal-lane E2E: 1/1 (register -> publish -> assign -> rules -> mint ->
  real url-filter-server fetch -> republish -> offboard invalidation).
- Apple PIR interop: see next section.

## Apple PIR query evidence (first actual round trip)

- Run 44238729494: first green round trip on `5495517e...`. Log markers:
  `PIR-LOOPBACK-RESULT: PASS (mode: base)` and
  `PIR-LOOPBACK-RESULT: PASS (mode: update)`.
  https://github.com/yossigo88-cyber/kosherguard-platform/actions/runs/44238729494
  Independent read-only verification of that run's 20 steps: base and update
  round trips (1 interop test each), parameter pins, PrivacyPass issuance,
  invalid-token 401 boundary, and a real SIGHUP dataset reload of the running
  server.
- Run 44242647306 (on `4b82b1ca621d973cb39e103975b19e69a0033258`):
  repeats the round trip with the root-caused `try #require` fix and prints
  every `PIR-` evidence line (per-keyword query results) into the job log.
  Green, with the complete per-keyword base/update, auth-boundary, SIGHUP
  reload and pin evidence present in the log (independently re-verified).
  https://github.com/yossigo88-cyber/kosherguard-platform/actions/runs/44242647306
  iOS unsigned build on the same tip (all three jobs green, portable suite
  included): run 44242647317
  (https://github.com/yossigo88-cyber/kosherguard-platform/actions/runs/44242647317).

Tested code vs this report: every green run above tested the tree at
`4b82b1ca621d973cb39e103975b19e69a0033258`. The commit that adds this
document changes only `docs/reviews/` and carries `[skip ci]`; no code
moved after the tested tip.
- The PIR service under test is Apple's own example, which Apple marks as not
  for production use. The OHTTP relay that would hide device IPs from the PIR
  service requires Apple approval and is NOT part of this evidence.

## Failure history (corrected; no false narratives)

Retained failed CI runs, each diagnosed from raw logs:

- 44233095317 / 44233095365: iOS compile errors (await hoisting; fixed in `09ab1596...` / `dffb043d...`).
- 44233884945 / 44234394372: PIR workflow runner-image and pin issues (fixed in `e6456541...` / `8999d300...` / `feced2a7...`).
- 44234330969: YAML flow scalar folded the `cp` continuation in the interop install step (`da524ad5...`).
- 44235948698 / 44237436996 / 44240484269: one root cause, finally
  source-verified: swift-testing's `#require` expands to
  `__check*(...).__required()` and `__required()` throws, so a bare
  `#require(...)` never compiles - `try #require(...)` is required. The
  `changeCurrentDirectoryPath` call itself compiled fine throughout; it is a
  non-throwing `Bool` on both platforms (swift-foundation at
  swift-6.1-RELEASE). Two intermediate diagnoses (throws-on-Linux; macro
  artifact) were wrong and are corrected here. Fix: `4b82b1ca...`, verified
  by local reproduction (bare form fails to compile; `try #require` compiles
  and the test passes).
- 44238188558 / 44238729456: new portable-tests job failed on macOS
  deployment target: the generated SPM manifest declared no `platforms:`,
  gating `Task` / `URLSession data(for:delegate:)` (fixed: macOS 12 in `2029730c...`).
- 44239179844: second availability layer: `URL.host(percentEncoded:)` is
  macOS 13+ (fixed in `10c7eeae...`).
- 44239887765: `testXcodeTargetSourceMembershipClosure` was nondeterministic:
  its type registry keyed one defining file per type name with
  filesystem-order overwrite, so three nested `State` enums made the verdict
  depend on directory enumeration order (passed Linux ext4, failed macOS
  APFS). Fixed deterministically in `4fed85be...`: the registry keeps every
  defining file; a reference is satisfied when any definer is a target
  member, which is all lexical analysis can prove. Mutation-checked: a
  genuine violation is still flagged.

Correction to an earlier claim: a previously reported "174/174 all pass" for
the portable suite was a hidden-skips artifact (`swift test` with a filter
matching nothing exits 0; 16 tests were skipped). Guards now make any skip
fatal in both the local script and CI, and the honest totals are the ones in
the Test evidence section.

## Limits - this lane is NOT code-complete

Deliberate, tested refusals (a safety subset, not silent drops):

1. Per-device policy divergence and per-device exception overlays are
   refused at publish time: one membership dataset cannot express them.
2. Block-default posture is unexpressible: the URL Filter dataset is
   membership-only (presence = block); there is no allow channel.
3. Timed schedules (`_schedules`) are refused loudly.
4. Ancestor-block + descendant-allow is unexpressible (no exceptions channel)
   and refused; whether this constraint is accepted as product behavior is a
   pending owner decision.
5. Staged activation (PIR export + regen hook before serving swap) is NOT
   atomic: residual directions are documented in `publication_watch.py`, and
   after a hook failure the PIR backend state is UNKNOWN (last good dataset
   keeps serving; retry next poll).
6. The dataset-status UI path is compile-verified only; it has not been
   visually verified on a device or simulator.
7. Apple's PIR example is marked by Apple as not for production; the OHTTP
   relay is approval-gated. Nothing here has run on a real device:
   NEURLFilter end-to-end requires signing + a device, which is not granted.

## Open owner decision: preserve full requirements or ship a reduced subset

The dataset on this lane is a single membership set (presence = block), so
the CURRENT DESIGN cannot express: per-device policy divergence, per-device
exception overlays, a block-default posture, timed schedules, or
ancestor-block + descendant-allow. The code refuses each loudly at publish
time (tested refusals) rather than silently approximating.

Boundary of this stage's evidence: whether any OTHER iOS mechanism could
express these requirements was not investigated or verified here. This stage
establishes only what the current dataset design cannot do; it does not
establish that these features require supervision, MDM, or any particular
alternative primitive, and no such claim should be read from this document.

The decision, which belongs to the owner and is NOT made here:

1. Ship the reduced subset: the personal lane ships with the loud refusals
   as accepted product behavior. This is a scope reduction relative to the
   original requirements and needs the owner's explicit approval.
2. Preserve the requirements: commission grounded research into which iOS
   primitives (if any) can express each requirement, with OS API/source
   evidence, before any further commitment.

Unvalidated research leads if the owner chooses to preserve requirements
(leads only - viability unknown, none verified by this stage): per-device
dataset variants (whose privacy impact on the PIR anonymity set is itself
unquantified here and would need grounding before any claim either way);
publish-time expansion of finitely enumerable descendant-allow lists;
other OS primitives outside the URL Filter dataset.

## Changed-file inventory (stage-14 range, 51 files, +6258/-171)

- Workflows: `.github/workflows/ios-unsigned-build.yml`,
  `.github/workflows/pir-local-interop.yml`
- control-plane: `alembic/versions/0029_device_registration_key.py`,
  `app/config.py`, `app/main.py`, `app/models.py`,
  `tests/test_migrations.py`, `tests/test_personal_lane_e2e.py`,
  `tests/test_personal_registration.py`,
  `tests/test_publication_watch_fixture.py`
- deploy: `kosherguard-url-filter.service` (config only),
  `pir/Dockerfile`, `pir/README.md`, `pir/prepare-dataset.sh`
- iOS: `Configuration/App-Info.plist`, `KosherGuard.xcodeproj/project.pbxproj`,
  `README.md`, `Sources/KosherGuard/AppBlockingView.swift`,
  `Sources/KosherGuard/AppShieldController.swift`,
  `Sources/KosherGuard/BackgroundRefreshScheduler.swift`,
  `Sources/KosherGuard/KosherGuardApp.swift`,
  `Sources/URLFilter/BackgroundRefreshPolicy.swift`,
  `Sources/URLFilter/ClientConfigClient.swift`,
  `Sources/URLFilter/FilterSyncController.swift`,
  `Sources/URLFilter/PIREndpointPolicy.swift`,
  `Sources/URLFilter/PersonalConfiguration.swift`,
  `Sources/URLFilter/PersonalRegistrationClient.swift`,
  `Sources/URLFilter/PersonalSetupCoordinator.swift`,
  `Sources/URLFilter/PrefilterUpdater.swift`,
  `Sources/URLFilter/URLFilterConfiguration.swift`,
  `Sources/URLFilter/URLFilterPrefilterSource.swift`
- tools: `pir-interop/KosherGuardInteropTests.swift`, `pir-interop/README.md`,
  `pir-interop/export_fixture_dataset.py`, `pir-interop/verify_pins.py`,
  `run-swift-portable-tests.sh`, `swift-portable-tests.swift`,
  `test_validate_ios_project.py`, `validate-ios-project.py`
- url-filter-server: `app/__main__.py`, `app/dataset.py`, `app/pir_export.py`,
  `app/publication_watch.py`, `app/revocations.py`, `app/server.py`,
  `tests/fixtures/published/categories.json`,
  `tests/fixtures/published/policy.json`, `tests/test_publication_watch.py`,
  `tests/test_reload.py`, `tests/test_revocations.py`,
  `tests/test_url_filter.py`

## What was NOT done (authorization boundaries)

No signing, no deploys, no purchases, no Apple capability registration, no
device changes; all work stayed on `stage-12-free-ios-build` (main, stage-10,
stage-11 untouched).

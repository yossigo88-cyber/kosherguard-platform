# PIR local interop (Stage 14)

Verifies the KosherGuard PIR dataset path against Apple's real PIR
stack - no mock, no reimplemented cryptography - on a free standard
GitHub-hosted Ubuntu runner. See
`.github/workflows/pir-local-interop.yml` for the executable form.

## Pieces

| File | Role |
| --- | --- |
| `export_fixture_dataset.py` | Emits a deterministic fixture dataset with the REAL exporter (`url-filter-server/app/pir_export.py`). Base rules plus an `--update` row for the dataset-update case. |
| `KosherGuardInteropTests.swift` | swift-testing file copied into the pinned `apple/pir-service-example` checkout (`Tests/PIRServiceTests/`) by the workflow. Runs Apple's own `PIRServiceTesting.PIRClient` against Apple's own server application over real loopback HTTP (HummingbirdTesting `.live`), serving the processed KosherGuard dataset. Contains no cryptography and reimplements no protocol piece. |
| `verify_pins.py` | Fails the job if SwiftPM's actual checkouts drifted from the pinned `Package.resolved` revisions (the swift-homomorphic-encryption pin is a branch pin and could otherwise move silently). |

## Source pins

- Service + client: `apple/pir-service-example` @
  `bbb215355b87be40e081756d072f29cd8f9f000b` (the pin recorded in
  `deploy/pir/Dockerfile`). Its `Package.resolved` pins every
  transitive dependency, including
  `apple/swift-homomorphic-encryption` (release/1.1) @
  `992cbe5a62938ca171e2e93a996c1e0d37f89a39`.
- Dataset tool: `PIRProcessDatabase` built from that exact
  swift-homomorphic-encryption revision (extracted from
  `Package.resolved` in the workflow, not hardcoded).
- RLWE parameters: `n_4096_logq_27_28_28_logt_5`, per Apple's
  documented NEURLFilter testing instructions (example value, not a
  tuned production parameter choice).

## What a green run proves

1. The real device export (`export_device_textpb`) textpb is accepted
   by Apple's `PIRProcessDatabase`.
2. Apple's client completes the full private-query protocol against
   the KosherGuard device dataset over real HTTP: Privacy Pass token
   issuance, `/config`, evaluation-key upload, encrypted `/queries`,
   decrypted response.
3. DEVICE presence semantics round-trip exactly (Apple's
   NEURLFilterDataFormat.md at the pin: a present keyword is a block;
   the value is the ignored placeholder "1"): `blocked-example.com`
   -> present, `ads-tracker.example` -> present (exporter
   case-normalization survives the whole pipeline), and the security
   boundary: `allowed-example.com` (allow-only) and
   `precedence-example.com` (explicit allow beats a category block)
   are ABSENT - on device, presence would block them.
4. Dataset update: after re-export + reprocess, a fresh service load
   returns a present result for `newly-blocked.example`, and the
   compiled `PIRService` binary serves the new config after SIGHUP.
5. Auth boundaries on the real binary: unauthenticated `/report` and
   `/queries` are rejected with 401; an unknown user token is rejected
   at `/issue` with 401.

## What it does NOT prove

- On-device NEURLFilter behavior (needs a supervised device, the
  approved url-filter-provider entitlement, CloudKit Identity & Trust
  registration of `com.kosherguard.app.url.filtering`, and Apple's
  OHTTP relay approval - all outstanding, tracked in docs/reviews).
- The OHTTP gateway/relay hop - the query here is direct loopback HTTP
  to the PIR service, the same arrangement Apple's own testing
  instructions use before a device is involved.
- Production readiness: Apple's README says pir-service-example
  "should not be run in production". This is a protocol-correctness
  reference, not production infrastructure.
- Performance at real dataset sizes (the fixture is 3-4 rows; the
  cuckoo table and shard parameters come from Apple's documented
  example values).
- Nothing beyond release-configuration correctness on Linux: the
  workflow builds release, mirroring Apple's own CI for this
  repository (their CI runs `swift test --configuration release` on
  Linux).

## Value format: device dataset semantics (decided, source-backed)

Apple's NEURLFilter data format (NEURLFilterDataFormat.md in the
pinned apple/pir-service-example) defines presence semantics: "If an
entry is found matching the URL key, it already indicates a match. So
the value for the record is simply set to the integer 1 serving as
place holder." A keyword PRESENT in the device dataset is BLOCKED;
the system ignores the value.

The device export (`export_device_textpb`) therefore:

- emits BLOCK rows only, with Apple's placeholder value "1";
- applies allow-over-block precedence per normalized keyword (the
  on-device engine's explicit-allow-beats-block order): a keyword
  with any allow rule is excluded even when a category block also
  names it - emitting it would block an explicitly allowed site;
- collapses duplicate block keywords.

The generic verdict-string export (`export_textpb`, values like
`block:<category>` / `allow`) remains for non-device consumers only
and is never a valid NEURLFilter dataset. The security invariant is
pinned by `TestPIRDeviceExport` in
`url-filter-server/tests/test_url_filter.py` and by the absent-host
assertions in the interop test.

## Corrections this work makes to `deploy/pir/`

- `deploy/pir/Dockerfile` runs
  `swift build --product PIRShardDatabase/PIRProcessDatabase` inside
  the pir-service-example checkout. At the pinned commit those are NOT
  products of pir-service-example (its products are `PIRService` and
  `ConstructDatabase`); the tools are products of
  `apple/swift-homomorphic-encryption` and must be built from a
  checkout of that repository at the revision pinned in
  `Package.resolved`. The Dockerfile as written cannot build them.
- `deploy/pir/prepare-dataset.sh` uses a two-step
  PIRShardDatabase -> PIRProcessDatabase flow. Apple's pinned NEURLFilter
  testing instructions use PIRProcessDatabase alone with a JSON config
  (`sharding` controls shard splitting). The workflow uses the
  documented one-step flow.

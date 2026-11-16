# Milestone 5 Review - Filtering enforcement surfaces

## Scope

URL filter server (Bloom prefilter + dataset + HTTP API), iOS Swift
sources, iOS Xcode project structure, APNs certificate lifecycle
(spec Part 7), PIR/OHTTP deployment layer.

## Status: IMPLEMENTATION CHECKPOINT - not complete

## What was built and verified

### url-filter-server (Python)
- Bloom filter prefilter, dataset model, HTTP dataset/verdict API.
- `pir_export.py`: exports the dataset in Apple's keyword-PIR textpb
  input format, grounded in apple/swift-homomorphic-encryption docs
  (PIRShardDatabase example) and the generated
  `apple.swift.homomorphic.encryption.pir.v1` schema.
- Tests: 16 passing locally (tree: local HEAD adfb27e, which matches
  published content; published-tree verification deferred to final
  fresh-clone run). Coverage: golden format, round-trip, escaping,
  empty-keyword rejection, dataset integration, plus the original 11
  prefilter/server tests.

### APNs (spec Part 7) - mdm/apns.py
- Push certificate lifecycle: CSR generation, upload/renewal tracking,
  expiry state machine, per-device push token registry.
- 14 tests passing locally. No real Apple credentials or connection
  involved or authorized; lifecycle artifacts and states only.

### iOS
- 8 Swift sources (app, filter extension, URL filter integration):
  UNCOMPILED, UNSIGNED, UNTESTED - no Swift toolchain, no Apple
  Developer account, no device.
- Xcode project structure added this milestone:
  `ios/KosherGuard.xcodeproj/project.pbxproj` (app target +
  filter-data extension target, embed phase, target dependency),
  `ios/Configuration/` Info.plists and entitlements. All hand-authored,
  UNVERIFIED - never opened in Xcode. The extension entitlement file
  carries `com.apple.developer.networkextension.url-filter-provider`,
  which needs Apple approval before distribution builds.

### PIR/OHTTP deployment layer - deploy/pir/
- Integrated Apple's vetted service instead of inventing protocol
  code: `apple/pir-service-example` pinned at commit
  bbb215355b87be40e081756d072f29cd8f9f000b (PIRService on Hummingbird,
  swift-homomorphic-encryption release/1.1, Privacy Pass issuer).
- Dockerfile (swift:6.1 build) + prepare-dataset.sh (our textpb export
  -> Apple PIRShardDatabase -> Apple PIRProcessDatabase).
- UNVERIFIED: never built (no Swift toolchain here). Apple's README
  warns the example "should not be run in production" - production
  readiness is an open review item.

## Explicitly NOT implemented (honest gaps)

| Item | State | What unblocks it |
| --- | --- | --- |
| OHTTP gateway | UNIMPLEMENTED - no vetted implementation selected | Implementation selection + build |
| OHTTP relay | BLOCKED | Apple approval (external) |
| PIR production readiness | OPEN REVIEW | Apple's example is reference-grade |
| iOS compile/sign/device test | BLOCKED | Xcode + Apple Developer account + supervised device |
| APNs live push validation | BLOCKED | Real Apple credentials (not authorized) |

## Unresolved issues

- Published-tree test re-verification for the newest files is folded
  into the final fresh-clone verification (M7); claims above are local
  tree only.
- project.pbxproj is hand-authored and may need regeneration once
  Xcode opens it; treat as structure-for-review.
- Per-device authenticated identity for dataset distribution and the
  admin category/domain management tools (approved seed-data fallback)
  remain outstanding from earlier milestones.

## Changed files this milestone

- url-filter-server/app/pir_export.py (new)
- url-filter-server/tests/test_url_filter.py (+TestPIRExport)
- mdm/apns.py, mdm/tests/test_apns.py (new, earlier commit)
- ios/KosherGuard.xcodeproj/project.pbxproj (new)
- ios/Configuration/{App-Info.plist,App.entitlements,FilterExtension-Info.plist,FilterExtension.entitlements} (new)
- deploy/pir/{Dockerfile,prepare-dataset.sh,README.md} (new)

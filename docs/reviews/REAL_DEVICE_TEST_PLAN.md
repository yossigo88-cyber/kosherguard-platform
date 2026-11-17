# Real-device test plan: website filtering, app blocking, policy updates, removal protection, failure handling

Stage 11 (2026-11-17), objective 8. This plan is written to be executed
in order; each phase's PASS evidence is the entry ticket to the next.
Nothing here has run yet: every iOS target is UNCOMPILED for iOS as of
this writing (first compile is Phase 0). No real-device claim may be
made until the phase covering it passes on hardware.

Devices needed (minimum): one spare iPhone that may be supervised and,
if supervision is via Apple Configurator, erased - with the user's
explicit approval first. A second unsupervised iPhone for the
personal/Screen Time path is strongly recommended.

## Phase 0 - Compile gates (no device)

| # | Test | Pass criteria | Evidence |
| --- | --- | --- | --- |
| 0.1 | Static project validation | `python3 tools/validate-ios-project.py` exits 0 | CI log |
| 0.2 | Unsigned SDK compile (GitHub macos-26, Xcode 26.6) | `ios-compile-check.yml` job green: app + 4 extensions build | Actions run log + xcodebuild.log artifact |
| 0.3 | Portable Swift suites | 136/136 unchanged | tools/run-swift-portable-tests.sh output |
| 0.4 | Server suites unchanged | control-plane 518, mdm 136, url-filter-server 50 | CI/local run logs |

## Phase 1 - Signed development build (Mac + free or paid account)

Prereq: real Team ID applied (tools/apply-apple-team-id.sh), App IDs
and App Group registered, Network Extension managed values GRANTED by
Apple (without this, filter extension signing fails - expected and
documented, not a build failure).

| # | Test | Pass criteria |
| --- | --- | --- |
| 1.1 | `xcodebuild -scheme KosherGuard -destination 'generic/platform=iOS' -allowProvisioningUpdates build` on the Mac | All 5 targets sign; entitlements match the granted profile (`codesign -d --entitlements -` on each .appex) |
| 1.2 | Install on device via Xcode | App launches; "Not configured by MDM" state shows (managed config absent) |
| 1.3 | App group + keychain sharing | App writes rule snapshot; extensions read the identical generation (log both sides) |

## Phase 2 - Website filtering (supervised device)

Prereq: device supervised (ADE or Configurator), MDM-enrolled, managed
app configuration pushed (server URL, device ID, PIR pair).

| # | Test | Pass criteria |
| --- | --- | --- |
| 2.1 | Enable NEFilterManager config from the app | System Settings shows the content filter active |
| 2.2 | Explicit blocked domain | Safari load fails closed; block observed for Safari AND a third-party browser AND an in-app WKWebView |
| 2.3 | Explicit allowed domain inside blocked parent | Allow wins per engine semantics |
| 2.4 | Unmatched host under default policy | defaultPolicy enforced (document which way it is set) |
| 2.5 | URL Filter path (iOS 26+, after PIR onboarding) | NEURLFilterManager enabled; prefilter fetched from the persisted artifact only; blocked category URL fails in Safari (WebKit/URLSession coverage only - document the known coverage limit) |
| 2.6 | DNS proxy path | NEDNSProxyProvider active; resolution for blocked name fails; allowed name resolves |

## Phase 3 - App blocking (both device classes)

| # | Test | Device | Pass criteria |
| --- | --- | --- | --- |
| 3.1 | Profile deny list (iOS 15-26) | supervised | Push `blockedAppBundleIDs` with a known App Store app: icon hidden/unlaunchable within seconds of the MDM command; removal restores it |
| 3.2 | DDM DeniedApps (iOS 27+) | supervised + ADE | Same observable result via `app.settings`; verify the deprecated profile keys are NOT emitted for iOS 27 devices |
| 3.3 | Screen Time shield set | personal | Local FamilyActivityPicker selection; server activates/pauses ONLY the chosen set; shield appears on launch; user revocation in Settings immediately wins over the server state |
| 3.4 | Launch vs network distinction | supervised | With launch blocking OFF and network filter ON for the same app: app opens, traffic fails. Documented as two separate states in the dashboard |

## Phase 4 - Policy updates

| # | Test | Pass criteria |
| --- | --- | --- |
| 4.1 | Dashboard publish -> device | Change policy, publish generation N+1; device reflects it after MDM push / next sync within the documented cadence |
| 4.2 | notifyRulesChanged propagation | Control provider detects the store change; data provider serves the NEW generation with no filter restart |
| 4.3 | Monotonic generations | Pushing generation N after N+1 is rejected (no rollback) |
| 4.4 | Identity binding | Snapshot minted for device A is refused on device B (foreign identity -> fail closed) |

## Phase 5 - Removal protection (supervised only)

| # | Test | Pass criteria |
| --- | --- | --- |
| 5.1 | MDM profile removal | Locked/ADE non-removable enrollment: Settings offers no removal |
| 5.2 | App deletion of the filter app | Per supervision policy (allowAppRemoval=false) deletion is blocked; filter persists |
| 5.3 | Personal path honesty check | On the unsupervised phone, document that the user CAN delete the app and revoke authorization - this is expected, not a bypass |

## Phase 6 - Failure handling

| # | Test | Pass criteria |
| --- | --- | --- |
| 6.1 | Offline past snapshot expiry | Airplane mode beyond the snapshot lifetime: fail-closed verdicts, only bootstrap infrastructure hosts pass |
| 6.2 | Corrupt store | Damage the app-group snapshot out-of-band: last-known-good inside its expiry window, then fail closed; no crash |
| 6.3 | First device lock | Rule persistence across the first lock (after-first-unlock data protection): filtering keeps working immediately after locking |
| 6.4 | Sign-out | All identity files incl. the app-policy mirror are removed; shield state returns to UNKNOWN; a late in-flight policy fetch cannot resurrect the old gate (Stage 10 v10 fix, verify on hardware) |
| 6.5 | Server down at sync time | Prior valid snapshot keeps serving within expiry; UI reports stale state honestly |
| 6.6 | 401 on credential mint | Stored session deleted; UI returns to sign-in (no loop) |

## Phase 7 - Evidence and sign-off

For every phase: capture device screen recordings/photos, MDM command
logs, and the exact build SHA + signing identity + entitlement dump.
Update the stage report marking each item VERIFIED-ON-DEVICE with the
evidence link. No item may be claimed from simulator or compile
evidence alone.

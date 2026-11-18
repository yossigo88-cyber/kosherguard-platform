# Stage 15 investigation: preserving the full filtering requirements

Date: 2026-11-18. Branch: `stage-12-free-ios-build`. This document is
investigation and design only: no production code changed, no architecture
chosen, no deployment performed. It answers the owner's 2026-11-18 instruction:
the reduced feature subset is NOT accepted; investigate alternative
architectures for the four capabilities the URL Filter lane cannot express,
with tradeoffs, before any implementation choice.

All Apple claims below cite primary sources fetched 2026-11-18
(developer.apple.com, support.apple.com, github.com/apple/pir-service-example
at the pinned commit `bbb215355b87be40e081756d072f29cd8f9f000b`, and
github.com/apple/device-management at branch `release`). Claims about this
repo's behavior cite code and test runs at the stated SHAs.

## 1. Requirement matrix: implemented vs outstanding

"Implemented" means code exists in this repo with passing tests at
`772cdb9b20af45b0bfdb2459c302cfae0ff869b6` (docs tip; tested code tip
`4b82b1ca621d973cb39e103975b19e69a0033258`, the two later commits are
docs-only). No requirement below has ever run on a real iPhone.

| # | Original requirement | Where implemented + tested | Where outstanding |
|---|---|---|---|
| R0 | Bulk category blocklist, privacy-preserving, system-enforced web filtering on personal iPhones | URL Filter lane: export pipeline, PIR round trip against Apple's real tools (runs 44238729494, 44242647306), 95/95 url-filter-server tests (re-run locally at docs tip: 95 passed), portable Swift 177/177 in CI (run 44242647317) | No real-device run (needs signing + device); PIR service is Apple's non-production example; OHTTP relay onboarding not started |
| R1 | Different policies and exceptions per device | DNS edge: authenticated per-device DoH identity (`dns-edge/doh_identity.py`), per-device policy selection (`dns-edge/device_policy.py`), delegated exception overlay with baseline floor (`dns-edge/policy_bundle.py`); 87/87 dns-edge tests pass locally at docs tip | Not expressible on the URL Filter lane (single shared dataset); per-device behavior on the device lane needs one of the alternatives in section 4 |
| R2 | Default-block (allowlist-only) posture | DNS edge: engine `default_policy: block` (`filtering-engine/src/policy_engine.py`), 337 filtering-engine tests pass locally at docs tip | URL Filter lane: unexpressible (membership-only dataset). Screen Time alternative exists (4.A) |
| R3 | Timed filtering schedules | DNS edge: weekly time-window schedules, allowlist always wins (`dns-edge/schedules.py`), incl. dated schedules tests (25 tests in `test_schedules.py` + 3 in `test_dated_schedules.py`, all passing) | URL Filter lane: refused loudly (dataset has no time dimension). Screen Time alternative exists (4.A/4.B) |
| R4 | Block a parent domain while allowing specific subdomains | Engine semantics: explicit allowlist beats blocklist, entries cover subdomains (`policy_engine.py` precedence 1-5) — so the DNS edge expresses this today | URL Filter lane: unexpressible and refused loudly (see 3.2) |
| R5 | Production-ready PIR service | Not implemented. Apple's example is pinned and interop-tested, but Apple marks it non-production (section 5) | Entire production hardening + Apple onboarding outstanding |
| R6 | Reliable dataset activation and recovery | Partially: hot reload without restart, last-good retention, publication watch (95/95 tests) | Staged activation is non-atomic; post-hook-failure PIR state UNKNOWN (Stage 14 limit 5). Design proposal in section 6 |
| R7 | Automatic background refresh within iOS scheduling limits | Partially: BGAppRefresh wiring compiles; expiry fails safe (Stage 14) | iOS discretion is a hard bound; better primitives identified (section 7) |
| R8 | Real service endpoints instead of placeholders | Not implemented: placeholders remain by design; enable-time refusal guards them (Stage 14) | Requires owner's deployment decision (section 8); nothing deployable without approval |

## 2. Correction of the Stage 14 evidence boundary

Stage 14 correctly established that the CURRENT URL Filter dataset design
cannot express R1-R4. It did not establish - and no finding in this
investigation establishes - that Apple universally prohibits these features
on personal iPhones. In fact:

1. **This repo already implements all four on the DNS edge layer**, with
   tests passing at the docs tip (87/87 dns-edge, locally re-run). The gaps
   are specific to the on-device URL Filter lane.
2. **Apple's Screen Time API provides primitives for three of the four on
   unsupervised devices** (section 4.A), and a full programmatic filter for
   child devices (4.B).

## 3. What the URL Filter lane can and cannot express (primary sources)

### 3.1 Verified Apple semantics

- The URL Filter examines all URL requests sent via WebKit and URLSession;
  the system consults an on-device Bloom prefilter first, then queries the
  vendor's PIR server on prefilter hits; a PIR match blocks the URL.
  (https://developer.apple.com/documentation/networkextension/url-filters.md)
- The dataset is a set of URL keys; presence means block, and the record
  value is a placeholder integer `1`.
  (github.com/apple/pir-service-example, `Sources/PIRService/PIRService.docc/NEURLFilterDataFormat.md`)
- The system enumerates sub-URLs by walking up both the domain and path
  hierarchies (default parsing excludes the scheme and the `www` subdomain;
  configurable from iOS 27 via `NEURLFilterManager.ParsingConfiguration`).
  (https://developer.apple.com/documentation/networkextension/neurlfiltermanager/parsingconfiguration)
- Neither the Bloom filter nor PIR supports wildcards or regular expressions.
  (https://developer.apple.com/documentation/networkextension/neurlfiltermanager)
- Blocked-URL reporting to the vendor exists as an optional endpoint but "is
  only allowed for supervised devices" - so on the personal lane the vendor
  does not learn blocked URLs, consistent with the privacy model.
  (`Sources/PIRService/PIRService.docc/HTTPEndpoints.md`, pinned commit)
- Coverage bound: WebKit + URLSession only; other apps must voluntarily use
  the `NEURLFilter` participation API (`verdict(for:)`).
  (url-filters.md, above)

### 3.2 Consequences (already enforced in code)

- No allow verdict exists, so R2 (default-block) and R4
  (ancestor-block/child-allow) are unexpressible: enumeration means a block
  key catches every descendant, and there is no negative verdict to carve an
  exception. `url-filter-server/app/pir_export.py::device_block_keywords`
  refuses these at publish time; the refusal is correct behavior for this
  lane.
- R1 (per-device divergence) conflicts with the shared-dataset PIR privacy
  model: the model assumes many clients query one database. Per-device
  databases would shrink the anonymity set; the exact privacy cost is
  UNQUANTIFIED here and no claim is made in either direction.
- R3 (schedules) has no representation in a membership dataset.

## 4. Alternative primitives on personal (unsupervised) iPhones

### 4.A Screen Time API: Family Controls + ManagedSettings + DeviceActivity

Primary sources:

- `ManagedSettingsStore` groups settings; apps apply and delete their own.
  "Restricting web content" includes `WebContentSettings`.
  (https://developer.apple.com/documentation/managedsettings/managedsettingsstore)
- `WebContentSettings.FilterPolicy` (iOS 15+):
  `.specific(Set<WebDomain>)` - "The policy blocks the specified domains",
  **up to 50 web domains**;
  `.all(except: Set<WebDomain>)` - "The system blocks all websites except
  the ones you specify", **up to 50 exceptions**;
  `.auto(_:except:)` - "The system blocks adult content" (iOS 15+);
  `.none`.
  (https://developer.apple.com/documentation/managedsettings/webcontentsettings/filterpolicy,
   .../filterpolicy/all(except:), .../filterpolicy/specific(_:),
   .../filterpolicy/auto(_:except:))
- `WebDomain` can be constructed programmatically from a domain string -
  no FamilyActivityPicker token needed.
  (https://developer.apple.com/documentation/managedsettings/webdomain)
- `ShieldSettings`: shield specific apps/websites (picker tokens) and
  categories of apps/websites, including `.all(except:)` category policies.
  (https://developer.apple.com/documentation/managedsettings/shieldsettings)
- `DeviceActivitySchedule`: calendar-based repeating intervals with optional
  warning time; the `DeviceActivityMonitor` extension receives
  intervalDidStart/intervalDidEnd callbacks. WWDC21: "Device Activity allows
  your app to run code on a schedule or on usage events even when your app
  is not being used." WWDC22 demonstrates exactly the schedule use case
  ("Allow for Evenings" un-restricts a named store on a 5-8pm window and
  re-applies it at window end; named stores compose most-restrictive-wins).
  (https://developer.apple.com/documentation/deviceactivity/deviceactivityschedule.md,
   https://developer.apple.com/videos/play/wwdc2021/10123/,
   https://developer.apple.com/videos/play/wwdc2022/110336/)
- Family Controls authorization: `.individual` (device owner authorizes with
  Face ID/Touch ID) and `.child` (parent/guardian approves). WWDC21: once
  the guardian approves the app, "it cannot be removed from the device
  without guardian approval."
  (https://developer.apple.com/documentation/familycontrols/authorizationcenter,
   WWDC21/10123)
- Distribution requires Apple's approval of the Family Controls
  (Distribution) entitlement via Capability Requests; development use is
  automatic in Xcode.
  (https://developer.apple.com/documentation/familycontrols/requesting-the-family-controls-entitlement.md)

What this layer can carry for the four requirements:

| Req | Screen Time mechanism | Tradeoffs |
|---|---|---|
| R1 per-device | Per-device `ManagedSettingsStore` values driven by server-synced policy (each device applies its own `.specific`/`.all(except:)` sets and shields) | 50-domain cap per policy set; no category-scale lists; enforcement scope across non-Safari WebKit not documented (needs on-device verification) |
| R2 default-block | `.all(except:)` natively | 50 allowed-domain cap; suits an "approved sites only" posture, not a large allowlist |
| R3 schedules | `DeviceActivitySchedule` + monitor extension applying/clearing named stores | Runs even when the app is not used; schedules apply store contents, so the filtered set per window is bounded by the same 50-domain caps |
| R4 parent-block/child-allow | Only in the default-block shape (`.all(except:)` lists the allowed subdomain); no carve-outs inside `.specific` documented | Exact `WebDomain` subdomain matching semantics are not documented; needs on-device verification |

### 4.B Screen Time content filter: NEFilterDataProvider (full programmatic verdicts)

Primary source: Apple TN3134 (Network Extension provider deployment),
content filter provider table:
(https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)

- iOS content filter providers: "supervised devices only" (iOS 9+), OR
  "**apps using Screen Time APIs**" (iOS 15+), OR per-app on managed devices
  (iOS 16+).
- In the Screen Time case, content filters are **only supported on child
  devices**: the user must be signed in as an under-18 child member of an
  iCloud family, the app requests `.child` authorization, and a parent or
  guardian authorizes. Family Controls (Distribution) entitlement approval
  is required before App Store submission.
- `NEFilterDataProvider` receives every new flow and returns pass/block
  verdicts; browser flows (`NEFilterBrowserFlow`) expose the full URL and
  HTTP request/response; socket flows expose hostname-level metadata. The
  data provider sandbox cannot exfiltrate network content; the control
  provider syncs rules into a shared location the data provider reads.
  (https://developer.apple.com/documentation/networkextension/nefilterdataprovider,
   /nefilterbrowserflow)

What this layer can carry:

| Req | Mechanism | Tradeoffs |
|---|---|---|
| R1 per-device | Rules synced per device via control provider into the app group; verdict code evaluates that device's full policy | Child devices only (under-18 iCloud family); rule-sync cadence is app-driven |
| R2 default-block | Verdict code defaults to block with an explicit allow set | Same child-only bound |
| R3 schedules | Verdict code evaluates time-window rules (mirrors `dns-edge/schedules.py` semantics) | Clock use inside the data provider sandbox needs on-device verification |
| R4 parent-block/child-allow | Verdict code implements longest-match with allow-precedence - exactly the reviewed engine's precedence | Same child-only bound |
| Coverage | Browser flows: full URL. Other apps: hostname via socket flows | TLS content is not inspectable; verdicts are per-flow metadata |

This is the only personal-lane primitive found that can express ALL FOUR
requirements at full policy-engine fidelity on-device. Its constraint -
child devices in an iCloud family - matches KosherGuard's stated product
case (parents bringing children's iPhones) but excludes adults managing
their own phone and children outside Family Sharing.

### 4.C Encrypted DNS profile (DoH) + KosherGuard resolver

Primary sources:

- `com.apple.dnsSettings.managed` payload: `supervised: false`,
  `allowmanualinstall: true`, iOS 14+ - installable on unsupervised devices,
  manually or via MDM. **Deprecated in iOS 27.0**; the replacement
  "DNS settings declarative configuration" (iOS 27+) requires no supervision
  but is delivered through Device Enrollment / Automated Device Enrollment
  (MDM channels) per its support page.
  (github.com/apple/device-management, `mdm/profiles/com.apple.dnsSettings.managed.yaml`;
   https://support.apple.com/guide/deployment/dns-settings-declarative-configuration-dep7e19a4b12/web)
- Manually installed profiles are user-removable on unsupervised devices.
  (https://support.apple.com/en-us/102400)

What this layer carries: all four requirements are implemented TODAY in
`dns-edge/` (per-device authenticated DoH, per-device policy, schedules,
engine precedence). Tradeoffs: domain-only granularity (no URL paths);
removable by the child on unsupervised devices; bypassable by VPN apps and
apps with hardcoded DNS; iOS 27 deprecation of the classic payload makes the
long-term install path on personal devices uncertain (the declarative
replacement is MDM-delivered; whether manual install survives is
unverified).

### 4.D MDM built-in Web Content Filter (evidence of a supervised-only shape)

- Apple's own payload schema: as of iOS 16 the web content filter payload
  can be installed on unsupervised devices **only if ContentFilterUUID is
  specified**, and ContentFilterUUID scopes the filter to managed apps
  carrying the same UUID - which requires MDM-managed apps. The built-in
  filter supports a whitelist posture ("Specific Web Sites Only"), allow and
  deny lists (deny list capped at 500 URLs), and substring URL matching.
  (github.com/apple/device-management, `mdm/profiles/com.apple.webcontent-filter.yaml`;
   https://support.apple.com/guide/deployment/web-content-filter-payload-settings-depc77c9609/web)
- Conclusion: the built-in whitelist filter does not deliver general
  Safari filtering on personal devices without MDM. Whether a manually
  installed BuiltIn filter without ContentFilterUUID applies on an
  unsupervised device is not documented as supported and is unverified;
  not pursued, because 4.A provides a documented non-MDM default-block.

### 4.E Per-device URL Filter datasets (assessed, not recommended as default)

Running one PIR database per device (or per small device group) would let
the URL Filter lane carry per-device policy. Costs: the PIR privacy model
assumes a shared database (anonymity set collapses toward 1 per unique
dataset); server-side PIR cost scales per dataset; dataset count multiplies
the activation/recovery surface. Not verified against any Apple guidance;
the privacy impact is unquantified. Kept as a fallback lead only.

## 5. Production-ready PIR: what Apple requires vs what exists

What exists: the pinned `apple/pir-service-example` interop-tested in CI
(base + update round trips, auth boundary, SIGHUP reload). Apple's own
warning: "While functional, this is just an example service and should not
be run in production." `PIRService.md`: "a non-scalable example".

Production requirements (all from the pinned repo's `Onboarding.md`,
`Authentication.md`, `HTTPEndpoints.md`, and the developer docs):

1. **OHTTP gateway** the vendor operates (HTTP/2 required); **Apple hosts
   the relay**. Onboarding is a form + checklist: expected request sizes and
   per-continent traffic estimates, a test identity in the dataset
   (`www.apple.com/url-filter-test`), gateway config resource URLs, a
   Privacy Pass issuer URL, a service URL, a bearer token Apple uses to
   validate the deployment, and a DNS TXT record
   `apple-url-filter=<app bundle id>` proving domain ownership.
2. **CloudKit Console** registration of the URL Filter configuration on the
   Identity & Trust page.
3. **URL rules enforced for App Store installs**: HTTPS only, subdomains
   instead of paths, no custom ports; the endpoints must also be declared in
   the app's Info.plist `NSPIRConfiguration` and match runtime values
   (system rejects mismatches from iOS/macOS 27.3). Xcode-installed builds
   skip the relay and the URL checks, which is the development path.
4. **Privacy Pass issuer operations**: publicly verifiable Blind RSA tokens;
   the system refills token caches proactively (~every 6 hours, adaptive
   batch), reactively, and on demand; each token lives one week, so
   verification keys must stay valid at least one week after last use
   (key rotation is an operational requirement).
5. **Scaling**: the example service is explicitly non-scalable. The
   processing pipeline (`PIRProcessDatabase` from
   apple/swift-homomorphic-encryption) is the documented dataset tool with
   parameter tuning guidance; the serving layer, gateway, issuer,
   monitoring, and rollout discipline are vendor work.

Cost/authorization note: no paid Apple prerequisite was identified in these
sources for the PIR path itself beyond the Developer Program membership
already required for signing/distribution; the OHTTP relay is Apple-hosted
after onboarding approval. Whether any step carries a fee was NOT asserted
by any source read; treat cost as unknown until the onboarding form is
reached, and no commitment has been made.

## 6. Reliable activation and recovery (design proposal, not implemented)

Current gap (Stage 14 limit 5): publication watcher regenerates the PIR
export via a hook before the serving swap; the sequence is not atomic and
after a hook failure the PIR backend state is UNKNOWN (last-good keeps
serving; retry next poll).

Proposed generation-pointer protocol:

1. Build all generation N+1 artifacts (Bloom prefilter, processed PIR
   shards, manifest) under a content-addressed path, never in place.
2. Load N+1 into the PIR service alongside N (the example service already
   supports dynamic database reload without restart; production service
   must support running two generations briefly).
3. Verify N+1 with canary queries through the real query path (the CI
   evidence harness already prints per-keyword results - the same probe,
   pointed at the new generation, including the Apple test identity).
4. Only after canary pass, atomically swap the serving generation pointer
   (single file rename / config value), then retire N after a grace window.
5. On any failure before the swap, N keeps serving and the PIR backend
   state is KNOWN (never half-activated); the status endpoint exposes
   generation state (active/pending/failed) so the app-visible freshness
   signal (already privacy-safe, `b6c7faaf...`) can surface it.

No code yet; this is the design the next build stage would implement.

## 7. Background refresh within iOS limits

- URL Filter dataset freshness does NOT depend on the app running:
  `NEURLFilterManager.prefilterFetchInterval` is "the time interval at
  which the filter control provider app extension runs" - the system
  schedules the extension. (NEURLFilterManager doc)
- Policy/config freshness today relies on BGAppRefresh, which iOS schedules
  at its discretion (Stage 14 already fails safe on expiry).
- A better system-scheduled trigger exists: a repeating `DeviceActivity`
  monitor interval fires the monitor extension "even when your app is not
  being used" (WWDC21). Using it to drive policy sync is a design option;
  whether the monitor extension may perform network fetches is NOT
  documented in the sources read and needs on-device verification.
- Honest bound: iOS does not guarantee wall-clock fetch timing for any
  third-party app mechanism; the product must keep treating server data as
  eventually-fresh and must never claim hard refresh deadlines.

## 8. Real endpoints (owner decision required)

Replacing the placeholder hosts requires a deployment the owner has not
approved. What a real deployment needs, per the sources above:

- Two HTTPS subdomain hosts (e.g. a PIR service host and a Privacy Pass
  issuer host) on infrastructure the owner chooses; paths/ports are not
  allowed for App Store installs.
- DNS TXT `apple-url-filter=<bundle id>` on the service host's domain.
- CloudKit Console Identity & Trust registration.
- Updated `NSPIRConfiguration` in the app Info.plist to match.
- The existing enable-time refusal of placeholder hosts
  (`PIREndpointPolicy`) is correct and stays until a verified deployment
  exists; no invented or reachability-unproven host will be substituted.

## 9. Items requiring on-device verification (not claimed)

1. `WebDomain` subdomain matching semantics in `.specific` / `.all(except:)`.
2. Enforcement scope of Screen Time web content settings across non-Safari
   WebKit apps and third-party browsers.
3. Whether a Screen Time content filter and the URL Filter can run
   simultaneously, and their interaction.
4. Network access from a DeviceActivityMonitor extension (for section 7).
5. Clock access inside a filter data provider sandbox (for 4.B schedules).
6. The iOS 27 manual-install story for encrypted DNS (classic payload
   deprecated; declarative replacement is MDM-channel per the support page).

## 10. Recommended direction (comparison summary; the choice is the owner's)

- Keep the URL Filter + productionized PIR lane for the bulk global category
  blocklist: it is the only personal-lane primitive that is
  system-enforced, privacy-preserving at million-URL scale, and OS-refreshed.
- Add the Screen Time layer (4.A, and 4.B on child devices) for the four
  requirements: it is documented, consent-based, and matches the product's
  child-device case; 4.B is the only full-fidelity on-device option.
- Keep the DNS edge as the coverage layer for non-WebKit apps and as the
  already-tested home of per-device policy, schedules, default-block and
  exceptions - with its unsupervised enforcement limits stated honestly.
- Do NOT pursue per-device PIR datasets (4.E) as a default; revisit only if
  the owner accepts the unquantified privacy cost.

Each alternative above preserves privacy/consent posture and uses documented
Apple APIs only. No reduced feature set is proposed or accepted anywhere in
this document.

## 11. Authorization boundaries for this stage

Investigation and documentation only: no code changed, no CI builds
dispatched, no signing, no deploys, no purchases, no Apple capability
registration or onboarding forms submitted, no device changes; `main`,
`stage-10-ios-runtime-integration`, `stage-11-apple-build-signing` and all
other branches untouched. Test runs reported here were read-only local
pytest runs on a fresh clone at the docs tip.

## 12. Local verification at the docs tip (fresh clone, 2026-11-18)

- dns-edge: 87 passed / 0 failed (`dns-edge/tests`).
- url-filter-server: 95 passed / 0 failed (`url-filter-server/tests`).
- filtering-engine: 337 passed / 0 failed.
- CI evidence from Stage 14 stands at the tested code tip: iOS unsigned
  build + portable suite run 44242647317; PIR round trips run 44242647306.

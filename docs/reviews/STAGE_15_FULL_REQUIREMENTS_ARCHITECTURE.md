# Stage 15 investigation: preserving the full filtering requirements

Date: 2026-11-18 (revised 2026-11-18 after first-pass review). Branch:
`stage-12-free-ios-build`. This document is investigation and design only:
no production code changed, no architecture chosen, no deployment performed.
It answers the owner's 2026-11-18 instruction: the reduced feature subset is
NOT accepted; investigate alternative architectures for the four capabilities
the URL Filter lane cannot express, with tradeoffs, before any implementation
choice.

Source discipline: Apple claims cite primary sources fetched 2026-11-18
(developer.apple.com, support.apple.com, github.com/apple/pir-service-example
at pinned commit `bbb215355b87be40e081756d072f29cd8f9f000b`,
github.com/apple/device-management at branch `release`). One clearly-labeled
secondary source (a third party's production deployment notes) informs the
operations comparison. Repo behavior claims cite code and test runs at the
stated SHAs. Design proposals are marked "Proposed (untested)"; nothing in
this document is presented as device-verified.

## 1. Requirement matrix: implemented vs outstanding

"Implemented server-side" means code exists in this repo with passing tests
at `772cdb9b20af45b0bfdb2459c302cfae0ff869b6` (docs tip; tested code tip
`4b82b1ca621d973cb39e103975b19e69a0033258`, later commits docs-only).
Server-side test passes are NOT device proof: no requirement below has run
on a real iPhone, and the DNS-layer rows have a device-delivery gap called
out explicitly per row.

| # | Original requirement | Implemented + tested | Outstanding |
|---|---|---|---|
| R0 | Bulk category blocklist, privacy-preserving, system-enforced web filtering on personal iPhones | URL Filter lane: export pipeline, real Apple PIR round trips (CI runs 44238729494, 44242647306), 95/95 url-filter-server tests (re-run locally at docs tip), portable Swift 177/177 in CI (run 44242647317) | No real-device run (needs signing + device); PIR service is Apple's non-production example; OHTTP relay onboarding not started |
| R1 | Different policies and exceptions per device | DNS edge SERVER-SIDE: authenticated per-device DoH identity (`dns-edge/doh_identity.py`), per-device policy selection (`dns-edge/device_policy.py`), delegated exception overlay with baseline floor (`dns-edge/policy_bundle.py`); 87/87 dns-edge tests pass locally at docs tip | **Device-delivery gap (verified, not inferred):** `docs/design/DOH_IOS_TRANSPORT.md` documents that the native iOS DNS path (`com.apple.dnsSettings.managed`) has NO header/credential field, so the header-based per-device identity cannot ride the system-wide DNS path; it works only where we control the HTTP client (our own app). Per-device URL-embedded credentials are rejected by the approved design rule against URL-transported tokens. So per-device DNS policy is NOT deliverable to a personal iPhone's system DNS today. URL Filter lane: unexpressible (single shared dataset). Alternatives: sections 4.A/4.B |
| R2 | Default-block (allowlist-only) posture | DNS edge: engine `default_policy: block` (`filtering-engine/src/policy_engine.py`); 337 engine tests pass locally at docs tip. Deliverable on the native DNS path (no identity needed) | URL Filter lane: unexpressible (membership-only dataset). Screen Time alternative exists (4.A). DNS granularity is domains only |
| R3 | Timed filtering schedules | DNS edge: weekly time-window schedules, allowlist always wins (`dns-edge/schedules.py`; 25 + 3 schedule tests pass). Deliverable on the native DNS path (resolver-side timing) | URL Filter lane: refused loudly (dataset has no time dimension). Screen Time alternative exists (4.A/4.B) |
| R4 | Block a parent domain while allowing specific subdomains | Engine semantics: explicit allowlist beats blocklist, entries cover subdomains (`policy_engine.py` precedence 1-5); deliverable resolver-side on the native DNS path | URL Filter lane: unexpressible, refused loudly (3.2). DNS granularity is domains only (no URL paths) |
| R5 | Production-ready PIR service | Not implemented; Apple's pinned example is interop-tested but Apple-marked non-production (5.1) | Candidate comparison in 5.2; all production hardening + Apple onboarding outstanding |
| R6 | Reliable dataset activation and recovery | Partially: hot reload without restart, last-good retention, publication watch (95/95 tests) | Staged activation non-atomic; post-hook-failure PIR state UNKNOWN (Stage 14 limit 5); mixed-generation consistency analyzed in section 6 (design proposal) |
| R7 | Automatic background refresh within iOS scheduling limits | Partially: BGAppRefresh wiring compiles; expiry fails safe (Stage 14) | iOS discretion is a hard bound; better primitives identified (section 7) |
| R8 | Real service endpoints instead of placeholders | Not implemented: placeholders remain by design; enable-time refusal guards them (Stage 14) | Requires owner's deployment decision (section 8); nothing deployable without approval |

## 2. Correction of the Stage 14 evidence boundary

Stage 14 correctly established that the CURRENT URL Filter dataset design
cannot express R1-R4. It did not establish - and no finding in this
investigation establishes - that Apple universally prohibits these features
on personal iPhones. In fact:

1. **This repo already implements R1-R4 server-side on the DNS edge
   layer** (87/87 dns-edge tests pass at the docs tip), subject to the
   device-delivery and granularity caveats in the matrix.
2. **Apple's Screen Time API provides primitives for R1-R3 on unsupervised
   devices** (4.A), and a full programmatic filter covering R1-R4 for child
   devices (4.B). The packet-tunnel/VPN route was checked and is explicitly
   unsupported by Apple for content filtering (4.F).

## 3. What the URL Filter lane can and cannot express (primary sources)

### 3.1 Verified Apple semantics

- The URL Filter examines all URL requests sent via WebKit and URLSession;
  the system consults an on-device Bloom prefilter first, then queries the
  vendor's PIR server on prefilter hits; a PIR match blocks the URL.
  (https://developer.apple.com/documentation/networkextension/url-filters.md)
- The dataset is a set of URL keys; presence means block, and the record
  value is a placeholder integer `1`.
  (`Sources/PIRService/PIRService.docc/NEURLFilterDataFormat.md`, pinned
  commit)
- The system enumerates sub-URLs by walking up both the domain and path
  hierarchies (default parsing excludes the scheme and the `www` subdomain;
  configurable from iOS 27 via `NEURLFilterManager.ParsingConfiguration`).
  (https://developer.apple.com/documentation/networkextension/neurlfiltermanager/parsingconfiguration)
- Neither the Bloom filter nor PIR supports wildcards or regular expressions.
  (https://developer.apple.com/documentation/networkextension/neurlfiltermanager)
- Blocked-URL reporting to the vendor exists as an optional endpoint but "is
  only allowed for supervised devices" - on the personal lane the vendor does
  not learn blocked URLs, consistent with the privacy model.
  (`Sources/PIRService/PIRService.docc/HTTPEndpoints.md`, pinned commit)
- Coverage bound: WebKit + URLSession only; other apps must voluntarily use
  the `NEURLFilter` participation API (`verdict(for:)`).
  (url-filters.md, above)

### 3.2 Consequences (already enforced in code)

- No allow verdict exists, so R2 and R4 are unexpressible: enumeration means
  a block key catches every descendant, and there is no negative verdict to
  carve an exception. `url-filter-server/app/pir_export.py::
  device_block_keywords` refuses these at publish time; the refusal is
  correct behavior for this lane.
- R1 conflicts with the shared-dataset PIR privacy model, which assumes many
  clients query one database. Per-device databases would shrink the
  anonymity set; the exact privacy cost is UNQUANTIFIED here and no claim is
  made in either direction (see 4.E).
- R3 has no representation in a membership dataset.

## 4. Alternative primitives on personal (unsupervised) iPhones

### 4.A Screen Time API: Family Controls + ManagedSettings + DeviceActivity

Primary sources:

- `ManagedSettingsStore` groups settings; apps apply and delete their own.
  Its "Restricting web content" group includes `WebContentSettings`.
  (https://developer.apple.com/documentation/managedsettings/managedsettingsstore)
- `WebContentSettings.FilterPolicy` (iOS 15+):
  `.specific(Set<WebDomain>)` - "The policy blocks the specified domains",
  **up to 50 web domains**;
  `.all(except: Set<WebDomain>)` - "The system blocks all websites except
  the ones you specify", **up to 50 exceptions**;
  `.auto(_:except:)` - "The system blocks adult content"; `.none`.
  (https://developer.apple.com/documentation/managedsettings/webcontentsettings/filterpolicy,
   .../filterpolicy/all(except:), .../filterpolicy/specific(_:),
   .../filterpolicy/auto(_:except:))
- `WebDomain` is constructible programmatically from a domain string - no
  FamilyActivityPicker token needed.
  (https://developer.apple.com/documentation/managedsettings/webdomain)
- `ShieldSettings`: shield specific apps/websites (picker tokens) and
  categories of apps/websites, including `.all(except:)` category policies.
  (https://developer.apple.com/documentation/managedsettings/shieldsettings,
   .../shieldsettings/activitycategorypolicy)
- `DeviceActivitySchedule`: calendar-based repeating intervals; the
  `DeviceActivityMonitor` extension receives interval callbacks. WWDC21:
  "Device Activity allows your app to run code on a schedule or on usage
  events even when your app is not being used." WWDC22 demonstrates the
  schedule use case directly (a named store un-restricted on a 5-8pm window
  and re-applied at window end; named stores compose most-restrictive-wins).
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

Requirement mapping for this layer:

| Req | Screen Time mechanism | Tradeoffs |
|---|---|---|
| R1 per-device | Per-device `ManagedSettingsStore` values driven by server-synced policy (each device applies its own `.specific`/`.all(except:)` sets and shields) | 50-domain cap per policy set; no category-scale lists; enforcement scope across non-Safari WebKit not documented (needs on-device verification) |
| R2 default-block | `.all(except:)` natively | 50 allowed-domain cap; suits an "approved sites only" posture, not a large allowlist |
| R3 schedules | `DeviceActivitySchedule` + monitor extension applying/clearing named stores | Runs even when the app is not used; per-window filtered set bounded by the same 50-domain caps |
| R4 parent-block/child-allow | Only in the default-block shape (`.all(except:)` lists the allowed subdomain); no carve-outs inside `.specific` documented | Exact `WebDomain` subdomain matching semantics are not documented; needs on-device verification |

### 4.B Screen Time content filter: NEFilterDataProvider (full programmatic verdicts)

Primary source: Apple TN3134, content filter provider table and the Screen
Time case:
(https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)

- iOS content filter providers: "supervised devices only" (iOS 9+), OR
  "**apps using Screen Time APIs**" (iOS 15+), OR per-app on managed devices
  (iOS 16+).
- In the Screen Time case, content filters are **only supported on child
  devices**: signed in as an under-18 child member of an iCloud family,
  `.child` authorization, parent/guardian approval. Family Controls
  (Distribution) entitlement approval is required before App Store
  submission.
- `NEFilterDataProvider` receives every new flow and returns pass/block
  verdicts; browser flows (`NEFilterBrowserFlow`) expose the full URL and
  HTTP request/response; socket flows expose hostname-level metadata. The
  data provider sandbox cannot exfiltrate network content; the control
  provider syncs rules into a shared location the data provider reads.
  (https://developer.apple.com/documentation/networkextension/nefilterdataprovider,
   /nefilterbrowserflow)

Requirement mapping:

| Req | Mechanism | Tradeoffs |
|---|---|---|
| R1 per-device | Rules synced per device via control provider into the app group; verdict code evaluates that device's full policy | Child devices only; rule-sync cadence is app-driven |
| R2 default-block | Verdict code defaults to block with an explicit allow set | Same child-only bound |
| R3 schedules | Verdict code evaluates time-window rules (mirrors `dns-edge/schedules.py` semantics) | Clock access inside the data provider sandbox needs on-device verification |
| R4 parent-block/child-allow | Verdict code implements longest-match with allow-precedence - the reviewed engine's precedence | Same child-only bound |
| Coverage | Browser flows: full URL. Other apps: hostname via socket flows | TLS content not inspectable; verdicts are per-flow metadata |

After checking the alternatives (4.F included), this is the most complete
personal-lane primitive found for R1-R4 at full policy-engine fidelity
on-device. Its eligibility bound is real and stated openly: it covers
children's devices inside iCloud Family Sharing only - see 4.G.

### 4.C Encrypted DNS profile (DoH) + KosherGuard resolver

Primary sources:

- `com.apple.dnsSettings.managed` payload: `supervised: false`,
  `allowmanualinstall: true`, iOS 14+ - installable on unsupervised devices,
  manually or via MDM. **Deprecated in iOS 27.0**; the replacement
  "DNS settings declarative configuration" (iOS 27+) requires no supervision
  but its support page lists MDM enrollment channels (Device Enrollment /
  Automated Device Enrollment) only.
  (github.com/apple/device-management, `mdm/profiles/com.apple.dnsSettings.managed.yaml`;
   https://support.apple.com/guide/deployment/dns-settings-declarative-configuration-dep7e19a4b12/web)
- Manually installed profiles are user-removable on unsupervised devices.
  (https://support.apple.com/en-us/102400)
- The payload has no header/credential field, so the repo's header-based
  per-device DoH identity cannot ride the native path (repo's own verified
  finding: `docs/design/DOH_IOS_TRANSPORT.md`).

What this layer carries: R2/R3/R4 resolver-side (implemented and tested in
`dns-edge/`); R1 server-side but NOT deliverable on the native iOS path
under the no-URL-credential design rule. Honest limits: domain-only
granularity (no URL paths); profile is user-removable on unsupervised
devices; bypassable by VPN apps and apps with hardcoded DNS; iOS 27
deprecation makes the long-term manual-install path uncertain (unverified).

### 4.D MDM built-in Web Content Filter (evidence of a managed-only shape)

- Apple's payload schema: as of iOS 16 the web content filter payload can be
  installed on unsupervised devices **only if ContentFilterUUID is
  specified**, and ContentFilterUUID scopes the filter to managed apps
  carrying the same UUID - which requires MDM-managed apps. The built-in
  filter supports a whitelist posture ("Specific Web Sites Only"), allow and
  deny lists (deny list capped at 500 URLs), and substring URL matching.
  (github.com/apple/device-management, `mdm/profiles/com.apple.webcontent-filter.yaml`;
   https://support.apple.com/guide/deployment/web-content-filter-payload-settings-depc77c9609/web)
- Conclusion: the built-in whitelist filter does not deliver general Safari
  filtering on personal devices without MDM. Whether a manually installed
  BuiltIn filter without ContentFilterUUID applies on an unsupervised device
  is not documented as supported and is unverified; not pursued, because 4.A
  provides a documented non-MDM default-block.

### 4.E Per-device URL Filter datasets (assessed, not recommended as default)

One PIR database per device (or small device group) would let the URL Filter
lane carry per-device policy. Costs: the PIR privacy model assumes a shared
database (anonymity set collapses toward 1 per unique dataset); server-side
PIR cost scales per dataset; dataset count multiplies the
activation/recovery surface; no Apple guidance was found endorsing or
forbidding this. Privacy impact unquantified. Fallback lead only.

### 4.F Packet tunnel ("local VPN") route: evaluated, rejected on Apple's own guidance

- Apple TN3120: "Do not use a packet tunnel provider to implement a network
  content filter. Packets ... are not meant to be dropped or re-injected
  back into the system. ... On iOS, implement a connection-based content
  filter using NEFilterDataProvider and NEFilterControlProvider."
  (https://developer.apple.com/documentation/technotes/tn3120-expected-use-cases-for-network-extension-packet-tunnel-providers)
- Practical limits even where used by third-party apps: occupies the single
  personal-VPN slot, and without TLS interception it sees DNS/IP/SNI-level
  metadata, not full URLs. Not pursued: Apple explicitly classifies it as an
  unsupported use, which is an App Store review and stability risk.

### 4.G Eligibility: whose personal devices each primitive can cover

The owner has not limited the product to children in iCloud Family Sharing,
so eligibility is stated per primitive rather than assumed:

| Device situation | URL Filter | Screen Time settings/schedules (4.A) | NEFilter content filter (4.B) | DNS profile (4.C) |
|---|---|---|---|---|
| Child, under-18 member of an iCloud family | Yes | Yes (.child; app non-removable by child) | Yes (.child) | Yes (removable by user) |
| Child NOT in iCloud Family Sharing | Yes | .child availability depends on Family Sharing; needs on-device verification | No (TN3134 requires child family member) | Yes (removable by user) |
| Adult's own phone (.individual) | Yes | Yes, but self-revocable - cooperative mode only | No | Yes (removable by user) |

Consequence for product design: system-enforced, non-removable filtering of
the full R1-R4 set on personal devices exists only on the child Family
Sharing path. Adult self-managed devices get cooperative-mode filtering
(the owner can always undo it). This is a product eligibility fact to
surface in requirements, not a silent restriction imposed here.

## 5. Production-ready PIR: requirements and candidate comparison

### 5.1 What Apple requires (primary sources)

What exists: the pinned `apple/pir-service-example`, interop-tested in CI
(base + update round trips, auth boundary, SIGHUP reload). Apple's own
warning: "While functional, this is just an example service and should not
be run in production." `PIRService.md`: "a non-scalable example".

From the pinned repo's `Onboarding.md`, `Authentication.md`,
`HTTPEndpoints.md`, plus developer docs:

1. **OHTTP gateway** the vendor operates (HTTP/2 required); **Apple hosts
   the relay**. Onboarding is a form + checklist: expected request sizes and
   per-continent traffic estimates, a test identity in the dataset
   (`www.apple.com/url-filter-test`), gateway config resource URLs, a
   Privacy Pass issuer URL, a service URL, a bearer token Apple uses to
   validate the deployment, and a DNS TXT record
   `apple-url-filter=<app bundle id>` proving domain ownership.
2. **CloudKit Console** registration of the URL Filter configuration on the
   Identity & Trust page.
3. **URL rules for App Store installs**: HTTPS only, subdomains instead of
   paths, no custom ports; endpoints declared in the app Info.plist
   `NSPIRConfiguration` and matching runtime values (system rejects
   mismatches from iOS/macOS 27.3). Xcode-installed builds skip the relay
   and URL checks (the development path).
4. **Privacy Pass issuer operations**: publicly verifiable Blind RSA tokens;
   proactive (~6h adaptive), reactive and on-demand refills; tokens live one
   week, so verification keys must stay valid at least one week after last
   use (key rotation is an operational requirement).
5. **Wire protocol**: Protobuf over HTTP; `/config` (unauthenticated
   bootstrap + authenticated status), `/key` (evaluation key upload),
   `/queries`, optional `/report` (supervised devices only). The system
   caches configurations; config propagation has caching delay.

Cost/authorization note: no source read asserts any fee for the PIR path
itself beyond the Developer Program membership already required for
signing/distribution; the OHTTP relay is Apple-hosted after onboarding
approval. Cost treated as unknown until the onboarding form is reached; no
commitment made or implied.

### 5.2 Production candidate comparison (grounded)

- **Candidate A - fork and harden `apple/pir-service-example`
  (Apache-2.0).** The example implements the full wire protocol, Privacy
  Pass issuance, dynamic database reload, and the processing pipeline via
  `PIRProcessDatabase` (from apple/swift-homomorphic-encryption, also
  Apache-2.0, with documented parameter tuning). Secondary evidence that
  this path reaches production: a third-party content-blocker vendor
  (Pledgely) published notes from running exactly this stack in production
  (https://pledgely.app/guides/running-apples-pir-server, 2026-10-17;
  SECONDARY source, not Apple-normative). Their reported findings: serving
  is cheap (tens of MB idle); database generation is the spiky batch job and
  should run offline as an artifact pipeline; the Bloom prefilter and PIR
  database must be built from the SAME snapshot in one pipeline step; the
  usecase name must equal `<app bundle id>.url.filtering`; the query path
  cannot be health-checked with curl (Privacy Pass tokens only iOS can
  produce), so monitoring must probe the token-key endpoint and gateway;
  after server restarts devices can hold stale parameters, recoverable via
  `resetPIRCache()` / `refreshPIRParameters()`; fail-closed mode makes the
  PIR service critical-path infrastructure; TestFlight/App Store builds go
  through OHTTP while Xcode builds do not, so the gateway path needs its own
  early test; and the backend itself did not require the client-side
  entitlement, so it can be deployed and learned before client approval.
  Gaps to close in a fork: horizontal scaling, HA, monitoring, key-rotation
  automation, OHTTP gateway selection (open component, not yet chosen), and
  the onboarding checklist itself.
- **Candidate B - build a vendor service directly on
  apple/swift-homomorphic-encryption +
  apple/swift-homomorphic-encryption-protobuf.** Maximum control over
  scaling and ops; re-implements the service layer the example already
  provides; higher build cost and more new-code risk on the crypto-adjacent
  path. The project rule against inventing cryptography is satisfied either
  way (both candidates use Apple's libraries for the protocol), but B writes
  more new protocol-serving code.
- **Candidate C - managed/commercial NEURLFilter PIR hosting.** None found
  as of 2026-11-18: searches surface Apple's example, Apple's docs, and
  self-hosting notes only. Not currently an option.
- **Optional hardening in both A and B: Symmetric PIR** (documented in the
  pinned repo's `SymmetricPIR.md`) additionally guarantees the client learns
  only the requested keyword-value pair, at extra processing cost.

Comparison summary: A has the only observed production precedent and the
lowest new-code risk; B is the control-maximizing fallback; C does not
exist today. No choice is made here - the decision is the owner's
(section 10).

## 6. Reliable activation and recovery (Proposed, untested)

Current gap (Stage 14 limit 5): the publication watcher regenerates the PIR
export via a hook before the serving swap; the sequence is not atomic, and
after a hook failure the PIR backend state is UNKNOWN (last-good keeps
serving; retry next poll).

**Mixed-generation consistency (the problem a pointer swap alone does not
solve):** during any transition, devices hold the Bloom prefilter of
generation N while the server may already serve PIR generation N+1. Two
failure shapes follow:

- A keyword REMOVED in N+1 still matches the device's stale Bloom N, so the
  device issues a PIR query; if the server answers from N+1 alone it
  returns no-match and the device ALLOWS a site the device's own policy
  still says to block (temporary weakening).
- A keyword ADDED in N+1 misses the stale Bloom N and is allowed until the
  prefilter refreshes (expected freshness bound; acceptable).
- Multi-replica rollouts create the same split-brain at the server side:
  replicas converge on the new generation at different times.

Proposed generation protocol:

1. Build generation N+1 artifacts (Bloom prefilter + processed PIR shards +
   manifest) from ONE policy snapshot in a single pipeline step, under
   content-addressed paths, never in place. (Same-snapshot construction is
   also what Apple's BloomFilterTool sample does and what the secondary
   production notes identify as mandatory.)
2. Serve an OVERLAP dataset during the transition window: N+1 content UNION
   the keys removed between N and N+1, kept for at least one
   `prefilterFetchInterval` plus margin after activation. This makes
   removals fail-toward-block for stale-Bloom devices and makes replica
   skew harmless (every replica serves a superset during the window). The
   window length is a configured policy, since the system controls actual
   prefilter refresh timing.
3. Verify N+1 with canary queries through the real query path before
   activation (the CI evidence harness already prints per-keyword results;
   point the same probe at the new generation, including Apple's test
   identity `www.apple.com/url-filter-test`). The secondary production
   notes add that real-query probing is impossible without iOS-issued
   tokens, so canaries must run on a device/simulator path or be limited to
   token-key and gateway probes - this constraint is now explicit.
4. Atomically swap the active-generation pointer only after canary pass;
   retain generation N's processed artifacts for rollback for a configured
   retention window. Rollback re-activates N with the same overlap rule.
5. On any failure before the swap, N keeps serving and the PIR backend
   state is KNOWN (never half-activated); the status endpoint exposes
   generation state (active/pending/failed) so the app-visible,
   privacy-safe freshness signal (`b6c7faaf...`) can surface it.
6. Client-side recovery knobs for stale on-device parameters after server
   restarts: `NEURLFilterManager.resetPIRCache()` and the manager call
   that "Refetches PIR parameters from the server" (both listed in Apple's
   NEURLFilterManager documentation; their operational value is reported
   by the secondary source). Wire them into the app's status/recovery UI
   (compile-level only until a device exists).

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
  being used" (WWDC21). Using it to drive policy sync is a design option
  (Proposed, untested); whether the monitor extension may perform network
  fetches is NOT documented in the sources read and needs on-device
  verification.
- Honest bound: iOS does not guarantee wall-clock fetch timing for any
  third-party app mechanism; the product must keep treating server data as
  eventually-fresh and must never claim hard refresh deadlines.

## 8. Real endpoints (owner decision required)

Replacing the placeholder hosts requires a deployment the owner has not
approved. What a real deployment needs, per the sources above:

- Two HTTPS subdomain hosts (PIR service, Privacy Pass issuer) on
  infrastructure the owner chooses; paths/ports are not allowed for App
  Store installs.
- DNS TXT `apple-url-filter=<bundle id>` on the service host's domain.
- CloudKit Console Identity & Trust registration.
- Updated `NSPIRConfiguration` in the app Info.plist to match.
- Sequencing note (secondary source): the backend can be deployed and
  operated before the client-side entitlement/approval, so endpoint work is
  not blocked on Apple - only on the owner's deployment decision.
- The enable-time refusal of placeholder hosts (`PIREndpointPolicy`) is
  correct and stays until a verified deployment exists; no invented or
  reachability-unproven host will be substituted.

## 9. Items requiring on-device verification (not claimed)

1. `WebDomain` subdomain matching semantics in `.specific` / `.all(except:)`.
2. Enforcement scope of Screen Time web content settings across non-Safari
   WebKit apps and third-party browsers.
3. Whether a Screen Time content filter and the URL Filter can run
   simultaneously, and their interaction.
4. Network access from a DeviceActivityMonitor extension (for section 7).
5. Clock access inside a filter data provider sandbox (for 4.B schedules).
6. The iOS 27 manual-install story for encrypted DNS (classic payload
   deprecated; declarative replacement lists MDM channels only).
7. `.child` Screen Time authorization availability for children whose
   devices are not in an iCloud family.

## 10. Recommended direction (comparison summary; the choice is the owner's)

- Keep the URL Filter + productionized PIR lane for the bulk global category
  blocklist: the only personal-lane primitive that is system-enforced,
  privacy-preserving at million-URL scale, and OS-refreshed.
- Add the Screen Time layer (4.A, and 4.B on child devices) for R1-R4:
  documented, consent-based, and matching the product's child-device case;
  4.B is the most complete on-device option, with the eligibility bound of
  4.G stated openly.
- Keep the DNS edge as the coverage layer for non-WebKit apps and as the
  already-tested server-side home of R2/R3/R4 - with its personal-iPhone
  delivery gap for R1 (DOH_IOS_TRANSPORT.md), domain-only granularity, and
  unsupervised removability stated honestly.
- Do NOT pursue per-device PIR datasets (4.E) as a default; revisit only if
  the owner accepts the unquantified privacy cost.
- Do NOT pursue the packet-tunnel route (4.F); Apple marks it an
  unsupported use for content filtering.
- Production PIR: candidate A (fork + harden) has the only observed
  production precedent (5.2); candidates B and C compared, no choice made.

Each alternative preserves the privacy/consent posture and uses documented
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

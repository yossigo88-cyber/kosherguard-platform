# GenTech Technical Investigation

KosherGuard platform - technical investigation into reproducing the observable functionality of GenTech's iPhone management and filtering system, and the architecture options for building our own backend, MDM infrastructure, filtering engine, policy management, and administrator dashboard.

Date: November 13, 2026
Status: Investigation only. No application code, no mockups, no deployments.

**Evidence labels used in this document:**

- **[Verified - GenTech]** - directly stated on GenTech's public website/help pages.
- **[Verified - Apple]** - directly stated in current Apple documentation fetched November 13, 2026.
- **[Evidence]** - third-party or indirect but checkable evidence.
- **[Hypothesis]** - our inference; not confirmed.

Nothing here is copied from any previous project. All Apple claims were re-checked against current documentation on the date above; the platform has changed recently (iOS 26/27), and some older guidance is now stale.

---

## 1. GenTech's observable iPhone management behavior

Sources: GenTech public pages (fetched November 13, 2026).

### 1.1 What GenTech publicly says it does

- GenTech sells a cloud-managed content filter built on the Livigent content filter. The filter is managed by GenTech staff in the cloud; users ask support to change levels or allow sites. "Removing GenTech requires the assistance of our customer support." **[Verified - GenTech]** (https://www.gentechsolution.com/how-it-works/)
- Livigent is described as a content-based filter that scans each page in real time and can block objectionable images on a page. **[Verified - GenTech]** (same page). We have no evidence about Livigent's private implementation; treat the "AI" description as marketing until independently verified. **[Hypothesis flag]**
- Public pricing page lists several per-device plans (Restricted / Safe / Email only / Apps Only / Pro) with prices in the roughly $22.49-$119.99 range for Apple devices and multi-device discounts. The page's table layout did not cleanly map every price to every plan; exact plan pricing should be confirmed before being quoted anywhere. **[Verified - GenTech]** (https://www.gentechsolution.com/gentech-pricing-table-new/)

### 1.2 Observable iOS installation flow

From GenTech's iOS installation page **[Verified - GenTech]** (https://www.gentechsolution.com/installation-ios/):

1. Requires a Windows PC with iTunes and GenTech's iOS installer; the iPhone is plugged in over USB and the user taps "Trust".
2. The user must turn off Find My iPhone before installation.
3. The installer offers a restrictions section and a "Blacklisted Apps" section that can remove apps and block them from the App Store, including preinstalled system apps. "Harmful apps designed to bypass filters were blacklisted by default."
4. The device restarts during installation.
5. Undoing optional settings requires uninstalling and reinstalling the filter.

### 1.3 Observable iOS filtering mechanism

From GenTech's iOS help center **[Verified - GenTech]** (https://www.gentechsolution.com/ios-help/):

- "We use the Apple supported feature to add a pac file to the device which sends the traffic to a proxy server." Traffic is routed to GenTech/Livigent proxy servers; per-site bypasses are configured in the PAC file.
- TLS inspection: the help center instructs users to install and fully trust root certificates ("GenTech Solution CA" and "Livigent CA") in Settings > General > About > Certificate Trust Settings. Full-trust root CAs plus a proxy means HTTPS traffic is decrypted and inspected at the proxy. **[Evidence]**
- "We don't use a VPN type of connection." The filter is proxy-based, not a Network Extension VPN/tunnel. **[Verified - GenTech]**
- Accounts are bound to the device's current IP; a web clip ("GenTech app") refreshes the binding when the IP changes. **[Verified - GenTech]**
- Captive Wi-Fi networks are a known pain point; handled via Apple's captive-bypass behavior and PAC bypass entries. **[Verified - GenTech]**

### 1.4 What this implies (hypotheses, not confirmed)

- The PC-based install with USB pairing, Find My iPhone off, and a device restart is consistent with the device being put into **supervised mode** (Apple documents that manual supervision via Apple Configurator erases the device and requires physical USB connection) followed by enrollment in an MDM service. **[Hypothesis]** (supervision mechanics: https://support.apple.com/en-gb/guide/deployment/dep1d89f0bff/web)
- The PAC-based global routing on iOS is consistent with the **Global HTTP Proxy payload**, which Apple documents as requiring supervision on iPhone. **[Hypothesis, strongly supported]** (https://support.apple.com/guide/deployment/filter-content-dep1129ff8d2/web and https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.proxy.http.global.yaml)
- App blacklisting is consistent with the MDM Restrictions payload's app-blocking keys (supervised). **[Hypothesis]** (https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.applicationaccess.yaml)
- GenTech's private implementation (server stack, MDM vendor, Livigent internals) is not public and is not investigated here beyond the above. **[Hypothesis flag]**

**Bottom line:** the observable GenTech iOS product is: supervised iPhone + MDM (restrictions, app blocking, non-removable management) + Global HTTP Proxy (PAC) to a cloud filtering proxy + trusted root CA for TLS inspection + a web clip for account refresh. Every one of those pieces uses documented Apple features. **[Evidence]**

---

## 2. How comparable systems achieve device supervision and management

### 2.1 Supervision

Supervision is Apple's organizational-ownership flag that unlocks the strongest management features. Current Apple documentation (https://support.apple.com/en-gb/guide/deployment/dep1d89f0bff/web): **[Verified - Apple]**

- **Automated Device Enrollment (ADE):** devices enrolled through Apple School Manager / Apple Business are supervised automatically during activation (iPhone iOS 13+).
- **Manual supervision via Apple Configurator for Mac:** requires physical possession, USB connection to a Mac, and **erases the device**.
- Consumer/personal devices are unsupervised by default; many restrictions and payloads are supervised-only.

### 2.2 Adding existing devices to Apple Business

Devices not purchased through an Apple authorized channel can still be added to Apple Business using **Apple Configurator for iPhone** (free, requires iOS 16+) or Apple Configurator for Mac. **[Verified - Apple]** (https://support.apple.com/guide/business/add-devices-using-apple-configurator-axm200a54d59/web)

- After assignment, the device behaves like any ADE device: mandatory supervision and MDM enrollment.
- Important caveat: for devices added manually this way, the user has a **30-day provisional period** during which they can release the device from Apple Business, supervision, and management. **[Verified - Apple]** (same page)

### 2.3 Management frameworks

All iPhone management flows through Apple's device management framework (built into iOS since iOS 4). **[Verified - Apple]** (https://support.apple.com/guide/deployment/intro-to-device-management-depc0aadd3fe/web)

- A device management service (MDM server) enrolls devices, sends configuration profiles/declarations and commands, queries device state, and can wipe/lock devices.
- Two delivery styles coexist: legacy XML configuration profiles and the newer Declarative Device Management (DDM) JSON declarations. Apple is actively migrating payloads to DDM (see section 6).
- Device identity for enrollment uses ACME (recommended in current docs) or SCEP certificate enrollment. **[Verified - Apple]** (same intro page)

---

## 3. How to build our own MDM server

### 3.1 What the server must implement

Per Apple's documentation, an MDM server must: **[Verified - Apple]**

1. Host an enrollment flow: serve an enrollment profile; the device obtains an identity certificate via ACME (recommended) or SCEP (https://support.apple.com/guide/deployment/intro-to-device-management-depc0aadd3fe/web).
2. Speak the MDM check-in and command protocol over HTTPS: the device contacts the server (Authenticate, TokenUpdate, Acknowledged/Idle/Error statuses), and the server queues commands (profiles, restrictions, app installs, queries, wipe).
3. Use APNs to wake the device: the server sends a push on the device's MDM topic; the device then contacts the server. APNs is the only supported way to reach the device; devices must reach Apple's network (ports 5223/443; 443/2197 server-side). **[Verified - Apple]** (https://support.apple.com/guide/deployment/configure-devices-to-work-with-apns-dep2de55389a/web)
4. Hold certificates: an APNs push certificate, a TLS certificate for HTTPS, and optionally a profile-signing certificate. **[Verified - Apple]** (same APNs page)

### 3.2 The APNs push certificate (the real gatekeeper)

The MDM APNs push certificate is the one component that cannot be self-generated. Current options:

1. **Own MDM Vendor CSR Signing Certificate.** Apple's current help page states that an Account Holder of the **Apple Developer Program** (standard, $99/year) **or** the Apple Developer Enterprise Program can request an MDM Vendor CSR Signing Certificate, which signs CSRs that are then exchanged at the Apple Push Certificates Portal (https://identity.apple.com) for the actual push certificate. **[Verified - Apple]** (https://developer.apple.com/help/account/certificates/mdm-vendor-csr-signing-certificate/) Note: older third-party guides (e.g. MicroMDM's 2019 blog, https://micromdm.io/blog/certificates/) say the Enterprise Program ($299/year) is required; that is stale relative to Apple's current page. The push certificate itself is free at identity.apple.com and must be **renewed yearly against the same topic** or enrolled devices can no longer be pushed. **[Evidence]** (MicroMDM blog for the renewal mechanics)
2. **Third-party signing service (mdmcert.download).** Free, organization-only per Apple terms - but the service was reported unreachable in 2026 (https://github.com/micromdm/micromdm/issues/1120) and the MicroMDM maintainer states it is not their project and unsupported. Treat as unreliable. **[Evidence]**
3. **Partner with an existing MDM vendor** for certificate issuance. Possible but introduces a dependency and usually cost. **[Hypothesis]**

Conclusion: the realistic, self-owned route is Apple Developer Program membership ($99/year) plus a vendor CSR signing certificate. Nothing else needs to be paid to Apple for MDM itself.

### 3.3 Build vs. reuse

- Open-source MDM servers exist and implement the protocol: **MicroMDM** (https://github.com/micromdm/micromdm, in maintenance mode) and **NanoMDM** (https://github.com/micromdm/nanomdm, a minimal toolkit for building custom MDM servers). **[Evidence]**
- Realistic path: build our server on NanoMDM-style components (protocol, APNs, storage) with our own policy engine, dashboard API, and enrollment flows on top - or write a fresh implementation against Apple's Device Management documentation (https://developer.apple.com/documentation/devicemanagement). This satisfies "build our own" without re-deriving TLS/APNs plumbing. **[Hypothesis - engineering judgment]**

---

## 4. Communicating with devices and delivering policy changes

- **Push-triggered updates:** server sends an APNs push on the MDM topic; the device checks in and receives queued commands/profile updates. Policy changes are effectively near-real-time whenever the device is online. **[Verified - Apple]** (https://support.apple.com/guide/deployment/configure-devices-to-work-with-apns-dep2de55389a/web)
- **No server-to-device direct channel exists:** Apple devices never accept inbound connections from an MDM server; APNs wake + device-initiated HTTPS is the only flow. **[Verified - Apple]** (same page, plus intro page)
- **DDM (Declarative Device Management):** devices can apply policy changes proactively and report status back via a status channel, reducing polling. Newer payloads (including app restrictions, DNS settings, content filters) are DDM configurations. **[Verified - Apple]** (https://developer.apple.com/documentation/devicemanagement and the spec repo https://github.com/apple/device-management)
- **Prerequisites for delivery:** device powered on, enrolled, valid APNs certificate, network access to Apple hosts. **[Verified - Apple]** (intro page)

---

## 5. Website and category filtering architecture

Apple's current "Filter content for Apple devices" page (published November 3, 2026) lists every supported approach with capability tables. **[Verified - Apple]** (https://support.apple.com/guide/deployment/filter-content-dep1129ff8d2/web)

### 5.1 The options Apple documents

| Approach | Supervision needed on iPhone | Filters full URLs | Filters non-HTTP(S) traffic | Notes |
| --- | --- | --- | --- | --- |
| Built-in WebContentFilter payload (limit adult content, block lists, allow-only lists) | No | Yes (Safari + apps) | No | Simple needs only; Apple steers complex needs to proxy/filter apps |
| Global HTTP Proxy (manual or PAC) | **Yes** | Yes | No (some apps like FaceTime bypass) | This matches GenTech's observable design |
| DNS Proxy payload (on-device DNS proxy app) | No on iOS 15+ (installed via MDM) | Hosts only | DNS lookups only | Needs a companion app with an Apple-granted entitlement |
| DNS Settings payload (DoH/DoT to a filtered resolver) | Lockable on supervised | Hosts only | DNS lookups only | Cheap, no proxy server needed |
| Content filter providers (Network Extension filter app) | App deletion preventable on supervised | Yes | Yes (packets) | On-device; runs in a restrictive sandbox |
| URL filters (NEUrlFilter, iOS 26+) | No | Yes, system-wide HTTP(S) | No | New: on-device Bloom filter + privacy-preserving PIR lookups over Apple's Oblivious HTTP Relay |
| VPN / packet tunnel | No (except Always-On VPN: supervised) | Within tunneled traffic | Yes | GenTech explicitly does NOT use this |

### 5.2 Global HTTP Proxy with TLS inspection (the GenTech model)

- The Global HTTP Proxy payload (`com.apple.proxy.http.global`) is **supervised-only on iOS** and supports PAC URLs and captive-network bypass. **[Verified - Apple]** (spec: https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.proxy.http.global.yaml, deployment guide as above)
- To read page content (not just hostnames) the proxy must terminate TLS, which requires installing and fully trusting a root CA on the device - exactly what GenTech's help pages show. **[Evidence]**
- Apple's own warning: "Apple services stop any connection that uses HTTPS Interception," so Apple service hosts must be excluded from interception per https://support.apple.com/en-us/101555. **[Verified - Apple]**
- Some apps (e.g. FaceTime) don't use HTTP and bypass an HTTP proxy entirely. **[Verified - Apple]** (filter-content page)

### 5.3 Where our filtering engine would live

- **Proxy-based (GenTech parity):** run our own filtering proxy (PAC-driven), with URL/category rules and optional TLS inspection. Full control of policy; needs reachable, scalable proxy infrastructure and a CA per device.
- **On-device URL filter (modern route):** an iOS 26+ Network Extension URL-filter app uses an on-device Bloom filter plus Private Information Retrieval over Apple's relay for misses. No proxy bandwidth, no root CA, works system-wide for HTTP(S). This is the newest Apple-sanctioned architecture and avoids TLS interception entirely. **[Verified - Apple]** (https://developer.apple.com/documentation/networkextension/url-filters.md)
- **Filtered DNS (cheap baseline):** DNS Settings payload to a DoH/DoT resolver we operate; host-level blocking only; a VPN app can override it on supervised devices if the management service allows VPN apps. **[Verified - Apple]** (filter-content page)
- Category databases (the "which sites are bad" data) are a separate problem from enforcement: build/maintain our own lists, or license a categorization feed (paid - flagged in section F).

---

## 6. App restrictions and application management

Grounded in Apple's current device-management spec (release branch, fetched November 13, 2026): https://github.com/apple/device-management

- **Current mechanism (iOS 27):** the declarative configuration `com.apple.configuration.app.settings` (supervised only) supports `DeniedApps` and `AllowedApps` by bundle ID; denying an app prevents it from showing or launching; `com.apple.webapp` covers web clips. **[Verified - Apple]** (https://github.com/apple/device-management/blob/release/declarative/declarations/configurations/app.settings.yaml)
- **Deprecation notice:** the older Restrictions-payload keys `blockedAppBundleIDs` and `allowListedAppBundleIDs` are marked `deprecated: '27.0'` with "use the declarative management `com.apple.configuration.app.settings` configuration." Any new implementation should target the DDM configuration, not the legacy keys. **[Verified - Apple]** (https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.applicationaccess.yaml)
- **Related supervised restrictions** (legacy Restrictions payload, still current): `allowAppInstallation=false` (disable App Store), `allowAppRemoval=false` (prevent deleting apps), `allowSystemAppRemoval=false`. **[Verified - Apple]** (same spec file)
- **Managed app installation:** the DDM `com.apple.configuration.app.managed` declaration can force-install an app (`InstallBehavior: Required` - "the user can't remove the app") and can prevent hiding/locking apps (iOS 18.1+). **[Verified - Apple]** (https://github.com/apple/device-management/blob/release/declarative/declarations/configurations/app.managed.yaml)
- GenTech's "blacklist apps incl. system apps" behavior is reproducible today via DeniedApps on supervised devices. **[Evidence]**

---

## 7. Preventing users from disabling or removing protection

What is actually enforceable, per Apple's current docs:

- **Enrollment profile removal:** only with **Automated Device Enrollment** can the management service choose that "only the device management service can remove it." Manually enrolled users can always remove the enrollment profile with the device passcode, even if marked Never. **[Verified - Apple]** (https://support.apple.com/guide/deployment/intro-to-device-management-depc0aadd3fe/web)
- **Profile removal password:** profiles installed by Apple Configurator (or manually on a supervised device) can require a removal password. **[Verified - Apple]** (same page)
- **Erasing the device:** `allowEraseContentAndSettings=false` (supervised) blocks Settings-based erase. **[Verified - Apple]** (restrictions spec)
- **Account/setting lockdown:** `allowAccountModification=false` (supervised) blocks adding/removing accounts. **[Verified - Apple]** (restrictions spec)
- **App deletion:** `allowAppRemoval=false` (supervised) prevents deleting the filter/companion app; content-filter apps "deletion can be prevented if the device is supervised." **[Verified - Apple]** (restrictions spec; filter-content page)
- **DNS override:** on supervised devices the DNS Settings configuration can be locked, but "a VPN app can override configuration if a device management service allows it" - so VPN-style bypass apps must also be denied (app restrictions) or App Store disabled. **[Verified - Apple]** (filter-content page)
- **Stolen Device Protection** adds a one-hour delay to manual MDM enrollment and passcode-profile changes in unfamiliar locations - relevant when a user tries to enroll/unenroll quickly. **[Verified - Apple]** (intro page)
- **Residual gaps (honest):** a DFU/recovery-mode restore erases any iPhone regardless of restrictions (see section 8 for what happens next); and devices manually added to Apple Business have the 30-day provisional release window. **[Evidence]**

---

## 8. Factory-reset recovery and re-enrollment

- **ADE devices:** after any erase (Settings or recovery-mode restore), the device must activate with Apple; because its serial is assigned in Apple Business to our MDM, activation forces Remote Management re-enrollment - management returns automatically. **[Verified - Apple]** (https://support.apple.com/guide/business/add-devices-using-apple-configurator-axm200a54d59/web)
- **Configurator-supervised devices:** "Supervision status manually set by Apple Configurator is also retained" across Return to Service / EACS resets. **[Verified - Apple]** (https://support.apple.com/guide/deployment/erase-devices-dep0a819891e/1/web/1.0)
- **Return to Service (RTS):** the MDM sends an erase command carrying Wi-Fi details and optionally the enrollment profile; the device erases, re-activates, re-enrolls, and lands on the Home Screen with no user setup. iOS 26 adds preservation of managed app binaries; iOS 27 adds language/region in the ADE profile, retry on failed enrollment, and user-initiated RTS from Control Center. **[Verified - Apple]** (https://support.apple.com/guide/deployment/use-return-to-service-for-apple-devices-dep17cb455a0/web)
- **Activation Lock:** on erased devices, Activation Lock (Find My) blocks reactivation without credentials; MDM can escrow bypass codes. Note the tension: GenTech's installer tells users to turn Find My OFF for installation. **[Verified - Apple]** (erase page; GenTech install page)
- **Policy restoration:** after re-enrollment, the server re-issues the device's profiles/declarations (filter, restrictions, apps) from stored policy - this is a server-side design requirement, not an Apple feature. **[Hypothesis - engineering judgment]**

---

## 9. Network filtering alternatives (beyond the device)

These complement (not replace) on-device enforcement, because a managed iPhone roams across Wi-Fi and cellular:

- **Home router / Wi-Fi DNS filtering:** point home routers at a filtered resolver. Free baseline (e.g. family-filtered public DNS resolvers exist), but only protects the home network and is trivially bypassed by cellular. **[Evidence]**
- **Filtered DNS services with per-device policies:** commercial DNS filters (various free tiers exist) give dashboard-managed categories without any proxy. Host-level only. **[Evidence]**
- **Self-hosted filtered resolver:** run our own DoH/DoT resolver with category rules and point the DNS Settings payload at it; lockable on supervised devices. Cost: server hosting only. **[Hypothesis - engineering judgment]**
- **Campus/office gateway filtering (firewall, TLS inspection):** viable for fixed locations; irrelevant on cellular. **[Evidence]**
- GenTech's own model (cloud proxy + PAC) is the proven way to keep filtering identical on any network, at the cost of running interception infrastructure. **[Evidence]**

---

## 10. Technical requirements, costs, security risks, and iOS limitations

### Requirements

- Apple Developer Program membership ($99 annual membership). **[Verified - Apple]** (https://developer.apple.com/programs/)
- MDM Vendor CSR Signing Certificate (request from the account; Apple Developer Program or Enterprise Program holders). **[Verified - Apple]** (https://developer.apple.com/help/account/certificates/mdm-vendor-csr-signing-certificate/)
- Apple Push Certificates Portal access for the yearly push certificate (free). **[Verified - Apple]** (https://support.apple.com/guide/deployment/configure-devices-to-work-with-apns-dep2de55389a/web)
- Apple Business organization (free signup; organization verification takes multiple business days and unverified organizations are deleted after 60 days). **[Verified - Apple]** (https://support.apple.com/guide/business/sign-up-and-verify-your-organization-axm402206497/web)
- Server with public HTTPS (TLS certificate; free via Let's Encrypt). **[Evidence]**
- A Mac is optional: supervision can be achieved through ADE with devices added by Apple Configurator for iPhone; Apple Configurator for Mac (free) is only needed for direct manual supervision. **[Verified - Apple]** (supervision page; Configurator page)

### Security risks

- **TLS inspection** concentrates sensitive traffic at our proxy and requires careful CA handling and Apple-host exclusions (https://support.apple.com/en-us/101555). **[Verified - Apple]**
- **Root CA on devices:** a fully trusted CA is powerful; compromise of its private key breaks every managed device's TLS. **[Evidence]**
- **Push certificate renewal discipline:** losing the yearly renewal or changing topics strands enrolled devices. **[Evidence]** (https://micromdm.io/blog/certificates/)
- **Proxy as outage point:** PAC failure modes can cut off all web access on managed phones. **[Evidence]** (GenTech's own help center documents this failure class)

### iOS limitations (real ones)

- No inbound connections to devices; APNs only. **[Verified - Apple]**
- Non-HTTP apps bypass HTTP proxies. **[Verified - Apple]**
- Host-only granularity for DNS-based filtering. **[Verified - Apple]**
- Strongest controls (app denial, non-removable enrollment, erase blocking, global proxy) all require supervision; ADE non-removability requires Apple Business. **[Verified - Apple]**
- The 30-day provisional release for Configurator-added devices is an unavoidable Apple policy. **[Verified - Apple]**
- Packet-level filtering requires a Network Extension app with Apple-granted entitlements (approval not guaranteed). **[Evidence]** (filter-content page; entitlement process per https://developer.apple.com/documentation/networkextension/url-filters.md and related NE docs)

---

## 11. What we can build independently vs. what Apple controls

**Fully ours to build:** MDM protocol server, policy engine, admin dashboard, filtering proxy, filtered DNS resolver, PAC logic, enrollment portal, logging, account/activation-code system.

**Apple-controlled gates:**

| Gate | Cost | Notes |
| --- | --- | --- |
| MDM APNs push certificate | Free cert; requires $99/year Developer Program for vendor CSR signing (or unreliable third-party signer) | Yearly renewal, same topic |
| Supervision | Free | Via ADE (Apple Business) or Configurator |
| Apple Business organization | Free | Verification required; organization must be real |
| Automated Device Enrollment | Free with Apple Business | Non-removable enrollment only here |
| Network Extension filter entitlements | Included in Developer Program | Apple approval required |
| App Store distribution of any companion app | Developer Program | App Review applies |

---

## A. Proposed system architecture

1. **KosherGuard server** (single deployable, e.g. Docker): MDM protocol endpoint (NanoMDM-derived or fresh), policy engine, admin REST API, enrollment portal (profile download + ACME/SCEP identity), APNs worker, and device/policy database.
2. **Admin dashboard** (web): devices, policies (filter level, app deny lists), enrollment codes, status channel.
3. **Filtering layer (phased):** start with filtered DNS (DNS Settings payload, supervised-locked) for a working baseline; add Global HTTP Proxy + PAC + our filtering proxy for GenTech parity; evaluate an iOS 26+ URL-filter app as the long-term no-proxy architecture.
4. **Device base:** supervised iPhones, added to Apple Business via Apple Configurator for iPhone, enrolled through ADE (non-removable), policy delivered via push + DDM.
5. **Recovery:** ADE re-enrollment on activation; Return to Service for managed resets; server-side policy replay.

## B. Features we can realistically reproduce

- Supervised enrollment with non-removable management (via Apple Business + ADE). 
- Push-triggered policy updates.
- Website/category filtering (DNS baseline immediately; proxy parity with GenTech's model; URL-filter app later).
- App deny lists including system apps (DDM app.settings, supervised).
- Prevention of app deletion, account changes, erase, and enrollment removal (supervised restrictions).
- Automated recovery after resets (ADE re-enrollment, RTS).
- A web dashboard for all of the above.
- Real-time page-content AI scanning comparable to Livigent's marketing claims: reproducible only with TLS inspection plus a real classification engine - significant work; treat GenTech's claims as unverified. **[Hypothesis flag]**

## C. Features requiring further investigation

- URL-filter Network Extension entitlement approval odds and exact data-flow requirements (PIR server obligations).
- Packet-level content filter providers on iOS vs macOS for our use case.
- Preventing unmanaged VPN configurations created outside MDM (needs a current spec check; older restriction keys have churned).
- Whether any third-party MDM/vendor certificate partnership is worth it as a fallback to the $99 route.
- Category-database sourcing: build vs. license (cost unknown until scoped).
- Behavior parity testing against an actual GenTech-managed device (observable behaviors only, with the device owner's consent).

## D. Recommended development order

1. Apple Business verification + Apple Developer Program enrollment (external lead times; start first, costs nothing until the $99 is actually needed for the vendor CSR).
2. MDM server core: HTTPS endpoint, enrollment (ACME/SCEP), APNs push, command queue - validated on one supervised test iPhone.
3. Restrictions + DDM app.settings policy delivery (app denial) on the test device.
4. Filtered DNS baseline (DNS Settings payload, locked) end-to-end.
5. Admin dashboard over the working policy engine.
6. Global HTTP Proxy + filtering proxy (GenTech parity), with CA issuance and Apple-host exclusions.
7. Return to Service / reset-recovery automation.
8. URL-filter Network Extension app evaluation (iOS 26+), possibly replacing the proxy.

## E. Required equipment and accounts

- One or more physical test iPhones (iOS 17+ recommended; iOS 26/27 for newest features).
- An iPhone with iOS 16+ for Apple Configurator for iPhone (can be the owner's own phone); a Mac optional for Configurator for Mac.
- Apple IDs: one for the Developer Program, one for Apple Business.
- Server: any Linux host with a public IP and domain name.
- A real organization identity for Apple Business verification (already in progress per project context).

## F. Expected costs, including free alternatives

| Item | Cost | Free alternative |
| --- | --- | --- |
| Apple Developer Program | $99/year **[Verified - Apple]** | None for own vendor CSR signing; third-party signing (mdmcert.download) is free but currently unreliable |
| MDM APNs push certificate | Free (identity.apple.com) | - |
| Apple Business | Free signup | - |
| Apple Configurator (iPhone/Mac) | Free | - |
| macOS Server / Profile Manager | Not used (discontinued path) | - |
| Server hosting | Free tiers exist (e.g. Oracle Cloud Always Free) or low-cost VPS; verify current provider pricing before committing | Free tier |
| Domain name | Typically roughly $10-15/year; verify at registrar | Free subdomains possible for development, own domain recommended for production |
| TLS certificate | Free (Let's Encrypt) | - |
| Category/URL database | Unknown until scoped (build vs. license) | Start with self-maintained lists |
| Test iPhone(s) | Hardware cost | Use existing family devices (with owners' consent) |
| **Minimum cash outlay to start** | **$0 until the APNs push certificate is needed; then $99/year** | - |

---

## Source list

GenTech (public pages, fetched November 13, 2026):

- https://www.gentechsolution.com/how-it-works/
- https://www.gentechsolution.com/installation-ios/
- https://www.gentechsolution.com/ios-help/
- https://www.gentechsolution.com/gentech-pricing-table-new/
- https://www.gentechsolution.com/installation-mdm/

Apple (fetched November 13, 2026):

- https://support.apple.com/guide/deployment/intro-to-device-management-depc0aadd3fe/web
- https://support.apple.com/en-gb/guide/deployment/dep1d89f0bff/web
- https://support.apple.com/guide/deployment/filter-content-dep1129ff8d2/web
- https://support.apple.com/guide/deployment/use-return-to-service-for-apple-devices-dep17cb455a0/web
- https://support.apple.com/guide/deployment/erase-devices-dep0a819891e/1/web/1.0
- https://support.apple.com/guide/deployment/configure-devices-to-work-with-apns-dep2de55389a/web
- https://support.apple.com/guide/business/sign-up-and-verify-your-organization-axm402206497/web
- https://support.apple.com/guide/business/add-devices-using-apple-configurator-axm200a54d59/web
- https://support.apple.com/en-us/101555
- https://developer.apple.com/help/account/certificates/mdm-vendor-csr-signing-certificate/
- https://developer.apple.com/programs/
- https://developer.apple.com/documentation/devicemanagement
- https://developer.apple.com/documentation/networkextension/url-filters.md
- https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.applicationaccess.yaml
- https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.proxy.http.global.yaml
- https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.webcontent-filter.yaml
- https://github.com/apple/device-management/blob/release/declarative/declarations/configurations/app.settings.yaml
- https://github.com/apple/device-management/blob/release/declarative/declarations/configurations/app.managed.yaml

Third-party:

- https://github.com/micromdm/micromdm
- https://github.com/micromdm/nanomdm
- https://micromdm.io/blog/certificates/
- https://github.com/micromdm/micromdm/issues/1120
- https://identity.apple.com

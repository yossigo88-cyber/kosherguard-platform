# GenTech Technical Investigation

KosherGuard platform - technical investigation into reproducing the observable functionality of GenTech's iPhone management and filtering system, and the architecture options for building our own backend, MDM infrastructure, filtering engine, policy management, and administrator dashboard.

Date: November 13, 2026 (revised same day after critical review: commercial MDM authorization, URL Filter limits, GenTech evidence separation, cost/feasibility recalculation, development decision)
Status: Investigation only. No application code, no mockups, no deployments.

**Evidence labels used in this document:**

- **[Verified - GenTech]** - directly stated on GenTech's public website/help pages.
- **[Verified - Apple]** - directly stated in current Apple documentation (including the public Developer Program License Agreement PDF) fetched November 13, 2026.
- **[Evidence]** - third-party, community, or indirect but checkable evidence; not official confirmation.
- **[Hypothesis]** - our inference; not confirmed.

Nothing here is copied from any previous project. All Apple claims were re-checked against current documentation on the date above; the platform has changed recently (iOS 26/27), and some older guidance is now stale.

---

## 1. GenTech's observable iPhone management behavior

Sources: GenTech public pages (fetched November 13, 2026).

### 1.1 What GenTech publicly says it does

- GenTech sells a cloud-managed content filter built on the Livigent content filter. The filter is managed by GenTech staff in the cloud; users ask support to change levels or allow sites. "Removing GenTech requires the assistance of our customer support." **[Verified - GenTech]** (https://www.gentechsolution.com/how-it-works/)
- Livigent is described as a content-based filter that scans each page in real time and can block objectionable images on a page. **[Verified - GenTech]** (same page). We have no evidence about Livigent's private implementation; treat the "AI" description as marketing until independently verified. **[Hypothesis flag]**
- Public pricing page lists several per-device plans (Restricted / Safe / Email only / Apps Only / Pro) with prices in the roughly $22.49-$119.99 range for Apple devices and multi-device discounts. The page's table layout did not cleanly map every price to every plan; exact plan pricing should be confirmed before being quoted anywhere. **[Verified - GenTech]** (https://www.gentechsolution.com/gentech-pricing-table-new/)
- Accounts are managed by GenTech directly by default, or by "participating associations" (such as TAG) on request. **[Verified - GenTech]** (https://www.gentechsolution.com/install-gentech-pro-ios/)

### 1.2 Observable iOS installation flow (verified)

From GenTech's iOS installation page **[Verified - GenTech]** (https://www.gentechsolution.com/installation-ios/):

1. Requires a Windows PC with iTunes and GenTech's iOS installer; the iPhone is plugged in over USB and the user taps "Trust".
2. The user must turn off Find My iPhone before installation.
3. The installer offers a restrictions section and a "Blacklisted Apps" section that can remove apps and block them from the App Store, including preinstalled system apps. "Harmful apps designed to bypass filters were blacklisted by default."
4. The device restarts during installation.
5. Undoing optional settings requires uninstalling and reinstalling the filter.

### 1.3 Observable iOS filtering mechanism (verified)

From GenTech's iOS help center **[Verified - GenTech]** (https://www.gentechsolution.com/ios-help/):

- "We use the Apple supported feature to add a pac file to the device which sends the traffic to a proxy server." Traffic is routed to GenTech/Livigent proxy servers; per-site bypasses are configured in the PAC file.
- TLS inspection: the help center instructs users to install and fully trust root certificates ("GenTech Solution CA" and "Livigent CA") in Settings > General > About > Certificate Trust Settings. Full-trust root CAs plus a proxy means HTTPS traffic is decrypted and inspected at the proxy. **[Evidence]**
- "We don't use a VPN type of connection." The filter is proxy-based, not a Network Extension VPN/tunnel. **[Verified - GenTech]**
- Accounts are bound to the device's current IP; a web clip ("GenTech app") refreshes the binding when the IP changes. **[Verified - GenTech]**
- Captive Wi-Fi networks are a known pain point; handled via Apple's captive-bypass behavior and PAC bypass entries. **[Verified - GenTech]**

### 1.4 Additional public evidence on the management/enrollment method

- GenTech's own wiki page "Apple Restrictions" lists the restrictions their product applies, and the list is a direct mirror of Apple's MDM Restrictions payload keys, with the same "Supervised Only" labels Apple uses (e.g. "Allow erase all content and settings", "Allow installing apps using App Store", "Allow pairing with Non-Configurator hosts", "Allow installing configuration profiles"). This is strong evidence that the product applies MDM restriction profiles and relies on supervised-only restriction keys. **[Evidence]** (https://www.gentechsolution.com/wiki/apple-restrictions/)
- Community filtering forums (jtechforums.org, August-September 2026) describe GenTech installs as "uses MDM not jailbreak", report that a factory reset is currently required to install on iOS 27 ("for now yes but shortly no"), and ask (unanswered) whether it runs supervised with ABM auto re-enrollment. Community reports, unverified. **[Evidence]** (https://jtechforums.org/t/ios-26-gentech-filter/8318)
- The USB install flow (Windows PC, Trust pairing, Find My iPhone off, device restart) is consistent with a supervision+enrollment step performed over the pairing channel, but GenTech's public pages do not state the exact mechanism (Apple Configurator-style supervision vs. Automated Device Enrollment vs. manual MDM enrollment), and we found no public page that proves it. The specific enrollment/supervision mechanism therefore remains a **[Hypothesis]**, strongly directionally supported by the evidence above: the product requires supervision-grade features (supervised-only restrictions, app blocking, PAC-based global proxy, which is supervised-only on iPhone).
- GenTech's private implementation (server stack, MDM vendor arrangement, Livigent internals) is not public and is not investigated beyond the above. **[Hypothesis flag]**

**Bottom line:** verified GenTech behavior is: cloud-managed policy + PAC/proxy filtering + trusted root CAs + a Windows USB install that applies restrictions and app blacklists. The exact supervision/enrollment mechanism is not publicly documented and stays a hypothesis. All of the observable pieces map onto documented Apple features. **[Evidence]**

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

### 3.2 The APNs push certificate - technical acquisition

The MDM APNs push certificate cannot be self-generated. Technical options:

1. **Own MDM Vendor CSR Signing Certificate.** Apple's current help page states that an Account Holder of the **Apple Developer Program** (standard, $99/year) **or** the Apple Developer Enterprise Program can request an MDM Vendor CSR Signing Certificate, which signs CSRs that are then exchanged at the Apple Push Certificates Portal (https://identity.apple.com) for the actual push certificate. **[Verified - Apple]** (https://developer.apple.com/help/account/certificates/mdm-vendor-csr-signing-certificate/) Older third-party guides (e.g. MicroMDM's 2019 blog, https://micromdm.io/blog/certificates/) say the Enterprise Program ($299/year) is required; that is stale relative to Apple's current page. The push certificate itself is free at identity.apple.com and must be **renewed yearly against the same topic** or enrolled devices can no longer be pushed. **[Evidence]** (MicroMDM blog for the renewal mechanics)
2. **Third-party signing service (mdmcert.download).** Free, organization-only per Apple terms - but the service was reported unreachable in 2026 (https://github.com/micromdm/micromdm/issues/1120) and the MicroMDM maintainer states it is not their project and unsupported. Treat as unreliable. **[Evidence]**

**Critical caveat:** being able to *technically acquire* a push certificate is not the same as being *authorized to operate a commercial MDM service*. The license terms are analyzed in section 3.4 - this is the biggest open risk in the whole project.

### 3.3 Build vs. reuse

- Open-source MDM servers exist and implement the protocol: **MicroMDM** (https://github.com/micromdm/micromdm, in maintenance mode) and **NanoMDM** (https://github.com/micromdm/nanomdm, a minimal toolkit for building custom MDM servers). **[Evidence]**
- Realistic path: build our server on NanoMDM-style components (protocol, APNs, storage) with our own policy engine, dashboard API, and enrollment flows on top - or write a fresh implementation against Apple's Device Management documentation (https://developer.apple.com/documentation/devicemanagement). **[Hypothesis - engineering judgment]**

### 3.4 Commercial MDM authorization (Developer Program License Agreement, Attachment 10)

Source: Apple's publicly posted Developer Program License Agreement PDF, Attachment 10 ("Additional Terms for the use of MDM"), current English version fetched November 13, 2026. **[Verified - Apple]** (https://developer.apple.com/support/downloads/terms/apple-developer-program/Apple-Developer-Program-License-Agreement-English.pdf)

What Attachment 10 actually says:

- **Two permitted uses only (A10 1.1):** (a) **in-house** management of your own employees' Apple devices owned or controlled by you, or your developers' test units; or (b) **if you are "selected by Apple as a third-party MDM developer"**, providing MDM access to your MDM Customers as part of an "MDM Compatible Product."
- **Selection is mandatory for any customer-facing product (A10 3.1):** you may only develop and distribute MDM Compatible Products to customers "if You have been selected by Apple as a third-party developer for such MDM Compatible Products." It adds that MDM may not be provided even "for non-commercial, personal use, unless otherwise expressly permitted in writing by Apple." A free community filter for other people's phones is still a third-party MDM product under this text.
- **Customer-specific certificates (A10 4.1):** every MDM Customer must obtain **its own** MDM certificate from Apple. The vendor signs the customer's CSR **only after verifying the customer's enterprise name and individual contact information**, must provide that information to Apple on request, and must cooperate with Apple about the customer's use of MDM.
- **Vendor certificate secrecy (A10 4.2):** the vendor may not share or transfer its own MDM certificate to anyone (including customers and resellers), may not embed it in the product, and **may not generate or access the customer's private key**. The customer keeps its own key; the vendor only signs the CSR.
- **Unilateral revocation (A10 5.3):** Apple may remove MDM access or revoke vendor or customer certificates at any time, at its sole discretion.

**Assessment for KosherGuard:** **[Evidence - applying the agreement text]**

- Managing parents'/customers' iPhones for them is a third-party MDM Compatible Product under A10. It is not "in-house" use, because those devices are not the organization's employees' devices owned or controlled by the organization.
- A $99 Apple Developer Program membership alone does **not** authorize commercial MDM operation. It is a prerequisite for *requesting* the vendor CSR signing certificate; operating for customers requires being **selected by Apple**.
- The selection criteria and process are not publicly documented anywhere we could find; the practical doorway is the "contact us" request for the MDM Vendor CSR Signing Certificate from the developer account. Whether a small, new entrant will be selected is **unknown** - this is the project's single biggest authorization risk and it has a binary outcome.
- Nothing in this project should attempt to work around these terms (e.g. using another entity's certificate, sharing one certificate across customers, or extracting customer keys); A10 4.1/4.2 explicitly prohibit those, and A10 5.3 makes the whole fleet revocable.

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
| Content filter providers (Network Extension filter app) | App deletion preventable on supervised | Yes | Yes (browser/socket filters on iOS; packet filter is macOS-only per the iOS 27 DDM config) | On-device; runs in a restrictive sandbox |
| URL filters (NEURLFilter, iOS 26+) | No | Yes - **but only WebKit/URLSession traffic by default** | No | New; strict coverage and reporting limits - see 5.4 |
| VPN / packet tunnel | No (except Always-On VPN: supervised) | Within tunneled traffic | Yes | GenTech explicitly does NOT use this |

### 5.2 Global HTTP Proxy with TLS inspection (the GenTech model)

- The Global HTTP Proxy payload (`com.apple.proxy.http.global`) is **supervised-only on iOS** and supports PAC URLs and captive-network bypass. **[Verified - Apple]** (spec: https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.proxy.http.global.yaml, deployment guide as above)
- To read page content (not just hostnames) the proxy must terminate TLS, which requires installing and fully trusting a root CA on the device - exactly what GenTech's help pages show. **[Evidence]**
- Apple's own warning: "Apple services stop any connection that uses HTTPS Interception," so Apple service hosts must be excluded from interception per https://support.apple.com/en-us/101555. **[Verified - Apple]**
- Some apps (e.g. FaceTime) don't use HTTP and bypass an HTTP proxy entirely. **[Verified - Apple]** (filter-content page)

### 5.3 Where our filtering engine would live

- **Proxy-based (GenTech parity):** run our own filtering proxy (PAC-driven), with URL/category rules and optional TLS inspection. Full control of policy; needs reachable, scalable proxy infrastructure and a CA per device.
- **Filtered DNS (cheap baseline):** DNS Settings payload to a DoH/DoT resolver we operate; host-level blocking only; a VPN app can override it on supervised devices if the management service allows VPN apps. **[Verified - Apple]** (filter-content page)
- **On-device URL filter (possible future route, with real limits):** see 5.4 - promising for privacy and for removing proxy bandwidth costs, but it is not a universal filter.
- Category databases (the "which sites are bad" data) are a separate problem from enforcement: build/maintain our own lists, or license a categorization feed (paid - flagged in section F).

### 5.4 iOS 26+ URL Filter: what it actually does and does not do

Sources: Apple's URL filter API documentation (https://developer.apple.com/documentation/networkextension/url-filters.md), the Web content filter plugin DDM configuration page (https://support.apple.com/guide/deployment/web-content-filter-plugin-declarative-depcbacfcb0e/web), and a technical first-look analysis (https://textslashplain.com/2025/06/10/apple-url-filter-api/).

**Coverage:**

- The system examines URL requests **sent via WebKit and URLSession only**. **[Verified - Apple]** Any app or browser that does not use WebKit/URLSession is **not** filtered by default; it can only participate **voluntarily** by calling the `NEURLFilter` Participation API (`verdict(for:)`) and honoring the verdict itself. A bypass app simply won't call it. This is not universal, enforceable system-wide filtering. **[Verified - Apple]**
- It filters URLs, not packets, and not non-HTTP(S) protocols. **[Verified - Apple]** (deployment guide capability table)
- Supervision is **not** required: the Web content filter plugin DDM configuration (iOS 27+) lists "Requires supervision: No" and supports User Enrollment, Device Enrollment, and ADE. **[Verified - Apple]** However, on unsupervised devices and User Enrollment, the filter is bound to **managed apps** via a Content filter UUID - i.e. coverage is tied to management for the apps it protects. **[Verified - Apple]** (same page)

**Infrastructure requirements:**

- The developer must host a **PIR (Private Information Retrieval) server** holding the off-device URL database; Apple provides an open-source container tool and sample project for it, and the configuration is registered in the CloudKit Console (Identity & Trust page). **[Verified - Apple]**
- On-device: a Bloom prefilter (built with Apple's Bloom filter tool) quickly allows URLs not in the block list; possible hits go to the PIR server over an **Apple-hosted Oblivious HTTP Relay**. **[Verified - Apple]**
- Prefilter refresh interval: default 1 day, minimum 45 minutes - database updates cannot propagate faster than that. **[Verified - Apple]** (DDM config page)
- A fail-closed option exists: block all URLs when the filter cannot reach a decision. **[Verified - Apple]** (same page)

**Reporting and feedback limits:** **[Evidence]** (text/plain analysis, consistent with the API's documented privacy design)

- The vendor cannot see which URLs were checked (PIR + relay by design), so per-user/per-device browsing reporting is impossible - a hard conflict with "accountability report" style features.
- No documented way to identify which device performed a check.
- Binary verdicts only: no "warn and override."
- No mechanism in Apple clients to report a false positive back to the filter service.

**Bottom line:** the iOS 26 URL Filter is a privacy-preserving **blocklist** engine for WebKit/URLSession traffic, not a universal content filter and not a reporting tool. It could complement the proxy/DNS layers (cheap first line for Safari/WebKit traffic) but cannot replace GenTech-style proxy filtering for arbitrary apps or provide category-based dynamic page analysis. **[Evidence]**

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
- **Erasing the device:** `allowEraseContentAndSettings=false` (supervised) blocks Settings-based erase. **[Verified - Apple]** (restrictions spec). GenTech's own restriction list includes this key as a default restriction - evidence that this is part of how their product resists removal. **[Evidence]** (https://www.gentechsolution.com/wiki/apple-restrictions/)
- **Account/setting lockdown:** `allowAccountModification=false` (supervised) blocks adding/removing accounts; "Allow installing configuration profiles" off blocks user-installed profiles; both appear in GenTech's published restriction set. **[Verified - Apple]** (restrictions spec); **[Evidence]** (GenTech wiki)
- **App deletion:** `allowAppRemoval=false` (supervised) prevents deleting the filter/companion app; content-filter apps "deletion can be prevented if the device is supervised." **[Verified - Apple]** (restrictions spec; filter-content page)
- **Pairing lockdown:** "Allow pairing with Non-Configurator hosts" off (supervised) stops the device being paired to another computer - also in GenTech's default restriction set. **[Verified - Apple]** (restrictions spec); **[Evidence]** (GenTech wiki)
- **DNS override:** on supervised devices the DNS Settings configuration can be locked, but "a VPN app can override configuration if a device management service allows it" - so VPN-style bypass apps must also be denied (app restrictions) or the App Store disabled. **[Verified - Apple]** (filter-content page)
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
- **Selection by Apple as a third-party MDM developer** for any customer-facing MDM product (DPLA Attachment 10; section 3.4). **[Verified - Apple]**
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
- **Revocation risk:** Apple can revoke MDM access or certificates at its sole discretion (A10 5.3); the entire fleet depends on continued good standing. **[Verified - Apple]**

### iOS limitations (real ones)

- No inbound connections to devices; APNs only. **[Verified - Apple]**
- Non-HTTP apps bypass HTTP proxies. **[Verified - Apple]**
- Host-only granularity for DNS-based filtering. **[Verified - Apple]**
- URL Filter covers WebKit/URLSession only; other apps opt in voluntarily. **[Verified - Apple]**
- Strongest controls (app denial, non-removable enrollment, erase blocking, global proxy) all require supervision; ADE non-removability requires Apple Business. **[Verified - Apple]**
- The 30-day provisional release for Configurator-added devices is an unavoidable Apple policy. **[Verified - Apple]**
- Packet-level filtering requires a Network Extension app with Apple-granted entitlements (approval not guaranteed); packet filters are macOS-only in the iOS 27 DDM content-filter configuration. **[Verified - Apple]** (https://support.apple.com/guide/deployment/web-content-filter-plugin-declarative-depcbacfcb0e/web)

---

## 11. What we can build independently vs. what Apple controls

**Fully ours to build:** MDM protocol server, policy engine, admin dashboard, filtering proxy, filtered DNS resolver, PAC logic, enrollment portal, logging, account/activation-code system.

**Apple-controlled gates:**

| Gate | Cost | Notes |
| --- | --- | --- |
| Third-party MDM developer selection (DPLA A10) | No published fee | **Binary approval risk; criteria not public; required for any customer-facing MDM** |
| MDM vendor CSR signing certificate | Requires $99/year Developer Program | Requested from the developer account ("contact us") |
| MDM APNs push certificate (per customer) | Free (identity.apple.com) | Customer's own certificate; yearly renewal, same topic; vendor must never hold customer keys |
| Supervision | Free | Via ADE (Apple Business) or Configurator |
| Apple Business organization | Free | Verification required; organization must be real |
| Automated Device Enrollment | Free with Apple Business | Non-removable enrollment only here |
| Apple Business built-in device management | Free (merged from Essentials, April 2026) | Apple's own MDM - a fallback platform, not ours (https://9to5mac.com/2026/03/24/apple-business-essentials-goes-free-as-apple-merges-enterprise-tools-into-apple-business/) **[Evidence]** |
| Network Extension filter entitlements | Included in Developer Program | Apple approval required |
| App Store distribution of any companion app | Developer Program | App Review applies |

---

## A. Proposed system architecture (revised)

The architecture separates into an **authorization-independent filtering stack** and an **authorization-gated management stack**:

1. **Filtering stack (no MDM authorization needed):** filtered DNS resolver (DoH/DoT) + policy engine; filtering proxy with PAC + optional TLS inspection; later, a URL-filter Network Extension app. All testable today on manually installed profiles on supervised test devices.
2. **Management stack (authorization-gated for customers, free for in-house):** MDM server (NanoMDM-derived or fresh) with enrollment (ACME/SCEP), APNs push, DDM policy delivery, Return to Service automation. In-house development and testing on organization-owned test devices is permitted without selection (A10 1.1); offering it to customers waits on selection.
3. **Admin dashboard** over both stacks: devices, filter levels, app deny lists, enrollment codes, status.
4. **Device base (target):** supervised iPhones added to Apple Business via Apple Configurator for iPhone, enrolled through ADE (non-removable).
5. **Recovery:** ADE re-enrollment on activation; Return to Service; server-side policy replay.

## B. Features we can realistically reproduce (revised)

Reproducible **today, without any Apple approval**, on our own test devices:

- Filtered DNS with locked settings (supervised devices).
- Global HTTP Proxy + PAC filtering proxy with TLS inspection (GenTech's verified filtering model).
- Restrictions and app-deny policy content (profiles/declarations) validated on supervised test devices.
- MDM protocol engine end-to-end against our own supervised test iPhones, under Attachment 10's in-house permission.
- The full dashboard and account/enrollment-code system against that test fleet.

Reproducible **only after Apple selection** (or via an authorized partner):

- Managing any customer device (push certificates for customers, non-removable ADE enrollment of customer devices, commercial offering of any kind, paid or free).

Not reproducible at all (by anyone) on current iOS:

- Universal, enforceable URL filtering of non-WebKit/URLSession apps without a proxy/VPN (the URL Filter Participation API is voluntary).
- Per-user URL reporting from Apple's URL Filter (privacy design forbids it).
- Preventing removal on unsupervised devices.
- GenTech-parity "real-time AI page scanning" claims remain unverified marketing; equivalent function exists only via TLS inspection plus a real classification engine - significant work. **[Hypothesis flag]**

## C. Features requiring further investigation

- The Apple third-party MDM developer selection process: criteria, timeline, realistic odds for a small new entrant. No public documentation; the only known channel is the developer-account "contact us" request for the vendor CSR signing certificate.
- URL-filter Network Extension entitlement approval odds and PIR server operating requirements.
- Partnering options with already-selected MDM vendors (who holds which certificate, per-customer cert flow under A10 4.1, pricing).
- Category-database sourcing: build vs. license (cost unknown until scoped).
- Behavior parity testing against an actual GenTech-managed device (observable behaviors only, with the device owner's consent) - would confirm or kill the supervision hypothesis in 1.4.

## D. Development decision and recommended order (revised)

**Decision: no implementation starts until the authorization question has a documented answer or a clearly identified testing path. That testing path exists and is listed below - it allows real progress without violating A10 and without spending the $99 prematurely.**

Phase 0 - authorization track (start immediately, runs in parallel):

1. Complete Apple Business organization verification (free; already possible now).
2. Enroll in the Apple Developer Program ($99) **when we are ready to request MDM vendor access** - the request itself is the selection doorway; treat the outcome as a project gate. Document Apple's answer either way before any customer-facing build.

Phase 1 - buildable and testable now (no customer devices, no selection needed):

3. Filtered DNS resolver + policy engine; DNS Settings profile locked on a supervised test iPhone.
4. Filtering proxy + PAC + CA issuance; Global HTTP Proxy profile on the test iPhone; validate filtering, captive bypass, and Apple-host exclusions.
5. MDM protocol engine (enrollment, APNs, commands, DDM) tested **in-house** on organization-owned supervised test iPhones - expressly permitted by A10 1.1. APNs push for the in-house test fleet still needs a push certificate, which needs the Developer Program request from step 2; until then, the protocol engine can be exercised with local/manual check-in testing (device polls without push).
6. Admin dashboard over the working policy engine and test fleet.

Phase 2 - gated on selection:

7. Customer enrollment flows (per-customer certificates under A10 4.1), ADE non-removable enrollment, production hardening.
8. Return to Service / reset-recovery automation.
9. URL-filter Network Extension app evaluation (entitlement request via the Developer Program).

## E. Required equipment and accounts

- One or more physical test iPhones (iOS 17+ recommended; iOS 26/27 for newest features), owned by the organization (in-house permission applies to devices the organization owns or controls).
- An iPhone with iOS 16+ for Apple Configurator for iPhone (can be the owner's own phone); a Mac optional for Configurator for Mac.
- Apple IDs: one for the Developer Program, one for Apple Business.
- Server: any Linux host with a public IP and domain name.
- A real organization identity for Apple Business verification (already in progress per project context).

## F. Expected costs, including free alternatives (recalculated)

| Item | Cost | Free alternative / note |
| --- | --- | --- |
| Apple Developer Program | $99/year **[Verified - Apple]** | Prerequisite to *request* vendor MDM access; **does not by itself authorize commercial MDM** (A10) |
| Third-party MDM developer selection | No published fee | Binary risk; if refused, see alternatives below |
| MDM APNs push certificate (per customer) | Free (identity.apple.com) | Customers obtain their own; vendor never holds customer keys (A10 4.1/4.2) |
| Apple Business (incl. built-in device management since April 2026) | Free **[Evidence]** (9to5Mac report of Apple's announcement; verify on business.apple.com when signing up) | Apple's built-in MDM is itself a fallback platform (see below) |
| Apple Configurator (iPhone/Mac) | Free | - |
| Server hosting | Free tiers exist (e.g. Oracle Cloud Always Free) or low-cost VPS; verify current provider pricing before committing | Free tier |
| Domain name | Typically roughly $10-15/year; verify at registrar | Free subdomains possible for development, own domain recommended for production |
| TLS certificate | Free (Let's Encrypt) | - |
| Category/URL database | Unknown until scoped (build vs. license) | Start with self-maintained lists |
| Test iPhone(s) | Hardware cost | Use existing family devices (with owners' consent) |
| **Minimum cash outlay** | **$0 through Phase 1 items 3-4; $99/year once we request MDM vendor access** | - |

**Legitimate alternatives if Apple does not select KosherGuard as a third-party MDM developer:**

1. **Partner with an already-selected MDM vendor:** they hold the vendor certificate and selection; KosherGuard builds the filtering engine, policy content, and dashboard on top of their MDM; each customer still gets its own certificate under A10 4.1. Cost: vendor pricing (unknown until scoped). This preserves most of the product.
2. **Apple Business built-in device management as the MDM layer** (free since the April 2026 merge): customers' devices live in Apple Business with Apple's own MDM; KosherGuard supplies the filtering layer (DNS/proxy) and setup service. Weaker: no custom MDM dashboard, less automation. **[Evidence]**
3. **In-house-only operation (A10 1.1):** manage only devices the organization itself owns/controls (e.g. organization-purchased devices lent to families). Permitted without selection, but changes the business model and raises device-ownership logistics.
4. **Non-MDM consumer filter app:** an App Store app using DNS proxy / URL filter Network Extension entitlements (separate Apple approval) with no MDM at all. Shippable without MDM selection, but no app-removal protection and weaker anti-tamper - a materially weaker product.
5. **Filtered-DNS service only:** resolver + setup service without device management; no enforcement against a determined user.

No option above, and nothing in this document, involves bypassing Apple's certificate or authorization requirements.

---

## Source list

GenTech (public pages, fetched November 13, 2026):

- https://www.gentechsolution.com/how-it-works/
- https://www.gentechsolution.com/installation-ios/
- https://www.gentechsolution.com/ios-help/
- https://www.gentechsolution.com/gentech-pricing-table-new/
- https://www.gentechsolution.com/installation-mdm/
- https://www.gentechsolution.com/install-gentech-ios/
- https://www.gentechsolution.com/install-gentech-pro-ios/
- https://www.gentechsolution.com/wiki/apple-restrictions/

Apple (fetched November 13, 2026):

- https://developer.apple.com/support/downloads/terms/apple-developer-program/Apple-Developer-Program-License-Agreement-English.pdf (Attachment 10)
- https://support.apple.com/guide/deployment/intro-to-device-management-depc0aadd3fe/web
- https://support.apple.com/en-gb/guide/deployment/dep1d89f0bff/web
- https://support.apple.com/guide/deployment/filter-content-dep1129ff8d2/web
- https://support.apple.com/guide/deployment/use-return-to-service-for-apple-devices-dep17cb455a0/web
- https://support.apple.com/guide/deployment/erase-devices-dep0a819891e/1/web/1.0
- https://support.apple.com/guide/deployment/configure-devices-to-work-with-apns-dep2de55389a/web
- https://support.apple.com/guide/business/sign-up-and-verify-your-organization-axm402206497/web
- https://support.apple.com/guide/business/add-devices-using-apple-configurator-axm200a54d59/web
- https://support.apple.com/guide/deployment/web-content-filter-plugin-declarative-depcbacfcb0e/web
- https://support.apple.com/en-us/101555
- https://developer.apple.com/help/account/certificates/mdm-vendor-csr-signing-certificate/
- https://developer.apple.com/programs/
- https://developer.apple.com/documentation/devicemanagement
- https://developer.apple.com/documentation/networkextension/url-filters.md
- https://developer.apple.com/documentation/networkextension/filtering-traffic-by-url
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
- https://textslashplain.com/2025/06/10/apple-url-filter-api/
- https://jtechforums.org/t/ios-26-gentech-filter/8318
- https://9to5mac.com/2026/03/24/apple-business-essentials-goes-free-as-apple-merges-enterprise-tools-into-apple-business/
- https://identity.apple.com

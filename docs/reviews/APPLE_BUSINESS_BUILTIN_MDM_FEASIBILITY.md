# Apple Business built-in MDM: KosherGuard feasibility and implementation plan

Date: 2026-11-17. Source baseline: `full-platform-build` at `19926b7db3270e9ee324c9f05bb1aeaedfa9fce7`.

## Decision

Apple Business has real, included device management and public APIs for custom configuration profiles and Blueprints. KosherGuard could control supported settings through those APIs for eligible organizational deployments, while keeping its own filtering servers and policy dashboard. That does **not** establish a supported architecture meeting the present combination of existing personal iPhones, whole-device filtering, and strong protection against removal. Built-in BYOD enrollment is unsupervised and limited to managed organizational data/apps; Apple's built-in Web Filter explicitly excludes personal devices. Changing MDM providers does not remove these enrollment restrictions.

Recommendation: keep KosherGuard's policy and filtering planes independent of the management provider; retain custom MDM as an engineering option, not a production-ready claim. Do not replace it with Apple Business or build a live adapter until eligibility and required filtering/enforcement capabilities are resolved. A built-in Apple Business connector is a conditional organizational deployment option, not the family-product solution. Under the unchanged requirements, **neither current architecture is proven to satisfy the product**.

This investigation adds documentation only. No Apple login, key creation, certificate operation, device action, deployment, production change, purchase, subscription, or main-branch change was performed. No undocumented endpoints or private APIs are proposed.

## 1. Scope and evidence standard

The approved Apple Business organization and administrator access are user-provided facts. They are not evidence that the built-in service is enabled, that an API account exists, that particular devices are eligible, or that Apple approved consumer-family use. No account inspection was performed. Public documentation and source code establish the findings below; no real APNs, Apple Business API, Xcode/iOS build, or device behavior was tested.

- **Documented:** a current public Apple page or schema describes the capability.
- **Source implemented:** the current repository contains the path; execution and hardware evidence are separate.
- **Not documented:** no supporting operation/field was found in the inspected public API surface. This is not proof of what Apple's private backend could do.
- **Conditional:** plausible supported components exist, but one or more account, distribution, integration or hardware gates remain.

Apple's current API landing page identifies Apple Business API 2.8+. Endpoint/schema inspection covered the API index and its public operation references, Custom Configuration create/update data, Blueprint attributes and relationships, managed device/detail fields and webhook event types. Official support guides, developer documentation/schema, WWDC explanation and current terms were cross-checked. Older Apple Business Essentials subscription descriptions were not used to infer current base-service charges.

## 2. What Apple supplies, and the no-payment boundary

Apple announced the base Apple Business service as free starting April 14, 2026, with built-in MDM; storage upgrades and AppleCare are separate optional purchases [A1]. Built-in MDM activation is documented at Devices > Management Services > Add new device management service > Turn on included device management [A2]. This is a future account action, not something done here.

The Business API setup requires an Organization Administrator to create an API account, assign a role and generate/download its private key [A3]. The documented Business API account procedure does not require buying Developer membership. An API authentication key is **not** an MDM APNs push certificate, MDM vendor CSR-signing certificate, ADE service token, or iOS app-signing credential. OAuth authentication is separately documented [A4].

Apple owns the push/device-management plane for its built-in MDM. No customer APNs certificate upload or export of Apple's APNs private identity is documented in this setup. KosherGuard must not attempt to borrow Apple's certificate, APNs device registration, or enrollment identity. Built-in management can avoid operating our own APNs transport for that deployment; it does not confer vendor-signing or iOS app-distribution rights.

Our own iOS Network Extension app remains a separate gate. Apple says advanced capabilities and app distribution require Developer/Enterprise program membership [A5]. The existing source is unsigned and uncompiled for iOS. Free base MDM does not sign or distribute it. A legitimately distributed third-party filter could avoid us distributing an app, but that is a different product dependency, has no established free compatible provider here, and is not a proven substitute for our engine. No purchase is proposed.

## 3. Exact public API coverage

Base URL: `https://api-business.apple.com`. These are documented integration candidates, **not implemented integrations**. API authorization is role-dependent; object existence and returned fields still require later authorized account testing. All paths below were read from Apple's public operation documentation.

| Need | Documented operations | KosherGuard use and boundary |
| --- | --- | --- |
| Organizational device inventory | `GET /v1/orgDevices`, `GET /v1/orgDevices/{id}` | ADE organizational inventory, not an API to add an arbitrary customer's serial number or establish enrollment. [A6] |
| Built-in enrolled device inventory | `GET /v1/mdmDevices`, `GET /v1/mdmDevices/{id}/details` | Built-in management records. List attributes include deviceName, enrolledUserId, productFamily, serialNumber. Details include OS/platform/model, lastCheckInDateTime, lock/erase/lost-mode states, storage and some hardware fields. Enrollment/privacy/platform can limit available data. [A7] |
| Service inventory and assignment | `GET/POST /v1/mdmServers`; `GET/PATCH/DELETE /v1/mdmServers/{id}`; `GET /v1/mdmServers/{id}/relationships/devices`; `GET /v1/orgDevices/{id}/assignedServer` and `/relationships/assignedServer` | Manage external service records and inspect assignments. Creating a service record is not enabling Apple's built-in MDM, not issuing an APNs certificate, and not enrolling a phone. [A6] |
| Assignment/migration/release activity | `POST /v1/orgDeviceActivities`; `GET /v1/orgDeviceActivities/{id}` | Assignment, unassignment, migration and release are distinct effects. A completed assignment activity is not a device InstallProfile acknowledgment. Release and migration must remain separately gated, never default synchronization behavior. [A8] |
| Policy profile objects | `GET/POST /v1/configurations`; `GET/PATCH/DELETE /v1/configurations/{id}` | Creation/update through the API is restricted to `CUSTOM_SETTING`, rather than arbitrary edits to every built-in Configuration type. Submit a configuration profile, not a KosherGuard policy JSON or raw MDM command. [A9] |
| Policy targeting | `GET/POST /v1/blueprints`; `GET/PATCH/DELETE /v1/blueprints/{id}`; `GET/POST/DELETE /v1/blueprints/{id}/relationships/{configurations,orgDevices,users,userGroups,apps,packages}` | Connect configurations and targets through Blueprint relationships. API uses `orgDevices`, not a presumed arbitrary `mdmDevices` relationship. Personal/User Enrollment uses user/user-group assignment; serial-number targeting requires ADE. [A10, A11] |
| App/package inventory and assignment | `GET /v1/apps`, `/v1/apps/{id}`, `/v1/packages`, `/v1/packages/{id}` plus Blueprint relationships | Existing licensed/distributable content can be assigned. No documented API here uploads an unsigned iOS binary, acquires a Developer entitlement, or accepts our InstallApplication command dictionary. [A6, A10] |
| Users/groups/organizational units | `GET /v1/users`, `/v1/users/{id}`, `/v1/userGroups`, `/v1/userGroups/{id}`, `/v1/userGroups/{id}/relationships/users`, `/v1/organizationalUnits` and related detail/member reads | Map eligible organizational subjects to targets. Do not turn family customers into organizational employees or Managed Apple Account users as a workaround. The inspected index exposes reads for these resources; WWDC's broad description is not a basis to invent additional write routes. [A6] |
| Audit and change signals | `GET /v1/auditEvents`; webhook CRUD, deliveries and ping operations | Useful for inventory reconciliation and management audit. Inspected webhook event enum covers organizational-device attribute, migration detail, assigned-server and warranty changes. It is not a generic per-profile installation, filtering decision or policy-enforcement webhook. [A12] |
| Activation Lock visibility | `GET /v1/orgDevices/{id}/activationLockStatus` | Visibility is not permission to clear Activation Lock or proof of filtering/removal protection. [A6] |

### Configuration request contract

Apple documents an outer `data.type` of `configurations`, `attributes.type` of `CUSTOM_SETTING`, a name, optional `configuredForPlatforms` (for example `PLATFORM_IOS`) and `customSettingsValues.configurationProfile`; `filename` is optional [A9]. The example submits XML profile text. The CustomSettingsValues schema labels configurationProfile as `byte` while describing XML and the example uses an XML string. A later connector must contract-test the actual accepted encoding; do not silently invent a base64 transformation from that type label.

The support guide requires a `.mobileconfig` file under 1 MB with at least one common platform across its payloads. Apple validates payload/platform/enrollment requirements [A13]. API acceptance or a saved resource does not establish device installation.

Blueprint creation warns that invalid resource IDs can be dropped. A connector must read back actual relationships and report omissions, not mark the requested targets successful. Blueprint status (`ACTIVE` or pending deletion) and `appLicenseDeficient` describe the Blueprint resource; they do not prove a profile is active on every phone [A10]. Conflicting configurations require priority/conflict handling; deleting/removing a Blueprint can remove apps and revert settings [A11]. This is not a harmless metadata-only rollback.

### Missing public API contracts for our current architecture

No documented operation was found in the inspected Apple Business API index/schemas for:

- Arbitrary raw MDM command submission, direct APNs push, retrieval of APNs token/PushMagic or an MDM private key.
- Pointing Apple's built-in MDM/DDM check-ins at our own command/declaration server.
- Arbitrary per-device `InstallProfile` command IDs and their MDM acknowledgment/error receipts.
- Raw DDM declaration CRUD or our declaration identifier/server-token application reports.
- Writing the initial managed-app configuration dictionary our iOS app currently consumes (`controlPlaneBaseURL` and `deviceID`) through the app/Blueprint API, or setting per-app ContentFilterUUID attributes. An app assignment alone does not establish either behavior.
- A Blueprint create/update attribute for `PreventUnenrollment`, supervision, bypassing the Configurator provisional release period, or guaranteed automatic post-reset policy restoration.
- A public enrollment-session creation/approval API equivalent to the portal's enrollment/approval workflow.

These boundaries apply to the **public API**, not every feature in Apple's portal. Apple documents portal lock, Lost Mode and erase actions [A14], and the public detail object reports some corresponding states. A readable lock/erase status field does not imply a public endpoint to issue the command. No browser automation of account operations is proposed as a substitute.

## 4. Current KosherGuard architecture inspected

All paths are relative to this repository at the baseline SHA.

| Area | Source inspected | Finding relevant to this decision |
| --- | --- | --- |
| Dashboard | `control-plane/web/app.js`, `control-plane/web/index.html`, `portal/`; legacy `dashboard/src/{server,engine_bridge,publishing,store}.py` | Current control-plane UI operates policies, assignments/groups, schedules, exceptions, apps, credentials, MDM ledger and audit. The earlier dashboard is not an Apple Business connector either. No API account, Blueprint or Configuration resource binding exists. |
| Policy authority | `control-plane/app/{policy_ops,publication_ops,publisher,worker,schedule_ops,exception_ops}.py` | Tenant-scoped policy versions, tighten-only comparisons, immutable generation publication and durable jobs. These are useful independently of who manages devices. An Apple Web Filter list is not a semantic replacement for categories, schedules, per-device policies and exceptions. |
| DNS/filtering | `filtering-engine/src/{policy_engine,category_db,dns_service,engine_set}.py`; `dns-edge/{doh_server,doh_identity,device_policy,policy_bundle}.py` | Server-side category/domain decisions and authenticated per-device DoH use our policy data. They do not depend on Apple hosting MDM, but devices must actually route traffic to them with supported identity. |
| Proxy/URL services | `proxy-edge/`; `url-filter-server/app/{server,dataset,pir_export,device_auth}.py` | Dataset distribution and edge/server components remain ours. A reachable server is not proof iOS traffic uses it; dataset endpoints are not themselves the system's full PIR path. |
| iOS | `ios/README.md`; `Sources/URLFilter/{AppConfiguration,URLFilterConfiguration,DNSOverHTTPSClient,CredentialIssuanceClient,PrefilterUpdater}.swift`; `Sources/FilterExtension/*` | No iOS compile/sign/device validation. Managed app config supplies server URL/device ID. App-mediated DoH only resolves traffic the app routes, not system interception. FilterDataProvider loads an empty rule dictionary; FilterControlProvider has a persistence comment rather than working app-group persistence. Switching MDM does not complete these paths. |
| Custom classic MDM | `mdm/{adapter,command_codec,profiles,identity,customer_apns,apns}.py`; `control-plane/app/{native_mdm,native_mdm_routes,native_mdm_worker,native_mdm_config,native_mdm_server,mdm_ops}.py` | Native identity issuance, signed one-use enrollment, socket client-cert validation, encrypted push registrations, durable push dispatch and classic command ledger exist. Customer-operated certificate transport is distinct from hosted Apple MDM. Real APNs/hardware behavior remains unverified. |
| App control/DDM | `mdm/app_management.py`; `control-plane/app/{app_ops,ddm_ops,ddm_routes,device_status_routes}.py` | Legacy app restrictions and app-settings DDM builders exist. NanoMDM adapter and native transport have different capabilities. Native codec does not support InstallApplication, RemoveApplication or DeclarativeManagement; native check-in only handles Authenticate/TokenUpdate/CheckOut. Existing DDM serving is HMAC-authenticated NanoMDM forwarding, not an Apple Business integration. Do not claim full custom command/DDM parity from the broad adapter interface. |
| Recovery/ADE | `mdm/{ade,nanodep,ade_identity}.py`; `control-plane/app/{ade_web,ade_web_routes}.py`; `docs/reviews/REAL_MDM_ENROLLMENT_REVIEW.md` | Current custom recovery is attended, fresh guardian MFA/approval; not unattended hardware-attested recovery. Manual removal flag is experimental and not device-proven. One configured ADE tenant per instance. |

Additional existing operational gaps: APNs annual-monitoring helpers are not integrated into a full onboarding/rotation flow. In `native_mdm.py`, APNs `cert_problem` parks work with no next attempt; ordinary scheduling only rearms idle/exhausted work. No dedicated certificate-replacement/rearm workflow exists. The dashboard's APNs status still reports unavailable. These are reasons to keep custom-MDM readiness qualified, not reasons to assume Apple Business meets requirements.

## 5. Can Apple's built-in MDM coexist with our filtering engine?

**Yes in principle for eligible, suitably enrolled devices.** MDM is a configuration/control plane, not necessarily the filter's data plane. Apple documents custom payload upload and third-party content-filter payloads [A13, A15]. No source requires us to replace our server-side category database/decision engine with Apple's built-in Web Filter.

A conditional flow would be:

`KosherGuard dashboard -> our policy publication -> our filtering services`

and separately:

`KosherGuard desired configuration -> Business Configuration + Blueprint -> Apple's MDM/APNs -> eligible iPhone`

There is **no** documented flow of `Apple Business -> our existing native /mdm or /checkin endpoints` for phones managed by Apple's built-in MDM. Only one management authority should own an enrollment; our command/DDM ledger must not masquerade as Apple's. Migration requires an enrollment plan, not simultaneous layering of two MDM enrollments [A17].

### Filtering mechanisms and actual limits

| Mechanism | What is supported | Why it is not the complete answer |
| --- | --- | --- |
| Apple's built-in Web Filter | Website blocking, up to 100 blocked addresses, built-in content filtering and up to 100 exemptions [A16] | Explicitly does not apply to personal devices. Different semantics/limits from our category engine, schedules, per-device exceptions and encrypted URL service. Does not run our Python engine. |
| Custom web-content-filter plugin payload | `com.apple.webcontent-filter`, PluginBundleID and filter options configure an installed compatible provider [A15] | Does not supply/install/sign our extension. For unsupervised/User Enrollment, ContentFilterUUID scopes filtering to managed apps with matching app attributes. This is not unrestricted personal-app filtering. The public Business API path for those app attributes was not established. |
| iOS 26 URL filter | Apple's framework uses a Bloom prefilter, PIR/Privacy Pass and Apple OHTTP relay; managed configuration requires supervision [A18] | Our app/extension and production relay/capability approval still needed. Apple networking APIs WebKit/URLSession are covered; other stacks must voluntarily participate. Not all encrypted app traffic is automatically filtered, and privacy prevents per-user URL tracing in that path. |
| Native encrypted DNS profile | Apple documents `com.apple.dnsSettings.managed`; allowed in device enrollment, not User Enrollment [A19] | Apple's current DNSSettings page says MDM-installed settings apply to managed Wi-Fi networks; do not promise all cellular/arbitrary-network coverage. Payload has no custom Authorization-header field, but our DoH server requires one. No unapproved bearer URL-token workaround. Current schema also marks this payload deprecated at iOS 27, so future-version design needs separate review. |
| App-mediated DoH | Our own client can attach the scoped credential header | Only covers app-routed queries; no complete system-wide routing/interception implemented. Does not become system DNS merely because Apple assigned the app. |
| VPN/proxy alternative | Apple has supported VPN/Network Extension mechanisms | Requires an actual implemented compatible transport, applicable entitlements/distribution, enrollment-specific non-disable guarantees, traffic/identity tests and resource review. Not implemented or established as a free drop-in here. |

Important schema qualification: WebContentFilter's top-level availability now permits iOS User Enrollment. This must **not** be read as whole-device filter permission. Apple's release schema says the unsupervised/User Enrollment route requires ContentFilterUUID and applies to matching managed apps. The general availability row, Apple's built-in Web Filter exclusion, and the supervised system-wide requirement describe different scopes, not a license to assume parity [A15, A16, A18].

Remote changes to our server-side rules can work without redeploying the same device profile when device routing/identity remains valid. Changes to filter endpoint/plugin settings need profile reconciliation. Neither an API write nor a push guarantees immediate receipt: offline devices, system fetch scheduling, cached rules and Apple rollout behavior remain. The URL-filter schema specifies a minimum prefilter fetch interval of 2700 seconds with scheduling variation; there is no justified near-instant URL-policy convergence guarantee from a Blueprint update [A15]. Do not weaken fail-closed, coverage or remote-control requirements to hide these limits.

## 6. Personal phones, supervision, removal and reset

Apple's current built-in enrollment guide distinguishes [A20]:

| Enrollment route | Existing phone/data | Supervision on iPhone | Removal/protection consequence |
| --- | --- | --- | --- |
| Account-driven User Enrollment (BYOD) | Existing personal phone, Managed Apple Account, separated organizational data | No | User-controlled removal of organizational management; does not satisfy durable whole-device family filtering. |
| Account-driven Device Enrollment | Existing organization-owned phone without erase; organizational/personal separation | No | Does not establish supervised non-removable management on an iPhone. Not a documented personal-BYOD loophole. |
| ADE, user/user-group Blueprint | New/erased eligible organization device; user identity involved | Yes | Platform permits prevent-unenrollment for supervised ADE. Personal Apple Account behavior differs from device-Blueprint enrollment; do not promise an unchanged consumer setup. |
| ADE, device Blueprint by serial | New/erased eligible organization device; no Managed Apple Account required for device enrollment | Yes | Strongest documented platform route; a personal Apple Account may be added afterward. Device eligibility, setup and enforcement still need validation. |
| Add existing device through Configurator, then ADE | Requires erase where already set up | Yes after proper enrollment | Mandatory management does not erase the documented **30-day provisional user-release window**, applicable to built-in and external MDM. Not non-removable from Day One. [A21] |

The platform's ADE documentation exposes Prevent unenrollment [A22]. That does not prove a Business API Blueprint setting exists for it: none was found. We have not verified the exact built-in service's enrollment-lock behavior for a particular account/Blueprint/device, so no current product claim of non-removability is justified.

A factory reset erases local app/profile/filter state. ADE's persistent organizational assignment can bring an eligible, still-assigned device back through Remote Management on activation with internet access; it is not proof our filter is already active during every setup stage, nor a promise of silent recovery without sign-in/approval. Apple documents re-enrolling found erased devices and its built-in guide includes enrollment approval cases [A14, A20]. Removal/release, loss of assignment, Configurator provisional release and a restore of ordinary manual enrollment are different states. Normal manual/User Enrollment is not automatic post-reset protection. Activation Lock is not a filtering-policy enforcement mechanism.

### Program-use gate is independent of technical enrollment

The **current Apple Business US Terms**, Attachment 2, are the relevant public terms reviewed [A23], rather than relying only on an older ABM agreement:

- Authorized Devices excludes personal BYOD from supervised management unless Apple agrees in writing (definitions, PDF pp. 22-23).
- Authorized Users are specified organizational users, not arbitrary paying family customers; the definition also requires age of majority. Permitted Entities/Users have narrow definitions. Generic guardian consent is not Apple's written exception.
- Section 2.1(C) limits general third-party deployment; 2.1(J) limits service use to internal business/IT purposes with stated exceptions or Apple's written agreement; 2.2 limits making the service available to third parties (pp. 24-25).
- Managed Apple Accounts are restricted to organizational use/authorized users (§2.4).

This is a documented permission gate, not a legal opinion that Apple can never approve any alternative. The applicable region/account agreement and any written exception must be checked before execution. KosherGuard's approved organization does not itself resolve this. Creating a customer account under KosherGuard's organization, relabeling children as staff, or treating Restricted App Mode as normal personal-phone use would not solve the stated product requirements.

## 7. Architecture comparison

| Criterion | Current custom MDM path | Apple Business built-in MDM + proposed connector |
| --- | --- | --- |
| MDM/APNs operator | Customer-controlled certificate worker + native server; optional NanoMDM integration paths | Apple |
| Paid Developer membership for base management | Customer push cert can come through a permitted authorized signer without customer buying membership; own vendor-signing authority is separate and unresolved | Base Business/MDM free; Business API setup docs do not require paid Developer membership |
| Our iOS app distribution/entitlements | Unresolved | Still unresolved; not supplied by Business MDM |
| Dashboard integration today | Implemented local control-plane API/UI and custom ledger, but hardware unverified | No connector implemented; documented configuration/Blueprint APIs give a real potential path |
| Policy engine/category/schedule control | Our own | Can remain ours if routing/profile/app compatibility is established; Apple's built-in Web Filter is not equivalent |
| Profile/app command control | Native subset; broader NanoMDM adapter path, not universal parity | Configuration objects + Blueprint assignment; no documented arbitrary command API |
| DDM | Existing NanoMDM forwarding path; native path incomplete | Apple owns DDM; no documented raw declaration injection/status forwarding to us |
| Status | Our command receipts and scoped DDM reports; not proof of filtering | Inventory/check-in and selected state fields, no documented per-profile acknowledgment/filter-verdict API |
| Personal iPhones without erase | Removable/limited enrollment is possible; experimental manual supervision/removal is unproven | Documented User Enrollment, unsupervised/managed-data scope |
| Strong removal protection | Eligible supervised ADE is platform route; own operational and authorization gaps remain | Same platform/device eligibility gates; built-in API lock-setting contract not established |
| Factory-reset recovery | Current implementation attended; no unattended claim | ADE conditional re-enrollment, not demonstrated silent filter restoration; manual/BYOD not equivalent |
| Consumer-family program eligibility | Not established | Not established; current terms expressly constrain relevant use |
| Operational burden | Identity CA/signing, enrollment TLS, APNs cert/renewal, push outbox, commands, audits | Less push/certificate operation, but API credentials, profile reconciliation, limited observability, provider dependency |
| Meets all unchanged requirements now | **No** | **No** |

The earlier APNs feasibility report remains relevant to the custom path; this investigation neither creates signer access nor changes any certificate. See `REAL_MDM_ENROLLMENT_REVIEW.md` for custom enrollment implementation evidence and limitations.

## 8. Recommended design and concrete implementation plan

### Decision order

1. **Current decision:** do not migrate or replace custom MDM, do not claim built-in MDM solves consumer non-removable BYOD, and do not invest in a speculative complete adapter.
2. **Conditional first choice for eligible organizational fleets:** retain our policy/filtering services; evaluate Apple-managed MDM as a separate provider for documented Configuration/Blueprint operations. If payload delivery, app configuration or required status cannot be supported, retain a properly authorized custom/partner MDM provider rather than simulating parity.
3. **Family product:** keep the existing-personal-phone and removal requirements explicit. Obtain a documented Apple-permitted deployment/distribution model before selecting a production management architecture. No presently documented option satisfies the combination here. Removable consumer apps or managed-app-only BYOD could be separately labeled products only if the owner explicitly changes requirements; they are not the recommendation for this assignment.

### Phase 0: completed in this investigation, no account changes

- Re-read official APIs, schemas, platform and enrollment docs, current US terms.
- Clone and inspect expected branch head; map code/provider differences and blocking transport assumptions.
- Record this feasibility report, comparison, capability boundaries and test plan only. No speculative runtime implementation or weakening of existing safety checks.

### Phase 1: useful local work available without Apple login/certificates

Only after agreeing that organizational evaluation is useful:

1. Add provider-neutral capability contracts rather than force Apple into `MDMAdapter.deliver_command/push`. Providers should advertise inventory read, profile-object write, Blueprint targeting, app assignment, command receipts, DDM and enrollment protection independently. Unsupported operations must fail explicitly; no fake acknowledgment or fallback to a different provider.
2. Build an **offline** Custom Configuration serializer/validator: deterministic stable identifiers, valid plist, shared-platform checks, size ceiling, no nested MDM enrollment payload, no embedded private keys, redacted credentials, and explicit per-payload enrollment/OS constraints. Keep policy category logic on our servers; no silent truncation to Apple's 100-site UI.
3. Add a disabled-by-default organization-scoped Business API connector with injected HTTP transport. Map tenant/organization/resource IDs explicitly; never match BYOD by unavailable serial alone. Persist desired revision, profile digest, remote ID, observed relationships and read-back time. Keep separate `submitted`, `relationship_observed`, `device_recently_reported` and `enforcement_unverified` states.
4. Mock public API responses for OAuth expiry, permissions, pagination, invalid/dropped target IDs, conflict, 429/backoff, 5xx, partial reconciliation, repeat requests, stale inventory, cross-tenant refusal, credential redaction, and unsupported commands. These are synthetic contract tests, not Apple certification or hardware proof. No real API key is necessary.
5. For destructive effects (Blueprint deletion, profile removal, release, migration), require explicit affected-target preview and existing fresh-MFA/approval controls. Default connector scope should be read-only, then additive test-profile operations. Never add release/erase to ordinary policy synchronization.
6. Keep our DNS header-identity limitation and iOS persistence/routing gaps visible. Build ordinary server-side regression improvements independently of the Apple connector if useful. Do not output a production profile that pretends an Authorization header can be supplied by DNSSettings.

**No Phase 1 runtime code was added in this investigation.** Its usefulness depends on a supported target deployment; documentation is the grounded improvement now.

### Phase 2: requires later specific account authorization, not included here

- Confirm applicable terms/region and written Apple eligibility if consumer/family/supervised personal use is intended. The next step can be preparing precise questions for Apple's official support channel; no message/request has been sent.
- Inspect actual base-service availability and role permissions; decline optional storage/AppleCare purchases.
- Have an Organization Administrator create the minimum-role API account at Settings > API > Add API Account, then Generate & Download the key [A3]. Treat the one-time private key as a persistent secret with restricted service-side custody; never put it in the dashboard browser, logs or repository.
- If approved, enable included management through the documented flow [A2]. Do not create an external MDM server record assuming it activates built-in MDM.
- Verify read-only inventory/permissions first. Then a separate authorized test Configuration/Blueprint on an isolated organizational target, not customer devices. Check profile encoding, payload acceptance, Blueprint read-back, targeting and actual device observations.

### Phase 3: requires separately approved spare hardware and distribution path

Test existing BYOD and eligible ADE as **different** cases, including cellular/unmanaged Wi-Fi, non-WebKit apps, alternate DNS/VPN, reboot, offline changes, expired credentials, app removal, management removal, reset/recovery and Configurator provisional release. Verify full policy differences (default deny, categories, schedules, per-device tighten-only changes and guardian exceptions), fail-closed and rollback behavior. Test the Apple API's actual profile installation/error visibility and managed-app settings delivery. A GUI success message is insufficient.

Do not test on customer phones or create signing/APNs certificates under this assignment. Production go/no-go requires a supported program-use model, real device evidence and a maintained credential/recovery runbook. If a must-have cannot be proven, report it as a blocker, not an unsupported feature to approximate.

## 9. Outstanding blockers and what could change the answer

| Blocker | Evidence / condition to clear |
| --- | --- |
| Supervised household BYOD / family users permitted? | Applicable Apple terms and written approval/exception covering actual users/devices/service model, not organization approval alone. |
| No-erase personal phones plus durable management | Documented enrollment method with required whole-device scope and removal protection. Current built-in BYOD guide does not supply it. |
| Built-in non-removable enrollment behavior | Public setting/contract or later authorized device evidence for the actual built-in service; API Blueprint attributes do not establish it. |
| Our iOS app viable without paid membership | Legitimate signing/distribution/capability route consistent with no-payment constraint, not free Personal Team assumed to support production distribution. |
| End-to-end engine routing/identity | Compatible profile/app configuration path, DoH auth transport, real supported Network Extension, app-group persistence and device tests. |
| Necessary API observability/control | Public supported routes for any required managed-app configuration, per-app attributes and per-device policy application evidence, or a design that honestly reports those unavailable. |
| Factory-reset protection | Eligible continuing ADE assignment plus demonstrated reprovision/enforcement sequence; do not equate non-removable enrollment with unerasable hardware. |
| Current custom operational readiness | Native command/DDM gaps, APNs lifecycle integration, actual iOS compilation/signing, Apple authorization and hardware testing remain. |

Apple could clarify additional supported Business APIs or grant a specific deployment exception, changing a gate. Such evidence must be verified before changing this verdict. Current docs do support a useful organizational integration surface; they do not support presenting this as a completed family-filtering alternative.

## 10. Validation ledger

- Fresh public clone of `full-platform-build` resolved to expected baseline `19926b7db3270e9ee324c9f05bb1aeaedfa9fce7`; no unexpected source drift at inspection.
- Official public pages and developer schema objects inspected on 2026-11-17. The operation index was enumerated from Apple's documentation, including exact REST paths and read/write verbs.
- Source review covered dashboard/control-plane, policy publication, filtering services, iOS clients/extensions, native/NanoMDM command paths, certificate transport, DDM, ADE and recovery as mapped above.
- Documentation-only change: this report. No runtime tests were claimed or needed to prove an unimplemented connector. Existing suites were not rerun merely to imply Apple compatibility.
- No Apple account/API calls, API key generation, certificate generation, real APNs or device/network enforcement tests. All hardware and operational feasibility claims remain qualified.

## Official source ledger

All accessed 2026-11-17. Support dates below are page publication dates when shown. Schema endpoints are public documentation resources, not authenticated account calls.

- **A1. Apple Newsroom, March 24, 2026:** free base-service rollout, included MDM, optional paid extras. https://www.apple.com/newsroom/2026/03/introducing-apple-business-a-new-all-in-one-platform-for-businesses-of-all-sizes/
- **A2. Apple Support, April 14, 2026:** built-in MDM enable/disable procedure. https://support.apple.com/guide/business/manage-the-built-in-device-management-service-axmc7864dd73/web
- **A3. Apple Support, September 23, 2026:** API account role, permissions and key-generation procedure. https://support.apple.com/guide/business/create-an-apple-business-api-account-axm33189f66a/web
- **A4. Apple Developer:** Business API OAuth authentication article. https://developer.apple.com/documentation/apple-school-and-business-manager-api/implementing-oauth-for-the-apple-school-manager-and-apple-business-api
- **A5. Apple Developer:** free registration vs membership; advanced capabilities and distribution. https://developer.apple.com/support/compare-memberships/
- **A6. Apple Developer:** current complete Apple Business API index and resource operation references. https://developer.apple.com/documentation/applebusinessapi ; machine-readable documentation https://developer.apple.com/tutorials/data/documentation/applebusinessapi.json
- **A7. Apple Developer:** built-in enrolled devices and detail fields. https://developer.apple.com/documentation/applebusinessapi/get-apple-mdm-enrolled-devices ; https://developer.apple.com/documentation/applebusinessapi/get-the-details-for-apple-mdm-enrolled-device ; https://developer.apple.com/documentation/applebusinessapi/mdmdevicedetail/attributes-data.dictionary
- **A8. Apple Developer:** assignment/migration/release activities. https://developer.apple.com/documentation/applebusinessapi/create-an-orgdeviceactivity
- **A9. Apple Developer:** exact Configuration create/update and XML contract. https://developer.apple.com/documentation/applebusinessapi/create-a-configuration ; https://developer.apple.com/documentation/applebusinessapi/update-a-configuration ; https://developer.apple.com/documentation/applebusinessapi/customsettingsvalues
- **A10. Apple Developer:** Blueprint create, attributes and relationship endpoints. https://developer.apple.com/documentation/applebusinessapi/create-a-blueprint ; https://developer.apple.com/documentation/applebusinessapi/blueprint/attributes-data.dictionary ; https://developer.apple.com/documentation/applebusinessapi/add-configurations-to-a-blueprint ; https://developer.apple.com/documentation/applebusinessapi/add-org-devices-to-a-blueprint
- **A11. Apple Support, April 14, 2026:** Blueprint targeting, conflicts and removal effects. https://support.apple.com/guide/business/apply-blueprints-axm0d43737a4/web
- **A12. Apple Developer:** documented webhook event types; not per-filter or profile acknowledgments. https://developer.apple.com/documentation/applebusinessapi/webhookeventtype
- **A13. Apple Support, April 14, 2026:** custom mobileconfig, 1 MB/platform and payload-validation rules. https://support.apple.com/guide/business/custom-configuration-axmcf4de99c4/web
- **A14. Apple Support, April 14, 2026:** portal locate/lock/erase capabilities and reenrollment. https://support.apple.com/guide/business/locate-lock-and-erase-devices-axmc3c3e0b1e/web
- **A15. Apple Developer / Apple device-management release schema:** web content plugin, per-managed-app UUID scope, URL filter parameters/fetch timing. https://developer.apple.com/documentation/devicemanagement/webcontentfilter.md ; https://raw.githubusercontent.com/apple/device-management/release/mdm/profiles/com.apple.webcontent-filter.yaml
- **A16. Apple Support, April 14, 2026:** built-in Web Filter limits and personal-device exclusion. https://support.apple.com/guide/business/web-filter-configuration-axmb90f8493c/web
- **A17. Apple Support, April 14, 2026:** assigning/reassigning services, built-in unenrollment before reassignment. https://support.apple.com/guide/business/assign-reassign-or-unassign-devices-axmf500c0851/web
- **A18. Apple Developer, WWDC25:** filter API traffic scope, supervised managed URL filtering, relay/distribution approval. https://developer.apple.com/videos/play/wwdc2025/234/
- **A19. Apple Developer / release schema:** DNSSettings payload limits, forbidden User Enrollment and current deprecation metadata. https://developer.apple.com/documentation/devicemanagement/dnssettings.md ; https://raw.githubusercontent.com/apple/device-management/release/mdm/profiles/com.apple.dnsSettings.managed.yaml
- **A20. Apple Support, April 14, 2026:** built-in enrollment matrix, data separation, accounts, supervision and approvals. https://support.apple.com/guide/business/enrollment-methods-axma9a72e8a5/web
- **A21. Apple Support, April 14, 2026:** Configurator erase flow and 30-day release period, both built-in and external services. https://support.apple.com/guide/business/add-devices-using-apple-configurator-axm200a54d59/web
- **A22. Apple Platform Deployment:** ADE platform Prevent unenrollment capability. https://support.apple.com/guide/deployment/automated-device-enrollment-and-mdm-dep73069dd57/web
- **A23. Apple Legal:** current Apple Business US Terms, particularly Attachment 2 definitions and §§2.1, 2.2, 2.4. https://www.apple.com/legal/platform-services/apple-business/abus.pdf ; region selector https://www.apple.com/legal/platform-services/apple-business/

Official sources establish public capability/terms. No third-party claim is used to overcome an Apple enrollment or account restriction. The applicable account's accepted agreement and any written Apple exception have not been inspected.

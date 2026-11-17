# Real MDM enrollment infrastructure review

Date: November 17, 2026
Repository: yossigo88-cyber/kosherguard-platform
Branch: full-platform-build only
Starting SHA: 40ea8201ab29f6b2db44c8a657f46cd17343639a

## Readiness and scope

Real local identity issuance, profile signing, HTTPS delivery, certificate-authenticated Apple check-in/command endpoints, enrollment lifecycle, attended ADE recovery and customer-owned APNs outbox/worker are implemented and automated-tested. **No real iPhone, Apple service or deployment has validated this build. It is not production/fleet-ready.** There is no Apple vendor/consumer authorization established. A valid generated plist or CMS signature is not proof iOS installs/enforces it.

The requested unattended automatic recovery after erase is **incomplete**: Apple's continuing eligible ADE assignment can return a device to enrollment, but this implementation deliberately requires a freshly authenticated attending guardian before releasing a new PKCS#12 identity. Captured signed MachineInfo is not a safe bearer token for a new device private key. This build implements a reusable *attended* configuration_web_url alternative, not an unsafe CMS-only automatic route. Unattended hardware-bound ACME attestation remains unimplemented, not simulated as working.

No main merge/modification, deployment, DNS/live site change, purchase, Apple contact/account setting, Apple certificate generation/request, real push, or iPhone enrollment/erase/modification occurred. Only synthetic test certificates were generated in temporary local fixture directories. No private credentials or test certificates are committed.

## Implemented behavior

### Identity and profiles

- Configured local-CA issuer generates a unique RSA2048 client identity per tenant/registered UDID, with random certificate serial, clientAuth EKU, non-CA constraints, SHA256 signature, validated CA/key and bounded lifetime. This is a **device identity CA**, not an Apple vendor CSR signer or customer APNs certificate.
- PKCS#12 is an Apple-supported identity delivery alternative to ACME/SCEP. Actual ACME/SCEP services are not implemented. Apple recommends those because the private key remains device-only. With PKCS#12 the key exists transiently at the issuer and in the sensitive profile; the password travels in the profile, so the container's encryption does not make profile sharing safe.
- Signed operational profiles use unique issued PKCS#12 bytes, not a placeholder Apple issuance URL. Profiles are signed as DER CMS and verified against explicit configured trust before delivery; no no-verification fallback. Profile-signing identity is separate from Apple's MDM vendor authorization. Apple permits unsigned profiles in some workflows; signed-only is this project's policy, not a universal Apple restriction.
- One-use ten-minute HTTPS profile URLs for ordinary/manual enrollment; no profile/key persistence or sensitive access logs in the dedicated listener. Lost download response requires local revoke/new attempt, not replayable token recovery. Ordinary enrollment omits removal protection. Experimental manual protection remains strict explicit operator declaration, matching serial, supervised=true boolean, evidence/operator and timezone-aware fresh timestamp; it is NOT hardware attestation and can be false.
- The legacy unsigned artifact builder remains explicitly undeliverable and now uses a visibly nonworking .invalid ACME URL instead of implying an Apple issuance service exists. Its other ordinary defaults remain intact. The operational builder is separate and does not advertise unsupported user-channel/bootstrap-token capabilities.
- Corrected ADE-only supervision comments. Apple explicitly documents top-level PayloadRemovalDisallowed for supervised iOS MDM profiles. Whether **this exact generated profile** is accepted and its Settings removal blocked remains experimental and untested.

### Endpoints and lifecycle

- Persistent new tables/migration0026 extend the existing control-plane database, not a competing database: native provisions, approved Apple inventory, short-lived web ceremonies, session-bound web activation attempts. Existing device/enrollment/command models remain the parent lifecycle records.
- Global current UDID and certificate uniqueness, existing one-current-enrollment-per-device index, token hashes, one-use delivery, serial/UDID/topic checks and tenant/device/command binding. Preregistered identifiers are operator inventory, not manufacturer proof.
- Guardian/device authorization, existing MFA/session checks and CSRF header protect issue/renew/revoke/inventory decisions. No key-upload endpoint. Missing explicit runtime leaves native issuance disabled and legacy behavior unchanged.
- Dedicated HTTPS listener reads real CA-verified TLS peer certificate bytes from the socket, then exact DB pin/current-validity/UDID/lifecycle checks. Never trusts certificate/tenant headers. Initial download may omit client cert; check-in/command cannot. TLS1.2 minimum,16-worker cap before handshake,60 admissions/IP/minute, bounded1024-IP LRU,3-second handshake/body timeouts,1MiB requests and malformed/entity/framing rejection. Local bounds are not Internet-scale DDoS proof; front-door deployment protection remains required.
- Lock order tenant -> Device FOR UPDATE -> provision -> enrollment, with refreshed ORM state after waits, prevents concurrent offboarding/check-in resurrection. Shared cleanup is integrated with existing offboarding completion, local revoke and CheckOut: clears push/pending identity, disables worker work and terminalizes queued/delivered/not_now commands. Local revocation is not physical profile removal, Apple release or erase. CheckOut is best-effort and may never arrive.
- Authenticate does not mark installed enrollment. First valid TokenUpdate does; latest push token/PushMagic replace old, omitted UnlockToken retains old. Push registration encrypted with external Fernet key.
- Native command wire codec and shared ledger cover read-only inventory/profile queries, InstallProfile/RemoveProfile and limited approved lock/restart/erase variants. Existing two-person destructive-command gate remains required. Native app-install/DDM/user-channel variants reject rather than pretend supported. Native commands cannot be accidentally sent/reconciled through NanoMDM.
- Same in-flight UUID redelivers on duplicate Idle. NotNow ends session; next poll resends same deferred UUID before later queued work. Exact duplicate authenticated responses are idempotent by body digest; conflicting/reused UUID answers reject. Acknowledged is not independent applied-filter proof, so native applied remains false. DeviceInformation may record device-reported supervision, not manufacturer attestation.

### Renewal and expiry

- Actual controlled-overlap replacement: same stable PayloadIdentifier per enrollment, fresh PKCS#12/CMS replacement encrypted at rest in queued command, old+pending certificate pins coexist. Pending-cert Authenticate is accepted without downgrading installed state; only valid pending-cert TokenUpdate promotes new identity and disables old pin. Successful promotion removes historical encrypted private-key payload from queue.
- Renew while enrolled and >24h before old expiry. Default identity30days,1..90day configured bound and issuer-expiry cap. Manual-protected replacement requires a fresh matching declaration and preserves experimental flag. Multiple pending rotations reject. A definitely undelivered queued replacement can be canceled; delivered/failed/ambiguous replacement cannot discard pending identity on a guess. Error/NotNow never retires old pin automatically.
- Expiry worker updates healthy/renewal_due(7days)/expired state and audit without unsolicited external messages. No production alert delivery was set up. Actual iOS PKCS#12 enrollment-profile replacement, exact check-in sequence, failed-install rollback and physical recovery are **unverified hardware gates**. Automated renewal scheduling is not enabled, and no fleet should rely on synthetic sequence tests alone.

### Separate ADE and manual strategies

**ADE:** policy builder generates supervised/mandatory/Prevent Unenrollment fields, with await_device_configured=false because DeviceConfigured setup gating is not implemented. Define Profile helper requires Apple's returned UUID before assignment. JSON is not Apple registration. Existing NanoDEP path preserved; corrected an audited preexisting endpoint mismatch: full list is POST/server/devices; POST/devices is Device Details with explicit serial list. Added nonadvancing pagination guard.

CurrentAssignmentLookup performs a real configured customer-server Device Details call on each decision and delivery, checks exact expected profile_uuid, assigned/pushed status, serial and nondeleted/nonreleased state, and associates UDID through separately approved inventory. Private config supplies actual customer NanoDEP URL/key/server/profile; none provisioned or called here. One configured ADE block supports **one tenant/server/profile**, not all tenants merely because state isolation supports many tenants. Other tenant attempts fail closed. Multi-tenant ADE registry is not implemented.

Stable /ade/enroll uses Apple's configuration_web_url GET/header format. Apple-root CMS inspection gives inventory, not fresh activation proof. An opaque HttpOnly cookie references encrypted server-side ceremony, expires10minutes; PostgreSQL admission caps1000 live anonymous ceremonies plus10 starts/IP/minute. Same-origin UI requires guardian MFA login AFTER ceremony start and<=5minutes old. Audited preapproved physical serial/UDID inventory and current customer assignment must match. CSRF-protected explicit guardian decision creates a one-use5minute attempt bound to that exact session+ceremony; final CMS profile is delivered only there, on the same host. A new recovery ceremony requires a new MFA login and explicit restart if replacing an old record. Restart locally disables previous identity and is not remote removal/erase. A captured envelope or final URL alone never returns a private profile. Generic CMS-only POST/ade is disabled(410); generic issue API modeADE redirects usage to attended flow(409).

Inventory POST requires freshTOTP and explicit confirmation. PATCH permits audited same-device/tenant correction only when no current enrollment exists; never rewrites installed identity. DELETE local inventory requires device already offboarded/no current enrollment plus freshTOTP/confirmation, does not release from Apple. Unique serial/UDID prevents silent cross-tenant reassignment.

This is **attended recovery only**. An Apple assignment can force the device back into the approved Remote Management flow, but this implementation does not complete it without guardian involvement. Real automatic hardware-bound ACME attestation would need Apple attestation root/chain, server-challenge freshness, exact serial/UDID/properties and CSR-key binding plus full protocol/state tests. It is not built here. Household eligibility/written authorization and per-device assignment remain independent legal/operational gates.

**Manual supervision:** Configurator Prepare with supervision and Do not enroll, finish setup, inspect same serial/supervision in Configurator/Settings, then generate guarded manual profile. No Apple Business is technically required for this route, but vendor/consumer authorization remains required. Exact Settings-removal behavior not tested. No automatic reenrollment after clean erase/factory/DFU/computer restore. Legacy same-device supervised-backup retention guidance applies to earlier systems; Apple's WWDC26 **pre-release27** guidance explicitly says iOS/iPadOS/visionOS27 no longer restore enrollment profile, management configuration or supervision from backup. Do not generalize the earlier exception to27, or treat backup restoration as protection persistence. Actual OS/version-specific behavior needs hardware validation.

### APNs and customer custody

CustomerAPNsTransport is a real HTTP/2 certificate-authenticated production-host client, UID/topic/key/validity checks, no JWT/token auth and no redirects. MDM push body is only mdm:PushMagic; no command/policy/personal data. APNs200 means acceptance, never delivery/applied. Customer-owned worker calls durable dispatch -> current encrypted registration -> customer push transport. Queue/TokenUpdate schedule work; persisted bounded backoff,8-attempt exhaustion, token/cert failure states survive worker restarts. Device contact resets wake state; invalid-token stage allows valid later TokenUpdate recovery. Expiry scanner shares worker. No worker was deployed and all APNs responses in tests are mocked.

**Custody boundary:** worker runs only inside customer-accessible instance, exactly one tenant/topic and customer's own key. Vendor must not generate/access customer APNs private key under Attachment10. No vendor-hosted key-upload, shared customer key store or vendor-global push certificate is supplied. Private file factory requires owner-only keys/config outside Git. Customer-instance hosting/access control, database segregation/least privilege, key custody proof and deployment monitoring remain operational requirements, not satisfied by naming a configuration field.

## First real-device test, not performed

1. Resolve actual Apple vendor/consumer permitted use and, for ADE, organization/device eligibility. Obtain separate owner authorization for any Apple certificate/account work, hosting/deploy and named spare iPhone. Existing build authorization forbids performing those operations now.
2. Provision separate customer-controlled APNs identity/key, device identity CA, trusted profile CMS signer and public TLS identity. Keep customer APNs key inaccessible to vendor. Obtain keys through approved secret collection, never chat/Git. Provision external Fernet key and approved authorization record. No placeholder endpoint or synthetic certificate may enter a real test.
3. Back up staging DB, run Alembic0026 upgrade and all tests at exact chosen SHA, inspect migrations/rollback. Do not migrate production merely because tests pass. Install dependencies from control-plane requirements; OpenSSL CMS CLI is required. Configure runtime explicitly through KG_NATIVE_MDM_CONFIG(mode0600 outside Git) and KG_DATABASE_URL secret environment.
4. Private config fields: identity_ca_file,identity_key_file,profile_signer_file,profile_signer_key_file,profile_chain_file,profile_trust_file,base_url,organization,tenant_topics,token_encryption_key_file,authorization_reference,tls_certificate_file,tls_private_key_file. Optional ade block: nanodep_url,nanodep_api_key_file,tenant_id,dep_name,profile_uuid,apple_root_file. Use official trusted Apple roots, actual current profile and customer server. Customer worker additionally needs customer_apns_certificate_file,customer_apns_private_key_file,customer_instance_reference and exactly one tenant/topic. No actual config/secrets bundled.
5. Start existing app.asgi with opt-in configuration and separate TLS listener: from control-plane run python3 -m app.native_mdm_server --config-factory app.native_mdm_config:factory --bind APPROVED_BIND --port APPROVED_PORT. Customer-owned worker: python3 -m app.native_mdm_worker --once for controlled trial, then supervised worker only after approval. API/ADE web must use public HTTPS on the SAME host as final profile. Dedicated device listener uses real mTLS, no cert-forwarding headers. Disable sensitive URL access logs and add approved ingress/monitoring limits. The shared file factory currently loads TLS key even in worker; provision only in approved same-customer boundary, not vendor custody.
6. Register physical spare's verified serial/UDID under correct guardian/device tenant. Ordinary/manual native enrollment API returns one-use10minute URL; treat as private key. For manual: approve backup/erase/Prepare(supervise,Do not enroll), setup, inspect actual same serial and supervised notice, record fresh honest declaration, mode manual_supervised, signed operational profile via Configurator Add>Profiles. Ordinary removable route is a separate control. Test actual profile acceptance and Settings deletion; stop on rejection. No backup modification or bypass.
7. For ADE attended: freshTOTP POST /api/mdm/devices/{id}/apple-inventory, confirm approve-device-inventory; configure real current lookup/server/profile. Register Apple's ADE profile using stable configuration_web_url=https://APPROVED_HOST/ade/enroll and same-host url, supervised/mandatory, is_mdm_removable=false; assign returned UUID only to eligible approved spare. After approved erase/activation, verify Apple's signed header arrives, UI loads in Setup Assistant, fresh guardian MFA login/physical inventory confirmation and explicit approval produce final signed profile in same session. Test second approved activation requires fresh login/restart but same stable configured URL. Do NOT call this unattended automatic enrollment. If login cookie/webview mechanics differ on iOS, stop and report; no fallback to unauthenticated profile delivery.
8. Confirm real TLS cert/UDID association, Authenticate remains pending, first TokenUpdate marks installed, latest push registration is correct/encrypted. Send one real customer-instance APNs wake, record Apple acceptance separately from actual device contact. Queue read-only DeviceInformation/ProfileList, compare UUID and actual serial/IsSupervised. Then an explicitly approved harmless restriction profile and verify actual behavior, not merely Acknowledged.
9. Test NotNow/device-poll order, offline/error/rotation/backoff, wrong cert/topic/tenant, replay/session theft, revoke/offboard and missing CheckOut. iOS27 DDM App settings is ADE-only; native DDM bridge and complete filtering/app delivery are separate incomplete work. Swift client remains uncompiled/unsigned/untested and intentionally rejects its own unsigned path; these enrollment URLs use OS/Configurator, not silent app installation.
10. Before expiry and with spare-device recovery authorization, POST /api/mdm/native-enrollments/{pk}/renew-identity (>24hours old-cert lifetime remaining; fresh declaration body for manual mode). Observe exact iOS replacement sequence, pending Authenticate if sent, install status and **new-certificate TokenUpdate before old pin retirement**. Simulated tests do not establish iOS will use this sequence. Test failure/NotNow, both pins retained and no management loss. Cancel only undelivered queue via DELETE pending-identity. Delivered/ambiguous update requires actual state verification, not guessed rollback.
11. Prove physical recovery before fleet use. If replacement fails/identity nears expiry, stop test use; owner separately approves removal/re-enrollment/erase as needed. Do not revoke last good cert before confirming recovery. ADE nonremoval may require authorized assignment/unenrollment/erase; manual flag may require Configurator/erase. No action is automatic from this report. Confirm OS-specific restore and cleanup behavior with real hardware.

## Remaining blockers / incomplete work

- Apple selection, household/consumer written permission/capability, Business eligibility and customer APNs authorization not established. Certificates do not authorize business model.
- No approved real device, actual credentials, TLS/issuer/customer deployment, Apple-root/device exchange, APNs push or hardware result. All integration/device compatibility remains unverified.
- Unattended automatic ADE identity/recovery remains NOT IMPLEMENTED; safe reusable attended alternative is built. Attested ACME future route is not a stub described as complete.
- Renewal crypto/state implementation is built, but iOS replacement/rollback/expiry recovery and automatic operational scheduling must be validated before production. Expiry metadata/audit is not an alerting service.
- ADE file configuration supports one tenant/server/profile. No multi-tenant ADE config registry. Native data isolation supports multiple tenants but is not proof of every deployment topology.
- Native DDM/app-install/user channels/full filtering payload delivery, production service orchestration, compliance, penetration/load tests and customer-instance custody audit remain out of this implementation. No iOS compatibility or working customer filtering claimed.

## Apple authorization, distinct gates

Official sources checked November17,2026. This is an engineering reading, not Apple approval or legal advice. No Apple contact/account action is authorized by this report.

| Requirement | What it provides | What it does NOT provide / current gap |
| --- | --- | --- |
| Apple Developer Program membership | Developer account/program access; Apple's enrollment page states eligibility and fee requirements | Not automatic MDM vendor selection, customer push certificate, Business qualification or approval of household business model. No purchase made. |
| MDM Vendor CSR Signing Certificate | Apple-selected third-party MDM vendor can sign verified customer CSRs under Attachment10 | Not a device identity CA, not a profile-signing requirement, not blanket commercial/consumer authorization. Selection not established. |
| Customer APNs MDM certificate | Customer-specific push topic and certificate authentication; yearly same-topic renewal needed | Not vendor authorization, not ADE assignment, not proof supervision or non-removal. Customer private key remains inaccessible to vendor. None provisioned. |
| Apple Business organization and assigned eligible devices | ADE assignment and supervised enrollment policy/recovery where supported | Business qualification isn't automatically available to a consumer service. Terms exclude personally-owned/BYOD supervised management absent written agreement. Prior Not Qualified state unresolved; no current account inspection/change performed. |
| Consumer/personal-use permission | DPLA Attachment10's permitted customer/use scope and any required written exception must cover the actual household service | Charging a household, parental consent or possession of certificates does not establish this exception. No written permission established. |
| App Review5.5 requested MDM capability | Apple describes a limited parental-control/device-security company approval route with privacy/data obligations | Not already granted to KosherGuard, and not an override of DPLA/Business terms. App-review permission, MDM vendor selection and Business eligibility are distinct. |

### Official source ledger

1. Apple identity methods, TLS and UDID association: https://developer.apple.com/documentation/devicemanagement/managing-certificates-for-device-management-services-and-devices.md
2. Apple enrollment delivery: https://developer.apple.com/documentation/devicemanagement/deploying-device-management-enrollment-profiles.md
3. Apple MDM payload/topic/production push semantics: https://developer.apple.com/documentation/devicemanagement/mdm.md and https://developer.apple.com/tutorials/data/documentation/devicemanagement/mdm.json
4. Top-level removal key and supervision: https://developer.apple.com/documentation/devicemanagement/toplevel and https://developer.apple.com/tutorials/data/documentation/devicemanagement/toplevel.json
5. Authenticate is not installation proof: https://developer.apple.com/documentation/devicemanagement/authenticate.md
6. Token rotation/first push/optional UnlockToken: https://developer.apple.com/documentation/devicemanagement/token-update.md
7. Best-effort CheckOut: https://developer.apple.com/documentation/devicemanagement/check-out.md
8. Deferred command retries: https://developer.apple.com/documentation/devicemanagement/handling-notnow-status-responses.md
9. ADE signed MachineInfo: https://developer.apple.com/documentation/devicemanagement/machineinfo.md
10. Classic POST and web-view distinction: https://developer.apple.com/documentation/devicemanagement/authenticating-through-web-views.md
11. ADE profile fields: https://developer.apple.com/tutorials/data/documentation/devicemanagement/profile.json and https://developer.apple.com/documentation/devicemanagement/define-profile.md
12. ADE server authentication (not device request authentication): https://developer.apple.com/documentation/devicemanagement/authenticating-for-automated-device-enrollment.md
13. MDM customer APNs certificate/key restrictions and no token-based MDM auth: https://developer.apple.com/documentation/devicemanagement/setting-up-push-notifications-for-your-device-management-customers.md
14. HTTP2 APNs request headers: https://developer.apple.com/documentation/usernotifications/sending-notification-requests-to-apns.md
15. MDM vendor CSR request requirements: https://developer.apple.com/help/account/certificates/mdm-vendor-csr-signing-certificate/
16. Developer Program eligibility/fees: https://developer.apple.com/support/enrollment/
17. DPLA Attachment10 sections1.1,3.1,4.1,4.2 and definitions (pp87-88 in checked copy): https://developer.apple.com/support/downloads/terms/apple-developer-program/Apple-Developer-Program-License-Agreement-English.pdf
18. Apple Business terms and BYOD supervised-management restriction: https://www.apple.com/legal/platform-services/apple-business/abli.pdf
19. App Review5.5 parental-control/device-security route: https://developer.apple.com/app-store/review/guidelines/
20. Profile signing is optional under Apple mechanisms; signed-only is KosherGuard policy: https://support.apple.com/guide/apple-configurator-mac/create-and-edit-configuration-profiles-pmd85719196/mac and https://support.apple.com/guide/security/configuration-enforcement-secf6fb9f053/web
21. Same-device supervised backup/unsupervise nuance: https://support.apple.com/guide/apple-configurator-mac/unsupervise-an-iphone-ipad-or-apple-tv-cadbf9b585/mac
22. Restore OS/path distinctions: https://support.apple.com/guide/deployment/restore-managed-apple-devices-depd44f04xc4/web
23. Current iOS/iPadOS27 App settings declaration is ADE-only: https://support.apple.com/guide/deployment/app-settings-depd65c456fa/web


Additional checked official sources:

- Apple profile payload delivery/signing/encryption and enterprise-only consumer-app warning: https://developer.apple.com/documentation/devicemanagement/configuring-multiple-devices-using-profiles.md . This is an additional unresolved scope constraint, not a claim that every parental-MDM approval route is impossible. App Review5.5 exists, but its grant is not established here.
- Current server-device list endpoint: https://developer.apple.com/tutorials/data/documentation/devicemanagement/fetch-devices.json . Serial Device Details request/body: https://developer.apple.com/tutorials/data/documentation/devicemanagement/device-details.json and https://developer.apple.com/tutorials/data/documentation/devicemanagement/devicelistrequest.json . Device profile/status fields: https://developer.apple.com/tutorials/data/documentation/devicemanagement/device.json . Apple does not provide UDID in that assignment response; separate inventory association is explicitly used.
- Apple27 backup change: https://support.apple.com/en-ca/guide/deployment/depd638aa061/1/web/1.0 . The source labels these features pre-release and subject to change; actual tested OS must be recorded, not assumed.
- Hardware-bound attested ACME future route, NOT implemented: https://developer.apple.com/documentation/devicemanagement/acmecertificate.md ; https://developer.apple.com/documentation/devicemanagement/validating-a-managed-device-attestation-attestation.md ; https://support.apple.com/guide/deployment/managed-device-attestation-dep28afbde6a/web . Challenge freshness and CSR key/device binding would be required, not just a ClientIdentifier or Apple-root-valid CMS.

## Actual test ledger and intermediate failures

All executions below were local synthetic/test services, never Apple/iPhone. Full control-plane inventory was split solely to fit the command timeout, with no skipped files: sorted test_*.py first21 and remaining files. Same source tree for both complete passing sweeps and MDM sweep, before documentation-only report additions.

| Actual command / phase | Actual result |
| --- | --- |
| Initial existing mdm suite | 88 passed |
| Identity/APNs/codec additions | 98,105,112 passed in successive complete mdm runs |
| Existing enrollment ticket regression | 16 passed |
| Initial full control-plane attempt | Process timed out at120s around86%; incomplete, NOT passing |
| Bounded -x diagnosis | 138 passed,1 failed: missing local dnslib test dependency; installed dependency, no app change |
| First split after dependencies | first20 files222 passed; remainder246 passed,2 failed because migration tests still expected old table set/head0025 |
| Migration contract updated, substantive upgrade/downgrade preserved | 4 passed; new table/index/columns asserted |
| Independent review found NotNow deferral, unbounded TLS admission, offboard lock/cleanup issues | Fixed with discriminating protocol/socket/Postgres concurrency regressions; not dismissed as simulations |
| Earlier narrow checkpoint combined mdm/native/migration | 141 then148 passed as implementation/test inventory grew |
| Final local control-plane first21: python3 -m pytest $(find control-plane/tests -maxdepth 1 -name 'test_*.py' \| sort \| head -21) -q | 228 passed,2 warnings,79.78s |
| Final local control-plane remainder: python3 -m pytest $(find control-plane/tests -maxdepth 1 -name 'test_*.py' \| sort \| tail -n +22) -q | 262 passed,2 warnings,85.93s |
| Final local MDM: python3 -m pytest mdm -q | 114 passed,7.54s |
| Local UI rendering | 390px mobile and1100px desktop screenshots visually inspected; readable, no horizontal overflow. This is not iOS Setup Assistant validation. |

Thus full local control-plane inventory is **490 passed** across complete split sweeps; MDM is **114 passed**. Counts are not inferred by adding only corrected failures. The current native suite has26 tests, ADE web6 and migrations4 within that full control-plane count. Warnings: XDG_RUNTIME_DIR unset runtime-directory fallback and upstream Starlette httpx TestClient deprecation. No application/security warning suppressed.

Not run: actual Apple APNs/NanoDEP endpoints, true iPhone enrollment/removal/renewal/restore, Xcode/iOS build/signing, production deployment/migrations, Internet load/penetration test, and unrelated full-platform filtering/dashboard/proxy/Swift suites. Existing offboarding, ticket, MFA/auth, isolation and migration tests are included in the full control-plane sweep.

### Independent review

Successive source checkpoints independently reviewed before publication. Confirmed fixes include NotNow retry ordering, migration table/head contract, bounded unauthenticated TLS admission, offboarding Device-lock serialization and shared native cleanup. Review reproduced synthetic cryptography/TLS/tenant/lifecycle/renewal/outbox tests and accepted the attended-only session-bound ADE design. Review is not real-device proof or Apple authorization. Final source/report delta verification and exact published-head fresh-clone results are recorded in the final publication addendum rather than inventing a SHA before publication.

### Evidence locations

The implementation source is the changed files on this branch. The companion source/diff index links the actual committed source and verified base-to-tested-head comparison, without duplicating implementation files. It contains no runtime secrets, generated keys, certificates or transcript/tool records. Final publication checks must compare all file bytes to the tested source and report the actual final SHA; no test is attributed to a commit that was not actually checked out and run.

## Every changed file

- control-plane/alembic/versions/0026_native_mdm_provisioning.py
- control-plane/app/ade_enroll.html
- control-plane/app/ade_enroll.js
- control-plane/app/ade_web.py
- control-plane/app/ade_web_routes.py
- control-plane/app/asgi.py
- control-plane/app/main.py
- control-plane/app/mdm_ops.py
- control-plane/app/models.py
- control-plane/app/native_mdm.py
- control-plane/app/native_mdm_config.py
- control-plane/app/native_mdm_routes.py
- control-plane/app/native_mdm_server.py
- control-plane/app/native_mdm_worker.py
- control-plane/app/offboarding_routes.py
- control-plane/requirements.txt
- control-plane/tests/test_ade_web.py
- control-plane/tests/test_migrations.py
- control-plane/tests/test_native_mdm.py
- mdm/ade.py
- mdm/ade_identity.py
- mdm/command_codec.py
- mdm/customer_apns.py
- mdm/identity.py
- mdm/nanodep.py
- mdm/profiles.py
- mdm/reconciler.py
- mdm/tests/pki_fixtures.py
- mdm/tests/test_command_codec.py
- mdm/tests/test_customer_apns.py
- mdm/tests/test_identity.py
- mdm/tests/test_nanodep.py
- docs/MDM_ENROLLMENT_AND_PUSH.md (historical status banner and corrected ADE-only nonremoval wording)
- docs/reviews/REAL_MDM_ENROLLMENT_REVIEW.md (this report)
- docs/reviews/REAL_MDM_ENROLLMENT_SOURCE_AND_DIFF.md (permanent source and diff index)

Secret hygiene: all35 changed text/source files scanned for PEM private-key blocks, GitHub token prefixes and AWS key prefixes, with no matches. No .pem/.key/.p12/.pfx/.db runtime artifacts added. This targeted scan is not a claim of a full external secrets-audit product.

## Verified publication and exact-head tests

Tested published code SHA: `ddbe40a066d6fa890704b2fb1e4103fed66bde3d`. Fresh single-branch clone of full-platform-build, all35 published files byte-equal to reviewed local source at that checkout (before documentation-only index/report finalization). No prefixed upload files or partial evidence files were committed.

Actual fresh-checkout commands, each exit0:

- `python3 -m pytest $(find control-plane/tests -maxdepth 1 -name 'test_*.py' | sort | head -21) -q`:228 passed,2 warnings,82.39s.
- `python3 -m pytest $(find control-plane/tests -maxdepth 1 -name 'test_*.py' | sort | tail -n +22) -q`:262 passed,2 warnings,91.58s.
- `python3 -m pytest mdm -q`:114 passed,7.56s.

All control-plane490 and MDM114 passed on the exact published SHA. Later commits only finalize this report and source/diff index; they do not change runtime code or tests and are not falsely attributed as separately executed test SHAs. Final delivery supplies the final documentation commit SHA.

No merge, main modification, deployment, Apple request/certificate generation, purchase or real-device operation occurred. All Apple/hardware/authorization and unattended-recovery limitations above remain.

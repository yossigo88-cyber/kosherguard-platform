# Supervised manual-enrollment path: review (2026-11-17)

Base: e699b2a9db2b0f5d10848b7c0a812707e0f0c2a2 on `full-platform-build`. Research and code only. No Apple contact, account, certificate or device was touched. **Non-removability is NOT proven.** No supervised iPhone test exists.

## 1. The PayloadRemovalDisallowed candidate

Apple's TopLevel page (https://developer.apple.com/documentation/devicemanagement/toplevel, read 2026-11-17) says: "If present and set to true, the user can't delete the profile unless the profile has a removal password and the user provides it." It then says "On iOS users can't remove a MDM profile. Requires a supervised device." The key is a top-level key of the Configuration payload and needs supervision. Confirmed.

Reading: Apple documents three things on that page: the key is a top-level profile key; "On iOS users can't remove a MDM profile"; and it "Requires a supervised device" (the iOS sentence is its own paragraph; direct JSON: https://developer.apple.com/tutorials/data/documentation/devicemanagement/toplevel.json). The intended use here is Settings-deletion protection for the supervised enrollment profile on the manual supervised route. That is the candidate this feature builds.

NOT PROVEN: that iOS accepts THIS generated artifact (an unsigned profile containing the `com.apple.mdm` payload plus the top-level key) or enforces the key on it. No supervised iPhone test exists. Earlier project notes record iOS once rejecting an MDM-payload profile carrying this flag; that is unverified here. The artifact is therefore marked EXPERIMENTAL. Separately, Apple's other documented enrollment-profile lock is ADE "Prevent unenrollment" (https://support.apple.com/guide/deployment/automated-device-enrollment-management-dep73069dd57/web: "A supervised device can't be unenrolled by the user"), which this route does not use.

## 2. Code change (corrected)

`mdm/profiles.py`: `build_enrollment_profile(..., removal_protection=None, device_serial=None, now=None)`.
- Default output is unchanged: no removal key, no experimental text.
- The top-level `PayloadRemovalDisallowed=true` is added only with a `ManualSupervisionDeclaration`: `supervised` strictly `True`, a recording operator, a serial equal to `device_serial`, a timezone-aware time within 7 days and not in the future, and all three evidence items: `configurator-device-window-supervised`, `settings-supervised-notice-seen`, `prepared-without-mdm-enrollment`. The profile description is marked EXPERIMENTAL.
- Bare booleans, wrong types, false/unknown supervision, missing evidence, missing operator, serial mismatch, stale/future/naive time raise `RemovalProtectionError`. `validate_profile_structure` rejects the key inside a payload entry or with a non-true value.
- Why not DeviceInformation: `IsSupervised` can only be queried after the device is enrolled, so it cannot gate the first enrollment profile (circular). A first version of this commit (4 commits earlier, 412a425) used a "device-reported attestation" object; that wording was wrong and is removed.
- What the declaration is: operator-asserted, shape-validated provisioning evidence. It does not prove supervision, is not hardware or cryptographic attestation, and cannot stop a mistaken or malicious caller. It is a documented-procedure checkpoint, not a security boundary.

Tests: `mdm/tests/test_supervised_profile.py` (defaults preserved, key location, EXPERIMENTAL marker, bare/wrong-type, unsupervised/unknown, each missing evidence item, operator, serial, time, removed old guard names, wrong location/value, existing HTTPS check).

## 3. Three different things

| Mechanism | What it is | Source |
|---|---|---|
| Manual supervision without Apple Business | Configurator Prepare > Manual Configuration > supervise. Device is erased. No Business registration, no provisional clock, no ADE re-enrollment. | https://support.apple.com/guide/deployment/about-device-supervision-dep1d89f0bff/web ; https://support.apple.com/guide/apple-configurator-mac/prepare-an-iphone-ipad-or-apple-tv-manually-cad99bc2a859/mac |
| Apple Business + ADE | Device assigned to an MDM in Apple Business, supervised wirelessly at setup, can set Prevent unenrollment. Configurator-added devices carry a 30-day user release. | https://support.apple.com/guide/business/add-devices-using-apple-configurator-axm200a54d59/web |
| Profile removal restriction | Top-level `PayloadRemovalDisallowed=true`, supervised devices only; Apple documents iOS non-removal of an MDM profile. Applied here to the enrollment profile as an experimental, untested candidate. | TopLevel link above |

## 4. Restore, recovery, DFU (corrected)

Apple: a supervised-device backup restored to the SAME device keeps supervision; restored to any other device it comes back unsupervised (https://support.apple.com/guide/apple-configurator-mac/unsupervise-an-iphone-ipad-or-apple-tv-cadbf9b585/mac). Erasing all content and settings unsupervises the device (same page). So a factory/clean restore of a manually supervised iPhone drops supervision and management, and nothing in Apple's documentation brings it back without an operator redoing the manual steps. A same-device restore from a supervised backup may keep it. Do not call either case reset-proof, and do not say every restore destroys supervision.

Restore behavior for enrolled devices (https://support.apple.com/guide/deployment/restore-managed-apple-devices-depd44f04xc4/web, published 2026-09-17): on iOS 26 and earlier, a same-device restore brings back the management configuration and enrollment profile and the device checks in; if the identity certificate is no longer valid or the server rejects it, the OS removes the enrollment. Hardware-bound ACME identities cannot be restored; devices in Apple Business then restart ADE. A different-device restore deletes management. On iOS 27, only devices enrolled by profile-based Device Enrollment or ADE that appear in Apple Business automatically re-enroll through ADE; otherwise the device does not enroll during the restore. A manually supervised, non-Business device has no ADE record, so clean-restore persistence is a manual-only gap.

Supervised restrictions can block on-device "Erase All Content and Settings" and, since iOS 14.5, an unpaired computer entering Recovery Mode by default (https://support.apple.com/guide/deployment/restrictions-for-supervised-devices-dep6b5ae23e9/web). A paired or physically operated restore is not blocked by those.

Install of a generated profile: Configurator's Add > Profiles installs profiles on supervised devices without user interaction (https://support.apple.com/guide/apple-configurator-mac/add-or-remove-configuration-profiles-cadb67fcd4f/mac). That documents the mechanism for profiles Configurator accepts; it does not show that iOS accepts our generated MDM artifact, nor that the removal key is enforced on it.

## 5. Manual route sequence (non-circular)

1. Customer permits the iPhone to be erased; back up; resolve Find My / Activation Lock. Prepare erases all data.
2. Mac with Apple Configurator, USB, device in physical possession.
3. Prepare > Manual Configuration; supervise; choose **Do not enroll in Device Management**; do not add to Apple Business (that brings the 30-day release and the section 7 terms). https://support.apple.com/guide/apple-configurator-mac/prepare-an-iphone-ipad-or-apple-tv-manually-cad99bc2a859/mac
4. Choose organization and supervision identity (changing it later means erase again); skip Setup Assistant panes; Wi-Fi profile; Prepare. Complete setup.
5. Operator inspects the device in Configurator (supervised group / device window, device serial) and the iPhone Settings notice "This iPhone is supervised...", then records the `ManualSupervisionDeclaration`. Sources: https://support.apple.com/guide/apple-configurator-mac/use-the-device-window-cad0118f840/mac ; https://support.apple.com/guide/apple-configurator-mac/view-device-info-cad24f188539/mac ; https://support.apple.com/guide/deployment/about-device-supervision-dep1d89f0bff/web
6. Generate the experimental protected enrollment artifact for that serial and install it by an Apple-supported route. Then test removal in Settings.

Installation blockers (pre-existing, not changed here): the builder's identity payload is a placeholder. `mdm/profiles.py` emits an ACME payload whose `DirectoryURL` is `https://mdmenrollment.apple.com/acme` (an Apple hostname that is not our ACME service), no ACME or SCEP issuer exists in this repo, and the profile is unsigned. So the artifact cannot enroll a real device yet. It also needs an MDM server, an APNs push certificate and vendor authorization (section 7). No certificate was generated or requested.

Gaps: Apple does not document whether non-Business manual enrollment is user-removable; that is the first test.

## 6. Existing filtering and iOS components: supported vs implemented

Inspected code in this branch (not docs):
- `mdm/profiles.py` builds only the enrollment profile. Nothing in the repo calls it outside tests. Its ACME identity payload is a placeholder (section 5).
- `mdm/app_management.py` builds `com.apple.applicationaccess` app allow/block profiles and MDM command dictionaries. These are our shapes, never installed on a device.
- No Python builder exists for DNS Settings, global HTTP proxy/PAC or content-filter payloads (searched `com.apple.dnsSettings`, `webcontent-filter`, `proxy.http.global`: no hits in `.py`). `proxy-edge/pac.py` serves PAC data only.
- `ios/Sources/URLFilter/MDMEnrollmentClient.swift` always throws `unsignedProfileRefused` by design. `URLFilterConfiguration.swift` implements only the standalone-app route (`enableStandaloneFilter`); the MDM-managed URL filter path is not implemented there. iOS Swift is uncompiled and untested (ios/README.md).

Apple support facts, kept separate from implementation:
- DNS Settings payload (`com.apple.dnsSettings.managed`) lists Device Enrollment and Automated Device Enrollment as supported enrollment methods; it is not stated as supervised-only. Installing it is a different question from locking it against removal, which needs supervision or a protected profile: https://support.apple.com/guide/deployment/dns-settings-payload-settings-dep86469ba99/web
- Global HTTP proxy, app-removal prevention and many restrictions are supervised-only (https://support.apple.com/guide/deployment/restrictions-for-supervised-devices-dep6b5ae23e9/web); iOS 26 URL Filter modes differ on supervision (docs/GENTECH_TECHNICAL_INVESTIGATION.md section 5.4).
- `mdm/app_management.py` has a legacy `com.apple.applicationaccess` builder and an iOS 27 DDM `com.apple.configuration.app.settings` declaration. The code comments cite third-party (Intune) documentation, say supervision is required, and assume ADE. Apple's App settings page (https://support.apple.com/guide/deployment/app-settings-depd65c456fa/web) states: minimum iOS 27, requires supervision: yes, supported enrollment methods: Automated Device Enrollment. So `app_settings_declaration` is INCOMPATIBLE with the manual supervised non-ADE route. Only the legacy applicationaccess payload (supervised-only per its own notes; never device-tested) is a candidate there. No parity with the ADE model.
So the supervised model could host these features, but no working filtering profile or enrollment flow exists in this repo today. Do not read this document as functioning profiles.

## 7. Authorization and terms (read directly from the Apple Developer Program License Agreement)

Source: https://developer.apple.com/support/downloads/terms/apple-developer-program/Apple-Developer-Program-License-Agreement-English.pdf (fetched 2026-11-17, Definitions and Attachment 10, p86-87).
- "MDM Compatible Products" are enterprise server products whose primary purpose is enterprise device management; consumer or personal-use products are excluded unless Apple expressly permits in writing. "MDM Customer" is a commercial enterprise, school or agency and "specifically excludes consumers or personal users" absent written permission.
- Att.10 1.1: MDM may be used for your own employees' devices or, "if You are selected by Apple as a third-party MDM developer", to give MDM to MDM Customers inside an MDM Compatible Product; each device needs a Configuration Profile and a Certificate assigned to you or that customer.
- Att.10 3.1: third-party use requires Apple's selection; no MDM for non-commercial personal use without written Apple permission.
- Att.10 4.1: customers obtain their own MDM certificate from Apple, which you enable by signing their CSR; you may sign CSRs only for customers whose enterprise name and contact you verified, and must provide that to Apple on request. 4.2: do not share your signing certificate; never generate or access a customer's private key.
- The MDM Vendor CSR help page only says an Account Holder of the Developer Program or Enterprise Program may ask Apple for the certificate (https://developer.apple.com/help/account/certificates/mdm-vendor-csr-signing-certificate/). It is not the selection standard. Apple Business membership is not vendor authorization.
- Current Apple Business terms also exclude supervised BYOD without written Apple agreement and restrict general third-party deployment: https://www.apple.com/legal/platform-services/apple-business/abli.pdf (Att.2 pp22-25). The manual route avoids that service but not the MDM terms above. A family/consumer model therefore needs written Apple permission or a path with a business customer relationship; unresolved.
- Nothing was requested or generated here, and Apple was not contacted.

## 8. Protects against / cannot protect against

Intended protection (acceptance and enforcement NOT PROVEN on hardware): the user deleting the supervised iPhone's enrollment profile in Settings, per Apple's TopLevel documentation; and on-device "Erase All Content and Settings" if that supervised restriction is separately applied.
Does not protect: a clean factory restore, Recovery/DFU restore or any erase (supervision and management are lost; no ADE record brings them back on this route); a restore of a supervised backup to a different device (comes back unsupervised). Restoring a supervised backup to the SAME device may keep supervision per Apple, but that is a restore path, not a protection. Also not covered: physical access, a false operator declaration, any claim the filtering works, devices without supervision.

## 9. Remaining blockers

Real supervised-iPhone test with Mac/Configurator and spare phone; vendor authorization and push certificate; legal/terms position on customer-owned devices; whether iOS accepts/enforces the key on the enrollment profile; the placeholder identity payload (section 5); MDM server not live. Other repo suites (control-plane needs `pgserver`) were not run for this change.

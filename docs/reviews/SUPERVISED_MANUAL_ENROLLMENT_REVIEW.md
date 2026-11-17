# Supervised manual-enrollment path: review (2026-11-17)

Base: e699b2a9db2b0f5d10848b7c0a812707e0f0c2a2 on `full-platform-build`. Research and code only. No Apple contact, account, certificate or device was touched. **Non-removability is NOT proven.** No supervised iPhone test exists.

## 1. The PayloadRemovalDisallowed candidate

Apple's TopLevel page (https://developer.apple.com/documentation/devicemanagement/toplevel, read 2026-11-17) says: "If present and set to true, the user can't delete the profile unless the profile has a removal password and the user provides it." It then says "On iOS users can't remove a MDM profile. Requires a supervised device." The key is a top-level key of the Configuration payload and needs supervision. Confirmed.

Caveat that decides the conclusion: the page's sentences about macOS talk about "MDM installed profiles" (profiles an MDM delivers). The iOS sentence reads in that same sense. Apple does not state there that the key makes the MDM enrollment profile itself (the one containing the `com.apple.mdm` payload) permanent. Earlier project notes record iOS rejecting an MDM-payload profile carrying this key; that is unverified here and must be tested. So the key is documented for locking settings profiles that an MDM installs on a supervised iPhone. For the enrollment profile, Apple's documented control is Automated Device Enrollment "Prevent unenrollment" (https://support.apple.com/guide/deployment/automated-device-enrollment-management-dep73069dd57/web: "A supervised device can't be unenrolled by the user").

## 2. Code change

`mdm/profiles.py`: `build_enrollment_profile(..., removal_protection=None, device_serial=None, now=None)`.
- Default output is unchanged and has no removal key.
- The top-level `PayloadRemovalDisallowed=true` is added only with a `SupervisionAttestation`: device-reported `IsSupervised=true` (source `mdm-device-information-is-supervised`), serial equal to `device_serial`, timezone-aware, at most 15 minutes old, not in the future. A bare boolean, our own database flag, an operator checkbox, an unsupervised result, a serial mismatch or stale data raise `RemovalProtectionError`.
- `validate_profile_structure` rejects the key inside a payload entry or with any value other than `true`.
- The attestation proves only what the device reported. It does not prove iOS will enforce the key, and a declared guard is not device proof.

Tests: `mdm/tests/test_supervised_profile.py` (plist structure, key location, default absence, bare flag, unsupervised, wrong source, serial mismatch, stale/future/naive time, wrong location/value, existing HTTPS check).

## 3. Three different things

| Mechanism | What it is | Source |
|---|---|---|
| Manual supervision without Apple Business | Configurator Prepare > Manual Configuration > supervise. Device is erased. No Business registration, no provisional clock, no ADE re-enrollment. | https://support.apple.com/guide/deployment/about-device-supervision-dep1d89f0bff/web ; https://support.apple.com/guide/apple-configurator-mac/prepare-an-iphone-ipad-or-apple-tv-manually-cad99bc2a859/mac |
| Apple Business + ADE | Device assigned to an MDM in Apple Business, supervised wirelessly at setup, can set Prevent unenrollment. Configurator-added devices carry a 30-day user release. | https://support.apple.com/guide/business/add-devices-using-apple-configurator-axm200a54d59/web |
| Profile removal restriction | `PayloadRemovalDisallowed` on a profile, supervised only. Per section 1, documented clearly for MDM-delivered profiles. | TopLevel link above |

## 4. Restore, recovery, DFU

Apple says supervision set during manual preparation is applied "prior to activation" on a new or fully erased device, and that changing it later means erase, prepare and supervise again (Configurator pages above). So a full erase or restore by Recovery/DFU returns the iPhone to unsupervised and unenrolled; a manually supervised device has no Apple Business record to pull it back into management (unlike an ADE-assigned device, which returns to ADE at activation). Supervised restrictions can block on-device "Erase All Content and Settings" and, since iOS 14.5, an unpaired computer entering Recovery Mode by default (https://support.apple.com/guide/deployment/restrictions-for-supervised-devices-dep6b5ae23e9/web). A paired or physically operated restore is not blocked by those. Do not describe this path as reset-proof.

## 5. Manual route sequence (from Apple's Configurator steps)

1. Customer owns/permits the iPhone; back up; accept that Prepare erases all data. Resolve Find My / Activation Lock.
2. Mac with Apple Configurator, USB, device in physical possession.
3. Prepare > Manual Configuration; tick supervise; choose "Do not enroll in Device Management" or add the MDM server (Settings > Servers, enrollment URL, https://support.apple.com/guide/apple-configurator-mac/mobile-device-management-settings-cadf6a58f82/mac). Do not choose "add to Apple Business" unless the 30-day release and the terms in section 7 are acceptable.
4. Pick/create the organization and supervision identity (changing it later means erase again).
5. Choose Setup Assistant panes to skip; supply a Wi-Fi profile; Prepare.
6. After setup, MDM enrolls; query `DeviceInformation` for `IsSupervised`; only then install the settings profiles with removal protection. The enrollment profile's own removability must be checked on a test device.

Gaps: Apple's manual-enrollment page does not state whether the enrollment is removable without Business. That is the first test.

## 6. Existing filtering and iOS components

Per docs/GENTECH_TECHNICAL_INVESTIGATION.md and docs/COMPATIBILITY.md: DNS Settings, Global HTTP Proxy/PAC, restrictions and app-removal prevention need supervision, so this model suits them. iOS 26 URL Filter modes differ on supervision (see section 5.4 of the investigation). None of it has run on a device. Supervision on its own proves no filtering behavior. Remote policy changes need a working MDM, which needs section 7.

## 7. Authorization

- Apple Business membership is not MDM vendor authorization. The MDM Vendor CSR Signing Certificate is requested by an Account Holder of the Apple Developer Program or Enterprise Program via Apple: https://developer.apple.com/help/account/certificates/mdm-vendor-csr-signing-certificate/ . It signs CSRs for MDM push certificates (identity.apple.com).
- Current Apple Business terms exclude supervised BYOD under the service without written Apple agreement and restrict general third-party deployment: https://www.apple.com/legal/platform-services/apple-business/abli.pdf (Attachment 2, pp22-25). The manual-without-Business path does not use that service, but Apple's documentation labels supervision an organization-ownership concept (https://support.apple.com/guide/deployment/about-device-supervision-dep1d89f0bff/web), and the push certificate still needs the vendor certificate.
- Nothing was requested or generated here.

## 8. Protects against / cannot protect against

Protects (if tests confirm): Settings removal of profiles the MDM installs on a supervised iPhone; on-device erase if that restriction is applied.
Cannot protect: a computer restore in Recovery/DFU; loss of supervision after it; any claim for the enrollment profile itself; physical access; filtering by itself; devices where supervision is absent.

## 9. Remaining blockers

Real supervised-iPhone test with Mac/Configurator and spare phone; vendor authorization and push certificate; legal/terms position on customer-owned devices; whether the enrollment profile accepts the key; MDM server not live. Other repo suites (control-plane needs `pgserver`) were not run for this change.

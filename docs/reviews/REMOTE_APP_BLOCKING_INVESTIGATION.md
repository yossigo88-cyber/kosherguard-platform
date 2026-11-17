# Remote app blocking: personally owned vs supervised iPhones

Stage 11 investigation (2026-11-17), objectives 6 and 7 of the Stage
11 brief. Every claim is tied to an Apple source fetched today. The
bottom line has not changed since the BYOD feasibility finding, but it
is now pinned to current (iOS 27-era) documentation.

## 1. The two different things called "app blocking" (objective 7)

These are independent mechanisms with independent gates. A product
can have either, both, or neither per device.

| | **Blocking app LAUNCHES** | **Blocking app INTERNET ACCESS** |
| --- | --- | --- |
| What the user sees | App icon hidden/greyed, or a shield screen on tap; the app never runs | App opens normally but its network traffic fails or hangs |
| Mechanisms | (a) MDM restrictions profile `com.apple.applicationaccess` `blockedAppBundleIDs` / `allowListedAppBundleIDs`; (b) DDM `com.apple.configuration.app.settings` `DeniedApps` / `AllowedApps` (iOS 27+); (c) Screen Time `ManagedSettingsStore` shields | (a) NEFilterDataProvider per-flow verdicts; (b) NEURLFilterManager system URL filter (iOS 26+, WebKit/URLSession traffic, binary verdicts); (c) NEDNSProxyProvider name-resolution control; (d) DNS-layer filtering (network path, not on-device app targeting) |
| Admin picks the apps remotely? | (a)/(b): **yes, but supervised devices only**. (c): **no - the on-device user picks** (opaque FamilyActivitySelection tokens; the server never learns bundle IDs) | Filter rules are host/category based, pushed by policy; per-APP network blocking is possible via per-app managed configurations on managed devices, not per-launch |
| Supervision required | (a) yes; (b) yes (Apple Support: "Requires supervision: Yes", ADE enrollment); (c) no - but requires on-device Family Controls authorization | NEFilter: supervised, or Screen Time child devices, or per-app on managed devices (TN3134). URL filter provider: iOS 26+, see TN3134 URL filter row. DNS proxy: supervised or per-app managed (TN3134) |
| Remotely revocable by admin | (a)/(b): yes via MDM. (c): the local user can revoke Family Controls authorization at any time; revocation always wins | Policy withdrawal / NEFilterManager disable; managed configuration removal |

Sources: Apple device-management documentation
(com.apple.applicationaccess payload: `blockedAppBundleIDs` iOS
15.0-27.0 supervised, `allowListedAppBundleIDs` iOS 15.0-27.0
supervised, both deprecated in iOS 27 in favor of the DDM
configuration); Apple Support "App settings declarative configuration"
(depd65c456fa, 2026-09-17: iOS 27+, **Requires supervision: Yes**,
Automated Device Enrollment); TN3134 (content filter: supervised, or
Screen Time child devices, or per-app managed from iOS 16; DNS proxy:
supervised or per-app managed; URL filter provider: iOS 26.0+ app
extension).

## 2. Personally owned (unsupervised) iPhones

Two different capabilities must not be conflated here:

- **Arbitrary, administrator-CHOSEN app blocking** (the admin picks
  which personal apps are blocked) is NOT available remotely on an
  unsupervised personal iPhone. Verified against current Apple
  sources below.
- **A consented remote gate** (the server remotely activates/pauses a
  shield set that the on-device user personally selected and
  authorized) IS available - that is the Stage 10 personal path.
  The selection and the revocation both belong to the device user.

Evidence for the first statement:

- `blockedAppBundleIDs` / `allowListedAppBundleIDs` are
  `supervised: true` and forbidden under User Enrollment (Apple
  device-management `com.apple.applicationaccess` documentation).
- The iOS 27 DDM replacement (`app.settings` DeniedApps/AllowedApps)
  **requires supervision** and Automated Device Enrollment (Apple
  Support depd65c456fa).
- Screen Time APIs (Family Controls + ManagedSettings) work on a
  personal phone but are **user-consented and user-selected on the
  device**: the app calls `AuthorizationCenter.requestAuthorization`,
  the person holding the phone picks apps in `FamilyActivityPicker`,
  and the selection comes back as opaque tokens. The admin cannot
  choose, enumerate or even learn the blocked bundle IDs, and the
  user can revoke authorization in Settings at any time. This is the
  path Stage 10 implemented (local selection, remote activate/pause
  of the locally chosen set only).

What IS remotely achievable on a personal iPhone today:

- **Network-layer filtering** via the deployed DNS/DoH edge and,
  after entitlements, an on-device content filter in per-app managed
  mode (managed devices only) or the Screen Time child path.
- **Activate/pause of a user-selected shield set** (Stage 10 code),
  with the honesty caveat that revocation belongs to the device user.
- MDM **User Enrollment** gives a managed-apps-only slice: it cannot
  touch personal apps at all.

## 3. Supervised iPhones

Full administrator-controlled remote app blocking exists:

| iOS version | Mechanism | Notes |
| --- | --- | --- |
| 15.0 - 26.x | Restrictions profile `com.apple.applicationaccess` with `blockedAppBundleIDs` (deny list) or `allowListedAppBundleIDs` (allow list; include `com.apple.webapp` to keep webclips) | Supervised only; delivered/updated/removed remotely over MDM. Repo implementation: `mdm/app_management.py` (profile path) |
| 27.0+ | DDM `com.apple.configuration.app.settings`: `DeniedApps` / `AllowedApps` (also denied/allowed binaries, always-allow-managed-apps, per-app privacy defaults) | Supervised only, ADE enrollment; the profile keys are deprecated in 27.0 in favor of this. Repo implementation: `control-plane/app/ddm_ops.py` |

Supervision itself requires either Automated Device Enrollment (device
bought/assigned through Apple Business) or Apple Configurator on a Mac
(**which erases the device**). The user's Apple Business org exists but
per the Stage 11 brief nothing is assumed configured; supervising a
spare iPhone for testing needs the user's explicit approval if it
involves erasing.

## 4. Consequences for the product

1. **Supervised fleet**: the design goal "admin chooses apps, remote
   apply/remove" is achievable today on iOS 15-26 (profile) and iOS
   27+ (DDM), and the repo already emits both. Removal protection for
   the management itself comes from supervision + ADE (non-removable
   enrollment option), not from any app-side trick.
2. **Personal iPhones**: admin-chosen remote app blocking is not
   available from Apple at any price or approval level. The product
   choices are: require supervision for app-blocking customers;
   accept the consented Screen Time model (Stage 10) with its
   revocation reality; or position app blocking as launch-blocking on
   supervised devices and network-blocking everywhere.
3. **Launch vs network**: never conflate them in UI or reports. A
   network-filtered app still launches (and may show errors); a
   launch-blocked app never reaches the network. The dashboard should
   say which mechanism is active per device.

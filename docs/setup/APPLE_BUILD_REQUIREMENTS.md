# Apple build requirements: macOS, Xcode, and Mac access

Stage 11 (2026-11-17). Every requirement below was checked against the
live source cited; this document separates what is verified from what
is still an assumption.

## 1. Exact macOS and Xcode requirements

Source: Apple, "SDKs and system requirements - Xcode"
(https://developer.apple.com/xcode/system-requirements/, fetched
2026-11-17).

| Need | Requirement |
| --- | --- |
| Current stable Xcode | Xcode 27.2 (27.3 beta 2 exists). Runs on **macOS Tahoe 26.6 or later**. Bundles iOS 27.2 SDK, Swift 6.4. |
| Minimum Xcode for THIS project | **Xcode 26.0 or later** - the URL Filter target and manager code use iOS 26 APIs (`NEURLFilterManager`, `NEURLFilterControlProvider`, `NEURLFilterPrefilter`). Everything else (NEFilter providers, NEDNSProxyProvider, Family Controls/ManagedSettings) is iOS 16/17 API. |
| Minimum macOS for Xcode 26.x | Xcode 26.0-26.3: macOS Sequoia 15.6 or later (also Tahoe 26.x). Xcode 26.4+: macOS Tahoe 26.2 or later. |
| App Store submission SDK floor | Builds uploaded to App Store Connect must be built with the **iOS 27 SDK (Xcode 27) starting April 2027** (Apple Developer News, 2026-09-09, https://developer.apple.com/news/?id=k1mtkt1k). Before that, Xcode 26 / iOS 26 SDK is accepted. Distribution is far away for this project, but any Mac bought now should run Xcode 27. |
| Project settings | `IPHONEOS_DEPLOYMENT_TARGET = 17.0`, `compatibilityVersion = "Xcode 14.0"` (project file format), Swift language mode 5.0. All compatible with Xcode 26/27; no setting change is required to open the project. |
| iOS-only APIs and deployment target | iOS 26-only symbols are guarded: `@available(iOS 26.0, *)` on `URLFilterConfiguration`, `URLFilterControlProvider`, and a runtime `if #available(iOS 26.0, *)` in `KosherGuardApp.swift`. Verified by inspection 2026-11-17. |

Practical minimum for a first build: **any Apple-silicon or Intel Mac
running macOS Sequoia 15.6+ with Xcode 26.0.1+**. Practical
recommendation: macOS Tahoe 26.6+ with Xcode 27.2 so the same machine
stays valid past the April 2027 App Store SDK floor.

## 2. Mac access check (objective 2 of Stage 11)

VERIFIED by direct inspection, 2026-11-17:

- The Instinct development sandbox (both execution environments) is
  **Linux x86_64** (`uname -a`: `Linux modal 7.3.4 ... x86_64`). No
  macOS, no `xcodebuild`, no `xcrun`, no `sw_vers`. **The agent does
  not have a local Mac.**
- Per project memory, the user's confirmed hardware is a **Windows
  PC**. **No accessible Mac was identified** - that is a statement
  about what could be found, not a claim that the user owns none.

### 2a. Working route found: GitHub-hosted macOS runners (free)

The repo is **public**, and GitHub Actions usage is **free for standard
GitHub-hosted runners in public repositories** (docs.github.com/en/
actions/concepts/billing-and-usage; unchanged by the 2026 Actions
pricing update, which states public-repo usage "will remain free").

The `macos-26` runner image (github.com/actions/runner-images,
images/macos/macos-26-Readme.md, fetched 2026-11-17) ships:

- macOS Tahoe 26 with **Xcode 26.6 (default), 26.5, 26.4.1, 26.3,
  26.2, 26.1.1, 26.0.1** - iOS 26.x SDK included, which covers the
  URL Filter APIs. Xcode 27 was listed as "available as a public
  preview" on that image line (runner-images issue 14404).

`ci/ios-compile-check.yml` (added in this stage) contains the
workflow definition for an **unsigned** compile of the app plus all
four extensions on every push to `stage-11-*`. It is PREPARED, NOT
ACTIVE: the git credential authorized for agent pushes lacks GitHub's
`workflow` scope, GitHub rejected the workflow-file push, and no new
credential may be requested. Enabling it requires a separately
authorized route that does not currently exist; nothing here should
be read as a user task. Until such a route exists, no CI run has
happened and the compile remains unverified. The prepared workflow
runs:

```
xcodebuild -project ios/KosherGuard.xcodeproj -scheme KosherGuard \
  -destination 'generic/platform=iOS' -configuration Debug \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO build
```

An unsigned compile needs **no Apple account, no certificate and no
entitlement grant**. It is the first real verification that the
hand-authored project compiles. It proves nothing about signing,
entitlements or device behavior.

Limits of this route: no signing identities, no entitlements, no
device/simulator runtime guarantees for Network Extension providers,
no Xcode UI. It answers "does it compile", not "does it run".

### 2b. Options for a full (signed) build environment

For signed builds and device testing a persistent Mac is needed:

| Option | Cost (checked 2026-11-17) | Notes |
| --- | --- | --- |
| GitHub Actions macos-26 (unsigned CI only) | **$0** (public repo) | Prepared this stage, NOT active (workflow-scope boundary, see 2a). Cannot sign or run devices. |
| Buy a Mac (Mac mini) | from $599 one-time (Apple list price; verify current) | Cheapest long-term; also runs Apple Configurator for supervising a spare iPhone. |
| MacStadium dedicated Mac mini | from **$109/month** (macstadium.com/pricing: $109/$149/$199/$249/$449 tiers) | Monthly rental, genuine Apple hardware, full admin. |
| MacinCloud | roughly $30+/month for rented server plans (comparison listings 2026; verify current plan page before buying) | Cheaper entry tiers exist; check Xcode version on the plan. |
| AWS EC2 Mac | per-hour dedicated-host billing with a 24-hour minimum allocation (roughly $1/hr class -> ~$26/day minimum; verify current AWS pricing) | Cost-inefficient for occasional builds. |
| Borrowed/existing Mac | $0 | Any Apple-silicon Mac with macOS Sequoia 15.6+ and Xcode 26+ works. |

NOT recommended: Hackintosh or macOS VMs on non-Apple hardware (Apple
license violation; the project charter requires Apple-supported
mechanisms only).

## 3. What each environment can verify

| Check | Linux sandbox | GitHub macOS runner | Signed Mac + spare iPhone |
| --- | --- | --- | --- |
| Portable Swift logic tests (136) | yes (done, Stage 10) | yes | yes |
| Static project validation | yes (tools/validate-ios-project.py) | yes | yes |
| Real iOS SDK compile | no | **yes (unsigned)** | yes |
| Signed build / entitlements check | no | no | yes (after Apple approvals) |
| On-device behavior | no | no | yes (after approvals + supervision) |

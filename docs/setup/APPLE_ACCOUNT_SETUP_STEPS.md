# Exact Apple setup steps for Yossi (with costs)

Stage 11 (2026-11-17). These are the steps only you can do - they
touch your Apple account, your money, or your hardware. Everything
that could be done without those is already done in this stage (see
docs/reviews/STAGE_11_APPLE_BUILD_SIGNING_PREP_REVIEW.md). Steps are
ordered: stop points where an approval arrives asynchronously are
marked [WAIT].

## Step 0 - Facts to confirm when you choose to proceed

Nothing in this document is a purchase, enrollment or device action;
each step below is the exact action required WHEN you approve it,
with its cost. Preparation did not include buying, joining, or
erasing anything, and it does not ask you to.

1. Mac access: no accessible Mac was identified during preparation
   (the agent environment is Linux-only; a Windows PC is the only
   confirmed hardware). If a Mac is or becomes available to you, any
   model running macOS Sequoia 15.6+ covers signed builds. If none
   is, the priced options when you decide are: Mac mini purchase
   (from $599 one-time, Apple; also runs Apple Configurator), or
   MacStadium dedicated Mac mini rental (from $109/month,
   macstadium.com/pricing). AWS EC2 Mac (~$26/day minimum) and
   MacinCloud (~$30+/month) also exist. Choosing among these is not
   part of this preparation stage.
2. Spare iPhone: testing needs one, and supervising it either
   assigns it in Apple Business (no Mac needed) or erases it via
   Apple Configurator on a Mac - the erase path only ever happens
   with your explicit approval.
3. Free compile check: the CI workflow is prepared at
   `ci/ios-compile-check.yml` but NOT active. GitHub rejected
   activating it with the existing authorized credential (missing
   `workflow` scope), and no new credential will be requested.
   Enabling it requires a separately authorized route; there is
   nothing for you to copy or commit.

## Step 1 - Apple Developer Program membership ($99/year) - when approved

Needed for: App IDs with the required capabilities, any entitlement
approval, TestFlight, and the MDM vendor certificate. Not needed for
the unsigned CI compile (workflow prepared; see step 0.3).
This is a purchase and happens only on your decision.

1. Go to https://developer.apple.com/programs/enroll/
2. Enroll with your Apple ID as an **Organization** (KosherGuard) if
   you want the org name on certificates and the MDM vendor CSR
   route; Individual is acceptable for development but commercial MDM
   vendor approval expects an organization.
3. Pay $99/year. [WAIT] activation (usually hours to 2 days).

## Step 2 - Request the gated capabilities (no extra cost) - once Step 1 exists, with your go-ahead

Once the program account is active, at
https://developer.apple.com/account (Certificates, Identifiers &
Profiles):

1. Create the 5 App IDs: `com.kosherguard.app`,
   `.FilterExtension`, `.FilterControlExtension`, `.DNSProxyExtension`,
   `.URLFilterExtension` (or your chosen prefix - note it for step 4).
   Enable: Network Extensions on all 5, App Groups on all 5
   (register `group.com.kosherguard.shared` or your chosen group),
   Family Controls on the app.
2. Request the managed Network Extension values for the App IDs:
   `content-filter-provider` (app + both filter extensions),
   `url-filter-provider` (app + URL filter extension), `dns-proxy`
   (DNS proxy extension). Request route: the Network Extension
   capability request form / Capability Requests tab. [WAIT] Apple
   approval (days to weeks).
3. Request **Family Controls (Distribution)** for the app and for any
   Screen Time extension you add later
   (https://developer.apple.com/documentation/familycontrols/
   requesting-the-family-controls-entitlement). [WAIT]
4. Start the **URL Filter PIR onboarding** with Apple: provide the
   PIR server and Privacy Pass issuer hosts, and put the DNS TXT
   record `apple-url-filter=<app bundle id>` on the service host.
   [WAIT] This is the long pole for the URL Filter path; start early.
5. For production MDM push: as Account Holder, **contact Apple** to
   request the MDM Vendor CSR Signing Certificate
   (https://developer.apple.com/help/account/certificates/
   mdm-vendor-csr-signing-certificate/). [WAIT] Interim free testing
   route for the push certificate alone: mdmcert.download
   (organizations only) - no purchase.

## Step 3 - Apple Business (free, org exists) - with your approval

1. In Apple Business, verify the organization and add the MDM server
   (KosherGuard) so Automated Device Enrollment can assign devices.
2. Do NOT link or purchase device enrollment until the MDM server has
   its APNs push certificate (step 2.5).
3. This account alone does not enable anything on devices - per your
   instruction nothing here is assumed configured, and nothing was
   changed in it during preparation.

## Step 4 - Apply your identifiers to the repo (any computer)

After clone/pull of the Stage 11 branch:

```sh
tools/apply-apple-team-id.sh --team-id YOURTEAMID \
    --bundle-prefix com.kosherguard \
    --app-group group.com.kosherguard.shared \
    --pir-server YOUR.PIR.HOST --pir-issuer YOUR.ISSUER.HOST --write
git diff ios/   # review, then commit
```

This replaces every placeholder consistently (team ID, app group,
bundle prefix, PIR hosts) and re-runs the static validator. Hand the
identifiers to the agent and it runs this for you; running it
yourself works identically.

## Step 5 - First signed build (Mac required)

1. Install Xcode 26.6+ (or 27.2) on macOS Tahoe.
2. Open ios/KosherGuard.xcodeproj, sign in with the developer account,
   keep automatic signing.
3. `xcodebuild -scheme KosherGuard -destination 'generic/platform=iOS'
   -allowProvisioningUpdates DEVELOPMENT_TEAM=YOURTEAMID build`
   (the project deliberately carries no committed team ID; pass it on
   the command line or pick the team once in Xcode's Signing tab)
4. If the filter extensions fail to sign: the managed Network
   Extension approvals (step 2.2) have not landed yet - expected;
   the app target alone still signs.
5. Then follow docs/reviews/REAL_DEVICE_TEST_PLAN.md from Phase 1.

## Cost summary (verified 2026-11-17)

| Item | Cost | When needed |
| --- | --- | --- |
| Unsigned Xcode compile via GitHub Actions | $0 | prepared this stage; NOT active - needs a separately authorized route (step 0.3) |
| Apple Developer Program | $99/year | signed builds, all approvals, distribution |
| Family Controls / Network Extension / URL Filter approvals | $0 (forms) | before the filters can run signed |
| Apple Business (ABM) | $0 | supervision via ADE |
| MDM push certificate (mdmcert.download route) | $0 | MDM testing |
| MDM Vendor CSR signing certificate | included in $99 program | production MDM push |
| Mac (none was identified as accessible) | $599+ once, or $109+/month rental | signed builds, Configurator, device debugging |
| Spare iPhone for testing | existing or any used iPhone | Phase 1+ of the test plan |

Notes on completeness: the $99/year program is the only fee Apple
itself charges in this plan; hardware and any third-party
rental/hosting are separate non-Apple costs. The CloudKit Identity
and Trust registration (`<bundle-id>.url.filtering`) required for the
URL Filter has an UNVERIFIED tier/cost - treat the total as not yet
final until that is confirmed during URL Filter enablement.

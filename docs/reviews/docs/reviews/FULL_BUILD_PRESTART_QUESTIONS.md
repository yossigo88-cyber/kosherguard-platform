# Full Build Pre-Start Review: Consolidated Questions on the 44 Phase 1 Answers

**Status: PRE-IMPLEMENTATION REVIEW. No implementation has begun. This document is for ChatGPT review and response before Milestone 1 starts.**

**Repository:** https://github.com/yossigo88-cyber/kosherguard-platform
**Branch:** `full-platform-build` (created for this review; contains this document only, no code changes)
**Source instruction:** the owner's message "KOSHERGUARD — FINAL BUILD AUTHORIZATION AND COMPLETE DEVELOPMENT INSTRUCTIONS" (WhatsApp, 2026-11-16 about 02:17 ET), which closes with: "Bef we start review the answers and if u have any questions on how to build it pls ask them and put them all in the repository so ChatGPT can look and respond."

## 1. What this document is

The full instruction was read end to end: all 44 answers, the three-plane platform description (Part 2), the security and quality requirements (Part 3), the development and GitHub rules (Part 4), the milestones (Part 5), and the final review process (Part 6).

The answers are complete and unusually consistent. Most details that could have blocked a build are either answered directly, explicitly delegated ("sensible technical defaults", Answer 42), or explicitly marked as unresolved external requirements to be handled through configuration and documentation rather than guesses.

This file therefore contains only:

1. **Section 3: the remaining questions** - five items where the instruction leaves a genuine fork that changes what gets built. Each has a recommendation so work can start on a stated default if the response agrees.
2. **Section 4: planned technical defaults** already authorized by Answer 42, listed so they can be challenged now instead of after implementation.
3. **Section 5: external gates** that block launch or specific integrations but not the code build. These are documented, not re-asked.
4. **Section 6: information the owner must supply later.** Not blocking.
5. **Sections 7-8: mandatory pre-build items and interpretations**, stated so misunderstandings surface now.

Everything not listed as a question in Section 3 is treated as settled by the answers.

## 2. Verified repository starting state

Checked live against the GitHub API on 2026-11-16 at about 02:20 ET:

- `main` = `5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a` (frozen at end of Stage 9A; unchanged)
- `stage-9b-deployment-preparation` = `9eaa2213ea357bcd7a7795a23063b8d9e283d771` (tip; contains Stages 9B, 10, 10.5, 11A, 11B, and 11C)
- Exactly these two branches exist. No other branches, and `main` was not touched.

Existing components on the feature branch, per its own committed review documents in `docs/reviews/`:

- `filtering-engine/` - Python 3 + dnslib DNS policy engine. Stage 10 added immutable policy revisions, publication, and descriptor-based safe hot reload. Stage 11A added client-address canonicalization. Stage 11C made the engine multi-policy (immutable engine sets, `devices.json` binding map, manifest validation, 316-test engine suite per its review report).
- `dashboard/` - Python + SQLite admin dashboard with hashed-password login, CSRF, lockout, audit log, policy/category/domain management (Stage 7, hardened in Stage 9A).
- `deploy/` - runbook, Caddyfile example, systemd unit, backup/restore scripts with a real restore test (Stage 9B).
- `docs/` - project charter, GenTech technical investigation, stage review reports, technical roadmaps.
- `render.yaml` - historical deployment config to be audited, not trusted as the current environment (Answer 9).

**Test-count honesty note:** historical counts (for example "316 engine tests") come from stage reports. Part 3 item 3 of the instruction requires reconciling reported counts against actual runs, and item 5 requires re-running everything. No historical count is treated as currently passing until Milestone 1 re-runs it on a fresh clone.

## 3. Questions for ChatGPT

### Q1. Base commit for the full build

**Fork:** branch from the tip of `stage-9b-deployment-preparation` (`9eaa221...`, includes Stages 10 through 11C, which have not all received final approval) or from frozen `main` (`5f75d21`, approved through Stage 9A)?

**Why it matters:** the base decides whether the Stage 10 policy-versioning and Stage 11 multi-policy work is the foundation or must be re-implemented. Discarding it would contradict Answer 7 (reuse reviewed working components) and Part 4 (do not overwrite or discard previous work, and start from the most recent development branch).

**Recommendation:** branch from the feature tip `9eaa2213ea357bcd7a7795a23063b8d9e283d771`. The fact that Stages 10-11C lack final approval does not disqualify them: Milestone 1 already requires auditing existing code and fixing confirmed issues, and Part 3 item 2 explicitly requires rechecking the Stage 11C generation-loader symlink concern there. This review branch `full-platform-build` was created from that tip; if you disagree, say so now and it will be recreated from `main` before any code is written.

### Q2. Review cadence during the build

**Fork:** the instruction says to work through Milestones 1-8 and "continue until the full code build is complete", with independent ChatGPT review at the end (Part 6). The prior workflow required stopping for owner approval after every stage.

**Interpretation to confirm:** this authorization supersedes per-stage stop-and-wait. Work will proceed through the milestones continuously, with (a) logical commits per milestone, (b) a committed review document per milestone in `docs/reviews/` following the existing naming convention, and (c) correction rounds whenever review findings arrive. Work pauses only when a question in this document is answered with "stop and wait", when a genuine contradiction blocks safe progress, or at the final Part 6 review gate.

**Recommendation:** confirm this reading. If you want hard stop-and-wait gates at specific milestones (for example after Milestone 1's foundation), name them now.

### Q3. Device identity for DNS filtering versus the Stage 11C binding model

**Fork:** Part 2C requires "device/group policy selection through authenticated identity" and states "Do not rely on IP address alone to identify an iPhone. Multiple phones may share NAT addresses and cellular addresses can change." Stage 11A-11C built exactly an IP-based binding model (`devices.json` maps canonicalized source addresses to policies).

**Proposed reading:** the Stage 11C binding engine stays as the network-layer mechanism (fixed home/filtering-server deployments where the resolver sees stable source addresses), and an authenticated DNS layer is added for device identity: per-device DoH/DoT endpoints with unique per-device credentials (token in the DoH path or DoT client identity), so a phone is identified by authentication, not address. The unified policy compiler would emit both bindings from one policy model.

**Recommendation:** confirm this two-layer reading, with per-device authenticated DNS as the primary identity path for iPhones and IP binding retained only as an explicit, labeled fallback. The alternative - removing IP-based binding entirely - would discard Stage 11A-11C work, so say clearly if that is what you intend.

### Q4. Native iOS source before any Apple tooling exists

**Fork:** Milestone 5 requires the native iOS app project, Network Extension architecture, and URL-filter implementation. Answer 40 confirms no Mac/Xcode access, no spare devices, and no cellular test device are currently confirmed, and no Apple Developer Program membership has been purchased (Answer 36 authorizes no spending). Swift source written now cannot be compiled, signed, installed, or tested.

**Options:** (a) write the complete Swift source, entitlements, and server-side URL-filter services (PIR database, Privacy Pass issuer, OHTTP gateway integration) now, with every iOS artifact labeled "not compiled, not signed, not tested - awaiting Apple tooling and approvals"; or (b) build all server-side components now and defer the Swift source until macOS/Xcode access exists.

**Recommendation:** (a), because Milestone 5 explicitly requires the app project and the architecture is easier to review as a whole, with honest labeling per the instruction's own rule ("Do not claim the native filter is operational until it has been built, signed, installed, and tested on a real authorized device"). If you consider untestable Swift source a liability, choose (b).

### Q5. Fallback if no free category source clears license review

**Fork:** Answer 22 requires starting with free category sources whose commercial-use and redistribution rights have been checked, and no paid feed is approved. It is possible the license review in Milestone 3 finds no source that is clearly cleared for commercial redistribution.

**Recommendation:** if that happens, ship the pipeline with a small hand-reviewed seed category set plus the admin-managed category/domain tooling (which exists in part already), document the finding, and request a separate decision on a paid or licensed feed. The alternative is blocking Milestone 3 on a sourcing decision. Confirm the fallback is acceptable.

**No other questions.** Every other candidate question was either answered in the 44 answers, delegated to technical defaults, or is an external gate documented below.

## 4. Planned technical defaults (authorized by Answer 42 - challenge now if you disagree)

- **D1. Control-plane stack:** Python with a maintained web framework (FastAPI planned for the API-centric control plane) and PostgreSQL, per the preferred architecture. The audited security mechanics from the existing dashboard (password hashing, CSRF, lockout, audit logging, rate limiting) are carried over and adapted rather than rewritten blindly; the dashboard UI is rebuilt to the Part 2A specification. Final framework choice and license notes will be documented in the Milestone 1 report.
- **D2. Monorepo layout:** existing `filtering-engine/`, `dashboard/`, `deploy/`, `docs/` stay; new top-level directories `control-plane/`, `mdm/`, `proxy-pac/`, `ios/`, and `ops/` are added for the new planes. Nothing existing is deleted without an audited migration note.
- **D3. MDM foundation:** NanoMDM and NanoDEP (Go) evaluated first in Milestone 4, as the instruction names them as reviewed components. The evaluation and the final adopt/reject decision, with license notes, will be documented before integration.
- **D4. MFA:** TOTP for privileged accounts using an established library. No invented cryptography anywhere (Answer 43).
- **D5. Public website:** built as part of the control-plane application, served and tested independently of the live kosherguard.xyz site. No DNS or live-site changes at any point (Answer 35, Part 4).
- **D6. Tenant model:** one family is one tenant; the parent is the customer administrator; children are managed devices, not user accounts. Derived from Answers 1, 5, and 29.
- **D7. Review trail:** one committed review document per milestone in `docs/reviews/`, same convention as the stage reports, so every correction prompt can reference exact files and SHAs.
- **D8. Migration:** tooling and procedures are designed and documented only. No existing customer data, accounts, or production records are touched (Answer 8).
- **D9. iOS minimum:** iOS 26 targeted for full-URL filtering; older versions get only tested features, tracked in a compatibility matrix (Answer 15).

## 5. External gates (documented, not questions, nothing here re-asked)

Per Answers 2, 15, 16, 26, 27, 36, and 40, these block launch or specific integrations but not the code build. For each, the build implements the real integration boundary, configuration handling, error handling, tests against fakes, and setup documentation clearly labeled "awaiting credentials/approval", exactly as Part 4 requires.

- **G1. Apple commercial MDM vendor authorization.** Blocks any real MDM operation. No approval exists and none will be claimed.
- **G2. Written Apple authorization for the family/personally-owned-device model.** Blocks the commercial family launch (Answer 1, 2).
- **G3. Apple Business organization enrollment.** Previously reported "Not Qualified"; unresolved. Blocks ADE assignment and Apple Configurator adds (Answers 2, 4).
- **G4. iOS 26 URL Filter entitlements and Apple OHTTP relay approval**, including the development-versus-distribution distinction (Part 2C).
- **G5. APNs MDM push certificate and topic.**
- **G6. Apple Developer Program membership** for app signing and entitlements. Not purchased; no spending authorized.
- **G7. Hardware:** Mac/Xcode access, dedicated spare supervised test iPhones, cellular test devices. Unconfirmed (Answer 40).
- **G8. Paid production hosting and any paid service.** No spending authorized (Answer 36); portable deployment configs and documented real cost estimates instead.
- **G9. Professional legal/privacy review** of draft privacy, terms, and consent documents before launch (Answer 32).

## 6. Information the owner must supply later (not blocking the build)

- Current Apple Developer Program account status and Apple Business enrollment status, when Milestones 4-5 approach.
- Brand asset files (logo, colors), if they exist beyond what is visible on the public site; otherwise a clean CSS-based brand treatment matching the live site will be used.
- Designation of at least two authorized organization contacts for critical operations (Answer 38).
- Confirmation of spare devices and Mac/Xcode access before any physical-device test (Answer 40).

## 7. Mandatory pre-build items acknowledged (Milestone 1 scope)

From Part 3, confirmed and planned, not deferred:

1. Recheck the Stage 11C generation-loader symlink concern: parent-directory symlinks must not allow reads outside the intended generation directory. Current `filtering-engine/src/generation_io.py` already uses descriptor-based safe open with no-follow protection on final path components; the recheck targets symlinked parent path components, adds safe directory-descriptor traversal, and adds regression tests.
2. Reconcile historical test counts against actual runs; re-run all suites on a fresh clone.
3. Fix confirmed security defects before reusing affected code.
4. Dependency and license audit; secret and credential scan of the tree and history.
5. Secure database migrations from the start; structured logs that never contain browsing history or secrets.
6. No auto-deployment path triggered by pushes; staging and production kept separate.

## 8. Interpretations stated for the record

- The staged plan's remaining items (Stage 11D publisher, Stage 11E last-seen) fold into Milestones 2-3 as part of the full build rather than continuing as separate stages.
- The Phase 1 assessment repository (`kosherguard-phase-1-review`) is a separate, static record and stays unchanged.
- `kosherguard-platform` remains the only working repository. No replacement repository, no merges into `main`, no force-pushes, no deletion of prior work at any point in this build (Part 4).
- All restrictions in Part 4 ("No external actions yet") apply for the entire build: no production deploys, no DNS changes, no live-site changes, no device enrollment or erasure, no destructive MDM commands, no purchases, no production Apple credentials, no changes to Oracle, Render, or other live infrastructure.

## 9. Next step

When ChatGPT's response arrives and any corrections are incorporated, Milestone 1 begins on this branch (or on a corrected base if Q1's answer changes it). The build then continues through the milestones under Q2's confirmed cadence, ending at the Part 6 independent review gate before anything external is connected.

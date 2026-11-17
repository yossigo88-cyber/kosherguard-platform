# Stage 12 - Free GitHub Actions Unsigned iOS Build: Investigation and Permission Review

- Repository: https://github.com/yossigo88-cyber/kosherguard-platform (public)
- Branch: `stage-12-free-ci-unsigned-build`
- Base: Stage 11 tip `62c0ccc36ab89d89b70f6b229b13d7c95dae83b7` (`stage-11-apple-build-signing`)
- Untouched: `main` `5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a`, `stage-10-ios-runtime-integration` `791f0ef647dabba449b1e5bee32fc75fec5ce2b5`
- Date: 2026-11-17 (America/New_York)
- Author: Instinct Stage 12 task agent
- Status: INVESTIGATION COMPLETE, PREPARATION COMMITTED. NO BUILD HAS RUN. Workflow activation awaits the user's permission decision in section 6 plus independent review, per Stage 11 precedent.

## 0. Scope and boundaries honored

Requested by Yossi 2026-11-17 18:55 EST: investigate a completely free iOS build using GitHub Actions on the public repo, inspect the Stage 11 inactive workflow, identify the exact rejection reason, determine and SHOW the minimum fine-grained token permissions before any authorization change; if it can work for free, prepare a Stage 12 branch for an unsigned build and capture actual Xcode results.

Honored: no purchases, no secrets exposed (token value never printed; vault file deleted after use), no changes to `main`/`stage-10`/`stage-11`, no Apple account changes, no deploys, no authorization changes, no compilation claim (no macOS run has happened). The workflow file is NOT pushed to `.github/workflows/` - that exact push is what requires the permission decision below.

## 1. Standard GitHub-hosted macOS runner is free for this repo

Source: https://docs.github.com/en/billing/concepts/product-billing/github-actions (fetched 2026-11-17):
- "Standard GitHub-hosted runners in public repositories" are listed as free usage; "Public repositories: This usage remains free."
- "Larger runners are billed for public repositories" - so the standard `macos-26` label must be used, never a larger runner label.
- Compute: explicitly free for public repositories on standard runners.
- Artifact storage: the docs' included GitHub Free allowance is 500 MB (shared with Packages); the workflow stores ONE xcodebuild.log (a few MB) with 30-day retention - a tiny fraction of the free allowance. This is a bounded footprint, not an open-ended "$0 regardless of usage" claim.

Conclusion: runner cost is $0 for this public repository on `macos-26`. No payment method or billing change is needed.

## 2. macOS runner with Xcode 26

Source: https://raw.githubusercontent.com/actions/runner-images/main/images/macos/macos-26-Readme.md (fetched 2026-11-17), image version 20260824.0517.1, OS macOS 26.6.1 (25G76):
- Xcode 26.6 (DEFAULT) at `/Applications/Xcode_26.6.app`; also 26.5, 26.4.1, 26.3, 26.2, 26.1.1, 26.0.1 installed.
- iOS SDKs: iphoneos26.0 through iphoneos26.5 (26.5 ships with Xcode 26.5/26.6) - covers the iOS 26 URL Filter APIs this project uses.
- Runner label: `runs-on: macos-26` (standard GitHub-hosted, free for public repos).

## 3. Stage 11 inactive workflow inspection

File: `ci/ios-compile-check.yml` on `stage-11-apple-build-signing` (inert - NOT under `.github/workflows/`, so it runs nothing). Contents verified at SHA `62c0ccc`:
- Triggers: push and pull_request on `stage-11-*`, plus `workflow_dispatch`.
- Job 1 `static-validation` (ubuntu-latest): `python3 tools/validate-ios-project.py`.
- Job 2 `xcode-compile` (macos-26): selects `/Applications/Xcode_26.6.app`, `xcodebuild -list`, then unsigned build: `CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO` on scheme `KosherGuard`, destination `generic/platform=iOS`, configuration Debug; uploads `xcodebuild.log` as an artifact (30-day retention).
- The workflow's own header documents why it is inert (token lacks the workflow permission) and that it proves only compilation, not signing/entitlements/device behavior.

Verdict: the workflow content is sound for its stated purpose (an unsigned compile check). The Stage 11 independent review verified the YAML and referenced paths statically. It cannot run while it sits outside `.github/workflows/`.

## 4. Exact GitHub rejection (verbatim)

First Stage 11 push attempt 2026-11-17 18:36:45 EST, ref update for the branch then containing `.github/workflows/ios-compile-check.yml`:

```
 ! [remote rejected] stage-11-apple-build-signing -> stage-11-apple-build-signing (refusing to allow a Personal Access Token to create or update workflow `.github/workflows/ios-compile-check.yml` without `workflow` scope)
error: failed to push some refs to 'https://github.com/yossigo88-cyber/kosherguard-platform/'
```

So: GitHub refused the push because the token lacks permission to create/update files under `.github/workflows/`. Everything else in that branch pushed fine once the workflow file was relocated - the rest of the token's access works.

## 5. Minimum additional fine-grained token permissions

Current token (existing approved vault item "GitHub KosherGuard token", fine-grained PAT, selected repositories only incl. this repo): **Contents: write** + **Metadata: read** (implicit). Nothing else.

GitHub documentation (fetched 2026-11-17):
- Fine-grained PAT repository permissions include `workflows` (display name "Workflows"), available at **write only** - https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens
- Repository "Actions" permission endpoints - https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens:
  - **Actions: write** = manual dispatch, enable/disable workflows, rerun/cancel runs, delete runs/artifacts.
  - **Actions: read** = read runs, jobs, logs, artifacts.

Required vs not required, for the Stage 12 goal:

| Capability needed | Permission | Required? |
| --- | --- | --- |
| Push a commit that adds/updates `.github/workflows/*.yml` (git HTTPS) | **Workflows: write** | YES - this is the exact rejection in section 4 |
| Trigger runs by pushing commits | (none beyond the push itself) | NO extra permission |
| Read run status/logs/artifacts so the agent can capture actual Xcode results | none on a public repo | NO - verified 2026-11-17: UNAUTHENTICATED `GET /repos/yossigo88-cyber/kosherguard-platform/actions/workflows` and `/actions/runs` both return HTTP 200, so results are readable anonymously (also in the web UI) |
| Manual re-run / workflow_dispatch / cancel | Actions: write | NO - optional; pushing another commit retriggers |

**Minimum proposed change: add ONLY `Workflows: write` to the existing fine-grained token, same selected repositories, nothing else.** No Actions permission needed, no organization permissions, no Secrets access, no Contents change, no new repos.

Token verification (2026-11-17): the existing "GitHub KosherGuard token" is confirmed a FINE-GRAINED PAT (github_pat_ prefix, verified programmatically without printing the value). Its Contents: write is proven working by the successful Stage 11/12 pushes; its lack of workflow-file write is proven by the section-4 rejection. Whether it holds Actions: read is untestable from outside (public repo allows anonymous reads) and irrelevant per the table.

Zero-permission-change alternative: the user creates `.github/workflows/ios-unsigned-build.yml` through the GitHub web UI (web sessions may commit workflow files). The agent could then still not read run results without `Actions: read`, and any later workflow edit by the agent would still be rejected - so this only defers the same decision.

## 6. Decision requested from the user (no change made)

Proposed, exact: on the existing "GitHub KosherGuard token" (fine-grained, this repo already selected):
1. Add **Workflows: write** - lets the agent push the workflow file and future workflow fixes. That is the ONLY permission change requested.

If approved, the user updates the token in GitHub settings (or replaces it in the vault); the agent does not touch the token itself.

## 7. Prepared Stage 12 workflow (NOT yet active)

File to be added as `.github/workflows/ios-unsigned-build.yml` on this branch after approval + independent review (verbatim):

```yaml
# Stage 12: unsigned iOS compile of the app + extensions on a free
# standard GitHub-hosted macOS runner (public repo: $0).
# Requires iOS SDK only; CODE_SIGNING_ALLOWED=NO means no Apple
# Developer account, certificate or provisioning is needed for a
# compile check. This proves compilation only - not signing,
# entitlements, installation or filtering behavior.
name: iOS unsigned build

on:
  push:
    branches: [stage-12-*]
  pull_request:
    branches: [stage-12-*]
  workflow_dispatch:

jobs:
  static-validation:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Validate project structure (no Xcode needed)
        run: python3 tools/validate-ios-project.py

  xcode-compile:
    runs-on: macos-26
    steps:
      - uses: actions/checkout@v4

      - name: Select Xcode 26.6 (iOS 26.5 SDK)
        run: |
          sudo xcode-select -s /Applications/Xcode_26.6.app/Contents/Developer
          xcodebuild -version

      - name: List project (diagnostics)
        run: xcodebuild -list -project ios/KosherGuard.xcodeproj

      - name: Unsigned compile of app + all extensions
        run: |
          set -o pipefail
          xcodebuild \
            -project ios/KosherGuard.xcodeproj \
            -scheme KosherGuard \
            -destination 'generic/platform=iOS' \
            -configuration Debug \
            CODE_SIGNING_ALLOWED=NO \
            CODE_SIGNING_REQUIRED=NO \
            build 2>&1 | tee xcodebuild.log

      - name: Upload build log
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: xcodebuild-log
          path: xcodebuild.log
          retention-days: 30
```

Note: no Apple Developer Program enrollment ($99) is needed for an unsigned compile. It becomes relevant only later for signing/device install, which Stage 12 does not attempt.

## 8. What is NOT verified

- No iOS build has ever run. Compilation success or failure is UNKNOWN until the macOS runner actually completes. Per the user's instruction, no compilation claim will be made before that.
- Whether Xcode 26.6 accepts the hand-authored project exactly as-is will only be known from the first real run; the log artifact captures any errors.

## 9. Verification log (all read-only, 2026-11-17 EST)

- `git ls-remote origin`: main `5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a`, stage-10 `791f0ef647dabba449b1e5bee32fc75fec5ce2b5`, stage-11 `62c0ccc36ab89d89b70f6b229b13d7c95dae83b7` (unchanged since Stage 11 closeout).
- `python3 tools/validate-ios-project.py` on the Stage 12 branch: "all checks passed (14 informational placeholder/note(s))" - same 14 expected placeholders as Stage 11 (TEAMIDPLACEHOLDER, group/bundle IDs, example domain).
- Stage 11 rejection evidence recovered verbatim from the Stage 11 writer's recorded transcript (timestamped 2026-11-17 18:36:45 EST push attempt; reported 18:39).
- GitHub billing doc, macos-26 runner readme, fine-grained PAT permission docs: fetched live 2026-11-17, quoted in sections 1, 2, 5.

## 10. Changes in this branch

Single commit, docs-only, no code or logic changes, no `.github/` path:
- `docs/reviews/STAGE_12_FREE_CI_BUILD_REVIEW.md` (this file, new)

## 11. Remaining steps after the user's permission decision

1. User approves (or declines) the token change in section 6.
2. Independent review of the workflow file and this branch (per Stage 11 precedent).
3. Agent pushes the activation commit adding `.github/workflows/ios-unsigned-build.yml`.
4. The push triggers the run; agent polls run status via Actions: read and captures the actual Xcode log.
5. Results (success or exact compilation errors) appended as a Stage 12 results report; final summary to the user with permanent links.

#!/usr/bin/env bash
# Compile only portable Foundation/network/dataset code, NOT an iOS build.
# Real SPM build with the pinned swift-crypto dependency and real XCTest -
# no API shims. Requires a Swift toolchain on PATH (see
# docs/setup/IOS_BUILD.md for the exact toolchain used in CI evidence).
# This proves nothing about NetworkExtension, Apple APIs, signing or
# device behavior; those files are not compiled here at all.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${KG_SWIFT_TEST_WORK:-$(mktemp -d)}"
mkdir -p "$WORK/Sources/Core" "$WORK/Tests/CoreTests"
cp "$ROOT/ios/Sources/URLFilter/"{AuthSessionClient,CredentialIssuanceClient,AppConfiguration,PrefilterUpdater,FilterRuleStore,FilterRulesClient,FilterSyncController,FilterVerdictEngine,SignInCoordinator,ApplePrefilter,DohTokenProvider,DNSProxyRelay,URLFilterPrefilterSource,AppBlockingPolicy,PersonalConfiguration,ClientConfigClient,PersonalRegistrationClient,PersonalSetupCoordinator,BackgroundRefreshPolicy,PIREndpointPolicy}.swift "$WORK/Sources/Core/"
cp "$ROOT/tools/swift-portable-tests.swift" "$WORK/Tests/CoreTests/CoreTests.swift"
cat > "$WORK/Package.swift" <<'SWIFT'
// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "PortableReview", dependencies: [
    .package(url: "https://github.com/apple/swift-crypto.git", exact: "3.12.3")
], targets: [
    .target(name: "Core", dependencies: [.product(name: "Crypto", package: "swift-crypto")]),
    .testTarget(name: "CoreTests", dependencies: ["Core"])
])
SWIFT
cd "$WORK"
set -o pipefail
# The suite has repo-reading tests gated on KG_REPO_ROOT (helpers
# repoRoot()/loadVectors()); without it they SKIP and the run looks
# green. Set it explicitly and treat any skip as fatal.
export KG_REPO_ROOT="$ROOT"
test -f "$KG_REPO_ROOT/tools/swift-portable-tests.swift" || {
    echo "ERROR: KG_REPO_ROOT $KG_REPO_ROOT missing required assets" >&2
    exit 1
}
swift test --jobs 4 2>&1 | tee "$WORK/test-output.log"
# Silent-pass guards: swift test exits 0 when a filter/bundle problem
# leaves zero XCTest tests, and a skipped test is a silent gap. Require
# a real XCTest summary with at least one executed test (the
# swift-testing runner's "0 tests" line is expected - the suite is
# XCTest) and no skips.
grep -qE "Executed [1-9][0-9]* tests" "$WORK/test-output.log" || {
    echo "ERROR: no XCTest tests executed (silent pass risk)" >&2
    exit 1
}
if grep -qE "with [1-9][0-9]* tests skipped" "$WORK/test-output.log"; then
    echo "ERROR: tests were skipped (missing KG_REPO_ROOT or assets?)" >&2
    exit 1
fi

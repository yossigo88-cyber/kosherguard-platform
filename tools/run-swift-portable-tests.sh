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
cp "$ROOT/ios/Sources/URLFilter/"{AuthSessionClient,CredentialIssuanceClient,AppConfiguration,PrefilterUpdater,FilterRuleStore,FilterRulesClient,FilterSyncController,FilterVerdictEngine,SignInCoordinator}.swift "$WORK/Sources/Core/"
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
KG_REPO_ROOT="$ROOT" swift test --jobs 4

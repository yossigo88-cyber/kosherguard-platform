#!/usr/bin/env bash
# Compile only portable Foundation/network/dataset code, NOT an iOS build.
# swift-crypto is Apple's CryptoKit-compatible implementation for Linux tests.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${KG_SWIFT_TEST_WORK:-$(mktemp -d)}"
mkdir -p "$WORK/Sources/Core" "$WORK/Tests/CoreTests"
cp "$ROOT/ios/Sources/URLFilter/"{AuthSessionClient,CredentialIssuanceClient,AppConfiguration,PrefilterUpdater}.swift "$WORK/Sources/Core/"
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
swift test --jobs 4

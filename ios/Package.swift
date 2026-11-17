// swift-tools-version: 5.9
// STATUS: PORTABLE-DEVELOPMENT PACKAGE ONLY. The canonical build
// route for the shippable targets is KosherGuard.xcodeproj (direct
// per-target source membership), because the filter providers import
// NetworkExtension and must compile as app extensions - something an
// SPM library target cannot produce. An earlier revision of this
// package declared a FilterExtension library target depending on
// URLFilter: it could never compile (the providers import
// NetworkExtension, unavailable to an SPM build here, and they use
// URLFilter internals without public visibility), so it was removed
// instead of left as a misleading artifact. UNCOMPILED, UNSIGNED,
// UNTESTED - see README.md.
import PackageDescription

let package = Package(
    name: "KosherGuard",
    platforms: [.iOS(.v17)],
    products: [
        .library(name: "KosherGuard", targets: ["KosherGuard"]),
        .library(name: "URLFilter", targets: ["URLFilter"]),
    ],
    targets: [
        .target(name: "KosherGuard", dependencies: ["URLFilter"]),
        .target(name: "URLFilter"),
    ]
)

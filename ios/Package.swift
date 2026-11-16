// swift-tools-version: 5.9
// STATUS: UNCOMPILED, UNSIGNED, UNTESTED - see README.md.
import PackageDescription

let package = Package(
    name: "KosherGuard",
    platforms: [.iOS(.v17)],
    products: [
        .library(name: "KosherGuard", targets: ["KosherGuard"]),
        .library(name: "FilterExtension", targets: ["FilterExtension"]),
        .library(name: "URLFilter", targets: ["URLFilter"]),
    ],
    targets: [
        .target(name: "KosherGuard"),
        .target(name: "FilterExtension"),
        .target(name: "URLFilter"),
    ]
)

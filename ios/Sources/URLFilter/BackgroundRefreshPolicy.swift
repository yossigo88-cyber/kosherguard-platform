// STATUS: portable logic compiled and XCTested on Linux with the real
// Swift toolchain (tools/run-swift-portable-tests.sh). The
// BGTaskScheduler wiring that consumes these values
// (Sources/KosherGuard/BackgroundRefreshScheduler.swift) is
// UNCOMPILED/UNVERIFIED (no Apple SDK here) - see ios/README.md.
import Foundation

/// Background policy-refresh scheduling constants, shared by the
/// app's BGTaskScheduler wiring and the Info.plist declaration. The
/// plist-parity portable test (swift-portable-tests.swift) proves the
/// declared identifier matches this constant, so the two can never
/// silently drift.
///
/// OS-DISCRETIONARY, stated plainly: BGTaskScheduler decides if and
/// when a background refresh runs. It may run hours late or never
/// (Low Power Mode, app rarely used, device off). This scheduling is
/// therefore a freshness OPTIMIZATION only - never a correctness or
/// safety mechanism. Safety lives in use-time expiry, which needs no
/// task to run: the explicit-rule layer refuses snapshots older than
/// FilterVerdictEngine.maxSnapshotAge on every flow, and the URL
/// Filter prefilter layer refuses artifacts older than
/// URLFilterPrefilterSource.maxArtifactAge on every load. When the
/// OS never wakes the app, both layers fail closed at those horizons
/// rather than enforce unboundedly stale policy.
public enum BackgroundRefreshPolicy {
    /// The BGTaskScheduler task identifier. MUST be declared in
    /// Configuration/App-Info.plist under
    /// BGTaskSchedulerPermittedIdentifiers (the portable plist test
    /// asserts this) or registration traps at runtime on device.
    public static let taskIdentifier = "com.kosherguard.app.policy-refresh"

    /// When the next refresh should be eligible to run. The cadence
    /// reuses MaintenancePolicy.nextInterval: hourly after a success,
    /// exponential backoff from 5 minutes (capped at the routine
    /// interval) after consecutive failures, so a broken server or
    /// expired session can never make background wakes storm the
    /// control plane. `earliestBeginDate` is a request, not a
    /// deadline: the OS runs the task at its discretion.
    public static func earliestBeginDate(now: Date,
                                         consecutiveFailures: Int) -> Date {
        now.addingTimeInterval(
            MaintenancePolicy.nextInterval(failures: consecutiveFailures))
    }
}

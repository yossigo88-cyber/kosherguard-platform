// STATUS: UNCOMPILED, UNSIGNED, UNTESTED - no Apple SDK in this
// environment, so this file has never been built or run (see
// ios/README.md). The scheduling VALUES it uses
// (BackgroundRefreshPolicy) are portable-XCTested, and the sync it
// drives (FilterSyncController) is portable-XCTested; the
// BGTaskScheduler interaction itself is Apple's runtime contract and
// remains UNVERIFIED until a signed on-device run.
#if canImport(BackgroundTasks)
import BackgroundTasks
import Foundation
#if canImport(URLFilter)
import URLFilter
#endif

/// BGTaskScheduler-based background policy refresh (Stage 12, B2).
///
/// WHAT THIS IS: a freshness optimization. When the OS grants a
/// background refresh, the app re-runs the ordinary, tested
/// FilterSyncController sync (rules + prefilter), so policy stays
/// closer to the dashboard state without the guardian opening the
/// app.
///
/// WHAT THIS IS NOT: a correctness mechanism. The OS is under no
/// obligation to run the task - it may be hours late or never run
/// (Low Power Mode, usage patterns, device off). Safety does NOT
/// depend on this task running: both enforcement layers expire stale
/// policy AT USE TIME (FilterVerdictEngine.maxSnapshotAge per flow,
/// URLFilterPrefilterSource.maxArtifactAge per load) and fail closed
/// at the horizon. "The OS never wakes the app" therefore degrades
/// to fail-closed filtering, not to unbounded stale enforcement.
///
/// Registration timing: register(...) must run before the app
/// finishes launching (Apple: registration after
/// application(_:didFinishLaunchingWithOptions:) returns is too
/// late). The app shell calls it from its init.
final class BackgroundRefreshScheduler {
    static let shared = BackgroundRefreshScheduler()

    private let defaults: UserDefaults
    /// Consecutive refresh outcomes that did not complete a sync.
    /// Drives MaintenancePolicy's bounded backoff; reset on success.
    /// Persisted because a background refresh can run in a process
    /// the user never sees - in-memory state would not survive it.
    private let failuresKey = "BackgroundRefreshConsecutiveFailures"
    private var syncHandler: (() async -> Bool)?

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    var consecutiveFailures: Int {
        defaults.integer(forKey: failuresKey)
    }

    /// Register the launch-time handler. Called exactly once from the
    /// app shell's init. The handler runs the app's normal sync and
    /// reports whether a sync completed (drives completion + cadence).
    func register(syncHandler: @escaping () async -> Bool) {
        self.syncHandler = syncHandler
        BGTaskScheduler.shared.register(
            forTaskWithIdentifier: BackgroundRefreshPolicy.taskIdentifier,
            using: nil) { [weak self] task in
                guard let self,
                      let refresh = task as? BGAppRefreshTask
                else {
                    task.setTaskCompleted(success: false)
                    return
                }
                self.handle(refresh)
            }
    }

    /// Request the next background refresh. Submitting with the same
    /// identifier REPLACES any pending request, so calling this at
    /// launch, on backgrounding and from the task itself cannot stack
    /// duplicates. A submit failure (e.g. the identifier missing from
    /// BGTaskSchedulerPermittedIdentifiers) leaves no pending request:
    /// acceptable, because correctness never depends on the task
    /// (use-time expiry fails closed). The cadence comes from the
    /// tested MaintenancePolicy: hourly after success, bounded
    /// exponential backoff after failures.
    func scheduleNext(now: Date = Date()) {
        let request = BGAppRefreshTaskRequest(
            identifier: BackgroundRefreshPolicy.taskIdentifier)
        request.earliestBeginDate =
            BackgroundRefreshPolicy.earliestBeginDate(
                now: now, consecutiveFailures: consecutiveFailures)
        try? BGTaskScheduler.shared.submit(request)
    }

    private func handle(_ task: BGAppRefreshTask) {
        // Apple's documented pattern: schedule the NEXT request up
        // front, so an expired/terminated task still leaves a pending
        // refresh behind.
        scheduleNext()
        guard let handler = syncHandler else {
            task.setTaskCompleted(success: false)
            return
        }
        let work = Task { await handler() }
        // The OS is reclaiming the runtime budget: cancel the sync.
        // FilterSyncController checks Task.isCancelled before every
        // commit, so a cancelled sync never writes partial state.
        task.expirationHandler = { work.cancel() }
        Task {
            let completed = await work.value
            let cancelled = work.isCancelled
            if completed && !cancelled {
                defaults.set(0, forKey: failuresKey)
            } else {
                defaults.set(consecutiveFailures + 1, forKey: failuresKey)
            }
            task.setTaskCompleted(success: completed && !cancelled)
        }
    }
}
#endif

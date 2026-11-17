// STATUS: UNCOMPILED, UNSIGNED, UNTESTED ON APPLE PLATFORMS.
// NetworkExtension symbols used here are checked against Apple's
// documentation (NEFilterControlProvider: startFilter,
// handleNewFlow(_:completionHandler:), notifyRulesChanged;
// NEFilterControlVerdict: drop(withUpdateRules:), updateRules()) but
// no Apple SDK has compiled this file. The decision logic lives in
// FilterVerdictEngine, which IS compiled and XCTested portably - see
// ios/README.md.
import NetworkExtension
import Foundation

/// NEFilterControlProvider: the SUPPORTED rule-maintenance path.
///
/// Apple's content-filter model gives the control provider the
/// database-maintenance role (NEFilterControlProvider overview: "the
/// Filter Control Provider can maintain a database of filtering rules
/// on disk in a location where the Filter Data Provider can read from
/// the database"). This is why the DATA PATH needs no host exception:
/// the provider channel that fetches rules is not a filtered user
/// flow. Device verification of that behavior is a documented
/// hardware test (docs/setup/IOS_BUILD.md) - UNVERIFIED here.
///
/// Sync inputs: the app mirrors its validated managed configuration
/// into the app-group store (FilterRuleStore.mirrorConfiguration);
/// credentials come from the shared keychain access group
/// (KeychainCredentialStore.sharedAccessGroup - placeholder team ID,
/// see docs/setup/IOS_BUILD.md). Without either, no sync is possible
/// and the filter stays fail-closed: an honest state, never a silent
/// fallback.
///
/// PACKAGING: Apple runs control providers only from the
/// com.apple.networkextension.filter-control extension point - a
/// SEPARATE app-extension target (KosherGuardFilterControl, wired in
/// the project and marked hand-authored/unverified-in-Xcode).
final class FilterControlProvider: NEFilterControlProvider {

    private let engine: FilterVerdictEngine?
    private let store: FilterRuleStore?
    /// All mutable flags below are touched from the provider's queue
    /// AND the sync Task's executor: every access goes through this
    /// serial queue.
    private let stateQueue = DispatchQueue(
        label: "com.kosherguard.controlprovider.state")
    private var syncInFlight = false
    private var consecutiveFailures = 0
    private var maintenanceScheduled = false
    private var stopped = false
    /// The in-flight sync Task's handle: stopFilter CANCELS it, and
    /// its completion is generation-guarded, so a task started before
    /// a stop can never commit-notify or reschedule after it.
    private var syncTask: Task<Void, Never>?
    /// Bumped on every stopFilter: timer fires and Task completions
    /// from an earlier generation are inert, even if they race the
    /// stop or a restart.
    private var generation = 0

    override init() {
        store = FilterRuleStore.appGroupStore()
        engine = store.map { FilterVerdictEngine(store: $0) }
        super.init()
    }

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        // A restart reuses this instance: stopped must be RESET or
        // the provider would stay permanently dead after one stop.
        stateQueue.sync { stopped = false }
        engine?.reloadIfChanged()
        kickSync()
        // The maintenance loop must exist even when the first sync
        // cannot run yet (no mirrored configuration before the app's
        // first launch, no credentials before sign-in): otherwise the
        // provider deadlocks until a flow callback arrives - which may
        // never happen.
        scheduleMaintenance()
        completionHandler(nil)
    }

    override func stopFilter(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        let task: Task<Void, Never>? = stateQueue.sync {
            stopped = true
            maintenanceScheduled = false
            generation += 1
            let t = syncTask
            syncTask = nil
            return t
        }
        task?.cancel()
        completionHandler()
    }

    /// Rule-management hook. If the store changed under us, announce
    /// it so the data provider reloads. Verdict choice, per Apple's
    /// NEFilterControlVerdict documentation:
    /// - notReady (no valid/current/identity-bound snapshot): FAIL
    ///   CLOSED - drop(withUpdateRules: false), and kick the supported
    ///   sync so the condition can actually resolve.
    /// - ready: updateRules() - the supported verdict whose only
    ///   effect is that the data provider re-reads its rules. We
    ///   deliberately do NOT use allow(withUpdateRules: true): per
    ///   its documentation it lets the flow's data through, and this
    ///   layer has no basis to bless a flow it was asked about.
    override func handleNewFlow(
        _ flow: NEFilterFlow,
        completionHandler: @escaping (NEFilterControlVerdict) -> Void
    ) {
        guard let engine else {
            kickSync()
            completionHandler(.drop(withUpdateRules: false))
            return
        }
        if engine.reloadIfChanged() {
            notifyRulesChanged()
        }
        if engine.isReady {
            completionHandler(.updateRules())
        } else {
            kickSync()
            completionHandler(.drop(withUpdateRules: false))
        }
    }

    /// One sync at a time, from the mirrored managed configuration.
    /// The sync's own outcomes (cleared-on-401, config-change, no
    /// effective policy) are handled inside FilterSyncController.
    /// When a sync CANNOT run yet (no mirrored configuration, no
    /// credentials), the maintenance timer still retries at the
    /// bounded backoff - a missing mirror is a transient pre-app
    /// state, never a permanent deadlock.
    private func kickSync() {
        var claimed = false
        stateQueue.sync {
            if !stopped && !syncInFlight {
                syncInFlight = true
                claimed = true
            }
        }
        guard claimed, let store,
              let configuration = store.mirroredConfiguration()
        else {
            if claimed {
                stateQueue.sync {
                    syncInFlight = false
                    consecutiveFailures += 1
                }
            }
            scheduleMaintenance()
            return
        }
        let controller = FilterSyncController(
            configuration: configuration,
            credentials: KeychainCredentialStore(
                accessGroup: KeychainCredentialStore.sharedAccessGroup),
            session: .shared,
            ruleStore: store,
            prefilterFile: store.configurationFile
                .deletingLastPathComponent()
                .appendingPathComponent("prefilter-snapshot.json"))
        let gen: Int = stateQueue.sync { generation }
        let task = Task { [weak self] in
            await controller.syncNow()
            guard let self else { return }
            // GENERATION + STOP guard BEFORE any notify/reschedule:
            // a sync that started before stopFilter (or before a
            // restart) must never announce rules or arm the timer for
            // a provider that is no longer running this generation.
            let live: Bool = self.stateQueue.sync {
                self.syncInFlight = false
                guard !self.stopped, self.generation == gen,
                      !Task.isCancelled
                else { return false }
                if case .synced = controller.state {
                    self.consecutiveFailures = 0
                } else {
                    self.consecutiveFailures += 1
                }
                return true
            }
            guard live else { return }
            if let changed = self.engine?.reloadIfChanged(), changed {
                self.notifyRulesChanged()
            }
            self.scheduleMaintenance()
        }
        stateQueue.sync { syncTask = task }
    }

    /// Bounded-rate maintenance loop (MaintenancePolicy): rule sync
    /// cannot depend on handleNewFlow callbacks - the data provider
    /// never returns needRules, so no callback may ever arrive, and
    /// the startup sync often runs before sign-in. Exactly one timer
    /// is pending at a time; stopFilter cancels the loop. Routine
    /// cadence hourly; exponential backoff after failures, keeping
    /// the data path fail-closed with NO host exception. UNVERIFIED
    /// on hardware.
    private func scheduleMaintenance() {
        let delay: TimeInterval = stateQueue.sync {
            if stopped || maintenanceScheduled { return -1 }
            maintenanceScheduled = true
            return MaintenancePolicy.nextInterval(
                failures: consecutiveFailures)
        }
        guard delay >= 0 else { return }
        let gen: Int = stateQueue.sync { generation }
        DispatchQueue.global().asyncAfter(deadline: .now() + delay) {
            [weak self] in
            guard let self else { return }
            // Stale fires (scheduled before a stop/restart) are inert:
            // they belong to an earlier generation.
            let active: Bool = self.stateQueue.sync {
                if self.stopped || self.generation != gen {
                    return false
                }
                self.maintenanceScheduled = false
                return true
            }
            guard active else { return }
            self.kickSync()
        }
    }
}

// STATUS: UNCOMPILED, UNSIGNED, UNTESTED ON APPLE PLATFORMS.
// NetworkExtension symbols used here are checked against Apple's
// documentation (NEFilterDataProvider: startFilter, handleNewFlow,
// handleRulesChanged; NEFilterNewFlowVerdict: allow/drop/needRules)
// but no Apple SDK has compiled this file. The decision logic lives in
// FilterVerdictEngine, which IS compiled and XCTested portably - see
// ios/README.md.
import NetworkExtension
import Foundation

/// NEFilterDataProvider: per-flow verdicts for traffic the system
/// routes through the content filter.
///
/// STRICTLY READ-ONLY against the app-group store (Apple's content
/// filter model: the data provider reads the rule database the
/// app/control provider maintains; it never writes, repairs or
/// deletes it). No network call happens on the flow path.
///
/// FAIL-CLOSED: without a valid, current, identity-bound snapshot the
/// engine blocks EVERY flow - there is no allow exception for any
/// host, including the control-plane infrastructure (rule sync runs
/// from the control provider's own channel, outside the filtered
/// data path). Unknown hosts are allowed by this layer ONLY in the
/// ready state: "this layer has no opinion" is only safe while a real
/// policy generation is actually in force.
final class FilterDataProvider: NEFilterDataProvider {

    private let engine: FilterVerdictEngine?

    override init() {
        engine = FilterRuleStore.appGroupStore().map {
            FilterVerdictEngine(store: $0)
        }
        super.init()
    }

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        engine?.reloadIfChanged()
        completionHandler(nil)
    }

    /// The system calls this after the control provider announces
    /// updated rules on disk via notifyRulesChanged().
    override func handleRulesChanged() {
        engine?.reloadIfChanged()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let engine else {
            // No shared store (app-group unavailable): fail closed.
            return .drop()
        }
        // Per-flow freshness: reload when the store file changed
        // (mtime+size+inode), so a sync applies to new flows
        // immediately; cheap no-op when unchanged. Expiry is checked
        // inside the verdict on every flow.
        engine.reloadIfChanged()
        // Host identification: NEFilterSocketFlow carries remoteHostname
        // for flows without a URL (per Apple's NEFilterSocketFlow
        // documentation); only then fall back to the URL host.
        let host = (flow as? NEFilterSocketFlow)?.remoteHostname
            ?? flow.url?.host
        switch engine.verdict(forHost: host) {
        case .block:
            return .drop()
        case .allow:
            return .allow()
        case .askControl:
            // No host at all: this layer can never judge the flow,
            // and allowing it would pass ALL of its data unchecked -
            // fail closed instead of needRules() (no rule update can
            // give us a host to match).
            return .drop()
        }
    }
}

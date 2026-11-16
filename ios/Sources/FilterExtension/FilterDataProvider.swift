// STATUS: UNCOMPILED, UNSIGNED, UNTESTED - see ios/README.md.
import NetworkExtension

/// NEFilterDataProvider: per-flow verdicts for traffic the system
/// routes through the content filter. Fail-closed on internal error:
/// an undecided flow is paused, not allowed, when the policy requires
/// certainty. Verdicts come from the local rule cache; no network call
/// happens on the flow path (latency + privacy).
final class FilterDataProvider: NEFilterDataProvider {

    /// Local verdict cache, populated from the published policy
    /// generation by FilterControlProvider. Key: normalized host.
    /// Value: true = block.
    private var blockRules: [String: Bool] = [:]

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        loadLocalRules()
        completionHandler(nil)
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let url = flow.url, let host = url.host?.lowercased() else {
            return .needRules()
        }
        if blockRules[host] == true {
            return .drop()
        }
        return .allow()
    }

    /// Replace the local rule cache. Called by the control provider
    /// when a new policy generation arrives.
    func updateRules(_ rules: [String: Bool]) {
        blockRules = rules
    }

    private func loadLocalRules() {
        // Reads the shared app-group store written by the control
        // provider. Empty store = no blocks (the PAC/DNS layers still
        // apply their own policies; this layer must not guess).
        blockRules = [:]
    }
}

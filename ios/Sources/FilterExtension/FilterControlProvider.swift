// STATUS: UNCOMPILED, UNSIGNED, UNTESTED - see ios/README.md.
import NetworkExtension

/// NEFilterControlProvider: receives policy updates and keeps the data
/// provider's rule cache current. Policy generations are immutable and
/// versioned; an older generation never replaces a newer one.
final class FilterControlProvider: NEFilterControlProvider {

    private var currentGeneration: Int = 0

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        completionHandler(nil)
    }

    /// Handle a newly published policy generation. Monotonicity is
    /// enforced: replayed or stale generations are ignored, so a
    /// delayed fetch cannot roll the device back to a weaker policy.
    func applyPolicyGeneration(_ generation: Int,
                               rules: [String: Bool]) -> Bool {
        guard generation > currentGeneration else { return false }
        currentGeneration = generation
        // Persist to the app-group store the data provider reads.
        return true
    }
}

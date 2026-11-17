import Foundation

/// The complete result of one authenticated session, persisted as ONE
/// keychain item. Nothing is written globally until the sign-in, the
/// mint AND the authority rotation have all succeeded - a partial or
/// stale attempt leaves no global credential behind, and two
/// concurrent attempts can never interleave into a mixed
/// session-A/dataset-B state.
public struct CredentialBundle: Codable, Equatable {
    public let session: String
    public let sessionOrigin: String
    public let datasetCredential: String
    public let datasetOrigin: String
    /// The lifecycle-authority nonce this bundle was committed under.
    /// The sync controller requires it to equal the admitted nonce
    /// BEFORE ANY REQUEST: a bundle written in the rotation gap (a
    /// sign-out/adoption landed between rotation and the vault
    /// write) is stale garbage and can never resurrect a session.
    public let authority: String

    public static let storageKey = "credentials.bundle"

    public static func load(from credentials: CredentialReading)
        -> CredentialBundle? {
        guard let raw = try? credentials.read(key: storageKey),
              let data = raw.data(using: .utf8)
        else { return nil }
        return try? JSONDecoder().decode(CredentialBundle.self,
                                         from: data)
    }

    public func encoded() throws -> String {
        String(decoding: try JSONEncoder().encode(self), as: UTF8.self)
    }
}

/// Writable credential storage (the shared-access-group keychain in
/// production; an in-memory fake in tests).
public protocol CredentialVault: CredentialReading {
    func save(key: String, value: String) throws
    func delete(key: String) throws
}

/// The two network phases, isolated behind protocols so the whole
/// orchestration is portable-testable with delayed fakes.
public protocol SessionSigningIn {
    func signIn(email: String, password: String,
                totpCode: String?) async throws -> String
}
public protocol SessionSigningOut {
    func signOut(sessionCookie: String) async throws
}
public protocol DatasetCredentialIssuing {
    func mintDatasetCredential(deviceID: Int,
                               sessionCookie: String) async throws -> String
}

/// Exclusive, authority-bound sign-in orchestration.
///
/// Concurrency contract: exactly ONE attempt is in flight per
/// coordinator (the second is refused, never queued). The attempt
/// token (the store's lifecycle nonce) is captured BEFORE the first
/// await and re-verified after every await; a sign-out, managed-config
/// change or adoption landing mid-flight makes the attempt stale and
/// it discards its results. On success the authority ROTATES
/// (conditionally), then the complete credential bundle is written as
/// a single item. Failure paths write nothing, so there is no cleanup
/// that could delete a newer session's credentials.
public actor SignInCoordinator {
    public enum SignInError: Error, Equatable {
        /// No store, corrupt/absent epoch, or tombstoned store.
        case storeNotReady
        /// Another attempt is already in flight.
        case alreadyInProgress
        /// Sign-out, config change or adoption landed mid-flight.
        case staleAttempt
        /// The server rejected the session or device.
        case sessionRejected
        /// The bundle could not be persisted; nothing was stored.
        case persistenceFailed(String)
        case failed(String)
    }

    private let ruleStore: FilterRuleStore?
    private let vault: CredentialVault
    /// The CURRENT managed-configuration source of truth (the app's
    /// UserDefaults mirror). Read AT EXECUTION TIME, never captured:
    /// a queued lifecycle task for a superseded push always sees the
    /// latest source, so rapid A -> B changes coalesce to B and a
    /// stale captured configuration is never re-adopted.
    private let configurationSource: (@Sendable () -> AppConfiguration)?
    private var inFlight = false

    public init(ruleStore: FilterRuleStore?, vault: CredentialVault,
                configurationSource: (@Sendable () -> AppConfiguration)? = nil) {
        self.ruleStore = ruleStore
        self.vault = vault
        self.configurationSource = configurationSource
    }

    /// origin: the configuration origin captured by the caller BEFORE
    /// the first await. currentOrigin: re-reads the caller's current
    /// origin after each await (a managed-config change invalidates
    /// the attempt immediately, even before the store rotates).
    public func signInAndIssue(
        configuration: AppConfiguration,
        email: String, password: String, totpCode: String?,
        deviceID: Int, origin: String,
        auth: SessionSigningIn, issuance: DatasetCredentialIssuing,
        currentOrigin: () -> String?
    ) async throws {
        guard !inFlight else { throw SignInError.alreadyInProgress }
        inFlight = true
        defer { inFlight = false }

        func authorityIntact(_ token: String) -> Bool {
            currentOrigin() == origin
                && ruleStore?.currentEpoch() == token
        }
        // ADMISSION BEFORE ANY NETWORK: the store must be valid and
        // untombstoned, the mirrored configuration must EXACTLY match
        // this attempt's configuration, and the caller's current
        /// origin must still be this attempt's origin. A queued
        /// sign-in for a superseded configuration is refused HERE -
        /// its email/password/TOTP never reach the network.
        guard let ruleStore, !ruleStore.isTombstoned()
        else { throw SignInError.storeNotReady }
        // CURRENT-SOURCE GATE: when a source is installed, this
        // attempt's captured configuration must still BE the current
        // one - a queued attempt from a superseded push is refused
        // before it can admit anything or reach the network.
        if let source = configurationSource,
           source() != configuration {
            throw SignInError.staleAttempt
        }
        guard let attemptToken = ruleStore.admit(
            configuration: configuration),
              currentOrigin() == origin
        else { throw SignInError.staleAttempt }

        let cookie: String
        do {
            cookie = try await auth.signIn(
                email: email, password: password, totpCode: totpCode)
        } catch let error as SignInError {
            throw error
        } catch {
            throw SignInError.failed(String(describing: error))
        }
        guard authorityIntact(attemptToken)
        else { throw SignInError.staleAttempt }

        let credential: String
        do {
            credential = try await issuance.mintDatasetCredential(
                deviceID: deviceID, sessionCookie: cookie)
        } catch let error as SignInError {
            throw error
        } catch {
            throw SignInError.failed(String(describing: error))
        }
        guard authorityIntact(attemptToken)
        else { throw SignInError.staleAttempt }

        // GATED WRITE, ONE LIFECYCLE TRANSACTION: the conditional
        // rotation and the bundle write run under the SAME store
        // lock, so no sign-out/adoption can land between them. The
        // bundle carries the NEW authority nonce; a reader requires
        // it to equal the admitted nonce before any request.
        let newNonce: String
        do {
            newNonce = try ruleStore.rotateAuthorityAndCommit(
                expectedEpoch: attemptToken) { nonce in
                let bundle = CredentialBundle(
                    session: cookie, sessionOrigin: origin,
                    datasetCredential: credential,
                    datasetOrigin: origin, authority: nonce)
                try vault.save(key: CredentialBundle.storageKey,
                               value: bundle.encoded())
            } ?? {
                throw SignInError.staleAttempt
            }()
        } catch let error as SignInError {
            throw error
        } catch {
            throw SignInError.persistenceFailed(
                String(describing: error))
        }
        // A teardown hook inside the vault (or a racing lifecycle
        // event in the same process) may have rotated the authority
        // during the write. If the committed bundle is already stale,
        // remove exactly OUR stale bundle and fail the attempt -
        /// never leave a resurrectable session behind.
        guard ruleStore.currentEpoch() == newNonce else {
            if CredentialBundle.load(from: vault)?.authority
                == newNonce {
                try? vault.delete(key: CredentialBundle.storageKey)
            }
            throw SignInError.staleAttempt
        }
        // Legacy per-key credentials can never masquerade as the
        // freshly issued bundle. Best-effort ONLY for these legacy
        // keys: the bundle above is authoritative.
        try? Self.clearCredentials(vault, includingBundle: false)
    }

    /// CURRENT-SOURCE apply: reads the managed configuration from the
    /// installed source AT EXECUTION TIME (never a caller-captured
    /// copy), then runs the same adoption/invalidation transaction.
    /// Rapid A -> B pushes coalesce: every queued task adopts the
    /// latest source, so an older queued task can never re-adopt a
    /// stale configuration. Fails closed when no source is installed.
    public func applyCurrentConfiguration() async throws
        -> ConfigurationApplyResult {
        guard let source = configurationSource
        else { throw SignInError.storeNotReady }
        return try await applyConfiguration(source())
    }

    /// THE lifecycle owner for configuration changes: adoption /
    /// invalidation and credential teardown are serialized through
    /// THIS actor together with sign-in and sign-out, so the app's
    /// observers can never independently adopt or delete outside the
    /// authority lock. Strict: adoption and teardown errors surface.
    public func applyConfiguration(_ configuration: AppConfiguration)
        async throws -> ConfigurationApplyResult {
        guard let ruleStore else { throw SignInError.storeNotReady }
        let result = try ConfigurationApplier.apply(
            configuration: configuration, to: ruleStore)
        switch result {
        case .adopted, .invalidated:
            try Self.clearCredentials(vault)
        case .alreadyCurrent:
            break
        }
        return result
    }

    /// THE lifecycle owner for sign-out with OPTIONAL remote logout.
    /// The bundle's session cookie and the origin it was issued for
    /// are captured BEFORE any await; local teardown runs FIRST
    /// (strict errors still surface); the server call happens LAST -
    /// and ONLY with a client the caller captured together with, and
    /// bound to, an origin equal to the bundle's session origin. A
    /// client whose origin cannot be proven to match (a managed-
    /// configuration change may have replaced it during the await)
    /// is NEVER handed the old cookie: remote logout is omitted.
    public func signOut<Auth: SessionSigningOut>(
        remoteLogout auth: Auth?, boundToOrigin clientOrigin: String?
    ) async throws {
        let bundle = CredentialBundle.load(from: vault)
        var firstError: Error?
        do {
            try await signOut()
        } catch { firstError = error }
        if let auth, let bundle,
           let clientOrigin, clientOrigin == bundle.sessionOrigin {
            try? await auth.signOut(sessionCookie: bundle.session)
        }
        if let firstError { throw firstError }
    }

    /// THE lifecycle owner for sign-out: local-first teardown
    /// (credentials first, then the store marker). Every step is
    /// attempted; the first error surfaces after all steps ran.
    public func signOut() async throws {
        var firstError: Error?
        do {
            try Self.clearCredentials(vault)
        } catch { firstError = error }
        if let ruleStore {
            do {
                try ruleStore.clear()
                ruleStore.recordStatus("rules cleared: signed out")
            } catch { if firstError == nil { firstError = error } }
        }
        if let firstError { throw firstError }
    }

    /// Local-first credential teardown (sign-out, config change).
    /// Bundle first, then any legacy keys. STRICT: deletion errors
    /// surface (a silently-kept credential is a security lie); an
    /// absent key is NOT an error (idempotent teardown).
    nonisolated public static func clearCredentials(
        _ vault: CredentialVault, includingBundle: Bool = true) throws {
        if includingBundle {
            try vault.delete(key: CredentialBundle.storageKey)
        }
        try vault.delete(key: "session")
        try vault.delete(key: "session.origin")
        try vault.delete(key: "credential.dataset")
        try vault.delete(key: "credential.dataset.origin")
    }
}

/// The app-side managed-configuration lifecycle, portable-testable.
///
/// THE RECOVERY RULE: a valid managed configuration must be adopted
/// even when the store was previously invalidated (tombstoned, mirror
/// removed) - otherwise one transient invalid push permanently
/// deadlocks the device (controller init refuses to re-mirror a
/// tombstoned store, and only the app's adoption may lift the
/// tombstone). All steps throw on failure (strict, never best-effort
/// tombstone/adoption).
public enum ConfigurationApplyResult: Equatable {
    /// Valid configuration newly established (identity cleared,
    /// authority rotated, mirror written, tombstone lifted). Stored
    /// credentials belong to the old origin/authority - drop them.
    case adopted
    /// The mirrored configuration already matches; nothing to do.
    case alreadyCurrent
    /// Invalid/absent configuration: authority rotated, identity and
    /// mirror removed, tombstone written.
    case invalidated
}

public enum ConfigurationApplier {
    public static func apply(
        configuration: AppConfiguration,
        to store: FilterRuleStore
    ) throws -> ConfigurationApplyResult {
        if FilterSyncController.configurationProblem(configuration)
            != nil {
            // An invalid/absent managed configuration is an
            // authoritative invalidation, NOT a passive "not
            // configured". Idempotent: a tombstoned store stays
            // tombstoned.
            if !store.isTombstoned() {
                try store.invalidateConfiguration()
            }
            return .invalidated
        }
        if !store.isTombstoned(),
           let mirrored = store.mirroredConfiguration(),
           FilterRuleStore.sameIdentity(mirrored, configuration) {
            return .alreadyCurrent
        }
        // Valid configuration with a MISSING mirror (post-invalidation
        // or first install from the app side), a DIFFERENT mirror, or
        // a tombstone: the app's atomic adoption is the only door.
        try store.adoptConfiguration(configuration)
        return .adopted
    }
}

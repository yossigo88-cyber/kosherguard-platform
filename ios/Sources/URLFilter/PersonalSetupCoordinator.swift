// STATUS: portable logic compiled and XCTested on Linux with the real
// Swift toolchain (tools/run-swift-portable-tests.sh). The full flow
// against a live control plane is UNVERIFIED - no signed iOS build
// exists. See ios/README.md.
import Foundation

/// Network seams for the personal-lane setup flow (fakes in tests, the
/// real clients in the app).
public protocol ClientConfigFetching {
    func fetchConfig(sessionCookie: String) async throws
        -> ClientConfigClient.ServiceConfig
}
public protocol PersonalDeviceRegistering {
    func register(name: String, registrationKey: String,
                  sessionCookie: String) async throws
        -> PersonalRegistrationClient.Registration
}

/// Personal-lane setup orchestration: turn "server address + guardian
/// sign-in" into a complete, persisted PersonalConfiguration.
///
/// Flow (each step real, no invented endpoints):
/// 1. Validate the server URL (plain https; credentials are never
///    sent to a plaintext or credential-embedding origin).
/// 2. Sign in (AuthSessionClient) - proves the guardian credentials
///    and yields the session that authorizes the next two calls.
/// 3. Discover the deployment's services (GET /api/client-config).
///    Nulls stay nil: an undeployed dataset/PIR service is an honest
///    "feature unavailable", never a substituted endpoint.
/// 4. Register the device idempotently (POST
///    /api/devices/personal-registration) with the per-install
///    registration key, so retries and reinstalls reuse one row.
/// 5. Persist the configuration atomically and drop the pending
///    identity. The temporary setup session is signed out
///    best-effort; the DURABLE credential bundle is written
///    afterwards by SignInCoordinator.signInAndIssue under its own
///    tested authority model (this coordinator never writes
///    credentials, so a failed setup can never leave a half-bound
///    session behind).
public actor PersonalSetupCoordinator {
    public enum SetupError: Error, Equatable {
        case alreadyInProgress
        /// Not a plain https URL with a host (no credentials/query).
        case invalidServerURL
        /// The app-group persistence is unavailable; nothing was set up.
        case storeUnavailable
        case invalidCredentials
        case rateLimited
        /// The auto-generated device name collided; retry (a fresh
        /// name suffix is generated per install).
        case nameConflict
        /// The device row exists but is not active (e.g. offboarded);
        /// reactivation is a dashboard action, never a silent app one.
        case deviceNotActive(String)
        case persistenceFailed(String)
        case failed(String)
    }

    private let store: PersonalConfigurationStore
    private var inFlight = false

    public init(store: PersonalConfigurationStore) {
        self.store = store
    }

    public func setUp(
        serverURL rawServer: String,
        email: String, password: String, totpCode: String?,
        auth: SessionSigningIn,
        config: ClientConfigFetching,
        registration: PersonalDeviceRegistering,
        signOut: SessionSigningOut?
    ) async throws -> PersonalConfiguration {
        guard !inFlight else { throw SetupError.alreadyInProgress }
        inFlight = true
        defer { inFlight = false }

        guard let serverURL =
                PersonalConfiguration.validatedHTTPSURL(rawServer)
        else { throw SetupError.invalidServerURL }

        let cookie: String
        do {
            cookie = try await auth.signIn(
                email: email, password: password, totpCode: totpCode)
        } catch let error as AuthSessionClient.AuthError {
            switch error {
            case .invalidCredentials:
                throw SetupError.invalidCredentials
            case .rateLimited: throw SetupError.rateLimited
            default:
                throw SetupError.failed(String(describing: error))
            }
        } catch {
            throw SetupError.failed(String(describing: error))
        }

        // Everything after the sign-in holds a live session. It is
        // signed out best-effort on EVERY exit path below: the setup
        // session is never persisted, so it must not linger
        // server-side longer than needed.
        var outcome: Result<PersonalConfiguration, SetupError>
        do {
            let services: ClientConfigClient.ServiceConfig
            do {
                services = try await config.fetchConfig(
                    sessionCookie: cookie)
            } catch let error as ClientConfigClient.ClientConfigError {
                switch error {
                case .unauthorized: throw SetupError.invalidCredentials
                default:
                    throw SetupError.failed(String(describing: error))
                }
            }

            let pending: PendingRegistration
            do {
                pending = try store.loadOrCreatePendingRegistration()
            } catch {
                throw SetupError.persistenceFailed(
                    String(describing: error))
            }

            // Bounded name-conflict recovery: a colliding
            // auto-generated name is regenerated (same key, new
            // suffix) and retried at most twice. A persistent
            // conflict surfaces as nameConflict rather than
            // dead-ending the user on an uneditable name.
            var attempt = pending
            var registered: PersonalRegistrationClient.Registration?
            for retry in 0...2 {
                do {
                    registered = try await registration.register(
                        name: attempt.deviceName,
                        registrationKey: attempt.registrationKey,
                        sessionCookie: cookie)
                    break
                } catch let error
                    as PersonalRegistrationClient.RegistrationError {
                    switch error {
                    case .unauthorized:
                        throw SetupError.invalidCredentials
                    case .nameConflict where retry < 2:
                        do {
                            attempt = try store.regeneratePendingName()
                        } catch {
                            throw SetupError.persistenceFailed(
                                String(describing: error))
                        }
                    case .nameConflict:
                        throw SetupError.nameConflict
                    default:
                        throw SetupError.failed(
                            String(describing: error))
                    }
                }
            }
            guard let registered else { throw SetupError.nameConflict }
            // A re-registered device that is offboarded/inactive is
            // NOT silently reactivated: the guardian re-enables it in
            // the dashboard. Surface the state instead.
            guard registered.state == "active" else {
                throw SetupError.deviceNotActive(registered.state)
            }

            let configuration = PersonalConfiguration(
                controlPlaneBaseURL: serverURL,
                datasetBaseURL: services.datasetBaseURL,
                dohServerURL: services.dohServerURL,
                pirServerURL: services.pirServerURL,
                pirPrivacyPassIssuerURL: services.pirPrivacyPassIssuerURL,
                deviceID: registered.deviceID,
                registrationKey: pending.registrationKey,
                deviceName: registered.name)
            do {
                try store.save(configuration)
                try store.clearPendingRegistration()
            } catch {
                throw SetupError.persistenceFailed(
                    String(describing: error))
            }
            outcome = .success(configuration)
        } catch let error as SetupError {
            outcome = .failure(error)
        } catch {
            // Network failures (URLError), cancellation, and every
            // other non-typed error land here so the best-effort
            // sign-out below still runs on EVERY exit path. The
            // session must never leak because an error type was not
            // anticipated.
            outcome = .failure(.failed(String(describing: error)))
        }
        if let signOut {
            try? await signOut.signOut(sessionCookie: cookie)
        }
        return try outcome.get()
    }
}

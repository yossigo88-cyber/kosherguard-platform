// STATUS: portable logic compiled and XCTested on Linux with the real
// Swift toolchain (tools/run-swift-portable-tests.sh). The provider
// that embeds it (DNSProxyProvider) is UNCOMPILED (no Apple SDK) - see
// ios/README.md.
import Foundation

/// Short-lived "doh"-scope credential lifecycle for the app-mediated
/// DoH path (docs/design/DOH_IOS_TRANSPORT.md, option 1: the approved
/// per-device identity design - Authorization-header scoped tokens,
/// never URL-borne, redacted from logs).
///
/// Properties:
/// - MEMORY ONLY: tokens are never written to disk, UserDefaults or
///   logs. A process restart simply mints again.
/// - PROACTIVE RENEWAL: a token is refreshed once 75% of its lifetime
///   has elapsed, so resolution never discovers expiry as a 401
///   mid-query. When the server omits expires_in_seconds (older
///   build), a conservative 15-minute assumption applies (server
///   lifetime is capped at 24h and equals at most the session
///   lifetime).
/// - SINGLE-FLIGHT: concurrent callers share one in-flight mint; a
///   DoH proxy under load can never stampede the issuance route.
/// - FAIL CLOSED: any mint/refresh failure leaves the provider
///   empty-handed and queries fail (DNSProxyRelay answers SERVFAIL);
///   there is no plaintext-DNS or unauthenticated fallback.
final class DohTokenProvider {

    enum TokenError: Error, Equatable {
        /// The mint route refused the session (401/403): the guardian
        /// session is gone or revoked. Resolution stays closed until
        /// a fresh sign-in supplies a new cookie.
        case unauthorized
        case unavailable
    }

    private let issuer: CredentialIssuanceClient
    private let deviceID: Int
    /// Injected so tests control time; the value is read at every
    /// decision, never captured.
    private let now: () -> Date
    /// Reads the CURRENT session cookie at mint time. Captured-at-init
    /// cookies go stale on sign-out/sign-in; reading late means a
    /// mint always uses the live session.
    private let sessionCookie: () -> String?

    private var cached: (token: String, expiresAt: Date)?
    private var inFlight: Task<(String, Date), Error>?
    private let lock = NSLock()

    /// Fraction of the server-reported lifetime after which a token
    /// counts as stale and is renewed on the next request.
    static let refreshAfterFraction: Double = 0.75
    /// Assumed lifetime when the server does not report one.
    static let fallbackLifetime: TimeInterval = 15 * 60

    init(issuer: CredentialIssuanceClient, deviceID: Int,
         now: @escaping () -> Date = Date.init,
         sessionCookie: @escaping () -> String?) {
        self.issuer = issuer
        self.deviceID = deviceID
        self.now = now
        self.sessionCookie = sessionCookie
    }

    /// A currently valid token, minting or renewing as needed.
    func currentToken() async throws -> String {
        // Loop: if invalidate() lands between the freshness check and
        // the cached-token read, the read finds no cache - mint anew
        // instead of reporting a spurious failure.
        while true {
            if let task: Task<(String, Date), Error> = lock.withLock({ () -> Task<(String, Date), Error>? in
                if let inFlight { return inFlight }
                if let cached, now() < cached.expiresAt {
                    return nil // fresh enough; answered below
                }
                let task = Task { [issuer, deviceID, now, sessionCookie] in
                    guard let cookie = sessionCookie(), !cookie.isEmpty else {
                        throw TokenError.unauthorized
                    }
                    let minted = try await issuer.mint(deviceID: deviceID,
                                                       scope: .doh,
                                                       sessionCookie: cookie)
                    return (minted.token,
                            now() + Self.lifetime(of: minted))
                }
                inFlight = task
                return task
            }) {
                do {
                    let (token, expiresAt) = try await task.value
                    lock.withLock {
                        cached = (token, expiresAt)
                        inFlight = nil
                    }
                    return token
                } catch let error as CredentialIssuanceClient.IssuanceError {
                    lock.withLock { inFlight = nil }
                    switch error {
                    case .unauthorized, .deviceNotFound, .noEffectivePolicy:
                        throw TokenError.unauthorized
                    default:
                        throw TokenError.unavailable
                    }
                } catch let error as TokenError {
                    lock.withLock { inFlight = nil }
                    throw error
                } catch {
                    lock.withLock { inFlight = nil }
                    throw TokenError.unavailable
                }
            }
            // Fresh cached token (answered outside the lock). If the
            // cache was invalidated between the two locks, loop and
            // mint - never a spurious failure.
            if let token = lock.withLock({ () -> String? in
                guard let cached, now() < cached.expiresAt
                else { return nil }
                return cached.token
            }) {
                return token
            }
        }
    }

    /// Forget the cached token (sign-out, origin change, 401 from
    /// dns-edge). The next query mints anew.
    func invalidate() {
        lock.withLock { cached = nil }
    }

    private static func lifetime(
        of credential: CredentialIssuanceClient.ScopedCredential
    ) -> TimeInterval {
        guard let reported = credential.expiresInSeconds, reported > 0 else {
            return fallbackLifetime
        }
        return TimeInterval(reported) * refreshAfterFraction
    }
}

// STATUS: UNCOMPILED, UNSIGNED, UNTESTED - see ios/README.md.
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Native session acquisition for the control plane. The published
/// server has no separate native-token exchange; the same JSON login
/// the admin UI uses (POST /api/auth/login) sets the session cookie,
/// and the CSRF header is a static marker a native client can send.
/// This client performs that login, extracts the session cookie, and
/// hands it to CredentialIssuanceClient - closing the "no way for the
/// app to authenticate" gap with real code instead of a design note.
///
/// MFA: when the account has TOTP enrolled the login body must carry
/// the current code; the caller supplies it.
///
/// No credential is persisted here; see KeychainCredentialStore for
/// the storage layer.
public struct AuthSessionClient {
    let baseURL: URL
    let session: URLSession

    public init(baseURL: URL, session: URLSession = .shared) {
        self.baseURL = baseURL
        self.session = session
    }

    public enum AuthError: Error, Equatable {
        /// Bad password OR missing/invalid TOTP code - the server
        /// returns the same 401 for both by design.
        case invalidCredentials
        case rateLimited
        case unexpectedStatus(Int)
        case noSessionCookie
        case malformedResponse
    }

    public struct Credentials {
        let email: String
        let password: String
        let totpCode: String?
        public init(email: String, password: String, totpCode: String?) {
            self.email = email
            self.password = password
            self.totpCode = totpCode
        }
    }

    /// Sign in and return the session cookie VALUE (not persisted).
    public func signIn(_ credentials: Credentials) async throws -> String {
        var req = URLRequest(url: baseURL
            .appendingPathComponent("api/auth/login"))
        req.httpMethod = "POST"
        req.setValue("application/json",
                     forHTTPHeaderField: "Content-Type")
        req.setValue("1", forHTTPHeaderField: "X-KosherGuard-Request")
        var body: [String: String] = [
            "email": credentials.email,
            "password": credentials.password,
        ]
        if let code = credentials.totpCode { body["totp_code"] = code }
        req.httpBody = try JSONEncoder().encode(body)

        // The session cookie must be captured from THIS response, so
        // the shared cookie store must not swallow it first.
        let (data, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse else {
            throw AuthError.malformedResponse
        }
        switch http.statusCode {
        case 200: break
        case 401, 403:
            // The server deliberately returns the SAME 401 for a bad
            // password and for a missing/invalid TOTP code
            // (anti-enumeration); the client cannot distinguish them.
            throw AuthError.invalidCredentials
        case 429: throw AuthError.rateLimited
        default: throw AuthError.unexpectedStatus(http.statusCode)
        }
        let fields = http.allHeaderFields.reduce(into: [String: String]()) {
            result, field in
            result[String(describing: field.key)] = String(describing: field.value)
        }
        let cookies = HTTPCookie.cookies(withResponseHeaderFields: fields,
                                         for: req.url!)
        guard let cookie = cookies.first(where: { $0.name == "kg_session" }) else {
            throw AuthError.noSessionCookie
        }
        _ = data
        return cookie.value
    }

    /// Sign out, invalidating the session server-side.
    public func signOut(sessionCookie: String) async throws {
        var req = URLRequest(url: baseURL
            .appendingPathComponent("api/auth/logout"))
        req.httpMethod = "POST"
        req.setValue("1", forHTTPHeaderField: "X-KosherGuard-Request")
        req.setValue("kg_session=\(sessionCookie)",
                     forHTTPHeaderField: "Cookie")
        _ = try await session.data(for: req)
    }
}

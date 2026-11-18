// STATUS: portable logic compiled and XCTested on Linux with the real
// Swift toolchain (tools/run-swift-portable-tests.sh). Network behavior
// against a live control plane is UNVERIFIED - no signed iOS build
// exists. See ios/README.md.
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Client for POST /api/devices/personal-registration - how an
/// unsupervised iPhone (no MDM to create its device record) registers
/// itself with the family's control plane after the guardian signs in.
///
/// Idempotency: the client generates one registration key per install
/// (persisted by PersonalConfigurationStore) and the server returns the
/// SAME device row for a repeated key, so a retried or post-reinstall
/// setup never accumulates duplicate devices. The key is a
/// device-secret: it is only ever sent to this control plane, over
/// HTTPS, in the request body - never in a URL, never logged.
///
/// Auth: guardian session cookie from /api/auth/login plus the static
/// CSRF marker header, the same contract as the other control-plane
/// clients.
public struct PersonalRegistrationClient {
    let baseURL: URL
    let session: URLSession

    public init(baseURL: URL, session: URLSession = .shared) {
        self.baseURL = baseURL
        self.session = session
    }

    public struct Registration: Equatable {
        public let deviceID: Int
        public let name: String
        /// "active" devices can sync and mint credentials; any other
        /// state (e.g. offboarded) is surfaced, not worked around.
        public let state: String
        /// false when the key already had a row (reinstall/retry): the
        /// pre-existing device was adopted, nothing new was created.
        public let created: Bool

        public init(deviceID: Int, name: String, state: String,
                    created: Bool) {
            self.deviceID = deviceID
            self.name = name
            self.state = state
            self.created = created
        }
    }

    public enum RegistrationError: Error, Equatable {
        case unauthorized
        /// The display name already belongs to a different device in
        /// this family; pick another name and retry.
        case nameConflict
        case unexpectedStatus(Int)
        case malformedResponse
        case invalidPayload
    }

    public func register(name: String, registrationKey: String,
                         sessionCookie: String)
        async throws -> Registration {
        var req = URLRequest(url: baseURL
            .appendingPathComponent("api/devices")
            .appendingPathComponent("personal-registration"))
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("1", forHTTPHeaderField: "X-KosherGuard-Request")
        req.setValue("kg_session=\(sessionCookie)",
                     forHTTPHeaderField: "Cookie")
        req.httpBody = try JSONEncoder().encode(
            ["name": name, "registration_key": registrationKey])

        let (data, response) = try await session.data(for: req)
        guard let http = response as? HTTPURLResponse else {
            throw RegistrationError.malformedResponse
        }
        switch http.statusCode {
        case 200: break
        case 401, 403: throw RegistrationError.unauthorized
        case 409: throw RegistrationError.nameConflict
        default:
            throw RegistrationError.unexpectedStatus(http.statusCode)
        }
        struct RegistrationBody: Decodable {
            let id: Int
            let name: String
            let state: String
            let created: Bool
        }
        guard let body = try? JSONDecoder().decode(RegistrationBody.self,
                                                        from: data)
        else { throw RegistrationError.malformedResponse }
        guard body.id > 0, !body.name.isEmpty, !body.state.isEmpty
        else { throw RegistrationError.invalidPayload }
        return Registration(deviceID: body.id, name: body.name,
                            state: body.state, created: body.created)
    }
}

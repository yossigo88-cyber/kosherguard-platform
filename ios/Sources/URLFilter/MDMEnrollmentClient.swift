// STATUS: UNCOMPILED, UNSIGNED, UNTESTED - see ios/README.md.
import Foundation

/// Client for KosherGuard's enrollment endpoint: fetches and installs
/// the (signed, in production) enrollment profile. In this build the
/// profile is unsigned and undeliverable; this client is the shape of
/// the flow, not a working enrollment.
///
/// Devices never accept inbound connections; all contact is outbound
/// (check-in on APNs wake). This client therefore has no listener.
struct MDMEnrollmentClient {
    let enrollmentURL: URL
    let session: URLSession

    enum EnrollmentError: Error {
        case unsignedProfileRefused
        case fetchFailed
    }

    /// Download the enrollment profile. REFUSES an unsigned profile:
    /// installing one would be a security downgrade, so the client
    /// treats unsigned data as an error, not a fallback.
    func fetchEnrollmentProfile() async throws -> Data {
        let (_, response) = try await session.data(from: enrollmentURL)
        guard let http = response as? HTTPURLResponse,
              http.statusCode == 200 else {
            throw EnrollmentError.fetchFailed
        }
        // Production check: verify the profile's CMS signature against
        // the platform's signing chain before handing it to the system.
        // There is no signing chain yet, so this always throws in this
        // build - deliberately.
        throw EnrollmentError.unsignedProfileRefused
    }
}

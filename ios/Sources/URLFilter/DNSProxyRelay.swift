// STATUS: portable logic compiled and XCTested on Linux with the real
// Swift toolchain (tools/run-swift-portable-tests.sh). The provider
// that embeds it (DNSProxyProvider) is UNCOMPILED (no Apple SDK) - see
// ios/README.md.
import Foundation

/// Wire-format DNS relay core for the app-mediated DoH path
/// (NEDNSProxyProvider -> DNSOverHTTPSClient). Everything here is
/// transport-agnostic so the whole decision surface is XCTested on
/// Linux; the NetworkExtension subclass is a thin adapter.
///
/// FAIL CLOSED, NO FALLBACK: any malformed query, oversized message,
/// credential failure or upstream error yields a SERVFAIL response
/// (or a dropped datagram when no transaction ID can be recovered).
/// There is deliberately NO plaintext-DNS or system-resolver escape:
/// this proxy exists to enforce authenticated per-device DNS, and a
/// silent downgrade would defeat it (user requirement, WhatsApp
/// 2026-11-16: authenticated per-device DNS is the intended identity
/// mechanism).
enum DNSProxyRelay {

    enum RelayRejection: Error, Equatable {
        case tooSmall
        case tooLarge
        case notAQuery
        case noTransactionID
        case noQuestion
        case truncationSet
    }

    /// RFC 1035 bounds for a UDP-carried query we will proxy.
    static let minimumQueryBytes = 12
    static let maximumQueryBytes = 4096

    /// Validate an inbound wire-format query before it is proxied.
    /// Only standard queries (QR=0) with at least one question and no
    /// truncation flag are eligible.
    static func validate(query: Data) throws {
        guard query.count >= minimumQueryBytes else {
            throw RelayRejection.tooSmall
        }
        guard query.count <= maximumQueryBytes else {
            throw RelayRejection.tooLarge
        }
        let flags = query[query.index(query.startIndex, offsetBy: 2)]
        // QR bit (0x80) must be clear: this is a query, not a looped
        // response; TC (0x02) set means the query was already
        // truncated and reassembly is not this layer's job. Opcode
        // (bits 0x78) must be 0 (standard QUERY): NOTIFY/UPDATE/etc.
        // are not resolver lookups and never reach DoH.
        guard flags & 0x80 == 0 else { throw RelayRejection.notAQuery }
        guard flags & 0x02 == 0 else { throw RelayRejection.truncationSet }
        guard flags & 0x78 == 0 else { throw RelayRejection.notAQuery }
        let qdcount = (Int(query[query.index(query.startIndex, offsetBy: 4)]) << 8)
            | Int(query[query.index(query.startIndex, offsetBy: 5)])
        guard qdcount >= 1 else { throw RelayRejection.noQuestion }
    }

    /// Build a SERVFAIL response echoing the query's transaction ID
    /// (and question section when fully present). RFC 1035: QR=1,
    /// RCODE=2. If the datagram is too short to even carry an ID the
    /// caller drops it instead (return nil).
    static func servfailResponse(to query: Data) -> Data? {
        guard query.count >= 2 else { return nil }
        var response = Data(count: max(query.count, minimumQueryBytes))
        response[0] = query[0]
        response[1] = query[1]
        if query.count >= 12 {
            // Copy the header and question section verbatim, then set
            // QR + RCODE. AN/NS/AR counts are zeroed.
            response.replaceSubrange(2..<query.count,
                                     with: query[2...])
        } else {
            for i in 2..<12 { response[i] = 0 }
        }
        response[2] = (response[2] & 0x01) | 0x80 // QR=1, keep RD
        response[3] = (response[3] & 0x70) | 0x02 // keep Z/RA low bits, RCODE=2
        // Zero the answer/authority/additional counts.
        if response.count >= 12 {
            for i in [6, 7, 8, 9, 10, 11] { response[i] = 0 }
        }
        return response
    }

    /// Relay one query through the authenticated DoH resolver.
    /// `resolve` is the DNSOverHTTPSClient call (or a test double) and
    /// receives the exact wire bytes; any throw becomes SERVFAIL.
    static func relay(query: Data,
                      resolve: (Data) async throws -> Data) async -> Data? {
        do {
            try validate(query: query)
        } catch {
            return servfailResponse(to: query)
        }
        do {
            let answer = try await resolve(query)
            guard answer.count >= 2,
                  answer[0] == query[0], answer[1] == query[1] else {
                // A mismatched transaction ID can never be trusted:
                // it may belong to another in-flight query.
                return servfailResponse(to: query)
            }
            return answer
        } catch {
            return servfailResponse(to: query)
        }
    }
}

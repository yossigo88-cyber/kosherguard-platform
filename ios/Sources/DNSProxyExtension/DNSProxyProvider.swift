// STATUS: UNCOMPILED, UNSIGNED, UNTESTED ON APPLE PLATFORMS.
// NEDNSProxyProvider / NEAppProxyUDPFlow / NEAppProxyTCPFlow symbols
// are written against Apple's NetworkExtension documentation; no
// Apple SDK has compiled this file. The relay decisions live in
// DNSProxyRelay and the credential lifecycle in DohTokenProvider,
// both compiled and XCTested portably - see ios/README.md.
//
// DEPLOYMENT TRUTH: the dns-proxy entitlement value is a managed
// Network Extension capability that requires Apple's approval and a
// supervised/managed device to run; none of that exists yet (see the
// stage report's Apple-dependent task list). This file makes the
// runtime path real code; it does not claim the path runs.
import NetworkExtension
import Foundation

/// NEDNSProxyProvider: the system-wide DNS path that CAN carry the
/// approved per-device identity (docs/design/DOH_IOS_TRANSPORT.md,
/// option 1 - app/extension-mediated resolution attaching the scoped
/// "doh" credential as an Authorization header, never in the URL).
///
/// FAIL CLOSED: if the managed configuration, session credential or
/// token mint is unavailable, the proxy refuses to start (or answers
/// SERVFAIL per query). There is NO plaintext/system-resolver
/// fallback: silent downgrade would defeat the authenticated
/// per-device requirement.
final class DNSProxyProvider: NEDNSProxyProvider {

    private var dohClient: DNSOverHTTPSClient?
    private var tokenProvider: DohTokenProvider?

    override func startProxy(
        options: [String: Any]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        guard let store = FilterRuleStore.appGroupStore(),
              let configuration = store.mirroredConfiguration(),
              let dohURL = configuration.dohServerURL,
              let controlPlane = configuration.controlPlaneBaseURL,
              let deviceID = configuration.deviceID
        else {
            completionHandler(NSError(
                domain: "com.kosherguard.dnsproxy", code: 1,
                userInfo: [NSLocalizedDescriptionKey:
                    "DNS proxy not configured (managed configuration "
                    + "missing or incomplete)"]))
            return
        }
        let keychain = KeychainCredentialStore(
            accessGroup: KeychainCredentialStore.sharedAccessGroup)
        // The session cookie is read AT MINT TIME from the shared
        // keychain, so a sign-out/sign-in between queries can never
        // send a stale cookie; origin binding is enforced by the
        // sign-in flow that wrote the bundle.
        let bundle = CredentialBundle.load(from: keychain)
        guard let bundle, !bundle.session.isEmpty else {
            completionHandler(NSError(
                domain: "com.kosherguard.dnsproxy", code: 2,
                userInfo: [NSLocalizedDescriptionKey:
                    "DNS proxy has no signed-in session"]))
            return
        }
        let issuer = CredentialIssuanceClient(baseURL: controlPlane)
        tokenProvider = DohTokenProvider(
            issuer: issuer, deviceID: deviceID,
            sessionCookie: {
                CredentialBundle.load(from: keychain)?.session
            })
        dohClient = DNSOverHTTPSClient(serverURL: dohURL, session: .shared)
        completionHandler(nil)
    }

    override func stopProxy(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        tokenProvider?.invalidate()
        dohClient = nil
        tokenProvider = nil
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        // Only DNS traffic reaches this provider (the system routes
        // port-53 flows to the dns-proxy extension point). UDP is the
        // primary transport; TCP is handled with RFC 1035 length
        // framing.
        if let udp = flow as? NEAppProxyUDPFlow {
            handleUDP(udp)
            return true
        }
        if let tcp = flow as? NEAppProxyTCPFlow {
            handleTCP(tcp)
            return true
        }
        return false
    }

    private func handleUDP(_ flow: NEAppProxyUDPFlow) {
        flow.open(withLocalEndpoint: nil) { [weak self] error in
            guard error == nil, let self else { return }
            self.readUDPLoop(flow)
        }
    }

    private func readUDPLoop(_ flow: NEAppProxyUDPFlow) {
        flow.readDatagrams { [weak self] datagrams, endpoints, error in
            guard let self, error == nil,
                  let datagrams, let endpoints else { return }
            Task {
                for (datagram, endpoint) in zip(datagrams, endpoints) {
                    let response = await self.relayOne(datagram)
                    if let response {
                        // Write errors are transient per-flow; the
                        // resolver will retry at its own layer.
                        try? await flow.writeDatagrams(
                            [response], sentBy: [endpoint])
                    }
                }
                self.readUDPLoop(flow)
            }
        }
    }

    private func handleTCP(_ flow: NEAppProxyTCPFlow) {
        flow.open(withLocalEndpoint: nil) { [weak self] error in
            guard error == nil, let self else { return }
            Task { await self.readTCPLoop(flow) }
        }
    }

    /// RFC 1035 4.2.2: TCP-carried DNS messages are prefixed with a
    /// two-byte length. Reads are best-effort framed; malformed or
    /// truncated framing closes the flow (fail closed).
    private func readTCPLoop(_ flow: NEAppProxyTCPFlow) async {
        do {
            while true {
                let prefix = try await readExact(flow, count: 2)
                let length = (Int(prefix[0]) << 8) | Int(prefix[1])
                guard length > 0,
                      length <= DNSProxyRelay.maximumQueryBytes else {
                    flow.closeReadWithError(nil)
                    flow.closeWriteWithError(nil)
                    return
                }
                let query = try await readExact(flow, count: length)
                if let answer = await relayOne(query) {
                    var framed = Data()
                    framed.append(UInt8((answer.count >> 8) & 0xFF))
                    framed.append(UInt8(answer.count & 0xFF))
                    framed.append(answer)
                    try await flow.write(framed)
                }
            }
        } catch {
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
        }
    }

    private func readExact(_ flow: NEAppProxyTCPFlow,
                           count: Int) async throws -> Data {
        var collected = Data()
        while collected.count < count {
            let chunk = try await readTCPChunk(flow)
            guard let chunk, !chunk.isEmpty else {
                throw NSError(domain: "com.kosherguard.dnsproxy", code: 3)
            }
            collected.append(chunk)
        }
        return collected
    }

    /// The iOS SDK exposes NEAppProxyTCPFlow.readData only in its
    /// completion-handler form (there is no async variant), so bridge
    /// it to async/await with a checked continuation. The system calls
    /// the completion handler exactly once per read request, and the
    /// if/else below resumes the continuation exactly once on that
    /// single callback: throwing on error, otherwise returning the
    /// data (nil at end-of-stream). Errors and EOF propagate to
    /// readExact/readTCPLoop, which close the flow (fail closed),
    /// unchanged from the previous behavior.
    private func readTCPChunk(
        _ flow: NEAppProxyTCPFlow
    ) async throws -> Data? {
        try await withCheckedThrowingContinuation {
            (continuation: CheckedContinuation<Data?, Error>) in
            flow.readData { data, error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: data)
                }
            }
        }
    }

    /// One query through the authenticated DoH path. Any failure is a
    /// SERVFAIL to the client (DNSProxyRelay), never a fallback.
    private func relayOne(_ query: Data) async -> Data? {
        guard let dohClient, let tokenProvider else { return nil }
        return await DNSProxyRelay.relay(query: query) { wire in
            let token = try await tokenProvider.currentToken()
            return try await dohClient.resolve(
                queryMessage: wire,
                credential: ScopedCredentialToken(token))
        }
    }
}

// STATUS: portable logic compiled and XCTested on Linux with the real
// Swift toolchain (tools/run-swift-portable-tests.sh). The Apple-system
// integration that consumes these values is UNVERIFIED (no Apple SDK) -
// see ios/README.md.
import Foundation

/// Apple's documented URL Filter prefilter construction (iOS 26
/// NEURLFilterPrefilter; developer.apple.com
/// NEURLFilterControlProvider fetchPrefilter(existingPrefilterTag:)
/// discussion, read 2026-11-17):
///
///     h1(x) = FNV-1a 32-bit(x)
///     h2(x) = MurmurHash3 32-bit(x, seed: murmurSeed)
///     hashes[i] = (h1(x) + i * h2(x)) mod bitCount   for i in 0..<hashCount
///
/// The dataset builder (url-filter-server/app/apple_prefilter.py) uses
/// the same functions; tools/apple-prefilter-vectors.json pins both
/// platforms to byte-identical output. FNV-1a and MurmurHash3 are
/// standard, published, non-cryptographic hashes; the bit array is a
/// probabilistic index, not a security boundary.
enum ApplePrefilterHash {
    static let fnv1a32Offset: UInt32 = 2166136261
    static let fnv1a32Prime: UInt32 = 16777619

    static func fnv1a32(_ data: [UInt8]) -> UInt32 {
        var h = fnv1a32Offset
        for byte in data {
            h ^= UInt32(byte)
            h = h &* fnv1a32Prime
        }
        return h
    }

    /// MurmurHash3 x86 32-bit, the standard reference algorithm.
    static func murmur3_32(_ data: [UInt8], seed: UInt32) -> UInt32 {
        let c1: UInt32 = 0xCC9E2D51
        let c2: UInt32 = 0x1B873593
        var h = seed
        let nblocks = data.count / 4
        for i in 0..<nblocks {
            let base = i * 4
            var k = UInt32(data[base])
                | UInt32(data[base + 1]) << 8
                | UInt32(data[base + 2]) << 16
                | UInt32(data[base + 3]) << 24
            k = k &* c1
            k = (k << 15) | (k >> 17)
            k = k &* c2
            h ^= k
            h = (h << 13) | (h >> 19)
            h = h &* 5 &+ 0xE6546B64
        }
        var k: UInt32 = 0
        let tail = data.count - nblocks * 4
        if tail >= 3 { k ^= UInt32(data[nblocks * 4 + 2]) << 16 }
        if tail >= 2 { k ^= UInt32(data[nblocks * 4 + 1]) << 8 }
        if tail >= 1 {
            k ^= UInt32(data[nblocks * 4])
            k = k &* c1
            k = (k << 15) | (k >> 17)
            k = k &* c2
            h ^= k
        }
        h ^= UInt32(data.count)
        h ^= h >> 16
        h = h &* 0x85EBCA6B
        h ^= h >> 13
        h = h &* 0xC2B2AE35
        h ^= h >> 16
        return h
    }

    /// The probe positions the system tests for an entry that is
    /// already Punycoded ASCII.
    static func positions(punycodeASCII raw: [UInt8], bitCount: Int,
                          hashCount: Int, murmurSeed: UInt32) -> [Int] {
        let h1 = fnv1a32(raw)
        let h2 = murmur3_32(raw, seed: murmurSeed)
        return (0..<hashCount).map { i in
            Int((UInt64(h1) + UInt64(i) * UInt64(h2)) % UInt64(bitCount))
        }
    }
}

/// Minimal RFC 3492 Punycode encoding for domain labels.
///
/// Scope note: Apple's prefilter documentation requires URLs to be
/// "already Punycoded". Dataset entries are normalized domains (or
/// host/path strings) lowercased at ingestion. This encoder covers
/// per-label IDNA-compatible Punycode for lowercased input WITHOUT
/// full nameprep/STD3 processing - the Python builder applies the same
/// scope via the "idna" codec, and the cross-language vectors pin the
/// agreement. Non-ASCII input outside a domain-label context is
/// rejected, never silently mangled.
enum Punycode {
    enum PunycodeError: Error {
        case nonASCIIPath
        case invalidLabel
    }

    /// Encode one already-lowercased domain (or host/path) string.
    static func encode(_ entry: String) throws -> String {
        var text = entry.trimmingCharacters(in: .whitespaces).lowercased()
        while text.hasSuffix(".") { text.removeLast() }
        guard !text.isEmpty else { throw PunycodeError.invalidLabel }
        let slash = text.firstIndex(of: "/")
        let host = slash.map { String(text[..<$0]) } ?? text
        let path = slash.map { String(text[$0...]) } ?? ""
        if !path.isEmpty && !path.allSatisfy({ $0.isASCII }) {
            throw PunycodeError.nonASCIIPath
        }
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        let encoded = try labels.map { try encodeLabel(String($0)) }
        return encoded.joined(separator: ".") + path
    }

    private static func encodeLabel(_ label: String) throws -> String {
        if label.isEmpty { throw PunycodeError.invalidLabel }
        if label.allSatisfy({ $0.isASCII }) { return label }
        // RFC 3492 parameters.
        // RFC 3492 constants; skew/damp are not used here (only
        // in adapt(), which declares its own copies).
        let base = 36, tmin = 1, tmax = 26
        let initialBias = 72, initialN = 128
        var output: [UInt8] = []
        for scalar in label.unicodeScalars where scalar.isASCII {
            output.append(UInt8(scalar.value))
        }
        let basicCount = output.count
        if basicCount > 0 { output.append(UInt8(45)) } // "-" delimiter
        var h = basicCount
        var n = initialN, delta = 0, bias = initialBias
        let scalars = label.unicodeScalars.map { Int($0.value) }
        while h < scalars.count {
            guard let m = scalars.filter({ $0 >= n }).min() else { break }
            delta += (m - n) * (h + 1)
            n = m
            for c in scalars {
                if c < n { delta += 1 }
                if c == n {
                    var q = delta
                    var k = base
                    while true {
                        let t = k <= bias ? tmin : (k >= bias + tmax ? tmax : k - bias)
                        if q < t { break }
                        output.append(digit(t + (q - t) % (base - t)))
                        q = (q - t) / (base - t)
                        k += base
                    }
                    output.append(digit(q))
                    bias = adapt(delta, h + 1, h == basicCount)
                    delta = 0
                    h += 1
                }
            }
            delta += 1
            n += 1
        }
        return "xn--" + String(bytes: output, encoding: .ascii)!
    }

    private static func digit(_ d: Int) -> UInt8 {
        d < 26 ? UInt8(97 + d) : UInt8(48 + d - 26)
    }

    private static func adapt(_ deltaIn: Int, _ numpoints: Int,
                              _ firsttime: Bool) -> Int {
        let base = 36, tmin = 1, tmax = 26, skew = 38, damp = 700
        var delta = firsttime ? deltaIn / damp : deltaIn / 2
        delta += delta / numpoints
        var k = 0
        while delta > ((base - tmin) * tmax) / 2 {
            delta /= base - tmin
            k += base
        }
        return k + (base - tmin + 1) * delta / (delta + skew)
    }
}

/// A validated Apple-format prefilter parameter set, parsed from the
/// dataset manifest the device downloaded. Every parameter the system
/// call needs is validated here; invalid or legacy-format manifests
/// fail closed (no prefilter handed to the system at all).
struct ApplePrefilterParameters: Equatable {
    static let expectedFormat = "apple-fnv1a-murmur3-doublehash-v1"

    let format: String
    let bitCount: Int
    let hashCount: Int
    let murmurSeed: UInt32
    let byteCount: Int
    let sha256: String

    enum ValidationError: Error, Equatable {
        case wrongFormat(String)
        case invalidParameters(String)
    }

    init(format: String, bitCount: Int, hashCount: Int,
         murmurSeed: UInt32, byteCount: Int,
         sha256: String) throws {
        guard format == Self.expectedFormat else {
            throw ValidationError.wrongFormat(format)
        }
        guard bitCount >= 8, bitCount <= 512 * 1024 * 1024 else {
            throw ValidationError.invalidParameters("bit_count out of range")
        }
        guard hashCount >= 1, hashCount <= 64 else {
            throw ValidationError.invalidParameters("hash_count out of range")
        }
        // byteCount must be exactly the bytes needed for bitCount bits.
        guard byteCount == (bitCount + 7) / 8 else {
            throw ValidationError.invalidParameters(
                "bytes does not match bit_count")
        }
        guard sha256.count == 64,
              sha256.allSatisfy({ $0.isHexDigit }) else {
            throw ValidationError.invalidParameters("sha256 malformed")
        }
        self.format = format
        self.bitCount = bitCount
        self.hashCount = hashCount
        self.murmurSeed = murmurSeed
        self.byteCount = byteCount
        self.sha256 = sha256.lowercased()
    }
}

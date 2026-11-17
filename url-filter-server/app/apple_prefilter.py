"""Apple URL Filter prefilter construction (iOS 26 NEURLFilterPrefilter).

Builds the Bloom prefilter with the EXACT construction Apple documents
for the URL Filter API (developer.apple.com NEURLFilterControlProvider
fetchPrefilter(existingPrefilterTag:) discussion, read 2026-11-17):

    h1(x) = FNV-1a 32-bit(x)
    h2(x) = MurmurHash3 32-bit(x, seed=murmurSeed)
    hashes[i] = (h1(x) + i * h2(x)) mod bitCount      for i in 0..<hashCount

For composition, set the bits at hashes[] to 1; membership tests verify
all those bits are 1. Sizing, per the same page:

    bitCount  = -n * ln(p) / (ln(2) ^ 2)
    hashCount = (bitCount / n) * ln(2)

All URLs must already be Punycoded before constructing the filter
(same page). FNV-1a and MurmurHash3 are standard, published,
non-cryptographic hash functions; nothing here is invented
cryptography. The bit array is a probabilistic index, not a security
boundary - final verdicts come from the off-device PIR database.

Cross-language exactness is enforced by tools/apple-prefilter-vectors.json:
the Swift URLFilter prefilter code computes the same functions over the
same vectors and the tests require byte-identical bit arrays.
"""

from __future__ import annotations

import hashlib
import math

FNV1A32_OFFSET = 2166136261
FNV1A32_PRIME = 16777619

# The published seed KosherGuard uses for every dataset build. It is
# NOT a secret: the prefilter is distributed to every device by design,
# so its parameters are public to all clients. The manifest carries it
# and the device passes it back to the system verbatim.
KOSHERGUARD_MURMUR_SEED = 0x4B470001

FORMAT_ID = "apple-fnv1a-murmur3-doublehash-v1"


def fnv1a32(data: bytes) -> int:
    """32-bit FNV-1a."""
    h = FNV1A32_OFFSET
    for byte in data:
        h ^= byte
        h = (h * FNV1A32_PRIME) & 0xFFFFFFFF
    return h


def murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86 32-bit, the standard reference algorithm."""
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    h = seed & 0xFFFFFFFF
    nblocks = len(data) // 4
    for i in range(nblocks):
        k = int.from_bytes(data[4 * i:4 * i + 4], "little")
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[4 * nblocks:]
    k = 0
    if len(tail) >= 3:
        k ^= tail[2] << 16
    if len(tail) >= 2:
        k ^= tail[1] << 8
    if len(tail) >= 1:
        k ^= tail[0]
        k = (k * c1) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * c2) & 0xFFFFFFFF
        h ^= k
    h ^= len(data)
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & 0xFFFFFFFF
    h ^= h >> 16
    return h


def to_punycode(entry: str) -> str:
    """Punycode the host portion of a dataset entry (Apple requires
    Punycoded URLs before construction).

    Entries are normalized domains or host/path strings (see
    pir_export.normalize_keyword). The host portion is IDNA-encoded
    label by label; an optional path is left untouched and must already
    be ASCII, since percent-encoding is a transport concern handled
    before dataset ingestion.
    """
    if not entry or not entry.strip():
        raise ValueError("empty dataset entry")
    text = entry.strip().lower().rstrip(".")
    host, sep, rest = text.partition("/")
    ascii_host = host.encode("idna").decode("ascii")
    if sep and rest:
        rest.encode("ascii")  # raises on non-ASCII path
        return f"{ascii_host}/{rest}"
    return ascii_host


class ApplePrefilter:
    """A Bloom prefilter in Apple's documented URL Filter format."""

    def __init__(self, item_count: int, fp_rate: float = 0.001,
                 murmur_seed: int = KOSHERGUARD_MURMUR_SEED) -> None:
        if item_count <= 0:
            raise ValueError("item_count must be positive")
        if not (0 < fp_rate < 1):
            raise ValueError("fp_rate must be in (0, 1)")
        if not (0 <= murmur_seed <= 0xFFFFFFFF):
            raise ValueError("murmur_seed must be a uint32")
        self.capacity = item_count
        self.fp_rate = fp_rate
        self.murmur_seed = murmur_seed
        self.bit_count = max(8, math.ceil(
            -item_count * math.log(fp_rate) / (math.log(2) ** 2)))
        self.hash_count = max(1, round(
            self.bit_count / item_count * math.log(2)))
        self.bits = bytearray((self.bit_count + 7) // 8)

    def positions(self, entry: str):
        """The probe positions Apple's system will test for `entry`.

        The entry is Punycoded first, matching Apple's documented
        requirement, so callers never have to remember that step.
        """
        raw = to_punycode(entry).encode("ascii")
        h1 = fnv1a32(raw)
        h2 = murmur3_32(raw, self.murmur_seed)
        m = self.bit_count
        for i in range(self.hash_count):
            yield (h1 + i * h2) % m

    def add(self, entry: str) -> None:
        for pos in self.positions(entry):
            self.bits[pos // 8] |= 1 << (pos % 8)

    def might_contain(self, entry: str) -> bool:
        return all(self.bits[pos // 8] >> (pos % 8) & 1
                   for pos in self.positions(entry))

    def to_bytes(self) -> bytes:
        return bytes(self.bits)

    def tag(self) -> str:
        """The prefilter tag handed to the system (SHA-256 of the exact
        bytes; Apple suggests 'such as the SHA-256 hash of the Bloom
        filter data')."""
        return hashlib.sha256(self.to_bytes()).hexdigest()

    @classmethod
    def from_bytes(cls, data: bytes, item_count: int,
                   fp_rate: float = 0.001,
                   murmur_seed: int = KOSHERGUARD_MURMUR_SEED
                   ) -> "ApplePrefilter":
        pf = cls(item_count, fp_rate, murmur_seed)
        expected = (pf.bit_count + 7) // 8
        if len(data) != expected:
            raise ValueError(
                f"bit array size mismatch: got {len(data)}, "
                f"expected {expected}")
        pf.bits = bytearray(data)
        return pf

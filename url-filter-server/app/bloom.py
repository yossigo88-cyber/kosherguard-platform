"""Bloom prefilter for the URL-filter dataset.

Apple's iOS 26 URL Filter architecture: the app/extension keeps a
local Bloom prefilter (built from the vendor's URL dataset); only
prefilter hits go to the off-device PIR database for a verdict
(WWDC25 session 234, per docs/GENTECH_TECHNICAL_INVESTIGATION.md
section 5.4). Apple ships its own Bloom filter tool for the exact
on-device format; this module builds the dataset-side bit array with
the standard Bloom construction (bit array + k double-hashed probes)
so sizing, membership semantics, and the false-positive budget are
settled and tested here. Final on-device serialization to Apple's
format happens with Apple's tool when the dataset ships.

A Bloom filter never has false negatives for inserted items; its
false-positive rate is a sizing function we verify empirically in
tests. Hashing uses SHA-256 double hashing (a standard construction,
not invented cryptography; this is a probabilistic index, not a
security boundary).
"""

from __future__ import annotations

import hashlib
import math


def _probes(item: bytes, k: int, m: int):
    h1 = int.from_bytes(hashlib.sha256(b"a" + item).digest()[:8], "big")
    h2 = int.from_bytes(hashlib.sha256(b"b" + item).digest()[:8], "big") or 1
    for i in range(k):
        yield (h1 + i * h2) % m


class BloomFilter:
    def __init__(self, capacity: int, fp_rate: float = 0.001) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        if not (0 < fp_rate < 1):
            raise ValueError("fp_rate must be in (0, 1)")
        self.capacity = capacity
        self.fp_rate = fp_rate
        self.m = max(8, math.ceil(-capacity * math.log(fp_rate)
                                / (math.log(2) ** 2)))
        self.k = max(1, round(self.m / capacity * math.log(2)))
        self.bits = bytearray((self.m + 7) // 8)

    def add(self, item: str) -> None:
        raw = item.encode()
        for pos in _probes(raw, self.k, self.m):
            self.bits[pos // 8] |= 1 << (pos % 8)

    def __contains__(self, item: str) -> bool:
        raw = item.encode()
        return all(self.bits[pos // 8] >> (pos % 8) & 1
                   for pos in _probes(raw, self.k, self.m))

    def to_bytes(self) -> bytes:
        return bytes(self.bits)

    @classmethod
    def from_bytes(cls, data: bytes, capacity: int,
                   fp_rate: float = 0.001) -> "BloomFilter":
        bf = cls(capacity, fp_rate)
        expected = (bf.m + 7) // 8
        if len(data) != expected:
            raise ValueError(
                f"bit array size mismatch: got {len(data)}, "
                f"expected {expected}")
        bf.bits = bytearray(data)
        return bf

"""Generate tools/apple-prefilter-vectors.json.

The Swift portable tests and the Python tests both verify against this
file, so the iOS code and the dataset builder compute byte-identical
Bloom prefilters (Apple's documented FNV-1a + MurmurHash3 double-hash
construction). Regenerate with:

    python3 tools/gen-apple-prefilter-vectors.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..",
                                "url-filter-server"))

from app.apple_prefilter import (KOSHERGUARD_MURMUR_SEED, ApplePrefilter,
                                 fnv1a32, murmur3_32, to_punycode)

HASH_INPUTS = ["", "a", "foo", "hello world", "abcd", "abcde",
               "bet365.com", "xn--bcher-kva.de",
               "sub.domain.example.co.uk"]
SEEDS = [0, 1, 7, 42, KOSHERGUARD_MURMUR_SEED]

BLOOM_ITEMS = ["bet365.com", "porn.example", "gambling-site.net",
               "bücher.de", "münchen.example/path"]
BLOOM_CAPACITY = 32
BLOOM_FP = 0.01


def main():
    out = {
        "fnv1a32": {s: fnv1a32(s.encode()) for s in HASH_INPUTS},
        "murmur3_32": {s: {str(seed): murmur3_32(s.encode(), seed)
                           for seed in SEEDS}
                       for s in HASH_INPUTS},
        "punycode": {raw: to_punycode(raw)
                     for raw in ["Example.COM.", "bücher.de",
                                 "münchen.example/path"]},
    }
    pf = ApplePrefilter(BLOOM_CAPACITY, BLOOM_FP)
    for item in BLOOM_ITEMS:
        pf.add(item)
    out["bloom"] = {
        "capacity": BLOOM_CAPACITY,
        "fp_rate": BLOOM_FP,
        "murmur_seed": KOSHERGUARD_MURMUR_SEED,
        "bit_count": pf.bit_count,
        "hash_count": pf.hash_count,
        "bytes_hex": pf.to_bytes().hex(),
        "tag": pf.tag(),
        "items": BLOOM_ITEMS,
        "positions": {item: list(pf.positions(item))
                      for item in BLOOM_ITEMS},
        "absent": ["wikipedia.org", "clean.example"],
    }
    dest = os.path.join(os.path.dirname(__file__),
                        "apple-prefilter-vectors.json")
    with open(dest, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"wrote {dest}")


if __name__ == "__main__":
    main()

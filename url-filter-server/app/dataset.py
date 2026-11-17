"""URL-filter dataset builder.

Builds the versioned URL dataset from the category pipeline's output
plus explicit URL rules: every blocked URL/domain goes into the Bloom
prefilter; the full verdict map is sharded for off-device lookup.
Shards are content-addressed so a PIR layer (Apple's container tool in
deployment) can serve fixed-size chunks without the server learning
which shard a device asked for.

Privacy boundary (investigation 5.4): per Apple's design the vendor
cannot see which URLs were checked; per-device browsing reporting is
impossible by design. This service therefore has no per-device logging
of queries - and none may be added without contradicting the product's
privacy model.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from .apple_prefilter import FORMAT_ID, KOSHERGUARD_MURMUR_SEED, ApplePrefilter

SHARD_SIZE = 4096


@dataclass
class URLRule:
    url: str
    verdict: str  # "block" | "allow"
    category: str = ""


@dataclass
class Dataset:
    version: int
    rules: list[URLRule] = field(default_factory=list)
    prefilter: ApplePrefilter | None = None
    shards: list[bytes] = field(default_factory=list)
    manifest: dict = field(default_factory=dict)


def build_dataset(rules: list[URLRule], version: int,
                  fp_rate: float = 0.001,
                  provenance: str = "",
                  murmur_seed: int = KOSHERGUARD_MURMUR_SEED) -> Dataset:
    """Build a complete dataset: prefilter + verdict shards + manifest.

    Block rules populate the prefilter (they are what the on-device
    filter must catch); allow rules are recorded in the verdict shards
    so the off-device service can return an explicit allow for a
    prefilter hit that is actually excepted (Bloom false positives and
    exceptions resolve off-device).

    The prefilter uses Apple's documented URL Filter construction
    (apple_prefilter.py): FNV-1a 32 + MurmurHash3 32 with double
    hashing, Punycoded entries. The manifest publishes every parameter
    the device needs to hand the system (bit_count, hash_count,
    murmur_seed) plus the format identifier and integrity hash.
    """
    if version < 1:
        raise ValueError("version must be >= 1")
    blocked = [r for r in rules if r.verdict == "block"]
    for r in rules:
        if r.verdict not in ("block", "allow"):
            raise ValueError(f"unknown verdict: {r.verdict!r}")
    prefilter = ApplePrefilter(max(1, len(blocked)), fp_rate,
                               murmur_seed)
    for r in blocked:
        prefilter.add(r.url)

    verdicts = json.dumps(
        {r.url: {"verdict": r.verdict, "category": r.category}
         for r in rules},
        sort_keys=True, separators=(",", ":")).encode()
    shards = [verdicts[i:i + SHARD_SIZE]
              for i in range(0, max(1, len(verdicts)), SHARD_SIZE)]

    manifest = {
        "version": version,
        "rule_count": len(rules),
        "blocked_count": len(blocked),
        "prefilter": {
            "format": FORMAT_ID,
            "bit_count": prefilter.bit_count,
            "hash_count": prefilter.hash_count,
            "murmur_seed": prefilter.murmur_seed,
            "bytes": len(prefilter.to_bytes()),
            "sha256": prefilter.tag(),
            "fp_rate_target": fp_rate,
        },
        "shard_size": SHARD_SIZE,
        "shard_count": len(shards),
        "shards_sha256": [hashlib.sha256(s).hexdigest() for s in shards],
        "provenance": provenance,
    }
    return Dataset(version=version, rules=rules, prefilter=prefilter,
                   shards=shards, manifest=manifest)


def load_categories(path: str) -> list[URLRule]:
    """Convert the pipeline's domains -> categories schema into block rules.

    Validate through the filtering engine, just like category-pipeline/build.py.
    Reject an unrelated schema instead of silently generating an empty dataset.
    """
    import sys
    from pathlib import Path
    engine_src = str(Path(__file__).resolve().parents[2] /
                     "filtering-engine" / "src")
    if engine_src not in sys.path:
        sys.path.insert(0, engine_src)
    from category_db import CategoryDB, CategoryDBError

    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict) or not isinstance(data.get("domains"), dict):
        raise CategoryDBError("category input must contain a domains object")
    validated = CategoryDB(data["domains"]).to_dict()["domains"]
    return [URLRule(url=domain, verdict="block", category=category)
            for domain, categories in validated.items()
            for category in categories]

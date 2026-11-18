#!/usr/bin/env python3
"""Fail if SwiftPM's actual dependency checkouts drifted from the pins.

apple/pir-service-example @ bbb215355b87be40e081756d072f29cd8f9f000b
pins every dependency revision in its Package.resolved - including
swift-homomorphic-encryption on the release/1.1 BRANCH. A branch pin
can silently move if SwiftPM re-resolves, so this script compares the
pinned revisions with the revisions SwiftPM actually checked out
(.build/workspace-state.json) and exits nonzero on any mismatch.

Usage: verify_pins.py Package.resolved .build/workspace-state.json
"""

import json
import sys


def load_pins(path):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    # Package.resolved: {"pins": [...]} (v2/v3)
    # workspace-state.json: {"object": {"pins": [...]}} (v5/v6) or flat
    if "pins" in data:
        return data["pins"]
    return data.get("object", {}).get("pins", [])


def main() -> None:
    expected_path, actual_path = sys.argv[1], sys.argv[2]
    expected = {p["identity"]: p.get("state", {})
                for p in load_pins(expected_path)}
    actual = {p.get("packageRef", {}).get("identity") or p.get("identity"):
              p.get("state", {}) for p in load_pins(actual_path)}
    failures = []
    for identity, state in sorted(expected.items()):
        want = state.get("revision")
        got = actual.get(identity, {}).get("revision")
        status = "OK      " if want == got else "MISMATCH"
        print(f"{status} {identity}: resolved={want} checked-out={got}")
        if want != got:
            failures.append(identity)
    if failures:
        print(
            f"PIN MISMATCH: {failures} - actual dependency checkouts "
            "differ from the pinned Package.resolved; build evidence "
            "would not be for the pinned sources.",
            file=sys.stderr)
        sys.exit(1)
    print(f"all {len(expected)} dependency pins verified")


if __name__ == "__main__":
    main()

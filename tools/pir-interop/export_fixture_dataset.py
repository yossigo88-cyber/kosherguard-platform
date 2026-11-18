#!/usr/bin/env python3
"""Deterministic KosherGuard DEVICE PIR fixture via the REAL exporter.

Uses the production device export path
(url-filter-server/app/pir_export.py: export_device_textpb) with a
fixed rule set so the CI round trip
(.github/workflows/pir-local-interop.yml) can assert exact
presence/absence through Apple's PIR tooling under Apple's NEURLFilter
data format (NEURLFilterDataFormat.md in the pinned
apple/pir-service-example): a keyword PRESENT in the dataset is BLOCKED
on device; the value is Apple's ignored placeholder "1".

  present : blocked-example.com     -> "1"
            ADS-tracker.EXAMPLE     -> "1" (exporter lowercases;
            asserts normalization survives the whole Apple pipeline)
  absent  : allowed-example.com     - allow-only rule, never exported
            precedence-example.com  - BOTH a category block and an
            explicit allow: allow wins (the engine's
            explicit-allow-beats-block order), so the host is EXCLUDED;
            presence would block an explicitly allowed site
            not-in-dataset.example  - never exported
  update  : --update appends newly-blocked.example -> "1" so the
            dataset-update path is re-processed and re-queried.

The generic verdict-string export (export_textpb, "block:<category>"/
"allow" values) remains for non-device consumers; it is NOT a valid
NEURLFilter dataset - see tools/pir-interop/README.md.
"""

import argparse
import os
import sys

sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "..", "url-filter-server"))

from app.dataset import URLRule  # noqa: E402
from app.pir_export import export_device_textpb  # noqa: E402

BASE_RULES = [
    URLRule("blocked-example.com", "block", "gambling"),
    URLRule("ADS-tracker.EXAMPLE", "block", "ads"),
    URLRule("allowed-example.com", "allow", ""),
    # Allow-over-block precedence fixture: the allow must exclude this
    # host from the device dataset entirely.
    URLRule("precedence-example.com", "block", "ads"),
    URLRule("precedence-example.com", "allow", ""),
]
UPDATE_ADDS = [URLRule("newly-blocked.example", "block", "adult")]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, help="output .txtpb path")
    parser.add_argument(
        "--update", action="store_true",
        help="append the update-fixture row (newly-blocked.example)")
    args = parser.parse_args()
    rules = BASE_RULES + (UPDATE_ADDS if args.update else [])
    text = export_device_textpb(rules)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"wrote {len(rules)} rules "
          f"({text.count('rows {')} device rows) to {args.out}")
    print(text)


if __name__ == "__main__":
    main()

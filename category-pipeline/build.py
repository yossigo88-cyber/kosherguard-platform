"""Build the engine categories.json from provenance-tracked sources.

Pipeline: read every sources/*.jsonl file -> validate each record with
the filtering engine's own validators -> check taxonomy membership ->
union categories per domain -> write categories.json in the engine's
storage format with _meta provenance.

Update path: add or edit a sources file, re-run this script, publish the
output through the control plane. The application is never rebuilt.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

_ENGINE_SRC = os.path.join(os.path.dirname(__file__), "..",
                           "filtering-engine", "src")
sys.path.insert(0, os.path.abspath(_ENGINE_SRC))

import category_db  # noqa: E402


class PipelineError(ValueError):
    pass


def load_taxonomy(path: str) -> set[str]:
    with open(path, encoding="utf-8") as fh:
        taxonomy = json.load(fh)
    if not isinstance(taxonomy, dict) or not isinstance(
            taxonomy.get("categories"), dict):
        raise PipelineError(f"{path}: expected an object with 'categories'")
    return set(taxonomy["categories"].keys())


def build(sources_dir: str, taxonomy_path: str) -> dict:
    known = load_taxonomy(taxonomy_path)
    domains: dict[str, set[str]] = {}
    counts: dict[str, int] = {}
    files = sorted(f for f in os.listdir(sources_dir) if f.endswith(".jsonl"))
    if not files:
        raise PipelineError(f"{sources_dir}: no .jsonl sources")
    for name in files:
        source_name = name[:-len(".jsonl")]
        path = os.path.join(sources_dir, name)
        with open(path, encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                where = f"{name}:{lineno}"
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise PipelineError(f"{where}: invalid JSON: {exc}")
                if not isinstance(record, dict):
                    raise PipelineError(f"{where}: record must be an object")
                src = record.get("source")
                if src != source_name:
                    raise PipelineError(
                        f"{where}: source field {src!r} does not match "
                        f"filename {source_name!r} (provenance mismatch)")
                domain = category_db.validate_domain(record.get("domain"))
                cats = record.get("categories")
                if not isinstance(cats, list) or not cats:
                    raise PipelineError(f"{where}: categories must be a non-empty list")
                validated = set()
                for c in cats:
                    cat = category_db.validate_category(c)
                    if cat not in known:
                        raise PipelineError(
                            f"{where}: category {cat!r} is not in the taxonomy")
                    validated.add(cat)
                domains.setdefault(domain, set()).update(validated)
                counts[source_name] = counts.get(source_name, 0) + 1
    doc = {
        "_meta": {
            "description": "KosherGuard category database",
            "dataset": "SEED DATA - NOT A COMPLETE WEBSITE DATABASE",
            "version": 1,
            "sources": {k: {"records": v} for k, v in sorted(counts.items())},
        },
        "domains": {d: sorted(c) for d, c in sorted(domains.items())},
    }
    # Final proof: the engine's own loader accepts the document.
    category_db.CategoryDB(doc["domains"], meta=doc["_meta"])
    return doc


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", default=os.path.join(
        os.path.dirname(__file__), "sources"))
    parser.add_argument("--taxonomy", default=os.path.join(
        os.path.dirname(__file__), "taxonomy.json"))
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    doc = build(args.sources, args.taxonomy)
    tmp = args.out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, args.out)
    print(f"wrote {args.out}: {len(doc['domains'])} domains from "
          f"{sum(s['records'] for s in doc['_meta']['sources'].values())} records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

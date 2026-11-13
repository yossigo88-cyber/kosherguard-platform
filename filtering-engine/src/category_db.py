"""Website category database for the KosherGuard core filtering engine.

Storage format (JSON):

    {
      "_meta": {
        "description": "...",
        "dataset": "TEST DATA - NOT A COMPLETE WEBSITE DATABASE",
        "version": 1
      },
      "domains": {
        "example.com": ["education", "reference"],
        ...
      }
    }

A domain may belong to several categories. The dataset shipped with this
repository is a small, clearly labeled TEST dataset; it is not a complete
website database and must not be presented as one.

Import format and process (also documented in README.md):

New or updated records are supplied as JSON Lines, one object per line:

    {"domain": "example.org", "categories": ["education", "reference"]}

Import them with:

    python src/category_db.py data/categories.test.json import new_records.jsonl \
        --out data/categories.test.json

The importer validates every record, rejects malformed ones with a line
number, and unions categories when a domain already exists. No proprietary
or unlicensed dataset may be imported; only data we have rights to use.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, Set, Tuple

from policy_engine import normalize_domain

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
CATEGORY_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")


class CategoryDBError(ValueError):
    """Raised when a category database or import record is invalid."""


def validate_domain(domain: str) -> str:
    domain = normalize_domain(domain)
    if not DOMAIN_RE.match(domain):
        raise CategoryDBError(f"invalid domain name: {domain!r}")
    return domain


def validate_category(category: str) -> str:
    category = category.strip().lower()
    if not CATEGORY_RE.match(category):
        raise CategoryDBError(f"invalid category name: {category!r}")
    return category


class CategoryDB:
    """In-memory category lookup over the JSON database file."""

    def __init__(self, domains: Dict[str, Iterable[str]], meta: dict | None = None) -> None:
        self.meta = meta or {}
        self._domains: Dict[str, Set[str]] = {}
        for domain, cats in domains.items():
            d = validate_domain(domain)
            if not isinstance(cats, (list, set, tuple)) or not cats:
                raise CategoryDBError(f"{d}: categories must be a non-empty list")
            validated = {validate_category(c) for c in cats}
            self._domains.setdefault(d, set()).update(validated)

    # -- loading / saving -------------------------------------------------

    @classmethod
    def load(cls, path: str | Path) -> "CategoryDB":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or not isinstance(raw.get("domains"), dict):
            raise CategoryDBError(f"{path}: expected an object with a 'domains' object")
        return cls(raw["domains"], meta=raw.get("_meta", {}))

    def to_dict(self) -> dict:
        return {
            "_meta": self.meta,
            "domains": {d: sorted(c) for d, c in sorted(self._domains.items())},
        }

    def save(self, path: str | Path) -> None:
        Path(path).write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    # -- lookup ------------------------------------------------------------

    def categories_for(self, domain: str) -> Set[str]:
        """Categories of the most specific entry covering `domain`.

        Matching walks up the parent domains (www.sub.example.com ->
        sub.example.com -> example.com) and returns the categories of the
        longest matching entry. If nothing matches, the set is empty.
        """
        domain = normalize_domain(domain)
        labels = domain.split(".")
        for i in range(len(labels) - 1):
            candidate = ".".join(labels[i:])
            if candidate in self._domains:
                return set(self._domains[candidate])
        return set()

    def known_domain_count(self) -> int:
        return len(self._domains)

    # -- import ------------------------------------------------------------

    def merge_records(
        self, records: Iterable[dict]
    ) -> Tuple[int, int]:
        """Merge import records; returns (added_domains, updated_domains)."""
        added = updated = 0
        for i, record in enumerate(records, start=1):
            try:
                domain = validate_domain(str(record["domain"]))
                cats = record["categories"]
                if not isinstance(cats, list) or not cats:
                    raise CategoryDBError("categories must be a non-empty list")
                cats = {validate_category(c) for c in cats}
            except (KeyError, TypeError) as exc:
                raise CategoryDBError(f"import line {i}: malformed record ({exc})") from exc
            except CategoryDBError as exc:
                raise CategoryDBError(f"import line {i}: {exc}") from exc
            if domain in self._domains:
                self._domains[domain] |= cats
                updated += 1
            else:
                self._domains[domain] = cats
                added += 1
        return added, updated


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(description="KosherGuard category database tool")
    parser.add_argument("db", help="path to the category database JSON file")
    sub = parser.add_subparsers(dest="command", required=True)
    imp = sub.add_parser("import", help="import JSON Lines domain/category records")
    imp.add_argument("records", help="path to a .jsonl file of records")
    imp.add_argument("--out", help="where to write the merged database (default: in place)")
    args = parser.parse_args(argv)

    db = CategoryDB.load(args.db)
    if args.command == "import":
        lines = Path(args.records).read_text(encoding="utf-8").splitlines()
        records = []
        for i, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                print(f"import line {i}: invalid JSON: {exc}", file=sys.stderr)
                return 1
        try:
            added, updated = db.merge_records(records)
        except CategoryDBError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        out = args.out or args.db
        db.save(out)
        print(f"imported {len(records)} records: {added} domains added, {updated} updated -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

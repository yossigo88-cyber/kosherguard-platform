"""Validated storage operations for the KosherGuard admin dashboard.

All dashboard data lives in one SQLite database (see db.py). Every
write goes through this module so validation, audit logging, and error
handling stay consistent. Domain and category syntax validation is the
filtering engine's own (imported via engine_bridge), so the dashboard
and the engine can never disagree about what a valid domain is.

Domain-record explicit rule: a domain record may carry an explicit
"allow" or "block" designation. This is stored administrative intent
only. It does NOT change filtering by itself: filtering decisions come
from policies evaluated by the filtering engine's PolicyEngine, whose
rule precedence is documented in filtering-engine and re-used here
unchanged. To make a designation effective, an administrator adds the
domain to a policy's allowlist or blocklist.

Category enable/disable semantics: disabled categories are excluded
from the category database used by the domain-test evaluator, so a
rule against a disabled category has no effect in simulation. The
records are kept and can be re-enabled at any time.

Policy enable/disable semantics: an administrative state shown in the
interface. No policy is applied to any live device or DNS traffic from
this dashboard; there is no device synchronization (that requires Apple
MDM authorization, which does not exist - see docs/MDM_ENROLLMENT_AND_PUSH.md).
"""

from __future__ import annotations

import sqlite3

import db as db_module
from engine_bridge import (
    CategoryDB,
    CategoryDBError,
    PolicyConfigError,
    PolicyEngine,
    validate_category,
    validate_domain,
    validate_policy,
)
from util import utcnow

MAX_NAME_LEN = 80
MAX_DESCRIPTION_LEN = 1000


class StoreError(Exception):
    """A client-facing store error. `status` is the HTTP status code."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _check_text(value, field: str, max_len: int, required: bool = True) -> str:
    if not isinstance(value, str):
        raise StoreError(f"{field} must be a string")
    value = value.strip()
    if required and not value:
        raise StoreError(f"{field} must not be empty")
    if len(value) > max_len:
        raise StoreError(f"{field} must be at most {max_len} characters")
    if any(ord(ch) < 32 for ch in value):
        raise StoreError(f"{field} must not contain control characters")
    return value


def _check_rule(rule, field: str = "rule"):
    if rule is not None and rule not in ("allow", "block"):
        raise StoreError(f"{field} must be 'allow', 'block', or null")
    return rule


class Store:
    def __init__(self, db_path):
        self.db_path = str(db_path)

    def _conn(self) -> sqlite3.Connection:
        return db_module.connect(self.db_path)

    # -- audit ---------------------------------------------------------

    def audit(self, conn: sqlite3.Connection, admin: str, action: str, detail: str = "") -> None:
        conn.execute(
            "INSERT INTO audit_log (admin, action, detail, created_at) VALUES (?, ?, ?, ?)",
            (admin, action, detail[:500], utcnow()),
        )

    def list_audit(self, limit: int = 200) -> list:
        limit = min(max(int(limit), 1), 1000)
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT id, admin, action, detail, created_at FROM audit_log"
                " ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    # -- overview --------------------------------------------------------

    def overview_counts(self) -> dict:
        conn = self._conn()
        try:
            def one(sql):
                return conn.execute(sql).fetchone()[0]

            return {
                "policies": one("SELECT COUNT(*) FROM policies"),
                "enabled_policies": one("SELECT COUNT(*) FROM policies WHERE enabled = 1"),
                "categories": one("SELECT COUNT(*) FROM categories"),
                "enabled_categories": one("SELECT COUNT(*) FROM categories WHERE enabled = 1"),
                "domains": one("SELECT COUNT(*) FROM domains"),
                "audit_events": one("SELECT COUNT(*) FROM audit_log"),
                # No device enrollment exists (Apple MDM prerequisites are
                # missing); this is a real count, not a placeholder.
                "devices": 0,
            }
        finally:
            conn.close()

    # -- categories ------------------------------------------------------

    def list_categories(self, search: str | None = None) -> list:
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT c.name, c.display_name, c.description, c.enabled, c.builtin,"
                " c.created_at, c.updated_at,"
                " (SELECT COUNT(*) FROM domain_categories dc WHERE dc.category = c.name)"
                "   AS domain_count"
                " FROM categories c ORDER BY c.name"
            ).fetchall()
            result = [dict(r) for r in rows]
            if search:
                needle = search.strip().lower()
                result = [
                    r for r in result
                    if needle in r["name"].lower()
                    or needle in r["display_name"].lower()
                    or needle in r["description"].lower()
                ]
            return result
        finally:
            conn.close()

    def get_category(self, conn: sqlite3.Connection, name: str) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM categories WHERE name = ?", (name,)).fetchone()
        if row is None:
            raise StoreError(f"category {name!r} does not exist", 404)
        return row

    def create_category(self, admin: str, data: dict) -> dict:
        try:
            name = validate_category(data.get("name"))
        except CategoryDBError as exc:
            raise StoreError(f"name: {exc}")
        display_name = _check_text(data.get("display_name"), "display_name", MAX_NAME_LEN)
        description = _check_text(data.get("description", ""), "description", MAX_DESCRIPTION_LEN, required=False)
        conn = self._conn()
        try:
            if conn.execute("SELECT 1 FROM categories WHERE name = ?", (name,)).fetchone():
                raise StoreError(f"category {name!r} already exists", 409)
            now = utcnow()
            with conn:
                conn.execute(
                    "INSERT INTO categories (name, display_name, description, enabled, builtin,"
                    " created_at, updated_at) VALUES (?, ?, ?, ?, 0, ?, ?)",
                    (name, display_name, description, 1 if data.get("enabled", True) else 0, now, now),
                )
                self.audit(conn, admin, "category.create", f"created category {name}")
            return dict(self.get_category(conn, name))
        finally:
            conn.close()

    def update_category(self, admin: str, name: str, data: dict) -> dict:
        # The category slug is its identity and is immutable; renaming
        # would silently rewrite domain and policy references.
        display_name = _check_text(data.get("display_name"), "display_name", MAX_NAME_LEN)
        description = _check_text(data.get("description", ""), "description", MAX_DESCRIPTION_LEN, required=False)
        conn = self._conn()
        try:
            self.get_category(conn, name)
            with conn:
                conn.execute(
                    "UPDATE categories SET display_name = ?, description = ?, updated_at = ?"
                    " WHERE name = ?",
                    (display_name, description, utcnow(), name),
                )
                self.audit(conn, admin, "category.update", f"updated category {name}")
            return dict(self.get_category(conn, name))
        finally:
            conn.close()

    def set_category_enabled(self, admin: str, name: str, enabled: bool) -> dict:
        if not isinstance(enabled, bool):
            raise StoreError("enabled must be a boolean")
        conn = self._conn()
        try:
            self.get_category(conn, name)
            with conn:
                conn.execute(
                    "UPDATE categories SET enabled = ?, updated_at = ? WHERE name = ?",
                    (1 if enabled else 0, utcnow(), name),
                )
                self.audit(
                    conn, admin, "category.enabled",
                    f"{'enabled' if enabled else 'disabled'} category {name}",
                )
            return dict(self.get_category(conn, name))
        finally:
            conn.close()

    # -- domains ---------------------------------------------------------

    def _require_categories_exist(self, conn: sqlite3.Connection, categories: list) -> list:
        if not isinstance(categories, list) or not categories:
            raise StoreError("categories must be a non-empty list")
        validated = []
        for entry in categories:
            try:
                cat = validate_category(entry)
            except CategoryDBError as exc:
                raise StoreError(f"categories: {exc}")
            if not conn.execute("SELECT 1 FROM categories WHERE name = ?", (cat,)).fetchone():
                raise StoreError(f"category {cat!r} does not exist; create it first")
            validated.append(cat)
        return sorted(set(validated))

    def _domain_dict(self, conn: sqlite3.Connection, row: sqlite3.Row) -> dict:
        cats = [
            r[0]
            for r in conn.execute(
                "SELECT category FROM domain_categories WHERE domain = ? ORDER BY category",
                (row["domain"],),
            ).fetchall()
        ]
        return {
            "domain": row["domain"],
            "categories": cats,
            "rule": row["rule"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def list_domains(self, search=None, category=None, rule=None) -> list:
        conn = self._conn()
        try:
            rows = conn.execute("SELECT * FROM domains ORDER BY domain").fetchall()
            result = [self._domain_dict(conn, r) for r in rows]
            if search:
                needle = search.strip().lower()
                result = [d for d in result if needle in d["domain"]]
            if category:
                result = [d for d in result if category in d["categories"]]
            if rule:
                result = [d for d in result if d["rule"] == rule]
            return result
        finally:
            conn.close()

    def get_domain(self, domain: str) -> dict:
        conn = self._conn()
        try:
            row = conn.execute("SELECT * FROM domains WHERE domain = ?", (domain,)).fetchone()
            if row is None:
                raise StoreError(f"domain {domain!r} does not exist", 404)
            return self._domain_dict(conn, row)
        finally:
            conn.close()

    def create_domain(self, admin: str, data: dict) -> dict:
        try:
            domain = validate_domain(data.get("domain"))
        except CategoryDBError as exc:
            raise StoreError(f"domain: {exc}")
        rule = _check_rule(data.get("rule"))
        conn = self._conn()
        try:
            categories = self._require_categories_exist(conn, data.get("categories"))
            if conn.execute("SELECT 1 FROM domains WHERE domain = ?", (domain,)).fetchone():
                raise StoreError(f"domain {domain!r} already exists", 409)
            now = utcnow()
            with conn:
                conn.execute(
                    "INSERT INTO domains (domain, rule, created_at, updated_at) VALUES (?, ?, ?, ?)",
                    (domain, rule, now, now),
                )
                for cat in categories:
                    conn.execute(
                        "INSERT INTO domain_categories (domain, category) VALUES (?, ?)",
                        (domain, cat),
                    )
                self.audit(
                    conn, admin, "domain.create",
                    f"added {domain} to {', '.join(categories)}"
                    + (f" (explicit {rule})" if rule else ""),
                )
            return self.get_domain(domain)
        finally:
            conn.close()

    def update_domain(self, admin: str, domain: str, data: dict) -> dict:
        rule = _check_rule(data.get("rule"))
        conn = self._conn()
        try:
            if not conn.execute("SELECT 1 FROM domains WHERE domain = ?", (domain,)).fetchone():
                raise StoreError(f"domain {domain!r} does not exist", 404)
            categories = self._require_categories_exist(conn, data.get("categories"))
            with conn:
                conn.execute(
                    "UPDATE domains SET rule = ?, updated_at = ? WHERE domain = ?",
                    (rule, utcnow(), domain),
                )
                conn.execute("DELETE FROM domain_categories WHERE domain = ?", (domain,))
                for cat in categories:
                    conn.execute(
                        "INSERT INTO domain_categories (domain, category) VALUES (?, ?)",
                        (domain, cat),
                    )
                self.audit(
                    conn, admin, "domain.update",
                    f"updated {domain}: categories {', '.join(categories)}"
                    + (f", explicit {rule}" if rule else ", no explicit rule"),
                )
        finally:
            conn.close()
        return self.get_domain(domain)

    def delete_domain(self, admin: str, domain: str) -> None:
        conn = self._conn()
        try:
            if not conn.execute("SELECT 1 FROM domains WHERE domain = ?", (domain,)).fetchone():
                raise StoreError(f"domain {domain!r} does not exist", 404)
            with conn:
                conn.execute("DELETE FROM domains WHERE domain = ?", (domain,))
                self.audit(conn, admin, "domain.delete", f"deleted {domain}")
        finally:
            conn.close()

    def import_domains(self, admin: str, records) -> dict:
        """Validated, atomic import of domain/category records.

        Records use the filtering engine's import shape:
        {"domain": "example.org", "categories": ["news"]}. Validation is
        the engine's own CategoryDB.merge_records: every record is
        checked before anything changes, a malformed record aborts the
        whole import with its line number, and categories union onto
        existing domains. On top of the engine's syntax validation, every
        referenced category must already exist in the dashboard, so an
        import can never silently create categories.
        """
        if not isinstance(records, list) or not records:
            raise StoreError("records must be a non-empty list")
        conn = self._conn()
        try:
            current = {
                r["domain"]: set(
                    x[0]
                    for x in conn.execute(
                        "SELECT category FROM domain_categories WHERE domain = ?",
                        (r["domain"],),
                    ).fetchall()
                )
                for r in conn.execute("SELECT domain FROM domains").fetchall()
            }
            try:
                merged_db = CategoryDB(current)
                added, updated = merged_db.merge_records(records)
            except CategoryDBError as exc:
                raise StoreError(str(exc))
            merged = merged_db.to_dict()["domains"]
            missing = sorted(
                {c for cats in merged.values() for c in cats}
                - {r[0] for r in conn.execute("SELECT name FROM categories").fetchall()}
            )
            if missing:
                raise StoreError(
                    f"import references categories that do not exist: {', '.join(missing)}"
                )
            now = utcnow()
            with conn:
                for domain, cats in merged.items():
                    conn.execute(
                        "INSERT INTO domains (domain, rule, created_at, updated_at)"
                        " VALUES (?, NULL, ?, ?)"
                        " ON CONFLICT(domain) DO UPDATE SET updated_at = excluded.updated_at",
                        (domain, now, now),
                    )
                    conn.execute("DELETE FROM domain_categories WHERE domain = ?", (domain,))
                    for cat in cats:
                        conn.execute(
                            "INSERT INTO domain_categories (domain, category) VALUES (?, ?)",
                            (domain, cat),
                        )
                self.audit(
                    conn, admin, "domain.import",
                    f"imported {len(records)} records: {added} added, {updated} updated",
                )
            return {"records": len(records), "added": added, "updated": updated}
        finally:
            conn.close()

    # -- policies --------------------------------------------------------

    def _validate_policy_payload(self, data: dict) -> dict:
        """Validate a policy create/update payload; returns normalized fields."""
        name = _check_text(data.get("name"), "name", MAX_NAME_LEN)
        description = _check_text(data.get("description", ""), "description", MAX_DESCRIPTION_LEN, required=False)
        default_policy = data.get("default_policy")
        if default_policy not in ("allow", "block"):
            raise StoreError("default_policy must be 'allow' or 'block'")
        enabled = data.get("enabled", True)
        if not isinstance(enabled, bool):
            raise StoreError("enabled must be a boolean")
        engine_dict = self._engine_dict_from_fields(data)
        try:
            normalized = validate_policy(engine_dict)
        except PolicyConfigError as exc:
            raise StoreError(f"invalid policy rules: {exc}")
        # Deduplicate while preserving the engine's normalization; the
        # database primary keys reject duplicate entries.
        engine = {
            "default_policy": normalized["default_policy"],
            "allowlist": sorted(set(normalized["allowlist"])),
            "blocklist": sorted(set(normalized["blocklist"])),
            "category_rules": {
                "allow": sorted(set(normalized["category_allow"])),
                "block": sorted(set(normalized["category_block"])),
            },
        }
        return {
            "name": name,
            "description": description,
            "default_policy": default_policy,
            "enabled": enabled,
            "engine": engine,
        }

    @staticmethod
    def _engine_dict_from_fields(data: dict) -> dict:
        return {
            "default_policy": data.get("default_policy"),
            "allowlist": data.get("allowlist", []),
            "blocklist": data.get("blocklist", []),
            "category_rules": {
                "allow": data.get("category_allow", []),
                "block": data.get("category_block", []),
            },
        }

    def _write_policy_rules(self, conn: sqlite3.Connection, policy_id: int, engine: dict) -> None:
        conn.execute("DELETE FROM policy_domains WHERE policy_id = ?", (policy_id,))
        conn.execute("DELETE FROM policy_categories WHERE policy_id = ?", (policy_id,))
        for domain in engine["allowlist"]:
            conn.execute(
                "INSERT INTO policy_domains (policy_id, domain, rule) VALUES (?, ?, 'allow')",
                (policy_id, domain),
            )
        for domain in engine["blocklist"]:
            conn.execute(
                "INSERT INTO policy_domains (policy_id, domain, rule) VALUES (?, ?, 'block')",
                (policy_id, domain),
            )
        for cat in engine["category_rules"]["allow"]:
            conn.execute(
                "INSERT INTO policy_categories (policy_id, category, rule) VALUES (?, ?, 'allow')",
                (policy_id, cat),
            )
        for cat in engine["category_rules"]["block"]:
            conn.execute(
                "INSERT INTO policy_categories (policy_id, category, rule) VALUES (?, ?, 'block')",
                (policy_id, cat),
            )

    def _policy_dict(self, conn: sqlite3.Connection, row: sqlite3.Row, detail: bool) -> dict:
        result = {
            "id": row["id"],
            "name": row["name"],
            "description": row["description"],
            "default_policy": row["default_policy"],
            "enabled": bool(row["enabled"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
        domain_rows = conn.execute(
            "SELECT domain, rule FROM policy_domains WHERE policy_id = ? ORDER BY domain",
            (row["id"],),
        ).fetchall()
        cat_rows = conn.execute(
            "SELECT category, rule FROM policy_categories WHERE policy_id = ? ORDER BY category",
            (row["id"],),
        ).fetchall()
        result["allowlist"] = [r["domain"] for r in domain_rows if r["rule"] == "allow"]
        result["blocklist"] = [r["domain"] for r in domain_rows if r["rule"] == "block"]
        result["category_allow"] = [r["category"] for r in cat_rows if r["rule"] == "allow"]
        result["category_block"] = [r["category"] for r in cat_rows if r["rule"] == "block"]
        if not detail:
            result["rule_count"] = len(domain_rows) + len(cat_rows)
        return result

    def list_policies(self, search=None, enabled=None) -> list:
        conn = self._conn()
        try:
            rows = conn.execute("SELECT * FROM policies ORDER BY name").fetchall()
            result = [self._policy_dict(conn, r, detail=False) for r in rows]
            if search:
                needle = search.strip().lower()
                result = [
                    p for p in result
                    if needle in p["name"].lower() or needle in p["description"].lower()
                ]
            if enabled is not None:
                result = [p for p in result if p["enabled"] is enabled]
            return result
        finally:
            conn.close()

    def get_policy(self, policy_id: int) -> dict:
        conn = self._conn()
        try:
            row = conn.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
            if row is None:
                raise StoreError(f"policy {policy_id} does not exist", 404)
            return self._policy_dict(conn, row, detail=True)
        finally:
            conn.close()

    def create_policy(self, admin: str, data: dict) -> dict:
        fields = self._validate_policy_payload(data)
        conn = self._conn()
        try:
            if conn.execute("SELECT 1 FROM policies WHERE name = ?", (fields["name"],)).fetchone():
                raise StoreError(f"policy named {fields['name']!r} already exists", 409)
            now = utcnow()
            with conn:
                cur = conn.execute(
                    "INSERT INTO policies (name, description, default_policy, enabled,"
                    " created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        fields["name"], fields["description"], fields["default_policy"],
                        1 if fields["enabled"] else 0, now, now,
                    ),
                )
                policy_id = cur.lastrowid
                self._write_policy_rules(conn, policy_id, fields["engine"])
                self.audit(conn, admin, "policy.create", f"created policy {fields['name']!r}")
            return self.get_policy(policy_id)
        finally:
            conn.close()

    def update_policy(self, admin: str, policy_id: int, data: dict) -> dict:
        fields = self._validate_policy_payload(data)
        conn = self._conn()
        try:
            row = conn.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
            if row is None:
                raise StoreError(f"policy {policy_id} does not exist", 404)
            clash = conn.execute(
                "SELECT 1 FROM policies WHERE name = ? AND id != ?",
                (fields["name"], policy_id),
            ).fetchone()
            if clash:
                raise StoreError(f"policy named {fields['name']!r} already exists", 409)
            with conn:
                conn.execute(
                    "UPDATE policies SET name = ?, description = ?, default_policy = ?,"
                    " enabled = ?, updated_at = ? WHERE id = ?",
                    (
                        fields["name"], fields["description"], fields["default_policy"],
                        1 if fields["enabled"] else 0, utcnow(), policy_id,
                    ),
                )
                self._write_policy_rules(conn, policy_id, fields["engine"])
                self.audit(conn, admin, "policy.update", f"updated policy {fields['name']!r}")
            return self.get_policy(policy_id)
        finally:
            conn.close()

    def set_policy_enabled(self, admin: str, policy_id: int, enabled: bool) -> dict:
        if not isinstance(enabled, bool):
            raise StoreError("enabled must be a boolean")
        conn = self._conn()
        try:
            row = conn.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
            if row is None:
                raise StoreError(f"policy {policy_id} does not exist", 404)
            with conn:
                conn.execute(
                    "UPDATE policies SET enabled = ?, updated_at = ? WHERE id = ?",
                    (1 if enabled else 0, utcnow(), policy_id),
                )
                self.audit(
                    conn, admin, "policy.enabled",
                    f"{'enabled' if enabled else 'disabled'} policy {row['name']!r}",
                )
            return self.get_policy(policy_id)
        finally:
            conn.close()

    def delete_policy(self, admin: str, policy_id: int) -> None:
        conn = self._conn()
        try:
            row = conn.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
            if row is None:
                raise StoreError(f"policy {policy_id} does not exist", 404)
            with conn:
                conn.execute("DELETE FROM policies WHERE id = ?", (policy_id,))
                self.audit(conn, admin, "policy.delete", f"deleted policy {row['name']!r}")
        finally:
            conn.close()

    # -- filtering-engine integration ------------------------------------

    def _evaluation_category_db(self, conn: sqlite3.Connection) -> CategoryDB:
        """The engine's CategoryDB built from this dashboard's records.

        Only enabled categories take part; a domain left with no enabled
        category is excluded (the engine requires non-empty category
        lists).
        """
        mapping = {}
        rows = conn.execute(
            "SELECT dc.domain, dc.category FROM domain_categories dc"
            " JOIN categories c ON c.name = dc.category WHERE c.enabled = 1"
        ).fetchall()
        for row in rows:
            mapping.setdefault(row["domain"], set()).add(row["category"])
        return CategoryDB(mapping)

    def test_domain(self, policy_id: int, domain: str) -> dict:
        """Evaluate a domain under a policy with the real filtering engine.

        Returns the engine's decision unchanged (action, rule, reason,
        category), plus the domain's dashboard record for context. The
        explicit rule on a domain record is administrative intent and is
        NOT part of the engine decision.
        """
        try:
            domain = validate_domain(domain)
        except CategoryDBError as exc:
            raise StoreError(f"domain: {exc}")
        conn = self._conn()
        try:
            row = conn.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
            if row is None:
                raise StoreError(f"policy {policy_id} does not exist", 404)
            policy = self._policy_dict(conn, row, detail=True)
            engine_dict = self._engine_dict_from_fields(policy)
            engine = PolicyEngine(engine_dict, self._evaluation_category_db(conn))
            decision = engine.decide(domain)
            record = conn.execute(
                "SELECT * FROM domains WHERE domain = ?", (domain,)
            ).fetchone()
            result = {
                "domain": domain,
                "policy_id": policy_id,
                "policy_name": policy["name"],
                "action": decision.action,
                "rule": decision.rule,
                "reason": decision.reason,
                "category": decision.category,
                "domain_record": self._domain_dict(conn, record) if record else None,
            }
            return result
        finally:
            conn.close()

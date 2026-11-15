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

Policy enable/disable semantics: an administrative state. Only a
policy that is explicitly SELECTED FOR PUBLICATION and then PUBLISHED
reaches the filtering engine's configuration files, and the running
engine only enforces it after a successful reload (Stage 10). A
dashboard edit by itself changes nothing the engine does. There is
still no device synchronization (that requires Apple MDM
authorization, which does not exist - see docs/MDM_ENROLLMENT_AND_PUSH.md).

Stage 10 additions: immutable policy version snapshots on every policy
mutation (with version-aware rollback), an explicit
selected-for-publication pointer, and complete published-configuration
revisions (policy + category database + content hashes) written to disk
through the generation publisher in publishing.py. Publication and
rollback are audited; historical versions and revisions are never
modified.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager

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
from publishing import Publisher, canonical_json, sha256_bytes
from util import utcnow

MAX_NAME_LEN = 80
MAX_DESCRIPTION_LEN = 1000


@contextmanager
def _write_txn(conn: sqlite3.Connection):
    """One serialized write transaction.

    BEGIN IMMEDIATE takes the database write lock BEFORE any invariant
    check runs, so an invariant check and the mutation it guards are
    atomic against concurrent requests: a check outside the lock could
    pass while another request changes the underlying state (for
    example selecting a policy for publication) before the mutation
    lands. Every mutation that touches the selected-for-publication
    invariant, and the selection write itself, goes through this.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield
    except BaseException:
        conn.rollback()
        raise
    else:
        conn.commit()


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
    def __init__(self, db_path, publish_root=None):
        self.db_path = str(db_path)
        # publish_root: directory the engine configuration generations
        # are published into (see publishing.py). None disables
        # publication entirely; the publish endpoints then fail clearly.
        self.publisher = Publisher(publish_root) if publish_root else None

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
        enabled = data.get("enabled", True)
        if not isinstance(enabled, bool):
            raise StoreError("enabled must be a boolean")
        conn = self._conn()
        try:
            if conn.execute("SELECT 1 FROM categories WHERE name = ?", (name,)).fetchone():
                raise StoreError(f"category {name!r} already exists", 409)
            now = utcnow()
            with conn:
                conn.execute(
                    "INSERT INTO categories (name, display_name, description, enabled, builtin,"
                    " created_at, updated_at) VALUES (?, ?, ?, ?, 0, ?, ?)",
                    (name, display_name, description, 1 if enabled else 0, now, now),
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
        version_row = conn.execute(
            "SELECT MAX(version) FROM policy_versions WHERE policy_id = ?",
            (row["id"],),
        ).fetchone()
        state = self._publication_state(conn)
        result = {
            "id": row["id"],
            "name": row["name"],
            "description": row["description"],
            "default_policy": row["default_policy"],
            "enabled": bool(row["enabled"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "current_version": version_row[0] or 0,
            "selected_for_publication": bool(
                state and state["selected_policy_id"] == row["id"]),
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
                version = self._snapshot_policy_version(conn, admin, policy_id)
                self.audit(
                    conn, admin, "policy.create",
                    f"created policy {fields['name']!r} (version {version})")
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
            with _write_txn(conn):
                # The selected-for-publication invariant is checked
                # under the write lock: an update with enabled=false
                # would disable the policy, so it is refused exactly
                # like an explicit disable.
                if not fields["enabled"]:
                    self._require_not_selected(conn, policy_id, "disable")
                conn.execute(
                    "UPDATE policies SET name = ?, description = ?, default_policy = ?,"
                    " enabled = ?, updated_at = ? WHERE id = ?",
                    (
                        fields["name"], fields["description"], fields["default_policy"],
                        1 if fields["enabled"] else 0, utcnow(), policy_id,
                    ),
                )
                self._write_policy_rules(conn, policy_id, fields["engine"])
                version = self._snapshot_policy_version(conn, admin, policy_id)
                self.audit(
                    conn, admin, "policy.update",
                    f"updated policy {fields['name']!r} (version {version})")
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
            with _write_txn(conn):
                # Checked under the write lock so a concurrent
                # select-for-publication cannot slip between check and
                # mutation.
                if not enabled:
                    self._require_not_selected(conn, policy_id, "disable")
                conn.execute(
                    "UPDATE policies SET enabled = ?, updated_at = ? WHERE id = ?",
                    (1 if enabled else 0, utcnow(), policy_id),
                )
                version = self._snapshot_policy_version(conn, admin, policy_id)
                self.audit(
                    conn, admin, "policy.enabled",
                    f"{'enabled' if enabled else 'disabled'} policy {row['name']!r}"
                    f" (version {version})",
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
            with _write_txn(conn):
                # Checked under the write lock (see set_policy_enabled).
                self._require_not_selected(conn, policy_id, "delete")
                # The final snapshot preserves the complete content of
                # the deleted policy; history survives deletion.
                self._snapshot_policy_version(conn, admin, policy_id, note="policy deleted")
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

    # -- policy versioning (Stage 10) --------------------------------------

    def _snapshot_policy_version(self, conn: sqlite3.Connection, admin: str,
                                 policy_id: int, note: str = "") -> int:
        """Append an immutable snapshot of the policy's complete current
        content. Returns the new version number. Historical rows are
        never updated or deleted; rollback works by ADDING a version.
        """
        row = conn.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
        if row is None:
            raise StoreError(f"policy {policy_id} does not exist", 404)
        policy = self._policy_dict(conn, row, detail=True)
        engine = {
            "default_policy": policy["default_policy"],
            "allowlist": policy["allowlist"],
            "blocklist": policy["blocklist"],
            "category_rules": {
                "allow": policy["category_allow"],
                "block": policy["category_block"],
            },
        }
        version = (policy["current_version"] or 0) + 1
        conn.execute(
            "INSERT INTO policy_versions"
            " (policy_id, version, name, description, default_policy, enabled,"
            "  engine_json, admin, note, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                policy_id, version, policy["name"], policy["description"],
                policy["default_policy"], 1 if policy["enabled"] else 0,
                json.dumps(engine, sort_keys=True), admin, note, utcnow(),
            ),
        )
        return version

    def list_policy_versions(self, policy_id: int) -> list:
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT policy_id, version, name, description, default_policy, enabled,"
                " admin, note, created_at FROM policy_versions"
                " WHERE policy_id = ? ORDER BY version DESC",
                (policy_id,),
            ).fetchall()
            if not rows and not conn.execute(
                    "SELECT 1 FROM policies WHERE id = ?", (policy_id,)).fetchone():
                raise StoreError(f"policy {policy_id} does not exist", 404)
            result = []
            for r in rows:
                d = dict(r)
                d["enabled"] = bool(d["enabled"])
                result.append(d)
            return result
        finally:
            conn.close()

    def get_policy_version(self, policy_id: int, version: int) -> dict:
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT * FROM policy_versions WHERE policy_id = ? AND version = ?",
                (policy_id, version),
            ).fetchone()
            if row is None:
                raise StoreError(
                    f"policy {policy_id} has no version {version}", 404)
            result = dict(row)
            result["enabled"] = bool(result["enabled"])
            engine = json.loads(result.pop("engine_json"))
            result["allowlist"] = engine["allowlist"]
            result["blocklist"] = engine["blocklist"]
            result["category_allow"] = engine["category_rules"]["allow"]
            result["category_block"] = engine["category_rules"]["block"]
            return result
        finally:
            conn.close()

    def rollback_policy(self, admin: str, policy_id: int, version: int) -> dict:
        """Roll a policy back to a historical version.

        Never rewrites history: the version content is copied into the
        live policy and recorded as a NEW version, so the audit trail
        shows exactly what happened and when.
        """
        if not isinstance(version, int) or version < 1:
            raise StoreError("version must be a positive integer")
        conn = self._conn()
        try:
            vrow = conn.execute(
                "SELECT * FROM policy_versions WHERE policy_id = ? AND version = ?",
                (policy_id, version),
            ).fetchone()
            if vrow is None:
                raise StoreError(
                    f"policy {policy_id} has no version {version}", 404)
            if not conn.execute(
                    "SELECT 1 FROM policies WHERE id = ?", (policy_id,)).fetchone():
                raise StoreError(
                    f"policy {policy_id} was deleted; create a new policy from "
                    "the version content instead", 409)
            engine = json.loads(vrow["engine_json"])
            rules = {
                "allowlist": engine["allowlist"],
                "blocklist": engine["blocklist"],
                "category_rules": engine["category_rules"],
            }
            with _write_txn(conn):
                # A rollback that would restore enabled=false disables
                # the policy, so the selected-for-publication invariant
                # applies exactly as it does to an explicit disable;
                # checked under the write lock.
                if not vrow["enabled"]:
                    self._require_not_selected(conn, policy_id, "disable")
                conn.execute(
                    "UPDATE policies SET name = ?, description = ?, default_policy = ?,"
                    " enabled = ?, updated_at = ? WHERE id = ?",
                    (vrow["name"], vrow["description"], vrow["default_policy"],
                     vrow["enabled"], utcnow(), policy_id),
                )
                self._write_policy_rules(conn, policy_id, rules)
                new_version = self._snapshot_policy_version(
                    conn, admin, policy_id, note=f"rollback to version {version}")
                self.audit(
                    conn, admin, "policy.rollback",
                    f"rolled back policy {vrow['name']!r} to version {version}"
                    f" (new version {new_version})")
            result = self.get_policy(policy_id)
            result["rolled_back_to"] = version
            return result
        finally:
            conn.close()

    # -- publication (Stage 10) --------------------------------------------

    @staticmethod
    def _publication_state(conn: sqlite3.Connection):
        return conn.execute(
            "SELECT * FROM publication_state WHERE id = 1").fetchone()

    def _require_not_selected(self, conn: sqlite3.Connection, policy_id: int,
                              verb: str) -> None:
        """Refuse to delete or disable the policy selected for
        publication. Removing it underneath the publication pointer
        would make the next publish ambiguous; the administrator must
        explicitly select a different policy first."""
        state = self._publication_state(conn)
        if state and state["selected_policy_id"] == policy_id:
            raise StoreError(
                f"cannot {verb} the policy selected for publication; "
                "select a different policy for publication first", 409)

    def select_policy_for_publication(self, admin: str, policy_id: int) -> dict:
        """Explicitly designate the policy whose configuration will be
        published to the filtering engine. Selection by itself changes
        nothing the engine does; only an explicit publish does."""
        conn = self._conn()
        try:
            row = conn.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
            if row is None:
                raise StoreError(f"policy {policy_id} does not exist", 404)
            if not row["enabled"]:
                raise StoreError(
                    f"policy {row['name']!r} is disabled; only an enabled policy "
                    "can be selected for publication", 409)
            now = utcnow()
            with _write_txn(conn):
                # Re-read under the write lock: this write is the other
                # side of the selected-policy invariant, so it must be
                # serialized against the checks in update/disable/
                # delete/rollback - and the policy must STILL be
                # enabled when the selection lands.
                current = conn.execute(
                    "SELECT enabled FROM policies WHERE id = ?", (policy_id,)).fetchone()
                if current is None:
                    raise StoreError(f"policy {policy_id} does not exist", 404)
                if not current["enabled"]:
                    raise StoreError(
                        f"policy {row['name']!r} is disabled; only an enabled policy "
                        "can be selected for publication", 409)
                conn.execute(
                    "INSERT INTO publication_state"
                    " (id, selected_policy_id, selected_by, selected_at, active_revision)"
                    " VALUES (1, ?, ?, ?,"
                    "  (SELECT active_revision FROM publication_state WHERE id = 1))"
                    " ON CONFLICT(id) DO UPDATE SET"
                    " selected_policy_id = excluded.selected_policy_id,"
                    " selected_by = excluded.selected_by,"
                    " selected_at = excluded.selected_at",
                    (policy_id, admin, now),
                )
                self.audit(
                    conn, admin, "config.select",
                    f"selected policy {row['name']!r} (id {policy_id}) for publication")
            return self.config_status()
        finally:
            conn.close()

    def _export_documents(self, conn: sqlite3.Connection, policy_row) -> tuple:
        """Build the exact engine configuration documents for a policy:
        the policy JSON and the category-database JSON, validated by the
        engine's own code. The category database contains only enabled
        categories (same rule as the domain-test evaluator)."""
        policy = self._policy_dict(conn, policy_row, detail=True)
        normalized = validate_policy(self._engine_dict_from_fields(policy))
        policy_doc = {
            "default_policy": normalized["default_policy"],
            "allowlist": normalized["allowlist"],
            "blocklist": normalized["blocklist"],
            "category_rules": {
                "allow": normalized["category_allow"],
                "block": normalized["category_block"],
            },
            "_meta": {
                "source": "kosherguard-dashboard",
                "policy_name": policy["name"],
                "policy_id": policy["id"],
                "policy_version": policy["current_version"],
            },
        }
        categories_doc = self._evaluation_category_db(conn).to_dict()
        categories_doc["_meta"] = {
            "description": "Exported from the KosherGuard dashboard; contains only "
                           "enabled categories and their domain assignments.",
            "source": "kosherguard-dashboard",
        }
        return policy_doc, categories_doc, policy

    def _publish_bytes(self, conn, admin: str, policy_bytes: bytes,
                       categories_bytes: bytes, meta: dict, action: str,
                       note: str = "") -> dict:
        """Reserve a revision, publish its generation, and record the
        outcome. Serialized by the publisher's lock; a failure keeps the
        previously published configuration live and marks the revision
        failed. Returns the published revision's public dict."""
        if self.publisher is None:
            raise StoreError(
                "publication is not configured on this server "
                "(no publish directory)", 500)
        with self.publisher.locked():
            with conn:
                cur = conn.execute(
                    "INSERT INTO config_revisions"
                    " (policy_id, policy_name, policy_version, admin, created_at,"
                    "  policy_json, categories_json, policy_sha256, categories_sha256,"
                    "  status, detail)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)",
                    (
                        meta["policy_id"], meta["policy_name"], meta["policy_version"],
                        admin, utcnow(),
                        policy_bytes.decode("utf-8"), categories_bytes.decode("utf-8"),
                        sha256_bytes(policy_bytes), sha256_bytes(categories_bytes),
                        note,
                    ),
                )
                revision = cur.lastrowid
            try:
                generation = self.publisher.publish(
                    revision, policy_bytes, categories_bytes,
                    {
                        "policy_id": meta["policy_id"],
                        "policy_name": meta["policy_name"],
                        "policy_version": meta["policy_version"],
                        "published_by": admin,
                        "published_at": utcnow(),
                        "note": note,
                    })
            except Exception as exc:
                with conn:
                    conn.execute(
                        "UPDATE config_revisions SET status = 'failed', detail = ?"
                        " WHERE revision = ?",
                        (f"{action} failed: {exc}"[:500], revision),
                    )
                    self.audit(
                        conn, admin, f"{action}.failed",
                        f"revision {revision} failed: {exc}")
                raise StoreError(
                    f"publication failed (revision {revision}): {exc}. "
                    "The previously published configuration is unchanged.", 500)
            with conn:
                conn.execute(
                    "UPDATE config_revisions SET status = 'published', generation = ?"
                    " WHERE revision = ?",
                    (generation, revision),
                )
                conn.execute(
                    "INSERT INTO publication_state (id, active_revision) VALUES (1, ?)"
                    " ON CONFLICT(id) DO UPDATE SET active_revision = excluded.active_revision",
                    (revision,),
                )
                self.audit(
                    conn, admin, action,
                    f"published revision {revision} (generation {generation}, "
                    f"policy {meta['policy_name']!r} v{meta['policy_version']}"
                    + (f", {note}" if note else "") + ")")
            return self.get_config_revision(revision, include_content=False)

    def publish_config(self, admin: str) -> dict:
        """Publish the selected policy plus the current domains and
        categories as one validated, atomic engine configuration
        generation."""
        conn = self._conn()
        try:
            state = self._publication_state(conn)
            if not state or state["selected_policy_id"] is None:
                raise StoreError(
                    "no policy is selected for publication; "
                    "select a policy first", 409)
            row = conn.execute(
                "SELECT * FROM policies WHERE id = ?",
                (state["selected_policy_id"],),
            ).fetchone()
            if row is None:
                raise StoreError(
                    "the policy selected for publication no longer exists; "
                    "select a policy first", 409)
            if not row["enabled"]:
                raise StoreError(
                    f"the policy selected for publication ({row['name']!r}) is "
                    "disabled; enable it or select a different policy", 409)
            policy_doc, categories_doc, policy = self._export_documents(conn, row)
            return self._publish_bytes(
                conn, admin,
                canonical_json(policy_doc), canonical_json(categories_doc),
                {"policy_id": policy["id"], "policy_name": policy["name"],
                 "policy_version": policy["current_version"]},
                "config.publish")
        finally:
            conn.close()

    def rollback_config(self, admin: str, revision: int) -> dict:
        """Publish a previous complete configuration as a NEW revision.

        The historical revision is read from its immutable stored
        snapshot and republished unchanged; neither the historical row
        nor its generation is ever modified. The engine reloads the new
        generation exactly like any other publication."""
        if not isinstance(revision, int) or revision < 1:
            raise StoreError("revision must be a positive integer")
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT * FROM config_revisions WHERE revision = ?",
                (revision,),
            ).fetchone()
            if row is None:
                raise StoreError(f"configuration revision {revision} does not exist", 404)
            if row["status"] != "published":
                raise StoreError(
                    f"configuration revision {revision} was never successfully "
                    "published and cannot be rolled back to", 409)
            return self._publish_bytes(
                conn, admin,
                row["policy_json"].encode("utf-8"),
                row["categories_json"].encode("utf-8"),
                {"policy_id": row["policy_id"], "policy_name": row["policy_name"],
                 "policy_version": row["policy_version"]},
                "config.rollback",
                note=f"rollback of revision {revision}")
        finally:
            conn.close()

    @staticmethod
    def _revision_dict(row: sqlite3.Row, include_content: bool) -> dict:
        result = {
            "revision": row["revision"],
            "policy_id": row["policy_id"],
            "policy_name": row["policy_name"],
            "policy_version": row["policy_version"],
            "admin": row["admin"],
            "created_at": row["created_at"],
            "policy_sha256": row["policy_sha256"],
            "categories_sha256": row["categories_sha256"],
            "generation": row["generation"],
            "status": row["status"],
            "detail": row["detail"],
        }
        if include_content:
            result["policy_json"] = json.loads(row["policy_json"])
            result["categories_json"] = json.loads(row["categories_json"])
        return result

    def list_config_revisions(self, limit: int = 100) -> list:
        limit = min(max(int(limit), 1), 1000)
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT * FROM config_revisions ORDER BY revision DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [self._revision_dict(r, include_content=False) for r in rows]
        finally:
            conn.close()

    def get_config_revision(self, revision: int, include_content: bool = True) -> dict:
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT * FROM config_revisions WHERE revision = ?",
                (revision,),
            ).fetchone()
            if row is None:
                raise StoreError(
                    f"configuration revision {revision} does not exist", 404)
            return self._revision_dict(row, include_content)
        finally:
            conn.close()

    def engine_status(self) -> dict | None:
        """The engine's self-reported status, if it shares this
        publication root and writes engine-status.json. None when the
        file is absent or unreadable - reported as unknown, never
        guessed."""
        if self.publisher is None:
            return None
        path = self.publisher.root / "engine-status.json"
        try:
            return json.loads(path.read_text("utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def config_status(self) -> dict:
        """The complete draft-versus-published picture.

        Distinguishes, explicitly: the policy selected for publication,
        the configuration revision most recently published to disk, the
        generation the disk pointer actually references, and what the
        engine reports it is running. Unpublished dashboard edits are
        detected by hashing a fresh in-memory export and comparing it
        with the active revision's recorded content hashes."""
        conn = self._conn()
        try:
            state = self._publication_state(conn)
            selected = None
            if state and state["selected_policy_id"] is not None:
                row = conn.execute(
                    "SELECT * FROM policies WHERE id = ?",
                    (state["selected_policy_id"],),
                ).fetchone()
                if row is not None:
                    policy = self._policy_dict(conn, row, detail=False)
                    selected = {
                        "id": policy["id"],
                        "name": policy["name"],
                        "enabled": policy["enabled"],
                        "current_version": policy["current_version"],
                        "selected_by": state["selected_by"],
                        "selected_at": state["selected_at"],
                    }
                else:
                    selected = {
                        "id": state["selected_policy_id"],
                        "missing": True,
                        "selected_by": state["selected_by"],
                        "selected_at": state["selected_at"],
                    }
            active = None
            if state and state["active_revision"] is not None:
                row = conn.execute(
                    "SELECT * FROM config_revisions WHERE revision = ?",
                    (state["active_revision"],),
                ).fetchone()
                if row is not None:
                    active = self._revision_dict(row, include_content=False)

            unpublished_changes = None  # None = nothing selected to compare
            if selected and not selected.get("missing") and selected["enabled"]:
                policy_row = conn.execute(
                    "SELECT * FROM policies WHERE id = ?", (selected["id"],),
                ).fetchone()
                policy_doc, categories_doc, _ = self._export_documents(conn, policy_row)
                current_hashes = {
                    "policy_sha256": sha256_bytes(canonical_json(policy_doc)),
                    "categories_sha256": sha256_bytes(canonical_json(categories_doc)),
                }
                if active is None:
                    unpublished_changes = True
                else:
                    unpublished_changes = (
                        current_hashes["policy_sha256"] != active["policy_sha256"]
                        or current_hashes["categories_sha256"] != active["categories_sha256"]
                    )

            disk = None
            if self.publisher is not None:
                try:
                    disk = self.publisher.current()
                except Exception as exc:
                    disk = {"error": str(exc)}
            engine = self.engine_status()
            engine_matches = None
            if engine and active:
                engine_matches = (
                    engine.get("policy_sha256") == active["policy_sha256"]
                    and engine.get("categories_sha256") == active["categories_sha256"]
                )
            return {
                "publication_configured": self.publisher is not None,
                "selected_policy": selected,
                "active_revision": active,
                "unpublished_changes": unpublished_changes,
                "disk": disk,
                "engine": engine,
                "engine_matches_active_revision": engine_matches,
            }
        finally:
            conn.close()

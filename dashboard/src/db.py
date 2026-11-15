"""SQLite persistence for the KosherGuard admin dashboard.

One file-based SQLite database holds administrators, sessions,
categories, domain records, policies, policy version history,
publication state, published-configuration revisions, the Stage 11A
device registry (devices, associations, policy assignments), and the
audit log. SQLite needs no server, no account, and no paid service, and it
lives next to the code it serves, which fits a development-stage admin
tool.

A fresh database is created and seeded by init_db(). The seed
categories are the starting catalogue named in the Stage 7
specification; they are labels with zero domains, not a claim that a
complete website database exists.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from util import utcnow

SCHEMA = """
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS categories (
    name TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    builtin INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS domains (
    domain TEXT PRIMARY KEY,
    rule TEXT CHECK (rule IN ('allow', 'block') OR rule IS NULL),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS domain_categories (
    domain TEXT NOT NULL REFERENCES domains(domain) ON DELETE CASCADE,
    category TEXT NOT NULL REFERENCES categories(name),
    PRIMARY KEY (domain, category)
);

CREATE TABLE IF NOT EXISTS policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    default_policy TEXT NOT NULL CHECK (default_policy IN ('allow', 'block')),
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_domains (
    policy_id INTEGER NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    domain TEXT NOT NULL,
    rule TEXT NOT NULL CHECK (rule IN ('allow', 'block')),
    PRIMARY KEY (policy_id, domain)
);

CREATE TABLE IF NOT EXISTS policy_categories (
    policy_id INTEGER NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    category TEXT NOT NULL,
    rule TEXT NOT NULL CHECK (rule IN ('allow', 'block')),
    PRIMARY KEY (policy_id, category)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin TEXT NOT NULL,
    action TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
"""

# Stage 10 additions. policy_versions: an immutable snapshot of a
# policy's complete content after every mutation; historical rows are
# never updated or deleted (only appended). There is intentionally no
# foreign key to policies: version history must survive policy
# deletion. publication_state: a single row (id = 1) recording which
# policy is selected for publication to the filtering engine.
# config_revisions: one immutable row per publication attempt holding
# the EXACT published policy and category-database JSON, their content
# hashes, and the generation directory the files were written to, so
# any historical published configuration can be recovered and
# republished (rollback) even if the files on disk are gone.
SCHEMA_STAGE10 = """
CREATE TABLE IF NOT EXISTS policy_versions (
    policy_id INTEGER NOT NULL,
    version INTEGER NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    default_policy TEXT NOT NULL,
    enabled INTEGER NOT NULL,
    engine_json TEXT NOT NULL,
    admin TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    PRIMARY KEY (policy_id, version)
);

CREATE TABLE IF NOT EXISTS publication_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    selected_policy_id INTEGER,
    selected_by TEXT,
    selected_at TEXT,
    active_revision INTEGER
);

CREATE TABLE IF NOT EXISTS config_revisions (
    revision INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id INTEGER,
    policy_name TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    admin TEXT NOT NULL,
    created_at TEXT NOT NULL,
    policy_json TEXT NOT NULL,
    categories_json TEXT NOT NULL,
    policy_sha256 TEXT NOT NULL,
    categories_sha256 TEXT NOT NULL,
    generation TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK (status IN ('pending', 'published', 'failed')),
    detail TEXT NOT NULL DEFAULT ''
);
"""

# Starting catalogue from the Stage 7 specification: (slug, display
# name, description). Slugs follow the engine's category syntax.
INITIAL_CATEGORIES = [
    ("adult-content", "Adult content", "Sexually explicit material."),
    ("gambling", "Gambling", "Betting, casinos, and lotteries."),
    ("social-media", "Social media", "Social networking sites."),
    ("video-streaming", "Video streaming", "Video streaming services."),
    ("games", "Games", "Online games and gaming platforms."),
    ("shopping", "Shopping", "Online stores and marketplaces."),
    ("news", "News", "News sites."),
    ("search-engines", "Search engines", "Web search engines."),
    ("messaging", "Messaging", "Chat and messaging services."),
    ("file-sharing", "File sharing", "File hosting and peer-to-peer sharing."),
    ("malware-phishing", "Malware and phishing", "Known or suspected malicious sites."),
]


# Stage 11A additions: the device registry. A "device" is a durable
# administrative record - never identified by its current IP address -
# that may represent one device OR a network/group (for example "Home
# Wi-Fi"); device_type router/network names group entries honestly.
# Associations are strictly separated by identity_class: network bindings
# (ipv4, ipv6_prefix) are routing hints, never identity; credentials
# (token_hash, a RESERVED kind in Stage 11A - no tokens are issued,
# stored, or authenticated) are the only proof-bearing associations. The
# combined CHECK constraint makes the permitted (kind, identity_class)
# pairs a property of the database itself: SQLite aborts any INSERT or
# UPDATE producing another combination, even if API validation is
# bypassed. Adding a future credential kind is a deliberate table-rebuild
# migration, never a silent widening. Binding values are stored ONLY in
# the canonical form produced by the engine package's
# address_canonicalization module, so the partial unique index below IS
# the canonical duplicate check. Removal is soft (state = 'removed'):
# bindings are retired and assignment history is kept, never hard-deleted.
SCHEMA_STAGE11 = """
CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  device_type TEXT NOT NULL DEFAULT 'other',
  os TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL DEFAULT 'active'
    CHECK (state IN ('active','inactive','disabled','removed')),
  management_status TEXT NOT NULL DEFAULT 'unmanaged'
    CHECK (management_status IN ('unmanaged','enrolled')),
  notes TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  registered_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_seen_at TEXT
);

CREATE TABLE IF NOT EXISTS device_associations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id INTEGER NOT NULL REFERENCES devices(id),
  kind TEXT NOT NULL CHECK (kind IN ('ipv4','ipv6_prefix','token_hash')),
  -- network_binding: an address/prefix routing hint; never identity.
  -- credential: proof-bearing identity (token_hash; MDM kinds later).
  identity_class TEXT NOT NULL
    CHECK (identity_class IN ('network_binding','credential')),
  -- Stored ONLY in canonical form (plan 6.2); the unique index below is
  -- therefore also the canonical duplicate check.
  value TEXT NOT NULL,
  created_at TEXT NOT NULL,
  retired_at TEXT,
  -- Database-enforced identity classes (plan 6.1): the ONLY permitted
  -- (kind, identity_class) pairs. SQLite aborts any INSERT or UPDATE
  -- producing another combination, even if API validation is bypassed.
  CHECK (
    (kind = 'ipv4'        AND identity_class = 'network_binding') OR
    (kind = 'ipv6_prefix' AND identity_class = 'network_binding') OR
    (kind = 'token_hash'  AND identity_class = 'credential')
  )
);
-- One live association value maps to at most one device.
CREATE UNIQUE INDEX IF NOT EXISTS uq_live_association
  ON device_associations (kind, value) WHERE retired_at IS NULL;

CREATE TABLE IF NOT EXISTS device_policy_assignments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id INTEGER NOT NULL REFERENCES devices(id),
  policy_id INTEGER NOT NULL REFERENCES policies(id),
  policy_version_at_assignment INTEGER NOT NULL,
  assigned_by TEXT NOT NULL,
  assigned_at TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1
);
-- At most one active assignment per device.
CREATE UNIQUE INDEX IF NOT EXISTS uq_active_assignment
  ON device_policy_assignments (device_id) WHERE active = 1;
"""


def connect(path) -> sqlite3.Connection:
    """Open (creating if needed) the database with safe pragmas."""
    path = Path(path)
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Create tables, seed the starting categories, and run the Stage 10
    migration (idempotent)."""
    conn.executescript(SCHEMA)
    conn.executescript(SCHEMA_STAGE10)
    conn.executescript(SCHEMA_STAGE11)
    _migrate_policy_versions(conn)
    now = utcnow()
    for slug, display, description in INITIAL_CATEGORIES:
        conn.execute(
            "INSERT OR IGNORE INTO categories"
            " (name, display_name, description, enabled, builtin, created_at, updated_at)"
            " VALUES (?, ?, ?, 1, 1, ?, ?)",
            (slug, display, description, now, now),
        )
    conn.commit()


def _migrate_policy_versions(conn: sqlite3.Connection) -> None:
    """Give every pre-Stage-10 policy an initial immutable version 1.

    Policies created before policy versioning existed have no
    policy_versions rows. For each such policy, version 1 is snapshotted
    from its current content. The snapshot is attributed to
    "system-migration" rather than to a person, because no administrator
    action created it. Runs inside init_db and is idempotent: a policy
    that already has versions is skipped.
    """
    import json

    rows = conn.execute(
        "SELECT p.* FROM policies p WHERE NOT EXISTS"
        " (SELECT 1 FROM policy_versions pv WHERE pv.policy_id = p.id)"
    ).fetchall()
    for row in rows:
        allow = [
            r[0] for r in conn.execute(
                "SELECT domain FROM policy_domains WHERE policy_id = ? AND rule = 'allow'"
                " ORDER BY domain", (row["id"],)).fetchall()
        ]
        block = [
            r[0] for r in conn.execute(
                "SELECT domain FROM policy_domains WHERE policy_id = ? AND rule = 'block'"
                " ORDER BY domain", (row["id"],)).fetchall()
        ]
        cat_allow = [
            r[0] for r in conn.execute(
                "SELECT category FROM policy_categories WHERE policy_id = ? AND rule = 'allow'"
                " ORDER BY category", (row["id"],)).fetchall()
        ]
        cat_block = [
            r[0] for r in conn.execute(
                "SELECT category FROM policy_categories WHERE policy_id = ? AND rule = 'block'"
                " ORDER BY category", (row["id"],)).fetchall()
        ]
        engine = {
            "default_policy": row["default_policy"],
            "allowlist": allow,
            "blocklist": block,
            "category_rules": {"allow": cat_allow, "block": cat_block},
        }
        conn.execute(
            "INSERT INTO policy_versions"
            " (policy_id, version, name, description, default_policy, enabled,"
            "  engine_json, admin, note, created_at)"
            " VALUES (?, 1, ?, ?, ?, ?, ?, 'system-migration', ?, ?)",
            (
                row["id"], row["name"], row["description"], row["default_policy"],
                row["enabled"], json.dumps(engine, sort_keys=True),
                "migrated to version 1 during the Stage 10 upgrade",
                row["updated_at"],
            ),
        )
    conn.commit()

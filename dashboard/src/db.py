"""SQLite persistence for the KosherGuard admin dashboard.

One file-based SQLite database holds administrators, sessions,
categories, domain records, policies, and the audit log. SQLite needs
no server, no account, and no paid service, and it lives next to the
code it serves, which fits a development-stage admin tool.

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
    action TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
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
    """Create tables and seed the starting categories (idempotent)."""
    conn.executescript(SCHEMA)
    now = utcnow()
    for slug, display, description in INITIAL_CATEGORIES:
        conn.execute(
            "INSERT OR IGNORE INTO categories"
            " (name, display_name, description, enabled, builtin, created_at, updated_at)"
            " VALUES (?, ?, ?, 1, 1, ?, ?)",
            (slug, display, description, now, now),
        )
    conn.commit()

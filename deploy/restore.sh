#!/usr/bin/env bash
# KosherGuard dashboard restore.
#
# Verifies a backup file (SQLite integrity check AND the expected
# dashboard tables), then atomically puts it in place as dashboard.db.
#
# IMPORTANT: stop the dashboard service FIRST
# (systemctl stop kosherguard-dashboard). The server keeps its database
# file open; swapping the file underneath it would leave it writing to
# the old file.
#
# Usage:
#   bash deploy/restore.sh BACKUP_FILE [DATA_DIR] [--force]
#     BACKUP_FILE  a file written by backup.sh
#     DATA_DIR     directory holding dashboard.db (default /var/lib/kosherguard)
#     --force      overwrite an existing dashboard.db without asking
#
# Failure behavior: any failed check exits non-zero and the existing
# dashboard.db (if any) is left byte-for-byte untouched.
set -euo pipefail

if [ $# -lt 1 ]; then
    echo "usage: bash deploy/restore.sh BACKUP_FILE [DATA_DIR] [--force]" >&2
    exit 2
fi

BACKUP="$1"
DATA_DIR="${2:-/var/lib/kosherguard}"
FORCE="${3:-}"
DEST="$DATA_DIR/dashboard.db"
TMP="$DATA_DIR/.dashboard.db.restore-in-progress"

if [ ! -f "$BACKUP" ]; then
    echo "restore: backup file not found: $BACKUP" >&2
    exit 1
fi

if [ -e "$DEST" ] && [ "$FORCE" != "--force" ]; then
    echo "restore: $DEST already exists; re-run with --force to overwrite it" >&2
    exit 1
fi

echo "restore: make sure the dashboard service is stopped (systemctl stop kosherguard-dashboard)"

rm -f "$TMP"
cp "$BACKUP" "$TMP"

python3 - "$TMP" <<'PY'
import sqlite3
import sys

path = sys.argv[1]
try:
    conn = sqlite3.connect(path)
    try:
        result = conn.execute("PRAGMA integrity_check").fetchone()[0]
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
    finally:
        conn.close()
except sqlite3.DatabaseError as exc:
    print(f"restore: not a readable SQLite database: {exc}", file=sys.stderr)
    sys.exit(1)

if result != "ok":
    print(f"restore: backup failed integrity check: {result}", file=sys.stderr)
    sys.exit(1)

required = {"admins", "categories", "domains", "policies", "audit_log"}
missing = required - tables
if missing:
    print(
        "restore: this file is not a KosherGuard dashboard database "
        f"(missing tables: {', '.join(sorted(missing))})",
        file=sys.stderr,
    )
    sys.exit(1)
PY

# Atomic rename into place; the existing database stays untouched
# until this moment.
mv -f "$TMP" "$DEST"
echo "restore: installed $BACKUP as $DEST"
echo "restore: now start the service again (systemctl start kosherguard-dashboard)"

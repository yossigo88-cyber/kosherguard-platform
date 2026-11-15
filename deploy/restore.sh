#!/usr/bin/env bash
# KosherGuard dashboard restore.
#
# Verifies a backup file (SQLite integrity check AND the expected
# dashboard tables), then atomically puts it in place as dashboard.db.
#
# IMPORTANT: the dashboard service MUST be stopped first
# (systemctl stop kosherguard-dashboard), and this script refuses to
# run until the operator explicitly confirms that with
# --service-stopped. The server keeps its database file open; swapping
# the file underneath it would leave it writing to the old file.
# --force alone only covers overwriting an existing database - it does
# NOT confirm that the service is stopped.
#
# Usage:
#   bash deploy/restore.sh BACKUP_FILE [DATA_DIR] --service-stopped [--force]
#     BACKUP_FILE        a file written by backup.sh
#     DATA_DIR           directory holding dashboard.db (default /var/lib/kosherguard)
#     --service-stopped  REQUIRED: explicit confirmation that the
#                        dashboard service has been stopped
#     --force            overwrite an existing dashboard.db without asking
#
# Failure behavior: any failed check exits non-zero, the existing
# dashboard.db (if any) is left byte-for-byte untouched, and the
# temporary restore file is always removed (EXIT trap).
set -euo pipefail

usage() {
    echo "usage: bash deploy/restore.sh BACKUP_FILE [DATA_DIR] --service-stopped [--force]" >&2
    exit 2
}

BACKUP=""
DATA_DIR=""
FORCE=0
SERVICE_STOPPED=0
for arg in "$@"; do
    case "$arg" in
        --force) FORCE=1 ;;
        --service-stopped) SERVICE_STOPPED=1 ;;
        --*) echo "restore: unknown option: $arg" >&2; usage ;;
        *)
            if [ -z "$BACKUP" ]; then
                BACKUP="$arg"
            elif [ -z "$DATA_DIR" ]; then
                DATA_DIR="$arg"
            else
                echo "restore: unexpected argument: $arg" >&2
                usage
            fi
            ;;
    esac
done
[ -n "$BACKUP" ] || usage
DATA_DIR="${DATA_DIR:-/var/lib/kosherguard}"
DEST="$DATA_DIR/dashboard.db"

# The restored database holds password hashes and session tokens:
# keep it owner-only.
umask 077

if [ ! -f "$BACKUP" ]; then
    echo "restore: backup file not found: $BACKUP" >&2
    exit 1
fi

if [ "$SERVICE_STOPPED" != "1" ]; then
    echo "restore: refusing without confirmation that the dashboard service is stopped" >&2
    echo "restore: stop it first (systemctl stop kosherguard-dashboard), then re-run with --service-stopped" >&2
    exit 1
fi

if [ -e "$DEST" ] && [ "$FORCE" != "1" ]; then
    echo "restore: $DEST already exists; re-run with --force to overwrite it" >&2
    exit 1
fi

# Stage the restore in a safely created, uniquely named temporary file
# inside the data directory (same filesystem as the destination, so the
# final rename is atomic; the unique name never conflicts with another
# restore attempt). The EXIT trap removes it on every failure path; it
# is cleared only after the atomic rename succeeds.
TMP="$(mktemp "$DATA_DIR/.dashboard.db.restore-in-progress.XXXXXXXX")"
trap 'rm -f "$TMP"' EXIT

cp "$BACKUP" "$TMP"
chmod 0600 "$TMP"

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
trap - EXIT
chmod 0600 "$DEST"
echo "restore: installed $BACKUP as $DEST"
echo "restore: now start the service again (systemctl start kosherguard-dashboard)"

#!/usr/bin/env bash
# KosherGuard dashboard backup.
#
# Makes a CONSISTENT copy of the dashboard SQLite database while the
# server may still be running (SQLite online backup API - no locking
# hacks, no copying a half-written file), verifies the copy with
# PRAGMA integrity_check BEFORE it is published, and rotates old
# backups.
#
# Safety properties:
#   - The copy is written to a temporary file whose name never matches
#     the dashboard-*.db backup pattern, and renamed to its final name
#     only after the integrity check passes: a failed run never leaves
#     a partial file that looks like a valid completed backup.
#   - Everything created here is private: the backup directory is
#     forced to 0700 (including a pre-existing world-readable one) and
#     backup files are 0600. Backups contain the full dashboard
#     database - session tokens and password hashes included.
#   - KEEP is validated as a positive integer BEFORE anything happens;
#     an invalid value (zero, negative, non-numeric) fails safely
#     without taking or deleting any backup.
#
# Usage:
#   bash deploy/backup.sh [DATA_DIR] [BACKUP_DIR]
#     DATA_DIR    directory containing dashboard.db   (default /var/lib/kosherguard)
#     BACKUP_DIR  where backups are written           (default DATA_DIR/backups)
#   KEEP=N        how many backups to keep            (default 14, environment)
#
# Requires: bash, python3 (already required by the dashboard itself).
# No third-party tools, no network access, no accounts.
set -euo pipefail

DATA_DIR="${1:-/var/lib/kosherguard}"
BACKUP_DIR="${2:-$DATA_DIR/backups}"
KEEP="${KEEP:-14}"
DB="$DATA_DIR/dashboard.db"

# Everything this script creates is owner-only.
umask 077

# Validate KEEP before taking or deleting anything: an invalid value
# must fail safely and never delete existing backups.
case "$KEEP" in
    ''|*[!0-9]*)
        echo "backup: KEEP must be a positive integer, got '$KEEP'" >&2
        exit 1
        ;;
esac
if [ "$KEEP" -lt 1 ]; then
    echo "backup: KEEP must be a positive integer, got '$KEEP'" >&2
    exit 1
fi

if [ ! -f "$DB" ]; then
    echo "backup: database not found: $DB" >&2
    exit 1
fi

mkdir -p "$BACKUP_DIR"
# Private directories only - including pre-existing ones that were
# left world-readable.
chmod 0700 "$BACKUP_DIR"
if [ -O "$DATA_DIR" ]; then
    chmod 0700 "$DATA_DIR"
fi

STAMP="$(date -u +%Y%m%d-%H%M%S)"
DEST="$BACKUP_DIR/dashboard-$STAMP.db"
if [ -e "$DEST" ]; then
    # Two backups within the same second: keep both.
    DEST="$BACKUP_DIR/dashboard-$STAMP-$$.db"
fi

# Write to a temporary name that never matches dashboard-*.db, then
# publish by rename only after verification. The trap removes the
# temporary file if any step fails.
TMP="$BACKUP_DIR/.dashboard-$STAMP.tmp.$$"
trap 'rm -f "$TMP"' EXIT

python3 - "$DB" "$TMP" <<'PY'
import os
import sqlite3
import sys

src_path, dest_path = sys.argv[1], sys.argv[2]
src = sqlite3.connect(src_path)
dest = sqlite3.connect(dest_path)
try:
    # Online backup API: a consistent copy even while the dashboard
    # is serving requests.
    with dest:
        src.backup(dest)
    result = dest.execute("PRAGMA integrity_check").fetchone()[0]
finally:
    dest.close()
    src.close()
if result != "ok":
    os.unlink(dest_path)
    print(f"backup: integrity check failed on the copy: {result}", file=sys.stderr)
    sys.exit(1)
PY

chmod 0600 "$TMP"
mv "$TMP" "$DEST"
trap - EXIT
echo "backup: wrote $DEST"

# Rotation: keep the newest $KEEP backups, delete the rest.
ls -1t "$BACKUP_DIR"/dashboard-*.db 2>/dev/null | tail -n "+$((KEEP + 1))" | while read -r old; do
    rm -f "$old"
    echo "backup: rotated out $old"
done

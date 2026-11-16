#!/usr/bin/env bash
# KosherGuard platform backup (PostgreSQL).
#
# Takes a consistent logical dump with pg_dump (custom format),
# verifies the archive is readable (pg_restore --list) BEFORE
# publishing it, publishes atomically without ever overwriting, and
# rotates old backups. Mirrors the safety properties of backup.sh:
# temporary-then-publish, integrity check before publication, no
# clobbering, owner-only permissions, validated KEEP.
#
# Usage:
#   bash deploy/pg_backup.sh DATABASE_URL [BACKUP_DIR]
#   KEEP=N  how many backups to keep (default 14, environment)
#
# Requires: pg_dump + pg_restore on PATH (postgresql client tools).
set -euo pipefail

URL="${1:?usage: pg_backup.sh DATABASE_URL [BACKUP_DIR]}"
BACKUP_DIR="${2:-/var/lib/kosherguard/backups}"
KEEP="${KEEP:-14}"

umask 077

case "$KEEP" in
    ''|*[!0-9]*) echo "backup: KEEP must be a positive integer" >&2; exit 1 ;;
esac
[ "$KEEP" -ge 1 ] || { echo "backup: KEEP must be a positive integer" >&2; exit 1; }

mkdir -p "$BACKUP_DIR"
chmod 0700 "$BACKUP_DIR"

STAMP="$(date -u +%Y%m%d-%H%M%S)"
TMP="$BACKUP_DIR/.kosherguard-$STAMP.dump.tmp.$$"
trap 'rm -f "$TMP"' EXIT

pg_dump --format=custom --no-owner --no-privileges \
        --file="$TMP" "$URL"

# Verify the archive is a readable pg_dump archive before it counts.
pg_restore --list "$TMP" > /dev/null

chmod 0600 "$TMP"

DEST=""
attempt=0
while [ "$attempt" -lt 100 ]; do
    if [ "$attempt" -eq 0 ]; then
        candidate="$BACKUP_DIR/kosherguard-$STAMP.dump"
    else
        candidate="$BACKUP_DIR/kosherguard-$STAMP-$attempt.dump"
    fi
    if ln "$TMP" "$candidate" 2>/dev/null; then DEST="$candidate"; break; fi
    if [ ! -e "$candidate" ]; then
        echo "backup: cannot publish safely: hard links not supported on $BACKUP_DIR" >&2
        exit 1
    fi
    attempt=$((attempt + 1))
done
[ -n "$DEST" ] || { echo "backup: no free backup filename" >&2; exit 1; }
rm -f "$TMP"
trap - EXIT
echo "backup: wrote $DEST"

ls -1t "$BACKUP_DIR"/kosherguard-*.dump 2>/dev/null \
    | tail -n "+$((KEEP + 1))" \
    | while read -r old; do rm -f "$old"; echo "backup: rotated out $old"; done

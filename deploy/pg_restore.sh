#!/usr/bin/env bash
# KosherGuard platform restore (PostgreSQL).
#
# Restores a pg_dump custom-format archive into a TARGET database
# after verifying the archive. The service MUST be stopped first;
# this script refuses without --service-stopped. Restores into a
# database you name explicitly - never silently into production.
#
# Usage:
#   bash deploy/pg_restore.sh BACKUP_FILE TARGET_DATABASE_URL --service-stopped
set -euo pipefail

BACKUP="${1:?usage: pg_restore.sh BACKUP_FILE TARGET_URL --service-stopped}"
URL="${2:?usage: pg_restore.sh BACKUP_FILE TARGET_URL --service-stopped}"
CONFIRM="${3:-}"

if [ "$CONFIRM" != "--service-stopped" ]; then
    echo "restore: refusing without --service-stopped" >&2
    exit 1
fi
[ -f "$BACKUP" ] || { echo "restore: backup not found: $BACKUP" >&2; exit 1; }

# Verify the archive before touching the target.
umask 077
TOC="$(mktemp)"
trap 'rm -f "$TOC"' EXIT
pg_restore --list "$BACKUP" > "$TOC" \
    || { echo "restore: unreadable archive" >&2; exit 1; }
# Old archives may include browsing history. Never restore that table's data.
# Schema remains, so migrations can run before any service starts.
sed -i '/ TABLE DATA public filter_decisions /d' "$TOC"

# --clean drops objects that exist in the target; --exit-on-error
# fails loudly rather than leaving a half-restored database.
pg_restore --clean --if-exists --exit-on-error --no-owner \
           --no-privileges --use-list="$TOC" --dbname="$URL" "$BACKUP"
echo "restore: restored $BACKUP into target database"
echo "restore: activity history excluded; run migrations and privacy maintenance before starting services"

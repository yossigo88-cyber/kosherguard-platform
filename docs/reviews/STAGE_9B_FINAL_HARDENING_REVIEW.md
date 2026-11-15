# Stage 9B Final Hardening - Review Document

**Repository:** https://github.com/yossigo88-cyber/kosherguard-platform
**Working branch:** `stage-9b-deployment-preparation` (all work on this branch only)
**Starting branch HEAD (verified live with `git ls-remote` before any change):**
`1f39dcae09d44df753dd87220dbb9fdfa94ba6d1`
**Main baseline (verified live at the same moment, and re-verified after the fix commits):**
`5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a`
**Branch HEAD after the fix commits:** `c5da0e12656e4d0f90adb2ea08a9ab99bb2c8ea7`

This document covers the two remaining issues found during independent
review of the Stage 9B corrections package, their fixes, and the complete
evidence. It is documentation only; it changes no functionality itself.

---

## 1. The two problems

### Problem 1: restore temporary file left behind on validation failure

`deploy/restore.sh` staged the restore at a FIXED path,
`.dashboard.db.restore-in-progress`, created with `rm -f` + `cp`. If the
Python validation failed after the copy, the script exited (via
`set -euo pipefail`) and the temporary file stayed on disk - a stale
partial restore artifact in the data directory. The fixed name could also
collide with a second concurrent restore attempt.

### Problem 2: simultaneous backups could collide and overwrite

`deploy/backup.sh` named the published backup `dashboard-<timestamp>.db`,
falling back to `dashboard-<timestamp>-<pid>.db` only if the primary name
already existed AT CHECK TIME. Two backup processes starting in the same
second could both pass the existence check and then both rename onto the
same final name (check-then-act race): the second `mv` would silently
overwrite the first process's completed, verified backup.

---

## 2. Correction 1 - restore temporary-file cleanup (as implemented)

`deploy/restore.sh` now:

1. Creates the staging file with `mktemp` INSIDE the destination data
   directory: `mktemp "$DATA_DIR/.dashboard.db.restore-in-progress.XXXXXXXX"`.
   Safely created (no symlink attacks), unique per attempt (no conflict
   with another restore), and on the same filesystem as the destination,
   which is what keeps the final rename atomic.
2. Installs an EXIT trap immediately after creation:
   `trap 'rm -f "$TMP"' EXIT`. Under `set -euo pipefail` every failure
   path - copy failure, validation failure, interrupt - runs the trap and
   removes the temporary file. The trap is cleared (`trap - EXIT`) only
   after the atomic rename succeeds (at that point the path no longer
   exists anyway).
3. Preserves the ordering of all gates: backup-file-exists check, then
   the required `--service-stopped` confirmation (refusal BEFORE any
   filesystem mutation), then the separate `--force` overwrite check, and
   only then staging + validation + atomic `mv` into place. The existing
   database is never touched until every check has passed.
4. Keeps `--service-stopped` mandatory and `--force` limited to overwrite
   permission, exactly as before.

## 3. Correction 2 - collision-safe concurrent backups (as implemented)

`deploy/backup.sh` now publishes with an ATOMIC NO-OVERWRITE operation
plus collision retry, instead of a check-then-act rename:

1. The verified temporary file (unique per process, never matching the
   `dashboard-*.db` pattern) is published with `ln "$TMP" "$candidate"` -
   a hard link. link(2) fails atomically with EEXIST if the name is
   taken; it can never overwrite an existing completed backup. The
   temporary file lives in the backup directory, so the link is always
   same-filesystem.
2. On collision the script retries with the next free name
   (`dashboard-<stamp>.db`, then `dashboard-<stamp>-1.db`, `-2.db`, ...
   up to 100 attempts), so every completed backup gets its own unique
   final filename. After 100 collisions it refuses rather than
   overwriting.
3. If `ln` fails for any reason OTHER than an existing target (checked
   with `[ ! -e "$candidate" ]`), the script fails clearly - hard links
   unsupported on this filesystem - instead of silently falling back to
   an unsafe overwrite.
4. Everything else is preserved: SQLite online backup API,
   `PRAGMA integrity_check` on the temporary file BEFORE publication,
   umask 077, 0700 backup/data directories (repairing pre-existing
   world-readable ones), 0600 backup files (chmod before linking, so the
   published file is 0600), KEEP validation before anything happens, and
   the existing rotation behavior (the suffixed names match the
   `dashboard-*.db` rotation glob).

---

## 4. Complete updated contents of `deploy/backup.sh`

````bash
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
#     the dashboard-*.db backup pattern, and published only after the
#     integrity check passes: a failed run never leaves a partial file
#     that looks like a valid completed backup.
#   - Publication is atomic and never overwrites: the verified file is
#     hard-linked to its final name (link(2) fails atomically if the
#     name exists), with collision retry, so concurrent backup processes
#     can never clobber each other's completed backups. If the
#     filesystem cannot hard-link, the script fails clearly instead of
#     falling back to an unsafe overwrite.
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

# Publish atomically and NEVER overwrite: ln(1) hard-links the verified
# temporary file to its final name and fails atomically if that name
# already exists (link(2) EEXIST), so concurrent backups can never
# overwrite one another - the loser retries with the next free name.
# The temporary file and the backup live in the same directory, so a
# hard link is guaranteed to be same-filesystem. If hard links are not
# supported at all, fail clearly rather than silently falling back to
# an unsafe overwrite.
DEST=""
attempt=0
while [ "$attempt" -lt 100 ]; do
    if [ "$attempt" -eq 0 ]; then
        candidate="$BACKUP_DIR/dashboard-$STAMP.db"
    else
        candidate="$BACKUP_DIR/dashboard-$STAMP-$attempt.db"
    fi
    if ln "$TMP" "$candidate" 2>/dev/null; then
        DEST="$candidate"
        break
    fi
    if [ ! -e "$candidate" ]; then
        echo "backup: cannot publish safely: hard links not supported on $BACKUP_DIR" >&2
        exit 1
    fi
    # Name already taken (another backup won the race): try the next one.
    attempt=$((attempt + 1))
done
if [ -z "$DEST" ]; then
    echo "backup: no free backup filename after 100 attempts; refusing to overwrite" >&2
    exit 1
fi
rm -f "$TMP"
trap - EXIT
echo "backup: wrote $DEST"

# Rotation: keep the newest $KEEP backups, delete the rest.
ls -1t "$BACKUP_DIR"/dashboard-*.db 2>/dev/null | tail -n "+$((KEEP + 1))" | while read -r old; do
    rm -f "$old"
    echo "backup: rotated out $old"
done

````

## 5. Complete updated contents of `deploy/restore.sh`

````bash
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

````

## 6. Complete updated contents of `dashboard/tests/test_backup_restore.py`

````python
"""Stage 9B: backup.sh and restore.sh are exercised end to end.

The scripts run as REAL subprocesses against a real dashboard database
served by a real server. The round-trip test proves the restored data
is exactly the backup-time state: the server is restarted on the
restored directory and every kind of content is checked through the
HTTP API. Failure cases (corrupt backup, existing destination, missing
files) are verified to fail without touching the destination.
"""

import hashlib
import os
import sqlite3
import stat
import subprocess
import threading
from pathlib import Path

import pytest

from conftest import ADMIN_PASSWORD, ADMIN_USERNAME, Client

from server import make_server

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKUP_SH = REPO_ROOT / "deploy" / "backup.sh"
RESTORE_SH = REPO_ROOT / "deploy" / "restore.sh"


def run_script(script, *args, env_extra=None):
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["bash", str(script), *[str(a) for a in args]],
        capture_output=True, text=True, timeout=60, env=env,
    )


def start_server(db_path):
    srv = make_server("127.0.0.1", 0, db_path, ADMIN_USERNAME, ADMIN_PASSWORD)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return srv, thread, Client(srv.server_address[1])


def stop_server(srv, thread):
    srv.shutdown()
    srv.server_close()
    thread.join(timeout=5)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def seed_data(client):
    """Create one of each kind of content; return what was created."""
    status, category = client.post("/api/categories", {
        "name": "shul-sites", "display_name": "Shul sites",
        "description": "Synagogue and community sites."})
    assert status == 201, category
    status, domain = client.post("/api/domains", {
        "domain": "myshul.example", "categories": ["shul-sites"],
        "rule": "allow"})
    assert status == 201, domain
    status, policy = client.post("/api/policies", {
        "name": "Shabbos baseline", "description": "Baseline policy.",
        "default_policy": "block",
        "allowlist": ["myshul.example"], "blocklist": ["casino.example.com"],
        "category_allow": ["shul-sites"], "category_block": ["gambling"],
        "enabled": True})
    assert status == 201, policy
    status, overview = client.get("/api/overview")
    assert status == 200
    status, audit = client.get("/api/audit")
    assert status == 200
    return category, domain, policy, overview, audit["entries"]


def test_backup_restore_round_trip(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    db_path = data_dir / "dashboard.db"
    srv, thread, client = start_server(db_path)
    try:
        status, _ = client.login()
        assert status == 200
        category, domain, policy, overview, audit_entries = seed_data(client)

        # Backup while the server is RUNNING (online backup API).
        result = run_script(BACKUP_SH, data_dir)
        assert result.returncode == 0, result.stderr
        backups = sorted((data_dir / "backups").glob("dashboard-*.db"))
        assert len(backups) == 1

        # Post-backup mutation that must NOT survive the restore.
        status, _ = client.post("/api/domains", {
            "domain": "after-backup.example", "categories": ["shul-sites"],
            "rule": "block"})
        assert status == 201
    finally:
        stop_server(srv, thread)

    # Restore over the existing (mutated) database.
    result = run_script(RESTORE_SH, backups[0], data_dir, "--force", "--service-stopped")
    assert result.returncode == 0, result.stderr

    # Serve the restored directory and verify EVERYTHING matches the
    # backup-time state.
    srv, thread, client = start_server(db_path)
    try:
        # The admin from the backup still signs in with the same password.
        status, _ = client.login()
        assert status == 200

        status, fetched = client.get("/api/domains/myshul.example")
        assert status == 200
        assert fetched == domain
        status, body = client.get("/api/domains/after-backup.example")
        assert status == 404  # post-backup mutation is gone

        status, body = client.get("/api/categories?search=shul-sites")
        assert status == 200
        assert len(body["categories"]) == 1
        restored_category = body["categories"][0]
        for key in ("name", "display_name", "description", "enabled", "builtin"):
            assert restored_category[key] == category[key], key

        status, body = client.get("/api/policies")
        assert status == 200
        restored = [p for p in body["policies"] if p["name"] == "Shabbos baseline"]
        assert len(restored) == 1
        status, detail = client.get(f"/api/policies/{restored[0]['id']}")
        assert status == 200
        for key in ("default_policy", "allowlist", "blocklist",
                    "category_allow", "category_block", "enabled"):
            assert detail[key] == policy[key], key

        # The post-restore login above is the ONLY new audit entry
        # (audit is newest-first), so the backup-time rows follow it.
        status, body = client.get("/api/overview")
        assert status == 200
        expected_overview = dict(overview)
        expected_overview["audit_events"] = overview["audit_events"] + 1
        assert body == expected_overview

        status, body = client.get("/api/audit")
        assert status == 200
        entries = body["entries"]
        assert len(entries) == len(audit_entries) + 1
        assert entries[0]["action"] == "auth.login"
        assert entries[1:] == audit_entries
    finally:
        stop_server(srv, thread)


def test_restore_refuses_corrupt_backup_and_keeps_destination(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    db_path = data_dir / "dashboard.db"
    srv, thread, _ = start_server(db_path)
    stop_server(srv, thread)
    before = sha256(db_path)

    garbage = tmp_path / "garbage.db"
    garbage.write_bytes(b"this is not a sqlite database at all" * 100)
    result = run_script(RESTORE_SH, garbage, data_dir, "--force", "--service-stopped")
    assert result.returncode != 0
    assert "restore:" in result.stderr
    # The existing database is byte-for-byte untouched.
    assert sha256(db_path) == before
    # No temporary restore file is left behind.
    assert list(data_dir.glob(".dashboard.db.restore-in-progress*")) == []


def test_restore_refuses_overwrite_without_force(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    db_path = data_dir / "dashboard.db"
    srv, thread, _ = start_server(db_path)
    stop_server(srv, thread)
    before = sha256(db_path)

    backup = tmp_path / "some-backup.db"
    backup.write_bytes(db_path.read_bytes())
    result = run_script(RESTORE_SH, backup, data_dir, "--service-stopped")  # no --force
    assert result.returncode != 0
    assert "--force" in result.stderr
    assert sha256(db_path) == before


def test_missing_files_fail_cleanly(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    # Backup of a nonexistent database.
    result = run_script(BACKUP_SH, data_dir)
    assert result.returncode != 0
    assert "not found" in result.stderr
    # Restore of a nonexistent backup file.
    result = run_script(RESTORE_SH, data_dir / "nope.db", data_dir)
    assert result.returncode != 0
    assert "not found" in result.stderr


def test_backup_rotation_keeps_newest(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    srv, thread, _ = start_server(data_dir / "dashboard.db")
    stop_server(srv, thread)

    for _ in range(3):
        result = run_script(BACKUP_SH, data_dir, env_extra={"KEEP": "2"})
        assert result.returncode == 0, result.stderr
    backups = sorted((data_dir / "backups").glob("dashboard-*.db"))
    assert len(backups) == 2  # the oldest was rotated out


def test_restore_requires_service_stopped_confirmation(tmp_path):
    """--force alone must NOT imply the service is stopped: the script
    refuses, and the existing database stays byte-for-byte unchanged."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    db_path = data_dir / "dashboard.db"
    srv, thread, _ = start_server(db_path)
    stop_server(srv, thread)
    before = sha256(db_path)

    backup = tmp_path / "some-backup.db"
    backup.write_bytes(db_path.read_bytes())
    result = run_script(RESTORE_SH, backup, data_dir, "--force")
    assert result.returncode != 0
    assert "--service-stopped" in result.stderr
    assert sha256(db_path) == before


def test_failed_backup_leaves_nothing_behind(tmp_path):
    """A failed backup leaves no partial file and nothing that looks
    like a valid completed backup."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "dashboard.db").write_bytes(b"not a database" * 1000)
    result = run_script(BACKUP_SH, data_dir)
    assert result.returncode != 0
    backup_dir = data_dir / "backups"
    leftovers = list(backup_dir.iterdir()) if backup_dir.exists() else []
    assert leftovers == []


@pytest.mark.parametrize("keep", ["0", "-3", "abc", "2.5", "14x"])
def test_rotation_rejects_invalid_keep(tmp_path, keep):
    """Invalid KEEP values fail safely: no new backup is taken and the
    existing backup is not deleted."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    srv, thread, _ = start_server(data_dir / "dashboard.db")
    stop_server(srv, thread)

    result = run_script(BACKUP_SH, data_dir)
    assert result.returncode == 0, result.stderr
    existing = sorted((data_dir / "backups").glob("dashboard-*.db"))
    assert len(existing) == 1

    result = run_script(BACKUP_SH, data_dir, env_extra={"KEEP": keep})
    assert result.returncode != 0
    assert "KEEP" in result.stderr
    assert sorted((data_dir / "backups").glob("dashboard-*.db")) == existing


@pytest.mark.skipif(os.name != "posix", reason="Unix permission bits")
def test_backup_files_and_directories_are_private(tmp_path):
    """The backup dir is forced to 0700 (even a pre-existing
    world-readable one), the data dir is private, and the backup file
    is 0600."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    os.chmod(data_dir, 0o755)
    backup_dir = data_dir / "backups"
    backup_dir.mkdir()
    os.chmod(backup_dir, 0o755)  # pre-existing world-readable
    srv, thread, _ = start_server(data_dir / "dashboard.db")
    stop_server(srv, thread)

    result = run_script(BACKUP_SH, data_dir)
    assert result.returncode == 0, result.stderr
    assert stat.S_IMODE(os.stat(backup_dir).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(data_dir).st_mode) == 0o700
    backups = list(backup_dir.glob("dashboard-*.db"))
    assert len(backups) == 1
    assert stat.S_IMODE(os.stat(backups[0]).st_mode) == 0o600


@pytest.mark.skipif(os.name != "posix", reason="Unix permission bits")
def test_restored_database_is_private(tmp_path):
    """A restored database is 0600, even when the file it replaced was
    world-readable."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    db_path = data_dir / "dashboard.db"
    srv, thread, _ = start_server(db_path)
    stop_server(srv, thread)

    backup = tmp_path / "some-backup.db"
    backup.write_bytes(db_path.read_bytes())
    os.chmod(db_path, 0o644)  # world-readable destination
    result = run_script(RESTORE_SH, backup, data_dir, "--force", "--service-stopped")
    assert result.returncode == 0, result.stderr
    assert stat.S_IMODE(os.stat(db_path).st_mode) == 0o600


def test_successful_restore_leaves_no_temporary_file(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    db_path = data_dir / "dashboard.db"
    srv, thread, _ = start_server(db_path)
    stop_server(srv, thread)

    backup = tmp_path / "some-backup.db"
    backup.write_bytes(db_path.read_bytes())
    result = run_script(RESTORE_SH, backup, data_dir, "--force", "--service-stopped")
    assert result.returncode == 0, result.stderr
    assert list(data_dir.glob(".dashboard.db.restore-in-progress*")) == []


def test_concurrent_backups_do_not_collide(tmp_path):
    """Genuinely concurrent backups: real backup.sh subprocesses started
    at the same time against the same database and backup directory.
    Every process must succeed, every completed backup must have its own
    unique filename (nothing overwritten), every backup must pass a
    SQLite integrity check, permissions must stay 0700/0600, and no
    partial or temporary file may be left behind."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    srv, thread, _ = start_server(data_dir / "dashboard.db")
    stop_server(srv, thread)

    count = 8
    procs = [
        subprocess.Popen(
            ["bash", str(BACKUP_SH), str(data_dir)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for _ in range(count)
    ]
    for proc in procs:
        _, err = proc.communicate(timeout=120)
        assert proc.returncode == 0, err

    backup_dir = data_dir / "backups"
    backups = sorted(backup_dir.glob("dashboard-*.db"))
    assert len(backups) == count
    assert len({b.name for b in backups}) == count  # none overwritten
    for backup in backups:
        assert backup.stat().st_size > 0  # nothing partially written
        if os.name == "posix":
            assert stat.S_IMODE(os.stat(backup).st_mode) == 0o600
        conn = sqlite3.connect(backup)
        try:
            result = conn.execute("PRAGMA integrity_check").fetchone()[0]
        finally:
            conn.close()
        assert result == "ok"
    # Nothing but completed backups remains (no temp files).
    others = [p for p in backup_dir.iterdir() if p not in backups]
    assert others == []
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(backup_dir).st_mode) == 0o700

````

---

## 7. Complete diffs of every modified file

Cumulative diff of the fix: `git diff 1f39dcae09d44df753dd87220dbb9fdfa94ba6d1..c5da0e12656e4d0f90adb2ea08a9ab99bb2c8ea7`

Files changed: `deploy/backup.sh`, `deploy/restore.sh`,
`dashboard/tests/test_backup_restore.py`, `dashboard/README.md`,
`README.md` (the two READMEs only track the real test count, 129 to 131,
and describe the new test coverage; no application code elsewhere).

````diff
diff --git a/README.md b/README.md
index 3a2d0eb..294443d 100644
--- a/README.md
+++ b/README.md
@@ -6,7 +6,7 @@ KosherGuard is an iPhone filtering and management platform under development. Th
 
 The core filtering engine (Stage 5, full testing and verification) is complete in [filtering-engine/](filtering-engine/README.md): the central policy engine, the DNS filtering service (UDP and TCP), the website category database, structured decision logging, and a 119-test automated suite. Device enrollment, push-triggered policy updates, iPhone management, and reset recovery described in the [project charter](docs/PROJECT_CHARTER.md) are not built yet. Nothing in this repository currently filters or manages an iPhone; there is no Apple commercial MDM authorization and no real-device test environment (see the [technical investigation](docs/GENTECH_TECHNICAL_INVESTIGATION.md)).
 
-Stage 7 (the [admin dashboard](dashboard/README.md)) is complete and approved at commit ad999b739075364dc05191bd95c2c500cad2a3e9: a development application (stdlib Python backend API, SQLite storage, session authentication, audit logging, browser interface) for managing filtering policies, categories, and domain records. Stage 9A hardened it (configurable Secure cookies with a deployment guard, trusted-proxy login limiting, a 12-character password minimum, failed-login auditing, expired-session cleanup, a health endpoint, strict request-body validation, and bounded request handling with a total request deadline); the dashboard now has a 129-test automated suite. Stage 9B added deployment preparation (a runbook and pre-launch checklist in docs/deployment/, Caddy and systemd examples and backup/restore scripts in deploy/); nothing is deployed. Policy evaluation is performed by the existing filtering engine. The dashboard manages local policy data only: no devices are enrolled, no Apple MDM connection exists, and no remote policy push is available. It is not deployed anywhere.
+Stage 7 (the [admin dashboard](dashboard/README.md)) is complete and approved at commit ad999b739075364dc05191bd95c2c500cad2a3e9: a development application (stdlib Python backend API, SQLite storage, session authentication, audit logging, browser interface) for managing filtering policies, categories, and domain records. Stage 9A hardened it (configurable Secure cookies with a deployment guard, trusted-proxy login limiting, a 12-character password minimum, failed-login auditing, expired-session cleanup, a health endpoint, strict request-body validation, and bounded request handling with a total request deadline); the dashboard now has a 131-test automated suite. Stage 9B added deployment preparation (a runbook and pre-launch checklist in docs/deployment/, Caddy and systemd examples and backup/restore scripts in deploy/); nothing is deployed. Policy evaluation is performed by the existing filtering engine. The dashboard manages local policy data only: no devices are enrolled, no Apple MDM connection exists, and no remote policy push is available. It is not deployed anywhere.
 
 Stage 6 (iPhone enrollment and push notifications) was attempted as a preparation stage. The prerequisite audit found that none of the four required Apple prerequisites exist (Apple MDM vendor selection, an MDM APNs push certificate, Apple Business enrollment credentials, and an approved test iPhone), so no MDM, enrollment, or push code was written. The architecture, required credentials, security requirements, enrollment and push flows, and exact remaining blockers are documented in [docs/MDM_ENROLLMENT_AND_PUSH.md](docs/MDM_ENROLLMENT_AND_PUSH.md).
 
diff --git a/dashboard/README.md b/dashboard/README.md
index 2ec7212..75cb17e 100644
--- a/dashboard/README.md
+++ b/dashboard/README.md
@@ -28,7 +28,7 @@ dashboard/
     index.html        - interface shell (login view + app shell)
     styles.css        - design system
     app.js            - interface logic (vanilla JS, hash routing)
-  tests/              - 129 pytest tests against a real running server
+  tests/              - 131 pytest tests against a real running server
 ```
 
 Technology choices, per the Stage 7 requirement to fit the existing
@@ -183,7 +183,7 @@ URL database).
 cd dashboard && python3 -m pytest tests/ -q
 ```
 
-129 tests run the real server on an ephemeral localhost port with a
+131 tests run the real server on an ephemeral localhost port with a
 throwaway database: policy CRUD and validation, rule precedence and
 conflicts, category management, domain validation and duplicates, the
 import process (including atomic abort and line-numbered errors),
@@ -204,11 +204,13 @@ run as real subprocesses - a full round trip (back up a live server,
 mutate, restore, restart, and verify every kind of data through the
 API), corrupt-backup refusal, overwrite refusal, the required
 --service-stopped restore confirmation (refusal leaves the database
-byte-for-byte unchanged), failed-backup cleanup (no partial file is
-left looking like a valid backup), rotation including invalid-KEEP
-refusal, and file/directory permission checks (backup dir 0700,
-backup files and restored database 0600), missing files, and valid
-rotation. No sleeps are used for synchronization; the server socket is
+byte-for-byte unchanged), restore temporary-file cleanup on success
+and on failure, failed-backup cleanup (no partial file is left looking
+like a valid backup), genuinely concurrent backup processes (collision-
+safe unique publication, nothing overwritten, every backup integrity-
+checked), rotation including invalid-KEEP refusal, and file/directory
+permission checks (backup dir 0700, backup files and restored database
+0600), missing files, and valid rotation. No sleeps are used for synchronization; the server socket is
 bound before the test client connects.
 
 ## Deployment (prepared, not done)
@@ -227,9 +229,11 @@ Nothing here is deployed. Stage 9B prepared the deployment assets:
   unprivileged user, sandboxing directives). Reviewed but NOT yet
   tested on a live system.
 - `deploy/backup.sh` / `deploy/restore.sh` - consistent online SQLite
-  backups written to a temporary file and published only after an
+  backups written to a temporary file and published atomically without
+  overwrite (hard-link publication with collision retry) only after an
   integrity check, validated rotation, and a verified atomic restore
-  that requires an explicit --service-stopped confirmation. Backup
+  that requires an explicit --service-stopped confirmation and always
+  cleans up its temporary file. Backup
   directories and files and restored databases are forced private
   (0700/0600); the systemd unit sets UMask=0077 and
   StateDirectoryMode=0700. Both scripts are exercised by automated
diff --git a/dashboard/tests/test_backup_restore.py b/dashboard/tests/test_backup_restore.py
index 5dd27fa..6a8dafd 100644
--- a/dashboard/tests/test_backup_restore.py
+++ b/dashboard/tests/test_backup_restore.py
@@ -10,6 +10,7 @@ files) are verified to fail without touching the destination.
 
 import hashlib
 import os
+import sqlite3
 import stat
 import subprocess
 import threading
@@ -169,6 +170,8 @@ def test_restore_refuses_corrupt_backup_and_keeps_destination(tmp_path):
     assert "restore:" in result.stderr
     # The existing database is byte-for-byte untouched.
     assert sha256(db_path) == before
+    # No temporary restore file is left behind.
+    assert list(data_dir.glob(".dashboard.db.restore-in-progress*")) == []
 
 
 def test_restore_refuses_overwrite_without_force(tmp_path):
@@ -303,3 +306,61 @@ def test_restored_database_is_private(tmp_path):
     result = run_script(RESTORE_SH, backup, data_dir, "--force", "--service-stopped")
     assert result.returncode == 0, result.stderr
     assert stat.S_IMODE(os.stat(db_path).st_mode) == 0o600
+
+
+def test_successful_restore_leaves_no_temporary_file(tmp_path):
+    data_dir = tmp_path / "data"
+    data_dir.mkdir()
+    db_path = data_dir / "dashboard.db"
+    srv, thread, _ = start_server(db_path)
+    stop_server(srv, thread)
+
+    backup = tmp_path / "some-backup.db"
+    backup.write_bytes(db_path.read_bytes())
+    result = run_script(RESTORE_SH, backup, data_dir, "--force", "--service-stopped")
+    assert result.returncode == 0, result.stderr
+    assert list(data_dir.glob(".dashboard.db.restore-in-progress*")) == []
+
+
+def test_concurrent_backups_do_not_collide(tmp_path):
+    """Genuinely concurrent backups: real backup.sh subprocesses started
+    at the same time against the same database and backup directory.
+    Every process must succeed, every completed backup must have its own
+    unique filename (nothing overwritten), every backup must pass a
+    SQLite integrity check, permissions must stay 0700/0600, and no
+    partial or temporary file may be left behind."""
+    data_dir = tmp_path / "data"
+    data_dir.mkdir()
+    srv, thread, _ = start_server(data_dir / "dashboard.db")
+    stop_server(srv, thread)
+
+    count = 8
+    procs = [
+        subprocess.Popen(
+            ["bash", str(BACKUP_SH), str(data_dir)],
+            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
+        for _ in range(count)
+    ]
+    for proc in procs:
+        _, err = proc.communicate(timeout=120)
+        assert proc.returncode == 0, err
+
+    backup_dir = data_dir / "backups"
+    backups = sorted(backup_dir.glob("dashboard-*.db"))
+    assert len(backups) == count
+    assert len({b.name for b in backups}) == count  # none overwritten
+    for backup in backups:
+        assert backup.stat().st_size > 0  # nothing partially written
+        if os.name == "posix":
+            assert stat.S_IMODE(os.stat(backup).st_mode) == 0o600
+        conn = sqlite3.connect(backup)
+        try:
+            result = conn.execute("PRAGMA integrity_check").fetchone()[0]
+        finally:
+            conn.close()
+        assert result == "ok"
+    # Nothing but completed backups remains (no temp files).
+    others = [p for p in backup_dir.iterdir() if p not in backups]
+    assert others == []
+    if os.name == "posix":
+        assert stat.S_IMODE(os.stat(backup_dir).st_mode) == 0o700
diff --git a/deploy/backup.sh b/deploy/backup.sh
index 9df0b2b..4e51edf 100644
--- a/deploy/backup.sh
+++ b/deploy/backup.sh
@@ -9,9 +9,15 @@
 #
 # Safety properties:
 #   - The copy is written to a temporary file whose name never matches
-#     the dashboard-*.db backup pattern, and renamed to its final name
-#     only after the integrity check passes: a failed run never leaves
-#     a partial file that looks like a valid completed backup.
+#     the dashboard-*.db backup pattern, and published only after the
+#     integrity check passes: a failed run never leaves a partial file
+#     that looks like a valid completed backup.
+#   - Publication is atomic and never overwrites: the verified file is
+#     hard-linked to its final name (link(2) fails atomically if the
+#     name exists), with collision retry, so concurrent backup processes
+#     can never clobber each other's completed backups. If the
+#     filesystem cannot hard-link, the script fails clearly instead of
+#     falling back to an unsafe overwrite.
 #   - Everything created here is private: the backup directory is
 #     forced to 0700 (including a pre-existing world-readable one) and
 #     backup files are 0600. Backups contain the full dashboard
@@ -65,11 +71,6 @@ if [ -O "$DATA_DIR" ]; then
 fi
 
 STAMP="$(date -u +%Y%m%d-%H%M%S)"
-DEST="$BACKUP_DIR/dashboard-$STAMP.db"
-if [ -e "$DEST" ]; then
-    # Two backups within the same second: keep both.
-    DEST="$BACKUP_DIR/dashboard-$STAMP-$$.db"
-fi
 
 # Write to a temporary name that never matches dashboard-*.db, then
 # publish by rename only after verification. The trap removes the
@@ -101,7 +102,39 @@ if result != "ok":
 PY
 
 chmod 0600 "$TMP"
-mv "$TMP" "$DEST"
+
+# Publish atomically and NEVER overwrite: ln(1) hard-links the verified
+# temporary file to its final name and fails atomically if that name
+# already exists (link(2) EEXIST), so concurrent backups can never
+# overwrite one another - the loser retries with the next free name.
+# The temporary file and the backup live in the same directory, so a
+# hard link is guaranteed to be same-filesystem. If hard links are not
+# supported at all, fail clearly rather than silently falling back to
+# an unsafe overwrite.
+DEST=""
+attempt=0
+while [ "$attempt" -lt 100 ]; do
+    if [ "$attempt" -eq 0 ]; then
+        candidate="$BACKUP_DIR/dashboard-$STAMP.db"
+    else
+        candidate="$BACKUP_DIR/dashboard-$STAMP-$attempt.db"
+    fi
+    if ln "$TMP" "$candidate" 2>/dev/null; then
+        DEST="$candidate"
+        break
+    fi
+    if [ ! -e "$candidate" ]; then
+        echo "backup: cannot publish safely: hard links not supported on $BACKUP_DIR" >&2
+        exit 1
+    fi
+    # Name already taken (another backup won the race): try the next one.
+    attempt=$((attempt + 1))
+done
+if [ -z "$DEST" ]; then
+    echo "backup: no free backup filename after 100 attempts; refusing to overwrite" >&2
+    exit 1
+fi
+rm -f "$TMP"
 trap - EXIT
 echo "backup: wrote $DEST"
 
diff --git a/deploy/restore.sh b/deploy/restore.sh
index 9c301e5..0b4a8a8 100644
--- a/deploy/restore.sh
+++ b/deploy/restore.sh
@@ -20,8 +20,9 @@
 #                        dashboard service has been stopped
 #     --force            overwrite an existing dashboard.db without asking
 #
-# Failure behavior: any failed check exits non-zero and the existing
-# dashboard.db (if any) is left byte-for-byte untouched.
+# Failure behavior: any failed check exits non-zero, the existing
+# dashboard.db (if any) is left byte-for-byte untouched, and the
+# temporary restore file is always removed (EXIT trap).
 set -euo pipefail
 
 usage() {
@@ -53,7 +54,6 @@ done
 [ -n "$BACKUP" ] || usage
 DATA_DIR="${DATA_DIR:-/var/lib/kosherguard}"
 DEST="$DATA_DIR/dashboard.db"
-TMP="$DATA_DIR/.dashboard.db.restore-in-progress"
 
 # The restored database holds password hashes and session tokens:
 # keep it owner-only.
@@ -75,7 +75,14 @@ if [ -e "$DEST" ] && [ "$FORCE" != "1" ]; then
     exit 1
 fi
 
-rm -f "$TMP"
+# Stage the restore in a safely created, uniquely named temporary file
+# inside the data directory (same filesystem as the destination, so the
+# final rename is atomic; the unique name never conflicts with another
+# restore attempt). The EXIT trap removes it on every failure path; it
+# is cleared only after the atomic rename succeeds.
+TMP="$(mktemp "$DATA_DIR/.dashboard.db.restore-in-progress.XXXXXXXX")"
+trap 'rm -f "$TMP"' EXIT
+
 cp "$BACKUP" "$TMP"
 chmod 0600 "$TMP"
 
@@ -118,6 +125,7 @@ PY
 # Atomic rename into place; the existing database stays untouched
 # until this moment.
 mv -f "$TMP" "$DEST"
+trap - EXIT
 chmod 0600 "$DEST"
 echo "restore: installed $BACKUP as $DEST"
 echo "restore: now start the service again (systemctl start kosherguard-dashboard)"

````

---

## 8. Tests - exact commands and actual terminal output

All outputs below are complete, unedited captures of runs that actually
executed. Nothing is reconstructed. "Working tree" = the local tree in
which the fixes were written; "fresh clone" = an anonymous
`git clone --branch stage-9b-deployment-preparation` of the committed
result, whose five changed files were verified byte-identical (`cmp`)
to the working tree before these runs.

### 8.1 Focused backup/restore tests (working tree)

````
$ cd <tree>/dashboard && python3 -m pytest tests/test_backup_restore.py -v
============================= test session starts ==============================
platform linux -- Python 3.10.12, pytest-9.2.0, pluggy-1.7.0 -- /usr/bin/python3
cachedir: .pytest_cache
rootdir: /tmp/verify9bd/dashboard
plugins: anyio-4.15.1, platformdirs-4.12.4
collecting ... collected 16 items

tests/test_backup_restore.py::test_backup_restore_round_trip PASSED      [  6%]
tests/test_backup_restore.py::test_restore_refuses_corrupt_backup_and_keeps_destination PASSED [ 12%]
tests/test_backup_restore.py::test_restore_refuses_overwrite_without_force PASSED [ 18%]
tests/test_backup_restore.py::test_missing_files_fail_cleanly PASSED     [ 25%]
tests/test_backup_restore.py::test_backup_rotation_keeps_newest PASSED   [ 31%]
tests/test_backup_restore.py::test_restore_requires_service_stopped_confirmation PASSED [ 37%]
tests/test_backup_restore.py::test_failed_backup_leaves_nothing_behind PASSED [ 43%]
tests/test_backup_restore.py::test_rotation_rejects_invalid_keep[0] PASSED [ 50%]
tests/test_backup_restore.py::test_rotation_rejects_invalid_keep[-3] PASSED [ 56%]
tests/test_backup_restore.py::test_rotation_rejects_invalid_keep[abc] PASSED [ 62%]
tests/test_backup_restore.py::test_rotation_rejects_invalid_keep[2.5] PASSED [ 68%]
tests/test_backup_restore.py::test_rotation_rejects_invalid_keep[14x] PASSED [ 75%]
tests/test_backup_restore.py::test_backup_files_and_directories_are_private PASSED [ 81%]
tests/test_backup_restore.py::test_restored_database_is_private PASSED   [ 87%]
tests/test_backup_restore.py::test_successful_restore_leaves_no_temporary_file PASSED [ 93%]
tests/test_backup_restore.py::test_concurrent_backups_do_not_collide PASSED [100%]

============================== 16 passed in 8.62s ==============================
````

### 8.2 Full dashboard suite (working tree)

````
$ cd <tree>/dashboard && python3 -m pytest tests/ -q
........................................................................ [ 54%]
...........................................................              [100%]
131 passed in 85.89s (0:01:25)
````

### 8.3 Full filtering-engine regression suite (working tree)

````
$ cd <tree>/filtering-engine && python3 -m pytest tests/ -q -rw
........................................................................ [ 60%]
...............................................                          [100%]
119 passed in 52.52s
````

Engine code is untouched by this change. One earlier run of the same
suite in the same session reported `119 passed, 3 warnings in 52.60s`;
the warnings summary capture above (re-run with `-rw`) reported no
warnings, so the warning source was transient (not a failure; all 119
passed in both runs).

### 8.4 Focused backup/restore tests (fresh anonymous clone of the committed branch)

````
$ cd <fresh-clone>/dashboard && python3 -m pytest tests/test_backup_restore.py -v
============================= test session starts ==============================
platform linux -- Python 3.10.12, pytest-9.2.0, pluggy-1.7.0 -- /usr/bin/python3
cachedir: .pytest_cache
rootdir: /tmp/verify9bh/dashboard
plugins: anyio-4.15.1, platformdirs-4.12.4
collecting ... collected 16 items

tests/test_backup_restore.py::test_backup_restore_round_trip PASSED      [  6%]
tests/test_backup_restore.py::test_restore_refuses_corrupt_backup_and_keeps_destination PASSED [ 12%]
tests/test_backup_restore.py::test_restore_refuses_overwrite_without_force PASSED [ 18%]
tests/test_backup_restore.py::test_missing_files_fail_cleanly PASSED     [ 25%]
tests/test_backup_restore.py::test_backup_rotation_keeps_newest PASSED   [ 31%]
tests/test_backup_restore.py::test_restore_requires_service_stopped_confirmation PASSED [ 37%]
tests/test_backup_restore.py::test_failed_backup_leaves_nothing_behind PASSED [ 43%]
tests/test_backup_restore.py::test_rotation_rejects_invalid_keep[0] PASSED [ 50%]
tests/test_backup_restore.py::test_rotation_rejects_invalid_keep[-3] PASSED [ 56%]
tests/test_backup_restore.py::test_rotation_rejects_invalid_keep[abc] PASSED [ 62%]
tests/test_backup_restore.py::test_rotation_rejects_invalid_keep[2.5] PASSED [ 68%]
tests/test_backup_restore.py::test_rotation_rejects_invalid_keep[14x] PASSED [ 75%]
tests/test_backup_restore.py::test_backup_files_and_directories_are_private PASSED [ 81%]
tests/test_backup_restore.py::test_restored_database_is_private PASSED   [ 87%]
tests/test_backup_restore.py::test_successful_restore_leaves_no_temporary_file PASSED [ 93%]
tests/test_backup_restore.py::test_concurrent_backups_do_not_collide PASSED [100%]

============================== 16 passed in 8.61s ==============================
````

### 8.5 Full dashboard suite (fresh anonymous clone of the committed branch)

````
$ cd <fresh-clone>/dashboard && python3 -m pytest tests/ -q
........................................................................ [ 54%]
...........................................................              [100%]
131 passed in 86.92s (0:01:26)
````

### 8.6 Shell syntax checks

````
$ bash -n deploy/backup.sh && bash -n deploy/restore.sh && echo SHELL_SYNTAX_OK
SHELL_SYNTAX_OK
````

(`bash -n` prints nothing on success; exit code 0.)

---

## 9. Specific evidence from the concurrent-backup test

The automated test `test_concurrent_backups_do_not_collide` starts 8
REAL `backup.sh` subprocesses concurrently (subprocess.Popen, all
launched before waiting) against the same live-created dashboard
database and the same backup directory, waits for every process, and
asserts: all 8 exit 0; 8 completed backups exist with 8 distinct
filenames (nothing overwritten); every backup is non-empty and passes
`PRAGMA integrity_check`; every backup file is 0600 and the backup
directory is 0700; and nothing except completed backups remains in the
directory (no partial or temporary files). It passed in every suite run
above (see 8.1 and 8.4). This is not a simulated race - the processes
genuinely run at the same time.

An additional manual demonstration (real run, captured verbatim) makes
the collision retry visible: 8 concurrent processes in the same second
produced the primary name plus `-1` through `-7` collision-retry names,
all integrity-ok, all 0600, directory 0700:

````
$ # create a real dashboard database, then launch 8 backup.sh processes at once
$ for i in $(seq 1 8); do bash deploy/backup.sh "$D" & done; wait
backup: wrote /tmp/tmp.UKSUsYXIlf/backups/dashboard-20261115-071150.db
backup: wrote /tmp/tmp.UKSUsYXIlf/backups/dashboard-20261115-071150-1.db
backup: wrote /tmp/tmp.UKSUsYXIlf/backups/dashboard-20261115-071150-2.db
backup: wrote /tmp/tmp.UKSUsYXIlf/backups/dashboard-20261115-071150-3.db
backup: wrote /tmp/tmp.UKSUsYXIlf/backups/dashboard-20261115-071150-4.db
backup: wrote /tmp/tmp.UKSUsYXIlf/backups/dashboard-20261115-071150-5.db
backup: wrote /tmp/tmp.UKSUsYXIlf/backups/dashboard-20261115-071150-6.db
backup: wrote /tmp/tmp.UKSUsYXIlf/backups/dashboard-20261115-071150-7.db

$ ls -la "$D/backups/"
total 616
drwx------ 2 sandbox sandbox  4096 Nov 15 02:11 .
drwx------ 3 sandbox sandbox  4096 Nov 15 02:11 ..
-rw------- 1 sandbox sandbox 77824 Nov 15 02:11 dashboard-20261115-071150-1.db
-rw------- 1 sandbox sandbox 77824 Nov 15 02:11 dashboard-20261115-071150-2.db
-rw------- 1 sandbox sandbox 77824 Nov 15 02:11 dashboard-20261115-071150-3.db
-rw------- 1 sandbox sandbox 77824 Nov 15 02:11 dashboard-20261115-071150-4.db
-rw------- 1 sandbox sandbox 77824 Nov 15 02:11 dashboard-20261115-071150-5.db
-rw------- 1 sandbox sandbox 77824 Nov 15 02:11 dashboard-20261115-071150-6.db
-rw------- 1 sandbox sandbox 77824 Nov 15 02:11 dashboard-20261115-071150-7.db
-rw------- 1 sandbox sandbox 77824 Nov 15 02:11 dashboard-20261115-071150.db

$ # PRAGMA integrity_check on every produced backup
dashboard-20261115-071150-1.db: ok
dashboard-20261115-071150-2.db: ok
dashboard-20261115-071150-3.db: ok
dashboard-20261115-071150-4.db: ok
dashboard-20261115-071150-5.db: ok
dashboard-20261115-071150-6.db: ok
dashboard-20261115-071150-7.db: ok
dashboard-20261115-071150.db: ok
````

---

## 10. Evidence: failed restores leave no temporary file and preserve the database

`test_restore_refuses_corrupt_backup_and_keeps_destination` (passing in
8.1 and 8.4): a garbage "backup" is fed to `restore.sh
--force --service-stopped`; the script fails; the existing database's
SHA-256 before and after is identical (byte-for-byte preserved); and
`data_dir.glob(".dashboard.db.restore-in-progress*")` is empty - the
EXIT trap removed the staged copy. `test_failed_backup_leaves_nothing_behind`
similarly proves a failed BACKUP leaves its backup directory completely
empty.

## 11. Evidence: successful restores leave no temporary file

`test_successful_restore_leaves_no_temporary_file` (passing in 8.1 and
8.4): a valid restore with both confirmations succeeds, and the same
glob proves no temporary restore file remains afterwards. The full
round-trip test (`test_backup_restore_round_trip`) additionally proves
the restored data is exactly the backup-time state through the HTTP API.

---

## 12. Remaining limitations / untested behavior

- The systemd unit, the Caddy configuration, and the backup SCHEDULE
  have NOT run on a live server (reviewed preparation only; the
  pre-launch checklist covers verifying them).
- Automatic backup scheduling and off-site backup storage are not
  configured automatically; the runbook shows the operator how.
- The concurrency test runs 8 processes; the 100-attempt collision
  ceiling and the no-hard-link filesystem failure path are implemented
  and reviewed but not exercised by an automated test (the runner's
  filesystem supports hard links, and 8 concurrent processes exercise
  the retry path, not the ceiling).
- The engine suite is not consistently green historically: one timing
  flake (`test_truncated_udp_upstream_large_answer_complete_over_tcp_downstream`)
  appeared once in the previous correction round on byte-identical code
  and passed in isolation and on re-runs; in this round both engine runs
  passed 119/119.

---

## 13. Confirmation: no deployment, no merge

- No production deployment has occurred; nothing in this change was
  deployed anywhere.
- No merge into main (or anywhere) occurred; main remains
  `5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a`, verified with
  `git ls-remote` after the fix commits.
- This document contains no passwords, tokens, private keys, or secrets.

---

## 14. Commit record

Fix commits on `stage-9b-deployment-preparation`, each with the exact
message `fix: harden Stage 9B backup and restore concurrency` (the
GitHub web editor commits per file, so the fix lands as five commits
with that single message; together they change exactly the five files
listed in section 7):

- `831f9dd` deploy/backup.sh
- `71931ae` deploy/restore.sh
- `cc6cff8` dashboard/tests/test_backup_restore.py
- `07dc1ef` dashboard/README.md
- `c5da0e1` README.md

Documentation commit (this file), separate, message
`docs: add Stage 9B final hardening review`: SHA reported in the final
summary that accompanies this document.

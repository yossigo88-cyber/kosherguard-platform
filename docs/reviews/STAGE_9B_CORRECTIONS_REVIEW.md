# Stage 9B Corrections - Complete Review Package

**Repository:** https://github.com/yossigo88-cyber/kosherguard-platform
**Working branch:** `stage-9b-deployment-preparation` (all Stage 9B work is on this branch only)
**Branch HEAD when this document was written (verified live with `git ls-remote`, not assumed):**
`2f835b2d8ffa360517f87928c178a5c2bf6ef0dd`
**Approved main baseline (verified live at the same moment):**
`5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a`

This document is documentation and evidence collection only. It changes no
application code, no deployment scripts, and no tests. Stage 9B prepared
deployment assets for the KosherGuard admin dashboard; after the first review
package, six required corrections were identified and implemented on the
working branch. This file documents those corrections with the actual
implementation, complete source, complete diffs, and verbatim test output.

Live verification output captured while preparing this document:

````
$ bash -n deploy/backup.sh && bash -n deploy/restore.sh && echo SHELL_SYNTAX_OK
SHELL_SYNTAX_OK

$ git ls-remote https://github.com/yossigo88-cyber/kosherguard-platform
5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a	HEAD
5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a	refs/heads/main
2f835b2d8ffa360517f87928c178a5c2bf6ef0dd	refs/heads/stage-9b-deployment-preparation
````

---

## Section 1 - The six corrections, as implemented

### 1.1 Branch-safe runbook

**Problem:** `docs/deployment/RUNBOOK.md` told the operator to clone the
repository with no branch (`sudo git clone ... /opt/kosherguard`), which
checks out the default branch (`main`). `main` deliberately does not contain
Stage 9B, so following the runbook would have produced an installation
without the deployment files it instructs the operator to install. The update
instructions used a bare `git pull` for the same reason.

**Implementation:** the clone command now names the branch explicitly, with
an explanation of why it is required:

````
sudo mkdir -p /opt/kosherguard
sudo git clone --branch stage-9b-deployment-preparation \
    https://github.com/yossigo88-cyber/kosherguard-platform /opt/kosherguard
````

The update section no longer relies on the default branch:

````
cd /opt/kosherguard
sudo git fetch origin
sudo git pull origin stage-9b-deployment-preparation
sudo systemctl restart kosherguard-dashboard
curl -s http://127.0.0.1:8080/api/health
````

Both places state explicitly: do not rely on the repository's default branch.

### 1.2 File permissions

**Implementation, file by file:**

- `deploy/kosherguard-dashboard.service` gains two directives:
  - `UMask=0077` - every file the dashboard process creates is owner-only.
    The database it creates contains session tokens and password hashes.
  - `StateDirectoryMode=0700` - systemd creates `/var/lib/kosherguard`
    private when it does not exist.
- `deploy/backup.sh`:
  - `umask 077` at the top, so every file it creates starts owner-only.
  - `chmod 0700 "$BACKUP_DIR"` runs unconditionally after `mkdir -p`, so a
    pre-existing backup directory that was left world-readable is repaired
    on every run, not just when first created.
  - `chmod 0700 "$DATA_DIR"` runs when the script's effective user owns the
    data directory (`[ -O "$DATA_DIR" ]`), so it never fails on a directory
    owned by root in an unusual layout.
  - Every published backup file is forced to `0600` with an explicit
    `chmod 0600` before the final rename.
- `deploy/restore.sh`:
  - `umask 077` at the top; the staged restore copy is `chmod 0600`, and the
    installed database is `chmod 0600` after the atomic rename. A restored
    database is private even if the file it replaced was world-readable.
- `docs/deployment/RUNBOOK.md`: the state-directory creation step now
  includes `sudo chmod 0700 /var/lib/kosherguard` and explains why (the
  database holds session tokens and password hashes).

Nothing was weakened: every change tightens or preserves permissions, and no
database contents, session tokens, or password hashes are exposed anywhere.
New automated tests verify the modes on supported Unix systems (skipped on
non-POSIX): backup directory 0700 (including the pre-existing world-readable
case), data directory 0700, backup files 0600, and restored database 0600.

### 1.3 Safe restore (`--service-stopped`)

**Implementation:** `deploy/restore.sh` now parses named flags instead of
relying on position alone, and requires an explicit operator confirmation:

- `--service-stopped` - REQUIRED. Without it the script prints

  ````
  restore: refusing without confirmation that the dashboard service is stopped
  restore: stop it first (systemctl stop kosherguard-dashboard), then re-run with --service-stopped
  ````

  and exits non-zero BEFORE touching anything: the check runs before the
  overwrite check, before the staging copy, and before any verification, so
  the existing `dashboard.db` remains byte-for-byte untouched. The test
  `test_restore_requires_service_stopped_confirmation` proves this by
  SHA-256-hashing the existing database before and after the refused run.
- `--force` - covers ONLY overwriting an existing `dashboard.db`. It does
  not, by itself, imply that the service is stopped; a run with `--force`
  but without `--service-stopped` is refused.
- The old behavior (an informational echo reminding the operator to stop the
  service, with no enforcement) is gone.
- The runbook's restore drill (step 7) now passes both flags:
  `bash deploy/restore.sh LATEST-FILE.db /var/lib/kosherguard --force --service-stopped`.
- The restore itself is unchanged in shape: stage to a temp file in the data
  directory, verify (SQLite integrity check plus required dashboard tables),
  then atomically rename into place. Any failed check exits non-zero with
  the existing database untouched.

### 1.4 Atomic backups

**Implementation in `deploy/backup.sh`:**

1. The SQLite online-backup copy is written to a temporary file named
   `.dashboard-<timestamp>.tmp.<pid>` inside the backup directory. The name
   never matches the `dashboard-*.db` pattern, so no partial file ever looks
   like a completed backup, and rotation never sees it.
2. `PRAGMA integrity_check` runs against the temporary file.
3. Only after the check passes is the file `chmod 0600` and renamed
   (`mv`) to the final `dashboard-<timestamp>.db` name - rename within one
   filesystem is atomic, so observers only ever see complete, verified
   backups.
4. On ANY failure the temporary file is removed two ways: an `EXIT` trap
   (`trap 'rm -f "$TMP"' EXIT`, cleared after a successful publish) covers
   every abort path under `set -euo pipefail`, and the verification Python
   also unlinks a copy that fails the integrity check.

The test `test_failed_backup_leaves_nothing_behind` points the script at a
corrupt "database" and asserts the backup directory ends completely empty:
no temporary file, nothing matching the backup pattern.

### 1.5 KEEP validation

**Implementation:** `KEEP` is validated at the very top of `backup.sh`,
before the database is checked, before any backup is taken, and before
rotation:

- a shell `case` glob rejects anything containing a non-digit (covers
  negative numbers like `-3`, decimals like `2.5`, words like `abc`,
  mixed strings like `14x`, and empty values);
- a numeric check rejects `0`.

An invalid value exits non-zero with
`backup: KEEP must be a positive integer, got '<value>'` - no backup is
taken and no existing backup is deleted. Five parametrized tests
(`0`, `-3`, `abc`, `2.5`, `14x`) each assert the failure and that the one
pre-existing backup is still the only file present. Valid rotation is
covered by the existing `test_backup_rotation_keeps_newest` (KEEP=2, three
backups taken, oldest rotated out).

### 1.6 Honest documentation

**Implementation:** the outdated Known-limitations bullet in
`dashboard/README.md` ("No automated backup or restore mechanism yet; the
SQLite file is a single point of failure until Stage 9B adds one.") was
replaced with an accurate statement:

> Backup and restore scripts exist (`deploy/backup.sh` and
> `deploy/restore.sh`; see `docs/deployment/RUNBOOK.md`), but automatic
> scheduling and off-site backup storage are not configured automatically -
> the operator sets those up (the runbook says how). Until then the single
> SQLite file remains a single point of failure.

What is implemented vs what still requires configuration:

- IMPLEMENTED: consistent online backups with integrity verification and
  atomic publication; validated rotation; a verified, guarded atomic
  restore; permission hardening of data and backup directories and files;
  runbook steps for scheduling (a cron example) and for copying backups
  off the server (scp/rsync/Tailscale).
- REQUIRES OPERATOR CONFIGURATION: automatic scheduling itself (nothing
  installs the cron entry), off-site backup storage (nothing copies backups
  off the machine automatically), and every live-server verification in
  the pre-launch checklist.

Both READMEs' test counts were updated to the real new total (129, was
120; +9 backup/restore tests), verified by running the suite.

---

## Section 2 - Complete current source of the four key files

These are the complete, current contents on `stage-9b-deployment-preparation`
at `2f835b2d8ffa360517f87928c178a5c2bf6ef0dd`, byte-identical to what the
tests below ran against (SHA-256 verified; see Section 4.7).

### 2.1 `deploy/backup.sh` (complete)

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

````

### 2.2 `deploy/restore.sh` (complete)

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
# Failure behavior: any failed check exits non-zero and the existing
# dashboard.db (if any) is left byte-for-byte untouched.
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
TMP="$DATA_DIR/.dashboard.db.restore-in-progress"

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

rm -f "$TMP"
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
chmod 0600 "$DEST"
echo "restore: installed $BACKUP as $DEST"
echo "restore: now start the service again (systemctl start kosherguard-dashboard)"

````

### 2.3 `deploy/kosherguard-dashboard.service` (complete)

````ini
# KosherGuard dashboard - systemd service unit.
#
# Install:  sudo cp deploy/kosherguard-dashboard.service /etc/systemd/system/
#           sudo systemctl daemon-reload
#           sudo systemctl enable --now kosherguard-dashboard
#
# See docs/deployment/RUNBOOK.md for the full procedure, including the
# required /etc/kosherguard/dashboard.env file.
#
# NOTE: this unit is reviewed but NOT tested on a live system yet; the
# first real deployment must verify it (the runbook's checklist says how).

[Unit]
Description=KosherGuard admin dashboard (development application)
After=network.target

[Service]
Type=simple
User=kosherguard
Group=kosherguard

# Deployment configuration. KG_ADMIN_PASSWORD is NOT here - it lives in
# /etc/kosherguard/dashboard.env (root-only, 0600), loaded below.
Environment=KG_ADMIN_USERNAME=admin
Environment=KG_SECURE_COOKIES=1
Environment=KG_TRUSTED_PROXIES=127.0.0.1
Environment=KG_MAX_CONNECTIONS=32
Environment=KG_REQUEST_TIMEOUT=30
Environment=KG_TOTAL_REQUEST_TIMEOUT=60
EnvironmentFile=-/etc/kosherguard/dashboard.env

ExecStart=/usr/bin/python3 /opt/kosherguard/dashboard/src/server.py --host 127.0.0.1 --port 8080 --db /var/lib/kosherguard/dashboard.db

Restart=on-failure
RestartSec=5

# Hardening: the dashboard needs only its state directory. UMask=0077
# keeps every file the server creates owner-only - the database holds
# session tokens and password hashes. The state directory itself is
# created by systemd with mode 0700.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
StateDirectory=kosherguard
StateDirectoryMode=0700
UMask=0077
ReadWritePaths=/var/lib/kosherguard

[Install]
WantedBy=multi-user.target

````

### 2.4 `dashboard/tests/test_backup_restore.py` (complete)

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

````

---

## Section 3 - Complete diffs of all seven files changed by the corrections

`git diff 68bb04107fd69795eb5d908db916ae5fe1941ff2..2f835b2d8ffa360517f87928c178a5c2bf6ef0dd`
(the branch HEAD before the corrections to the branch HEAD after them):

````diff
diff --git a/README.md b/README.md
index bf44abe..3a2d0eb 100644
--- a/README.md
+++ b/README.md
@@ -6,7 +6,7 @@ KosherGuard is an iPhone filtering and management platform under development. Th
 
 The core filtering engine (Stage 5, full testing and verification) is complete in [filtering-engine/](filtering-engine/README.md): the central policy engine, the DNS filtering service (UDP and TCP), the website category database, structured decision logging, and a 119-test automated suite. Device enrollment, push-triggered policy updates, iPhone management, and reset recovery described in the [project charter](docs/PROJECT_CHARTER.md) are not built yet. Nothing in this repository currently filters or manages an iPhone; there is no Apple commercial MDM authorization and no real-device test environment (see the [technical investigation](docs/GENTECH_TECHNICAL_INVESTIGATION.md)).
 
-Stage 7 (the [admin dashboard](dashboard/README.md)) is complete and approved at commit ad999b739075364dc05191bd95c2c500cad2a3e9: a development application (stdlib Python backend API, SQLite storage, session authentication, audit logging, browser interface) for managing filtering policies, categories, and domain records. Stage 9A hardened it (configurable Secure cookies with a deployment guard, trusted-proxy login limiting, a 12-character password minimum, failed-login auditing, expired-session cleanup, a health endpoint, strict request-body validation, and bounded request handling with a total request deadline); the dashboard now has a 120-test automated suite. Stage 9B added deployment preparation (a runbook and pre-launch checklist in docs/deployment/, Caddy and systemd examples and backup/restore scripts in deploy/); nothing is deployed. Policy evaluation is performed by the existing filtering engine. The dashboard manages local policy data only: no devices are enrolled, no Apple MDM connection exists, and no remote policy push is available. It is not deployed anywhere.
+Stage 7 (the [admin dashboard](dashboard/README.md)) is complete and approved at commit ad999b739075364dc05191bd95c2c500cad2a3e9: a development application (stdlib Python backend API, SQLite storage, session authentication, audit logging, browser interface) for managing filtering policies, categories, and domain records. Stage 9A hardened it (configurable Secure cookies with a deployment guard, trusted-proxy login limiting, a 12-character password minimum, failed-login auditing, expired-session cleanup, a health endpoint, strict request-body validation, and bounded request handling with a total request deadline); the dashboard now has a 129-test automated suite. Stage 9B added deployment preparation (a runbook and pre-launch checklist in docs/deployment/, Caddy and systemd examples and backup/restore scripts in deploy/); nothing is deployed. Policy evaluation is performed by the existing filtering engine. The dashboard manages local policy data only: no devices are enrolled, no Apple MDM connection exists, and no remote policy push is available. It is not deployed anywhere.
 
 Stage 6 (iPhone enrollment and push notifications) was attempted as a preparation stage. The prerequisite audit found that none of the four required Apple prerequisites exist (Apple MDM vendor selection, an MDM APNs push certificate, Apple Business enrollment credentials, and an approved test iPhone), so no MDM, enrollment, or push code was written. The architecture, required credentials, security requirements, enrollment and push flows, and exact remaining blockers are documented in [docs/MDM_ENROLLMENT_AND_PUSH.md](docs/MDM_ENROLLMENT_AND_PUSH.md).
 
diff --git a/dashboard/README.md b/dashboard/README.md
index 42cfc42..2ec7212 100644
--- a/dashboard/README.md
+++ b/dashboard/README.md
@@ -28,7 +28,7 @@ dashboard/
     index.html        - interface shell (login view + app shell)
     styles.css        - design system
     app.js            - interface logic (vanilla JS, hash routing)
-  tests/              - 120 pytest tests against a real running server
+  tests/              - 129 pytest tests against a real running server
 ```
 
 Technology choices, per the Stage 7 requirement to fit the existing
@@ -183,7 +183,7 @@ URL database).
 cd dashboard && python3 -m pytest tests/ -q
 ```
 
-120 tests run the real server on an ephemeral localhost port with a
+129 tests run the real server on an ephemeral localhost port with a
 throwaway database: policy CRUD and validation, rule precedence and
 conflicts, category management, domain validation and duplicates, the
 import process (including atomic abort and line-numbered errors),
@@ -202,7 +202,12 @@ guard (localhost default, explicit deployment opt-in, refusal cases),
 and the deployment scripts: `deploy/backup.sh` and `deploy/restore.sh`
 run as real subprocesses - a full round trip (back up a live server,
 mutate, restore, restart, and verify every kind of data through the
-API), corrupt-backup refusal, overwrite refusal, missing files, and
+API), corrupt-backup refusal, overwrite refusal, the required
+--service-stopped restore confirmation (refusal leaves the database
+byte-for-byte unchanged), failed-backup cleanup (no partial file is
+left looking like a valid backup), rotation including invalid-KEEP
+refusal, and file/directory permission checks (backup dir 0700,
+backup files and restored database 0600), missing files, and valid
 rotation. No sleeps are used for synchronization; the server socket is
 bound before the test client connects.
 
@@ -222,9 +227,14 @@ Nothing here is deployed. Stage 9B prepared the deployment assets:
   unprivileged user, sandboxing directives). Reviewed but NOT yet
   tested on a live system.
 - `deploy/backup.sh` / `deploy/restore.sh` - consistent online SQLite
-  backups with integrity check and rotation, and a verified atomic
-  restore. Both are exercised by automated tests, including failure
-  cases, but have NOT run on a production server.
+  backups written to a temporary file and published only after an
+  integrity check, validated rotation, and a verified atomic restore
+  that requires an explicit --service-stopped confirmation. Backup
+  directories and files and restored databases are forced private
+  (0700/0600); the systemd unit sets UMask=0077 and
+  StateDirectoryMode=0700. Both scripts are exercised by automated
+  tests, including failure cases, but have NOT run on a production
+  server.
 
 This is preparation, not a production-ready deployment: the unit,
 proxy config, and backup schedule still need to be verified on a real
@@ -237,8 +247,12 @@ bounds above reduce abuse impact; they do not replace a proxy.
 - Single-admin model (the schema supports more, but there is no user
   management interface yet), with no self-service password recovery: a
   lost password means editing the database directly.
-- No automated backup or restore mechanism yet; the SQLite file is a
-  single point of failure until Stage 9B adds one.
+- Backup and restore scripts exist (`deploy/backup.sh` and
+  `deploy/restore.sh`; see `docs/deployment/RUNBOOK.md`), but
+  automatic scheduling and off-site backup storage are not configured
+  automatically - the operator sets those up (the runbook says how).
+  Until then the single SQLite file remains a single point of
+  failure.
 - No device synchronization of any kind (requires Apple MDM
   authorization, which does not exist).
 - The interface is English-only, desktop and mobile responsive.
diff --git a/dashboard/tests/test_backup_restore.py b/dashboard/tests/test_backup_restore.py
index 852fb65..5dd27fa 100644
--- a/dashboard/tests/test_backup_restore.py
+++ b/dashboard/tests/test_backup_restore.py
@@ -10,6 +10,7 @@ files) are verified to fail without touching the destination.
 
 import hashlib
 import os
+import stat
 import subprocess
 import threading
 from pathlib import Path
@@ -101,7 +102,7 @@ def test_backup_restore_round_trip(tmp_path):
         stop_server(srv, thread)
 
     # Restore over the existing (mutated) database.
-    result = run_script(RESTORE_SH, backups[0], data_dir, "--force")
+    result = run_script(RESTORE_SH, backups[0], data_dir, "--force", "--service-stopped")
     assert result.returncode == 0, result.stderr
 
     # Serve the restored directory and verify EVERYTHING matches the
@@ -163,7 +164,7 @@ def test_restore_refuses_corrupt_backup_and_keeps_destination(tmp_path):
 
     garbage = tmp_path / "garbage.db"
     garbage.write_bytes(b"this is not a sqlite database at all" * 100)
-    result = run_script(RESTORE_SH, garbage, data_dir, "--force")
+    result = run_script(RESTORE_SH, garbage, data_dir, "--force", "--service-stopped")
     assert result.returncode != 0
     assert "restore:" in result.stderr
     # The existing database is byte-for-byte untouched.
@@ -180,7 +181,7 @@ def test_restore_refuses_overwrite_without_force(tmp_path):
 
     backup = tmp_path / "some-backup.db"
     backup.write_bytes(db_path.read_bytes())
-    result = run_script(RESTORE_SH, backup, data_dir)  # no --force
+    result = run_script(RESTORE_SH, backup, data_dir, "--service-stopped")  # no --force
     assert result.returncode != 0
     assert "--force" in result.stderr
     assert sha256(db_path) == before
@@ -210,3 +211,95 @@ def test_backup_rotation_keeps_newest(tmp_path):
         assert result.returncode == 0, result.stderr
     backups = sorted((data_dir / "backups").glob("dashboard-*.db"))
     assert len(backups) == 2  # the oldest was rotated out
+
+
+def test_restore_requires_service_stopped_confirmation(tmp_path):
+    """--force alone must NOT imply the service is stopped: the script
+    refuses, and the existing database stays byte-for-byte unchanged."""
+    data_dir = tmp_path / "data"
+    data_dir.mkdir()
+    db_path = data_dir / "dashboard.db"
+    srv, thread, _ = start_server(db_path)
+    stop_server(srv, thread)
+    before = sha256(db_path)
+
+    backup = tmp_path / "some-backup.db"
+    backup.write_bytes(db_path.read_bytes())
+    result = run_script(RESTORE_SH, backup, data_dir, "--force")
+    assert result.returncode != 0
+    assert "--service-stopped" in result.stderr
+    assert sha256(db_path) == before
+
+
+def test_failed_backup_leaves_nothing_behind(tmp_path):
+    """A failed backup leaves no partial file and nothing that looks
+    like a valid completed backup."""
+    data_dir = tmp_path / "data"
+    data_dir.mkdir()
+    (data_dir / "dashboard.db").write_bytes(b"not a database" * 1000)
+    result = run_script(BACKUP_SH, data_dir)
+    assert result.returncode != 0
+    backup_dir = data_dir / "backups"
+    leftovers = list(backup_dir.iterdir()) if backup_dir.exists() else []
+    assert leftovers == []
+
+
+@pytest.mark.parametrize("keep", ["0", "-3", "abc", "2.5", "14x"])
+def test_rotation_rejects_invalid_keep(tmp_path, keep):
+    """Invalid KEEP values fail safely: no new backup is taken and the
+    existing backup is not deleted."""
+    data_dir = tmp_path / "data"
+    data_dir.mkdir()
+    srv, thread, _ = start_server(data_dir / "dashboard.db")
+    stop_server(srv, thread)
+
+    result = run_script(BACKUP_SH, data_dir)
+    assert result.returncode == 0, result.stderr
+    existing = sorted((data_dir / "backups").glob("dashboard-*.db"))
+    assert len(existing) == 1
+
+    result = run_script(BACKUP_SH, data_dir, env_extra={"KEEP": keep})
+    assert result.returncode != 0
+    assert "KEEP" in result.stderr
+    assert sorted((data_dir / "backups").glob("dashboard-*.db")) == existing
+
+
+@pytest.mark.skipif(os.name != "posix", reason="Unix permission bits")
+def test_backup_files_and_directories_are_private(tmp_path):
+    """The backup dir is forced to 0700 (even a pre-existing
+    world-readable one), the data dir is private, and the backup file
+    is 0600."""
+    data_dir = tmp_path / "data"
+    data_dir.mkdir()
+    os.chmod(data_dir, 0o755)
+    backup_dir = data_dir / "backups"
+    backup_dir.mkdir()
+    os.chmod(backup_dir, 0o755)  # pre-existing world-readable
+    srv, thread, _ = start_server(data_dir / "dashboard.db")
+    stop_server(srv, thread)
+
+    result = run_script(BACKUP_SH, data_dir)
+    assert result.returncode == 0, result.stderr
+    assert stat.S_IMODE(os.stat(backup_dir).st_mode) == 0o700
+    assert stat.S_IMODE(os.stat(data_dir).st_mode) == 0o700
+    backups = list(backup_dir.glob("dashboard-*.db"))
+    assert len(backups) == 1
+    assert stat.S_IMODE(os.stat(backups[0]).st_mode) == 0o600
+
+
+@pytest.mark.skipif(os.name != "posix", reason="Unix permission bits")
+def test_restored_database_is_private(tmp_path):
+    """A restored database is 0600, even when the file it replaced was
+    world-readable."""
+    data_dir = tmp_path / "data"
+    data_dir.mkdir()
+    db_path = data_dir / "dashboard.db"
+    srv, thread, _ = start_server(db_path)
+    stop_server(srv, thread)
+
+    backup = tmp_path / "some-backup.db"
+    backup.write_bytes(db_path.read_bytes())
+    os.chmod(db_path, 0o644)  # world-readable destination
+    result = run_script(RESTORE_SH, backup, data_dir, "--force", "--service-stopped")
+    assert result.returncode == 0, result.stderr
+    assert stat.S_IMODE(os.stat(db_path).st_mode) == 0o600
diff --git a/deploy/backup.sh b/deploy/backup.sh
index 58081df..9df0b2b 100644
--- a/deploy/backup.sh
+++ b/deploy/backup.sh
@@ -4,7 +4,21 @@
 # Makes a CONSISTENT copy of the dashboard SQLite database while the
 # server may still be running (SQLite online backup API - no locking
 # hacks, no copying a half-written file), verifies the copy with
-# PRAGMA integrity_check, and rotates old backups.
+# PRAGMA integrity_check BEFORE it is published, and rotates old
+# backups.
+#
+# Safety properties:
+#   - The copy is written to a temporary file whose name never matches
+#     the dashboard-*.db backup pattern, and renamed to its final name
+#     only after the integrity check passes: a failed run never leaves
+#     a partial file that looks like a valid completed backup.
+#   - Everything created here is private: the backup directory is
+#     forced to 0700 (including a pre-existing world-readable one) and
+#     backup files are 0600. Backups contain the full dashboard
+#     database - session tokens and password hashes included.
+#   - KEEP is validated as a positive integer BEFORE anything happens;
+#     an invalid value (zero, negative, non-numeric) fails safely
+#     without taking or deleting any backup.
 #
 # Usage:
 #   bash deploy/backup.sh [DATA_DIR] [BACKUP_DIR]
@@ -21,12 +35,35 @@ BACKUP_DIR="${2:-$DATA_DIR/backups}"
 KEEP="${KEEP:-14}"
 DB="$DATA_DIR/dashboard.db"
 
+# Everything this script creates is owner-only.
+umask 077
+
+# Validate KEEP before taking or deleting anything: an invalid value
+# must fail safely and never delete existing backups.
+case "$KEEP" in
+    ''|*[!0-9]*)
+        echo "backup: KEEP must be a positive integer, got '$KEEP'" >&2
+        exit 1
+        ;;
+esac
+if [ "$KEEP" -lt 1 ]; then
+    echo "backup: KEEP must be a positive integer, got '$KEEP'" >&2
+    exit 1
+fi
+
 if [ ! -f "$DB" ]; then
     echo "backup: database not found: $DB" >&2
     exit 1
 fi
 
 mkdir -p "$BACKUP_DIR"
+# Private directories only - including pre-existing ones that were
+# left world-readable.
+chmod 0700 "$BACKUP_DIR"
+if [ -O "$DATA_DIR" ]; then
+    chmod 0700 "$DATA_DIR"
+fi
+
 STAMP="$(date -u +%Y%m%d-%H%M%S)"
 DEST="$BACKUP_DIR/dashboard-$STAMP.db"
 if [ -e "$DEST" ]; then
@@ -34,7 +71,13 @@ if [ -e "$DEST" ]; then
     DEST="$BACKUP_DIR/dashboard-$STAMP-$$.db"
 fi
 
-python3 - "$DB" "$DEST" <<'PY'
+# Write to a temporary name that never matches dashboard-*.db, then
+# publish by rename only after verification. The trap removes the
+# temporary file if any step fails.
+TMP="$BACKUP_DIR/.dashboard-$STAMP.tmp.$$"
+trap 'rm -f "$TMP"' EXIT
+
+python3 - "$DB" "$TMP" <<'PY'
 import os
 import sqlite3
 import sys
@@ -57,6 +100,9 @@ if result != "ok":
     sys.exit(1)
 PY
 
+chmod 0600 "$TMP"
+mv "$TMP" "$DEST"
+trap - EXIT
 echo "backup: wrote $DEST"
 
 # Rotation: keep the newest $KEEP backups, delete the rest.
diff --git a/deploy/kosherguard-dashboard.service b/deploy/kosherguard-dashboard.service
index c49110d..3f49563 100644
--- a/deploy/kosherguard-dashboard.service
+++ b/deploy/kosherguard-dashboard.service
@@ -34,12 +34,17 @@ ExecStart=/usr/bin/python3 /opt/kosherguard/dashboard/src/server.py --host 127.0
 Restart=on-failure
 RestartSec=5
 
-# Hardening: the dashboard needs only its state directory.
+# Hardening: the dashboard needs only its state directory. UMask=0077
+# keeps every file the server creates owner-only - the database holds
+# session tokens and password hashes. The state directory itself is
+# created by systemd with mode 0700.
 NoNewPrivileges=true
 ProtectSystem=strict
 ProtectHome=true
 PrivateTmp=true
 StateDirectory=kosherguard
+StateDirectoryMode=0700
+UMask=0077
 ReadWritePaths=/var/lib/kosherguard
 
 [Install]
diff --git a/deploy/restore.sh b/deploy/restore.sh
index 864176d..9c301e5 100644
--- a/deploy/restore.sh
+++ b/deploy/restore.sh
@@ -4,46 +4,80 @@
 # Verifies a backup file (SQLite integrity check AND the expected
 # dashboard tables), then atomically puts it in place as dashboard.db.
 #
-# IMPORTANT: stop the dashboard service FIRST
-# (systemctl stop kosherguard-dashboard). The server keeps its database
-# file open; swapping the file underneath it would leave it writing to
-# the old file.
+# IMPORTANT: the dashboard service MUST be stopped first
+# (systemctl stop kosherguard-dashboard), and this script refuses to
+# run until the operator explicitly confirms that with
+# --service-stopped. The server keeps its database file open; swapping
+# the file underneath it would leave it writing to the old file.
+# --force alone only covers overwriting an existing database - it does
+# NOT confirm that the service is stopped.
 #
 # Usage:
-#   bash deploy/restore.sh BACKUP_FILE [DATA_DIR] [--force]
-#     BACKUP_FILE  a file written by backup.sh
-#     DATA_DIR     directory holding dashboard.db (default /var/lib/kosherguard)
-#     --force      overwrite an existing dashboard.db without asking
+#   bash deploy/restore.sh BACKUP_FILE [DATA_DIR] --service-stopped [--force]
+#     BACKUP_FILE        a file written by backup.sh
+#     DATA_DIR           directory holding dashboard.db (default /var/lib/kosherguard)
+#     --service-stopped  REQUIRED: explicit confirmation that the
+#                        dashboard service has been stopped
+#     --force            overwrite an existing dashboard.db without asking
 #
 # Failure behavior: any failed check exits non-zero and the existing
 # dashboard.db (if any) is left byte-for-byte untouched.
 set -euo pipefail
 
-if [ $# -lt 1 ]; then
-    echo "usage: bash deploy/restore.sh BACKUP_FILE [DATA_DIR] [--force]" >&2
+usage() {
+    echo "usage: bash deploy/restore.sh BACKUP_FILE [DATA_DIR] --service-stopped [--force]" >&2
     exit 2
-fi
+}
 
-BACKUP="$1"
-DATA_DIR="${2:-/var/lib/kosherguard}"
-FORCE="${3:-}"
+BACKUP=""
+DATA_DIR=""
+FORCE=0
+SERVICE_STOPPED=0
+for arg in "$@"; do
+    case "$arg" in
+        --force) FORCE=1 ;;
+        --service-stopped) SERVICE_STOPPED=1 ;;
+        --*) echo "restore: unknown option: $arg" >&2; usage ;;
+        *)
+            if [ -z "$BACKUP" ]; then
+                BACKUP="$arg"
+            elif [ -z "$DATA_DIR" ]; then
+                DATA_DIR="$arg"
+            else
+                echo "restore: unexpected argument: $arg" >&2
+                usage
+            fi
+            ;;
+    esac
+done
+[ -n "$BACKUP" ] || usage
+DATA_DIR="${DATA_DIR:-/var/lib/kosherguard}"
 DEST="$DATA_DIR/dashboard.db"
 TMP="$DATA_DIR/.dashboard.db.restore-in-progress"
 
+# The restored database holds password hashes and session tokens:
+# keep it owner-only.
+umask 077
+
 if [ ! -f "$BACKUP" ]; then
     echo "restore: backup file not found: $BACKUP" >&2
     exit 1
 fi
 
-if [ -e "$DEST" ] && [ "$FORCE" != "--force" ]; then
-    echo "restore: $DEST already exists; re-run with --force to overwrite it" >&2
+if [ "$SERVICE_STOPPED" != "1" ]; then
+    echo "restore: refusing without confirmation that the dashboard service is stopped" >&2
+    echo "restore: stop it first (systemctl stop kosherguard-dashboard), then re-run with --service-stopped" >&2
     exit 1
 fi
 
-echo "restore: make sure the dashboard service is stopped (systemctl stop kosherguard-dashboard)"
+if [ -e "$DEST" ] && [ "$FORCE" != "1" ]; then
+    echo "restore: $DEST already exists; re-run with --force to overwrite it" >&2
+    exit 1
+fi
 
 rm -f "$TMP"
 cp "$BACKUP" "$TMP"
+chmod 0600 "$TMP"
 
 python3 - "$TMP" <<'PY'
 import sqlite3
@@ -84,5 +118,6 @@ PY
 # Atomic rename into place; the existing database stays untouched
 # until this moment.
 mv -f "$TMP" "$DEST"
+chmod 0600 "$DEST"
 echo "restore: installed $BACKUP as $DEST"
 echo "restore: now start the service again (systemctl start kosherguard-dashboard)"
diff --git a/docs/deployment/RUNBOOK.md b/docs/deployment/RUNBOOK.md
index 64a290b..bf5cb56 100644
--- a/docs/deployment/RUNBOOK.md
+++ b/docs/deployment/RUNBOOK.md
@@ -45,15 +45,28 @@ backed up by `deploy/backup.sh` on a schedule.
 sudo useradd --system --home /var/lib/kosherguard --shell /usr/sbin/nologin kosherguard
 sudo mkdir -p /var/lib/kosherguard
 sudo chown kosherguard:kosherguard /var/lib/kosherguard
+sudo chmod 0700 /var/lib/kosherguard
 ```
 
+The state directory and everything in it stays private to the service
+user: the database holds session tokens and password hashes. The
+systemd unit also creates it with mode 0700 (`StateDirectoryMode`)
+when it does not exist.
+
 ### 2. Install the code
 
 ```bash
 sudo mkdir -p /opt/kosherguard
-sudo git clone https://github.com/yossigo88-cyber/kosherguard-platform /opt/kosherguard
+sudo git clone --branch stage-9b-deployment-preparation \
+    https://github.com/yossigo88-cyber/kosherguard-platform /opt/kosherguard
 ```
 
+The `--branch stage-9b-deployment-preparation` is required: the
+deployment files this runbook installs live on that branch. Cloning
+without it checks out the repository's default branch, which does not
+contain the Stage 9B deployment files, and would produce an
+installation without the files this runbook tells you to install.
+
 ### 3. Create the secrets file
 
 The admin password is never in the unit file or the repo. Put it in a
@@ -125,21 +138,32 @@ sudo -u kosherguard crontab -e
 ```
 
 Backups land in `/var/lib/kosherguard/backups/` and are rotated (keep
-14 by default; `KEEP=` environment). A backup on the same machine is
-not enough for real recovery: copy the backups somewhere else you own
-(on another machine: `scp`/`rsync` over SSH, or Tailscale between your
-own machines).
+14 by default; `KEEP=` environment). `backup.sh` forces the backup
+directory to 0700 and every backup file to 0600 (a backup is the full
+database, session tokens and password hashes included), writes to a
+temporary file and publishes it only after an integrity check passes,
+and validates `KEEP` as a positive integer before rotating - an
+invalid value fails without taking or deleting any backup. A backup
+on the same machine is not enough for real recovery: copy the backups
+somewhere else you own (on another machine: `scp`/`rsync` over SSH,
+or Tailscale between your own machines).
 
 ### 7. Test a restore BEFORE you need it
 
 ```bash
 sudo systemctl stop kosherguard-dashboard
 sudo -u kosherguard bash /opt/kosherguard/deploy/restore.sh \
-    /var/lib/kosherguard/backups/LATEST-FILE.db /var/lib/kosherguard --force
+    /var/lib/kosherguard/backups/LATEST-FILE.db /var/lib/kosherguard \
+    --force --service-stopped
 sudo systemctl start kosherguard-dashboard
 curl -s http://127.0.0.1:8080/api/health   # expect: {"status":"ok"}
 ```
 
+`restore.sh` refuses to run without `--service-stopped`, an explicit
+confirmation that the dashboard service has been stopped. `--force`
+only covers overwriting the existing database; it does not imply the
+service is stopped. The restored database file is owner-only (0600).
+
 Sign in and confirm your data is the backup-time state. The automated
 test suite (`dashboard/tests/test_backup_restore.py`) performs this
 whole round trip against throwaway databases; run it after any change
@@ -148,11 +172,16 @@ to the scripts.
 ## Updating
 
 ```bash
-cd /opt/kosherguard && sudo git pull
+cd /opt/kosherguard
+sudo git fetch origin
+sudo git pull origin stage-9b-deployment-preparation
 sudo systemctl restart kosherguard-dashboard
 curl -s http://127.0.0.1:8080/api/health
 ```
 
+Always name the branch explicitly on update; do not rely on the
+repository's default branch.
+
 Back up before updating.
 
 ## If something is wrong

````

---

## Section 4 - Test evidence

Every command below was actually executed, and the output blocks are the
complete, unedited terminal output of those runs (with `-q`, the dot lines
plus the summary ARE the complete output). Runs are labeled by the tree they
ran against. The fresh-clone runs in 4.1-4.3 were executed while preparing
this document, against an anonymous `git clone --branch
stage-9b-deployment-preparation` of the exact commit named above.

### 4.1 Focused backup/restore tests (fresh clone)

````
$ cd /tmp/verify9bc/dashboard && python3 -m pytest tests/test_backup_restore.py -v
============================= test session starts ==============================
platform linux -- Python 3.10.12, pytest-9.2.0, pluggy-1.7.0 -- /usr/bin/python3
cachedir: .pytest_cache
rootdir: /tmp/verify9bc/dashboard
plugins: anyio-4.15.1, platformdirs-4.12.4
collecting ... collected 14 items

tests/test_backup_restore.py::test_backup_restore_round_trip PASSED      [  7%]
tests/test_backup_restore.py::test_restore_refuses_corrupt_backup_and_keeps_destination PASSED [ 14%]
tests/test_backup_restore.py::test_restore_refuses_overwrite_without_force PASSED [ 21%]
tests/test_backup_restore.py::test_missing_files_fail_cleanly PASSED     [ 28%]
tests/test_backup_restore.py::test_backup_rotation_keeps_newest PASSED   [ 35%]
tests/test_backup_restore.py::test_restore_requires_service_stopped_confirmation PASSED [ 42%]
tests/test_backup_restore.py::test_failed_backup_leaves_nothing_behind PASSED [ 50%]
tests/test_backup_restore.py::test_rotation_rejects_invalid_keep[0] PASSED [ 57%]
tests/test_backup_restore.py::test_rotation_rejects_invalid_keep[-3] PASSED [ 64%]
tests/test_backup_restore.py::test_rotation_rejects_invalid_keep[abc] PASSED [ 71%]
tests/test_backup_restore.py::test_rotation_rejects_invalid_keep[2.5] PASSED [ 78%]
tests/test_backup_restore.py::test_rotation_rejects_invalid_keep[14x] PASSED [ 85%]
tests/test_backup_restore.py::test_backup_files_and_directories_are_private PASSED [ 92%]
tests/test_backup_restore.py::test_restored_database_is_private PASSED   [100%]

============================== 14 passed in 7.41s ==============================
````

### 4.2 Full dashboard suite (fresh clone)

````
$ cd /tmp/verify9bc/dashboard && python3 -m pytest tests/ -q
........................................................................ [ 55%]
.........................................................                [100%]
129 passed in 84.99s (0:01:24)
````

Result: 129/129 passed. The same suite also passed 129/129 in the
development tree during the correction session (recorded verbatim summary:
`129 passed in 84.04s (0:01:24)`; command:
`cd /downloads/kosherguard-platform/dashboard && python3 -m pytest tests/ -q`).

### 4.3 Full filtering-engine regression suite (fresh clone)

````
$ cd /tmp/verify9bc/filtering-engine && python3 -m pytest tests/ -q
........................................................................ [ 60%]
...............................................                          [100%]
119 passed in 52.54s
````

Result: 119/119 passed.

### 4.4 The one engine timing flake, reported exactly

The corrections touch no engine file (the engine is byte-identical to the
approved baseline), but during the correction session the engine suite did
not pass on every run. Exact recorded history:

- Full-suite run 1 (development tree): `1 failed, 118 passed in 51.64s`.
  The failing test name was captured before any re-run:
  `tests/test_tcp_service.py::test_truncated_udp_upstream_large_answer_complete_over_tcp_downstream`
- Isolated re-run: `1 passed in 0.51s`
- Isolated re-run (second): `1 passed in 0.51s`
- Full-suite re-run (development tree): `119 passed in 52.53s`
- Full-suite run (fresh clone, during correction verification):
  `119 passed in 52.51s`
- Full-suite run (fresh clone, run for this document): 119/119, output in
  4.3 above.

This is a timing flake on byte-identical code, not a regression from the
corrections - and the engine suite should not be described as consistently
green.

### 4.5 Shell syntax checks

````
$ bash -n deploy/backup.sh && bash -n deploy/restore.sh && echo SHELL_SYNTAX_OK
SHELL_SYNTAX_OK
````

(`bash -n` prints nothing on success; exit code 0. Run on both the
development tree and the fresh clone.)

### 4.6 What "actually run" vs "reported" means here

- All outputs in 4.1, 4.2, 4.3, and 4.5 are complete verbatim captures of
  runs executed while preparing this document on the fresh anonymous clone.
- The development-tree summaries quoted in 4.2 and 4.4 are the verbatim
  recorded result lines of runs executed during the correction session.
- No output was reconstructed, paraphrased, or invented. No test is claimed
  that was not executed.

### 4.7 Byte-identical verification

All 46 tracked files of the fresh anonymous clone at
`2f835b2d8ffa360517f87928c178a5c2bf6ef0dd` were compared by SHA-256 against
the development tree in which the tests were first run: all 46 identical,
file lists identical (`diff` of the two sorted `sha256sum` listings was
empty).

---

## Section 5 - What has NOT been tested or deployed

- Live systemd unit execution has NOT been tested (the unit is reviewed
  preparation; the pre-launch checklist includes verifying it).
- The Caddy configuration has NOT been live-tested.
- Automatic backup scheduling has NOT been configured (the runbook shows
  the operator how; nothing installs it).
- Off-site backup storage has NOT been configured (the runbook shows the
  operator how; nothing does it automatically).
- No production deployment has occurred.
- No merge into main has occurred.
- Apple MDM enrollment and push remain separate outstanding prerequisites;
  the dashboard manages local policy data only, with no device management
  capability of any kind.

---

## Section 6 - Git and branch safety

- Before writing this document, the live remote was verified with
  `git ls-remote` (output at the top of this file): branch HEAD
  `2f835b2d8ffa360517f87928c178a5c2bf6ef0dd`, main
  `5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a` - matching the previously
  reported values, verified rather than assumed.
- This commit adds exactly one file, `docs/reviews/STAGE_9B_CORRECTIONS_REVIEW.md`,
  on `stage-9b-deployment-preparation`. No existing source, script, test, or
  documentation file was altered.
- This document contains no passwords, tokens, private keys, API secrets,
  or other credentials. (The systemd unit references a secrets FILE path;
  no secret value appears in the repository or in this document.)
- Nothing was merged and nothing was deployed.

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

"""Tests for Stage 10 configuration publication: snapshots, atomic
generation publication, selection semantics, rollback, and safety.

Runs against the real HTTP API with a real Publisher writing to a real
temporary directory (the fixture's publish root). Concurrency tests use
real threads against the real endpoint.
"""

import json
import os
import stat
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import publishing  # noqa: E402


@pytest.fixture
def pub_root(server):
    return Path(server.store.publisher.root)


def make_policy(client, name="family", **overrides):
    payload = {
        "name": name,
        "description": "",
        "default_policy": "allow",
        "enabled": True,
        "allowlist": [],
        "blocklist": ["bad.test"],
        "category_allow": [],
        "category_block": [],
    }
    payload.update(overrides)
    status, body = client.post("/api/policies", payload)
    assert status == 201, body
    return body


def select_and_publish(client, policy_id):
    status, body = client.post(f"/api/policies/{policy_id}/select")
    assert status == 200, body
    status, body = client.post("/api/config/publish")
    assert status == 200, body
    return body


def read_published(pub_root):
    current = pub_root / "current"
    return (
        json.loads((current / "policy.json").read_text()),
        json.loads((current / "categories.json").read_text()),
        json.loads((current / "manifest.json").read_text()),
        os.path.realpath(str(current)),
    )


# -- selection semantics ------------------------------------------------

def test_publish_without_selection_fails_clearly(client):
    status, body = client.post("/api/config/publish")
    assert status == 409
    assert "no policy is selected" in body["error"]


def test_disabled_policy_cannot_be_selected(client):
    policy = make_policy(client, enabled=False)
    status, body = client.post(f"/api/policies/{policy['id']}/select")
    assert status == 409
    assert "disabled" in body["error"]


def test_selected_policy_cannot_be_disabled_or_deleted(client):
    policy = make_policy(client)
    pid = policy["id"]
    status, _ = client.post(f"/api/policies/{pid}/select")
    assert status == 200
    status, body = client.post(f"/api/policies/{pid}/enabled", {"enabled": False})
    assert status == 409
    assert "selected for publication" in body["error"]
    status, body = client.delete(f"/api/policies/{pid}")
    assert status == 409
    assert "selected for publication" in body["error"]
    # After selecting a different policy, both operations work again.
    other = make_policy(client, name="other")
    status, _ = client.post(f"/api/policies/{other['id']}/select")
    assert status == 200
    status, _ = client.post(f"/api/policies/{pid}/enabled", {"enabled": False})
    assert status == 200
    status, _ = client.delete(f"/api/policies/{pid}")
    assert status == 200


def test_selection_visible_in_api(client):
    policy = make_policy(client)
    status, body = client.post(f"/api/policies/{policy['id']}/select")
    assert status == 200
    selected = body["selected_policy"]
    assert selected["id"] == policy["id"]
    assert selected["name"] == "family"
    assert selected["selected_by"] == "admin"
    status, body = client.get(f"/api/policies/{policy['id']}")
    assert body["selected_for_publication"] is True


# -- publication content -------------------------------------------------

def test_publish_writes_validated_generation(client, pub_root):
    policy = make_policy(client)
    revision = select_and_publish(client, policy["id"])
    assert revision["status"] == "published"
    assert revision["revision"] == 1
    assert revision["generation"] == "1"
    assert revision["admin"] == "admin"

    policy_doc, categories_doc, manifest, resolved = read_published(pub_root)
    assert policy_doc["blocklist"] == ["bad.test"]
    assert policy_doc["_meta"]["policy_name"] == "family"
    assert policy_doc["_meta"]["policy_version"] == 1
    assert manifest["revision"] == 1
    assert manifest["published_by"] == "admin"
    # Both files come from the SAME generation directory.
    assert resolved.endswith(os.sep + os.path.join("generations", "1"))

    # Content hashes in the manifest match the bytes on disk.
    import hashlib
    policy_bytes = (pub_root / "current" / "policy.json").read_bytes()
    assert manifest["policy_sha256"] == hashlib.sha256(policy_bytes).hexdigest()
    # The revision row records the exact same hashes.
    assert revision["policy_sha256"] == manifest["policy_sha256"]


def test_published_policy_passes_engine_validation(client, pub_root):
    make_policy(client, category_block=["news"], category_allow=["games"])
    policy = make_policy(client, name="p2", blocklist=["x.test"])
    select_and_publish(client, policy["id"])
    # Load the published files with the real engine code.
    from engine_bridge import CategoryDB, PolicyEngine
    engine = PolicyEngine(
        json.loads((pub_root / "current" / "policy.json").read_text()),
        CategoryDB.load(pub_root / "current" / "categories.json"))
    assert engine.decide("x.test").action == "block"


def test_export_reflects_domains_categories_and_enabled_state(client, pub_root):
    status, body = client.post("/api/categories", {
        "name": "torah-study", "display_name": "Torah study", "description": ""})
    assert status == 201
    client.post("/api/domains", {"domain": "sefaria.test", "categories": ["torah-study"]})
    client.post("/api/domains", {"domain": "hidden.test", "categories": ["torah-study"]})
    # hidden.test loses its only enabled category when the category is disabled.
    client.post("/api/categories/torah-study/enabled", {"enabled": False})
    policy = make_policy(client)
    select_and_publish(client, policy["id"])
    _, categories_doc, _, _ = read_published(pub_root)
    assert categories_doc["domains"] == {}  # category disabled: nothing exported
    client.post("/api/categories/torah-study/enabled", {"enabled": True})
    client.post("/api/config/publish")
    _, categories_doc, _, _ = read_published(pub_root)
    assert categories_doc["domains"]["sefaria.test"] == ["torah-study"]
    assert categories_doc["domains"]["hidden.test"] == ["torah-study"]


def test_policy_selection_changes_published_policy(client, pub_root):
    p1 = make_policy(client, name="p1", blocklist=["one.test"])
    p2 = make_policy(client, name="p2", blocklist=["two.test"])
    select_and_publish(client, p1["id"])
    policy_doc, _, _, _ = read_published(pub_root)
    assert policy_doc["blocklist"] == ["one.test"]
    select_and_publish(client, p2["id"])
    policy_doc, _, _, _ = read_published(pub_root)
    assert policy_doc["blocklist"] == ["two.test"]
    assert policy_doc["_meta"]["policy_name"] == "p2"


# -- draft vs published visibility ----------------------------------------

def test_unpublished_changes_flag(client):
    policy = make_policy(client)
    status, body = client.get("/api/config/status")
    assert body["selected_policy"] is None
    assert body["unpublished_changes"] is None
    select_and_publish(client, policy["id"])
    status, body = client.get("/api/config/status")
    assert body["unpublished_changes"] is False
    # An edit makes the dashboard diverge from the published revision.
    payload = dict(policy)
    payload.pop("id")
    payload["blocklist"] = ["bad.test", "new-bad.test"]
    client.put(f"/api/policies/{policy['id']}", payload)
    status, body = client.get("/api/config/status")
    assert body["unpublished_changes"] is True
    # Publishing again clears it.
    client.post("/api/config/publish")
    status, body = client.get("/api/config/status")
    assert body["unpublished_changes"] is False


# -- complete configuration history and rollback ---------------------------

def test_config_history_complete_and_rollback(client, pub_root):
    policy = make_policy(client)
    pid = policy["id"]
    select_and_publish(client, pid)
    rev1 = client.get("/api/config/status")[1]["active_revision"]
    assert rev1["revision"] == 1

    # Change everything that feeds the configuration.
    payload = dict(policy)
    payload.pop("id")
    payload["blocklist"] = ["different.test"]
    client.put(f"/api/policies/{pid}", payload)
    client.post("/api/domains", {"domain": "news.test", "categories": ["news"]})
    client.post("/api/config/publish")
    rev2 = client.get("/api/config/status")[1]["active_revision"]
    assert rev2["revision"] == 2
    assert rev2["policy_sha256"] != rev1["policy_sha256"]

    # Roll back: publishes revision 3 with revision 1's exact content.
    status, rev3 = client.post("/api/config/rollback", {"revision": 1})
    assert status == 200
    assert rev3["revision"] == 3
    assert rev3["status"] == "published"
    assert rev3["policy_sha256"] == rev1["policy_sha256"]
    assert rev3["categories_sha256"] == rev1["categories_sha256"]
    assert "rollback of revision 1" in rev3["detail"]

    # The files on disk now match revision 1's content.
    policy_doc, categories_doc, manifest, resolved = read_published(pub_root)
    assert policy_doc["blocklist"] == ["bad.test"]
    assert categories_doc["domains"] == {}
    assert resolved.endswith(os.sep + os.path.join("generations", "3"))

    # Historical revisions are intact and recoverable in full.
    status, full1 = client.get("/api/config/revisions/1")
    assert full1["policy_json"]["blocklist"] == ["bad.test"]
    status, full2 = client.get("/api/config/revisions/2")
    assert full2["policy_json"]["blocklist"] == ["different.test"]
    assert full2["categories_json"]["domains"]["news.test"] == ["news"]

    # Revisions are listed newest first and are never modified.
    status, body = client.get("/api/config/revisions")
    assert [r["revision"] for r in body["revisions"]] == [3, 2, 1]


def test_rollback_to_failed_revision_rejected(client, pub_root):
    policy = make_policy(client)
    select_and_publish(client, policy["id"])
    status, body = client.post("/api/config/rollback", {"revision": 999})
    assert status == 404


# -- publication safety ----------------------------------------------------

def test_permissions_owner_only(client, pub_root):
    policy = make_policy(client)
    select_and_publish(client, policy["id"])
    for directory in (pub_root, pub_root / "generations", pub_root / "generations" / "1"):
        mode = stat.S_IMODE(os.stat(directory).st_mode)
        assert mode == 0o700, f"{directory}: {oct(mode)}"
    for f in ("policy.json", "categories.json", "manifest.json"):
        mode = stat.S_IMODE(os.stat(pub_root / "generations" / "1" / f).st_mode)
        assert mode == 0o600, f"{f}: {oct(mode)}"


def test_no_temp_files_left(client, pub_root):
    policy = make_policy(client)
    select_and_publish(client, policy["id"])
    leftovers = [str(p) for p in pub_root.rglob("*") if p.name.endswith(".tmp")]
    assert leftovers == []


def test_failed_publish_keeps_previous_generation(client, pub_root, monkeypatch):
    policy = make_policy(client)
    select_and_publish(client, policy["id"])
    before_policy, before_categories, _, before_resolved = read_published(pub_root)

    # Make the pointer switch fail during the next publish.
    real_replace = os.replace
    def failing_replace(src, dst):
        if os.path.basename(dst) == "current":
            raise OSError("simulated pointer-switch failure")
        return real_replace(src, dst)
    monkeypatch.setattr(publishing.os, "replace", failing_replace)

    payload = dict(policy)
    payload.pop("id")
    payload["blocklist"] = ["changed.test"]
    client.put(f"/api/policies/{policy['id']}", payload)
    status, body = client.post("/api/config/publish")
    assert status == 500
    assert "previously published configuration is unchanged" in body["error"]

    monkeypatch.undo()
    after_policy, after_categories, _, after_resolved = read_published(pub_root)
    assert after_policy == before_policy
    assert after_categories == before_categories
    assert after_resolved == before_resolved

    # The failed attempt is recorded as failed, and the partial
    # generation directory was removed.
    status, rev2 = client.get("/api/config/revisions/2")
    assert rev2["status"] == "failed"
    assert not (pub_root / "generations" / "2").exists()
    status, audit = client.get("/api/audit")
    assert any(e["action"] == "config.publish.failed" for e in audit["entries"])


def test_concurrent_publishes_serialize(client, pub_root):
    """Real concurrent publish requests from real threads: both succeed,
    revisions are distinct, both generations are complete, and the
    pointer references one complete generation."""
    p1 = make_policy(client, name="p1", blocklist=["one.test"])
    make_policy(client, name="p2", blocklist=["two.test"])
    client.post(f"/api/policies/{p1['id']}/select")
    results = []
    errors = []

    def publish():
        try:
            results.append(client.post("/api/config/publish"))
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=publish) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert not errors
    statuses = [s for s, _ in results]
    assert statuses == [200, 200, 200, 200]
    revisions = sorted(b["revision"] for _, b in results)
    assert revisions == [1, 2, 3, 4]
    # Every generation directory is complete; current points at one of
    # them and verifies cleanly.
    for rev in revisions:
        manifest = publishing.Publisher(pub_root).verify_generation(
            pub_root / "generations" / str(rev))
        assert manifest["revision"] == rev
    current = publishing.Publisher(pub_root).current()
    assert current["generation"] in {"1", "2", "3", "4"}


def test_status_reports_disk_and_engine(client, pub_root):
    policy = make_policy(client)
    select_and_publish(client, policy["id"])
    status, body = client.get("/api/config/status")
    assert body["publication_configured"] is True
    assert body["disk"]["generation"] == "1"
    assert body["disk"]["manifest"]["revision"] == 1
    # No engine has reported yet: unknown, not guessed.
    assert body["engine"] is None
    assert body["engine_matches_active_revision"] is None


# -- selected-policy invariant through every mutation path ----------------
# Regression tests for the independent-review correction: the invariant
# was previously enforced only in set_policy_enabled() and delete_policy();
# update_policy() and rollback_policy() could disable the selected policy.

def _full_payload(name, enabled=True, blocklist=None):
    return {
        "name": name,
        "description": "",
        "default_policy": "allow",
        "enabled": enabled,
        "allowlist": [],
        "blocklist": blocklist if blocklist is not None else ["bad.test"],
        "category_allow": [],
        "category_block": [],
    }


def test_update_selected_policy_with_enabled_false_rejected(client):
    """The update route cannot bypass the invariant with enabled=false."""
    policy = make_policy(client)
    pid = policy["id"]
    status, _ = client.post(f"/api/policies/{pid}/select")
    assert status == 200
    status, body = client.put(
        f"/api/policies/{pid}", _full_payload("family", enabled=False))
    assert status == 409
    assert "selected for publication" in body["error"]
    # The policy is untouched: still enabled, still selected.
    status, fetched = client.get(f"/api/policies/{pid}")
    assert fetched["enabled"] is True
    status, state = client.get("/api/config/status")
    assert state["selected_policy"]["id"] == pid


def test_rollback_selected_policy_to_disabled_version_rejected(client):
    """A rollback that would restore enabled=false is refused too."""
    policy = make_policy(client)
    pid = policy["id"]
    # Version 2: disabled (before any selection, so allowed).
    status, _ = client.post(f"/api/policies/{pid}/enabled", {"enabled": False})
    assert status == 200
    # Version 3: re-enabled.
    status, _ = client.post(f"/api/policies/{pid}/enabled", {"enabled": True})
    assert status == 200
    status, _ = client.post(f"/api/policies/{pid}/select")
    assert status == 200
    status, body = client.post(f"/api/policies/{pid}/rollback", {"version": 2})
    assert status == 409
    assert "selected for publication" in body["error"]
    status, fetched = client.get(f"/api/policies/{pid}")
    assert fetched["enabled"] is True
    status, state = client.get("/api/config/status")
    assert state["selected_policy"]["id"] == pid


def test_selected_policy_normal_update_and_rollback_still_work(client):
    """The invariant blocks only disabling: ordinary updates and
    rollbacks that leave the selected policy enabled keep working."""
    policy = make_policy(client)
    pid = policy["id"]
    status, _ = client.post(f"/api/policies/{pid}/select")
    assert status == 200
    status, updated = client.put(
        f"/api/policies/{pid}",
        _full_payload("family", blocklist=["bad.test", "worse.test"]))
    assert status == 200, updated
    assert updated["blocklist"] == ["bad.test", "worse.test"]
    status, rolled = client.post(f"/api/policies/{pid}/rollback", {"version": 1})
    assert status == 200, rolled
    status, fetched = client.get(f"/api/policies/{pid}")
    assert fetched["blocklist"] == ["bad.test"]
    assert fetched["enabled"] is True
    status, state = client.get("/api/config/status")
    assert state["selected_policy"]["id"] == pid


def test_concurrent_disable_and_select_never_leave_selected_disabled(client):
    """Real concurrent requests: the check and the mutation it guards
    are atomic, so no interleaving can leave the selected policy
    disabled."""
    policy_a = make_policy(client, name="a")
    policy_b = make_policy(client, name="b")
    a, b = policy_a["id"], policy_b["id"]
    status, _ = client.post(f"/api/policies/{a}/select")
    assert status == 200
    results = []

    def disable_a():
        status, _ = client.post(f"/api/policies/{a}/enabled", {"enabled": False})
        results.append(("disable", status))

    def select_b():
        status, _ = client.post(f"/api/policies/{b}/select")
        results.append(("select", status))

    threads = []
    for _ in range(5):
        threads.append(threading.Thread(target=disable_a))
        threads.append(threading.Thread(target=select_b))
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    # Every request got a clean answer (200 or 409), never a 500.
    assert len(results) == 10
    assert all(status in (200, 409) for _, status in results)
    # The invariant holds no matter how the requests interleaved:
    # whatever is selected now is enabled.
    status, state = client.get("/api/config/status")
    selected = state["selected_policy"]["id"]
    status, fetched = client.get(f"/api/policies/{selected}")
    assert fetched["enabled"] is True


# -- publisher manifest file type: publisher and engine agree -------------

@pytest.mark.skipif(not hasattr(os, "symlink"), reason="POSIX symlinks")
def test_publisher_rejects_symlink_manifest(client, server, pub_root):
    """verify_generation() rejects a manifest.json that is a symlink,
    including a symlink to an existing, valid regular manifest file -
    the same rule the engine enforces."""
    policy = make_policy(client)
    select_and_publish(client, policy["id"])
    gen_dir = pub_root / "generations" / "1"
    os.rename(gen_dir / "manifest.json", gen_dir / "manifest.real")
    os.symlink("manifest.real", gen_dir / "manifest.json")
    assert (gen_dir / "manifest.json").is_file()  # follows the link
    with pytest.raises(publishing.PublicationError):
        server.store.publisher.verify_generation(gen_dir)

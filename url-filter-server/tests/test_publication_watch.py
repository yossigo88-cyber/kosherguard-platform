"""B5 automatic chain: a control-plane publish (generation symlink
flip) must reach the served prefilter/shards by itself - no human
POST, no restart - with last-good retention, same-generation
atomicity and per-tenant isolation."""

import json
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.dataset import URLRule, build_dataset  # noqa: E402
from app.publication_watch import PublicationWatcher  # noqa: E402
from app.server import DatasetRef, create_app  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


def publish(root, generation, blocklist, allowlist=None,
            categories=None, category_block=None):
    """Mirror the control-plane Publisher: write generations/<N> then
    atomically flip the current symlink."""
    gen_dir = os.path.join(root, "generations", str(generation))
    os.makedirs(gen_dir)
    policy = {"default_policy": "allow", "blocklist": blocklist,
              "allowlist": allowlist or [],
              "category_block": category_block or [],
              "category_allow": []}
    with open(os.path.join(gen_dir, "policy.json"), "w") as fh:
        json.dump(policy, fh)
    with open(os.path.join(gen_dir, "categories.json"), "w") as fh:
        json.dump(categories or {"domains": {}}, fh)
    with open(os.path.join(gen_dir, "manifest.json"), "w") as fh:
        json.dump({"revision": generation, "generation": str(generation)},
                  fh)
    tmp = os.path.join(root, ".current.test.tmp")
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    os.symlink(f"generations/{generation}", tmp)
    os.rename(tmp, os.path.join(root, "current"))


@pytest.fixture()
def rig(tmp_path):
    root = str(tmp_path / "tenant-1")
    os.makedirs(root)
    publish(root, 1, ["old.example"])
    ref = DatasetRef(build_dataset([URLRule("old.example", "block", "")],
                                   version=1, provenance="seed"))
    watcher = PublicationWatcher(root, ref)
    client = TestClient(create_app(ref.current, dataset_ref=ref))
    return root, ref, watcher, client


class TestAutomaticPublicationChain:
    def test_publish_reaches_served_artifacts_without_human_post(self, rig):
        root, ref, watcher, c = rig
        assert watcher.check_once() == "unchanged"  # already current
        publish(root, 2, ["new.example"])
        assert watcher.check_once() == "updated"
        manifest = c.get("/v1/dataset/manifest").json()
        assert manifest["version"] == 2
        shard0 = c.get("/v1/dataset/shards/0").content
        assert b"new.example" in shard0
        assert b"old.example" not in shard0
        # Same-generation atomicity: the served prefilter hash equals
        # the served manifest's declared hash - no torn artifacts.
        pf = c.get("/v1/dataset/prefilter")
        assert pf.headers["X-SHA256"] == manifest["prefilter"]["sha256"]

    def test_unchanged_generation_does_not_rebuild(self, rig):
        _, _, watcher, _ = rig
        assert watcher.check_once() == "unchanged"
        assert watcher.build_count == 0

    def test_failed_publish_keeps_last_good(self, rig):
        root, _, watcher, c = rig
        gen_dir = os.path.join(root, "generations", "2")
        os.makedirs(gen_dir)
        with open(os.path.join(gen_dir, "policy.json"), "w") as fh:
            fh.write("{not json")
        with open(os.path.join(gen_dir, "manifest.json"), "w") as fh:
            json.dump({"revision": 2, "generation": "2"}, fh)
        tmp = os.path.join(root, ".current.test.tmp")
        os.symlink("generations/2", tmp)
        os.rename(tmp, os.path.join(root, "current"))
        assert watcher.check_once() == "failed"
        assert watcher.status()["last_error"]
        assert c.get("/v1/dataset/manifest").json()["version"] == 1
        # Recovery on the next good publish.
        publish(root, 3, ["new.example"])
        assert watcher.check_once() == "updated"
        assert c.get("/v1/dataset/manifest").json()["version"] == 3

    def test_category_block_expands_into_dataset(self, rig):
        root, _, watcher, c = rig
        publish(root, 2, [], category_block=["gambling"],
                categories={"domains": {"casino.example": ["gambling"],
                                        "news.example": ["news"]}})
        assert watcher.check_once() == "updated"
        shard0 = c.get("/v1/dataset/shards/0").content
        assert b"casino.example" in shard0
        assert b"news.example" not in shard0

    def test_per_tenant_isolation(self, rig, tmp_path):
        root_a, _, watcher_a, c_a = rig
        root_b = str(tmp_path / "tenant-2")
        os.makedirs(root_b)
        publish(root_b, 5, ["tenant-b-only.example"])
        # Watcher A never sees tenant B's publication.
        assert watcher_a.check_once() == "unchanged"
        shard0 = c_a.get("/v1/dataset/shards/0").content
        assert b"tenant-b-only.example" not in shard0
        publish(root_a, 2, ["tenant-a.example"])
        assert watcher_a.check_once() == "updated"
        shard0 = c_a.get("/v1/dataset/shards/0").content
        assert b"tenant-a.example" in shard0
        assert b"tenant-b-only.example" not in shard0

    def test_refresh_loop_updates_without_any_call(self, rig):
        root, ref, watcher, c = rig
        stop = watcher.start_refresh_loop(interval=0.05)
        try:
            publish(root, 2, ["auto.example"])
            deadline = time.time() + 5
            while time.time() < deadline:
                if c.get("/v1/dataset/manifest").json()["version"] == 2:
                    break
                time.sleep(0.05)
            assert c.get("/v1/dataset/manifest").json()["version"] == 2
        finally:
            stop.set()

    def test_manifest_generation_mismatch_is_refused(self, rig):
        root, _, watcher, c = rig
        gen_dir = os.path.join(root, "generations", "2")
        os.makedirs(gen_dir)
        with open(os.path.join(gen_dir, "policy.json"), "w") as fh:
            json.dump({"default_policy": "allow", "blocklist": [],
                       "allowlist": [], "category_block": [],
                       "category_allow": []}, fh)
        with open(os.path.join(gen_dir, "manifest.json"), "w") as fh:
            json.dump({"revision": 2, "generation": "99"}, fh)
        tmp = os.path.join(root, ".current.test.tmp")
        os.symlink("generations/2", tmp)
        os.rename(tmp, os.path.join(root, "current"))
        assert watcher.check_once() == "failed"
        assert c.get("/v1/dataset/manifest").json()["version"] == 1

    def test_on_swap_hook_runs_after_swap_not_on_unchanged(self, rig):
        root, ref, _, _ = rig
        seen = []
        w = PublicationWatcher(root, ref, on_swap=seen.append)
        publish(root, 2, ["hooked.example"])
        assert w.check_once() == "updated"
        assert len(seen) == 1 and seen[0].version == 2
        assert w.check_once() == "unchanged"
        assert len(seen) == 1

    def test_hook_failure_recorded_without_rollback(self, rig):
        root, ref, _, c = rig

        def bad_hook(_dataset):
            raise RuntimeError("regen failed")

        w = PublicationWatcher(root, ref, on_swap=bad_hook)
        publish(root, 2, ["hookfail.example"])
        assert w.check_once() == "updated"
        assert w.status()["hook_error"] == "regen failed"
        assert c.get("/v1/dataset/manifest").json()["version"] == 2

    def test_confinement_violation_recorded_as_failure(self, rig):
        root, ref, _, _ = rig
        w = PublicationWatcher(root, ref)
        link = os.path.join(root, "current")
        os.unlink(link)
        os.symlink("/etc", link)
        assert w.check_once() == "failed"
        assert "tenant root" in w.status()["last_error"]


class TestDeploymentEntrypoint:
    def test_refuses_without_publication_root(self):
        from app.__main__ import main
        old = os.environ.pop("KG_PUBLICATION_ROOT", None)
        try:
            with pytest.raises(SystemExit):
                main()
        finally:
            if old is not None:
                os.environ["KG_PUBLICATION_ROOT"] = old

    def test_refuses_to_serve_without_published_generation(
            self, tmp_path, monkeypatch):
        from app.__main__ import main
        monkeypatch.setenv("KG_PUBLICATION_ROOT", str(tmp_path))
        with pytest.raises(SystemExit, match="refusing to serve"):
            main()

    def test_export_hook_writes_device_pir_textpb(self, rig, tmp_path):
        root, ref, _, _ = rig
        export = str(tmp_path / "device.textpb")

        def hook(dataset):
            from app.pir_export import export_device_textpb
            tmp = export + ".tmp"
            with open(tmp, "w") as fh:
                fh.write(export_device_textpb(dataset.rules))
            os.replace(tmp, export)

        w = PublicationWatcher(root, ref, on_swap=hook)
        publish(root, 2, ["exported.example"])
        assert w.check_once() == "updated"
        with open(export) as fh:
            text = fh.read()
        assert "exported.example" in text
        from app.pir_export import DEVICE_EXPORT_MARKER
        assert DEVICE_EXPORT_MARKER.split(":")[0] in text

    def test_build_runtime_wires_watcher(self, rig):
        from app.server import build_runtime
        root, _, _, _ = rig
        app, stop = build_runtime(
            build_dataset([URLRule("old.example", "block", "")],
                          version=1, provenance="seed"),
            publication_root=root, watch_interval=0.05,
            device_token_key=None)
        c = TestClient(app)
        try:
            publish(root, 2, ["runtime-wired.example"])
            deadline = time.time() + 5
            version = 0
            while time.time() < deadline:
                version = c.get("/v1/dataset/manifest").json()["version"]
                if version == 2:
                    break
                time.sleep(0.05)
            assert version == 2
            assert b"runtime-wired.example" in \
                c.get("/v1/dataset/shards/0").content
        finally:
            stop.set()

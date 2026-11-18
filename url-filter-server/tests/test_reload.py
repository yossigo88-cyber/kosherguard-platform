"""B5: dataset hot-reload - a publish that rebuilds the dataset must
reach the served prefilter/shards WITHOUT a process restart, and a
failed rebuild must leave the last good dataset serving."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.dataset import URLRule, build_dataset  # noqa: E402
from app.server import create_app  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

RELOAD = "reload-admin-token"


def _ds(host: str, version: int):
    return build_dataset([URLRule(host, "block", "ads")],
                         version=version, provenance="reload-test")


@pytest.fixture()
def rig():
    state = {"host": "old.example", "version": 1, "fail": False}

    def rebuild():
        if state["fail"]:
            raise RuntimeError("source unavailable")
        return _ds(state["host"], state["version"])

    app = create_app(_ds("old.example", 1), reload_callback=rebuild,
                     reload_token=RELOAD)
    return state, TestClient(app)


class TestDatasetHotReload:
    def test_publish_reaches_served_artifacts_without_restart(self, rig):
        state, c = rig
        before = c.get("/v1/dataset/manifest").json()
        assert before["version"] == 1
        shard0 = c.get("/v1/dataset/shards/0").content
        assert b"old.example" in shard0

        # A publish upstream -> the rebuild source now yields gen 2.
        state["host"], state["version"] = "new.example", 2
        r = c.post("/v1/admin/reload",
                   headers={"Authorization": f"Bearer {RELOAD}"})
        assert r.status_code == 200, r.json()
        assert r.json()["version"] == 2

        after = c.get("/v1/dataset/manifest").json()
        assert after["version"] == 2
        assert (after["prefilter"]["sha256"]
                != before["prefilter"]["sha256"])
        shard0 = c.get("/v1/dataset/shards/0").content
        assert b"new.example" in shard0
        assert b"old.example" not in shard0
        # The served prefilter changed bytes (the device updater keys
        # off the tag/sha to decide a refetch).
        pf = c.get("/v1/dataset/prefilter")
        assert pf.headers["X-SHA256"] == after["prefilter"]["sha256"]

    def test_failed_rebuild_keeps_last_good_dataset(self, rig):
        state, c = rig
        state["fail"] = True
        r = c.post("/v1/admin/reload",
                   headers={"Authorization": f"Bearer {RELOAD}"})
        assert r.status_code == 502
        assert c.get("/v1/dataset/manifest").json()["version"] == 1
        # Recovery: a later successful rebuild swaps normally.
        state["fail"] = False
        state["host"], state["version"] = "new.example", 2
        assert c.post("/v1/admin/reload",
                      headers={"Authorization": f"Bearer {RELOAD}"}
                      ).status_code == 200
        assert c.get("/v1/dataset/manifest").json()["version"] == 2

    def test_reload_requires_the_admin_token(self, rig):
        _, c = rig
        assert c.post("/v1/admin/reload").status_code == 401
        assert c.post("/v1/admin/reload",
                      headers={"Authorization": "Bearer wrong"}
                      ).status_code == 401

    def test_reload_callback_without_token_is_rejected_at_startup(self):
        with pytest.raises(ValueError):
            create_app(_ds("a.example", 1), reload_callback=lambda: None,
                       reload_token=None)

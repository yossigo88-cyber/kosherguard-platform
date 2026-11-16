"""URL-filter server tests: Bloom correctness, dataset integrity,
serving. No network, no Apple tooling - the PIR/OHTTP deployment
layer is out of scope for these tests by design."""

import hashlib
import json
import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.bloom import BloomFilter  # noqa: E402
from app.dataset import SHARD_SIZE, URLRule, build_dataset  # noqa: E402
from app.server import create_app  # noqa: E402


class TestBloom:
    def test_no_false_negatives(self):
        bf = BloomFilter(500)
        items = [f"blocked-{i}.example" for i in range(500)]
        for i in items:
            bf.add(i)
        assert all(i in bf for i in items)

    def test_false_positive_rate_bounded(self):
        bf = BloomFilter(2000, 0.001)
        for i in range(2000):
            bf.add(f"b{i}.example")
        fps = sum(f"clean-{i}.example" in bf for i in range(20000))
        # Generous bound: sizing targets 0.1%; require < 1%.
        assert fps / 20000 < 0.01

    def test_roundtrip(self):
        bf = BloomFilter(100)
        bf.add("a.example")
        bf.add("b.example")
        bf2 = BloomFilter.from_bytes(bf.to_bytes(), 100)
        assert "a.example" in bf2 and "b.example" in bf2
        assert "c.example" not in bf2

    def test_from_bytes_size_mismatch_rejected(self):
        bf = BloomFilter(100)
        with pytest.raises(ValueError, match="size mismatch"):
            BloomFilter.from_bytes(bf.to_bytes() + b"x", 100)


def sample_rules():
    return [URLRule("bet365.com", "block", "gambling"),
            URLRule("porn.example", "block", "adult"),
            URLRule("wikipedia.org", "allow", "")]


class TestDataset:
    def test_manifest_integrity(self):
        ds = build_dataset(sample_rules(), version=3,
                           provenance="test seed")
        m = ds.manifest
        assert m["version"] == 3 and m["rule_count"] == 3
        assert m["blocked_count"] == 2
        assert hashlib.sha256(
            ds.prefilter.to_bytes()).hexdigest() == m["prefilter"]["sha256"]
        assert len(m["shards_sha256"]) == m["shard_count"]
        for shard, digest in zip(ds.shards, m["shards_sha256"]):
            assert hashlib.sha256(shard).hexdigest() == digest

    def test_prefilter_holds_blocked_only(self):
        ds = build_dataset(sample_rules(), version=1)
        assert "bet365.com" in ds.prefilter
        assert "porn.example" in ds.prefilter
        assert "wikipedia.org" not in ds.prefilter

    def test_invalid_verdict_rejected(self):
        with pytest.raises(ValueError, match="unknown verdict"):
            build_dataset([URLRule("x.example", "maybe")], version=1)

    def test_shards_reassemble_to_verdicts(self):
        ds = build_dataset(sample_rules(), version=1)
        blob = b"".join(ds.shards)
        verdicts = json.loads(blob)
        assert verdicts["bet365.com"]["verdict"] == "block"
        assert verdicts["wikipedia.org"]["verdict"] == "allow"
        assert all(len(s) <= SHARD_SIZE for s in ds.shards)


class TestServer:
    @pytest.fixture()
    def client(self):
        ds = build_dataset(sample_rules(), version=7,
                           provenance="test seed")
        return TestClient(create_app(ds))

    def test_manifest_served(self, client):
        r = client.get("/v1/dataset/manifest")
        assert r.status_code == 200
        assert r.json()["version"] == 7

    def test_prefilter_served_with_integrity_headers(self, client):
        r = client.get("/v1/dataset/prefilter")
        assert r.status_code == 200
        assert hashlib.sha256(r.content).hexdigest() == \
            r.headers["x-sha256"]
        bf = BloomFilter.from_bytes(
            r.content, capacity=2, fp_rate=0.001)
        assert "bet365.com" in bf

    def test_shard_served_and_404(self, client):
        r = client.get("/v1/dataset/shards/0")
        assert r.status_code == 200
        assert hashlib.sha256(r.content).hexdigest() == \
            r.headers["x-sha256"]
        assert client.get("/v1/dataset/shards/999").status_code == 404

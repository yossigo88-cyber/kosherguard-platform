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


class TestPIRExport:
    """Dataset export in Apple's PIR tooling input format (grounded in
    the PIRShardDatabase doc example). The private query service itself
    is Apple's Swift binary - not reimplemented here."""

    def test_golden_format(self):
        from app.pir_export import export_textpb
        out = export_textpb([URLRule("Bet365.COM", "block", "gambling")])
        assert out == ('rows {\n'
                       '  keyword: "bet365.com"\n'
                       '  value: "block:gambling"\n'
                       '}\n')

    def test_roundtrip(self):
        from app.pir_export import export_textpb, parse_textpb
        rules = [URLRule("a.example", "block", "adult"),
                 URLRule("b.example", "allow", "")]
        rows = parse_textpb(export_textpb(rules))
        assert rows == [("a.example", "block:adult"),
                        ("b.example", "allow")]

    def test_escaping(self):
        from app.pir_export import export_textpb, parse_textpb
        rules = [URLRule('quo"te.example', "block", "cat")]
        out = export_textpb(rules)
        assert '\\"' in out
        assert parse_textpb(out)[0][0] == 'quo\\"te.example'

    def test_empty_keyword_rejected(self):
        from app.pir_export import export_textpb
        with pytest.raises(ValueError):
            export_textpb([URLRule("  ", "block")])

    def test_dataset_export_integration(self):
        from app.pir_export import export_textpb, parse_textpb
        ds = build_dataset(sample_rules(), version=1)
        rows = parse_textpb(export_textpb(ds.rules))
        assert len(rows) == 3
        assert dict(rows)["bet365.com"] == "block:gambling"


class TestDeviceAuth:
    """Per-device scoped credentials (approved design: no long-lived
    bearer tokens in URLs; Authorization header; short expiry)."""

    KEY = b"test-signing-key-32-bytes-padded!!!"

    def test_issue_verify_roundtrip(self):
        from app.device_auth import issue_token, verify_token
        tok = issue_token(self.KEY, "dev-1", "tenant-1", "dataset")
        payload = verify_token(self.KEY, tok, "dataset")
        assert payload["device_id"] == "dev-1"
        assert payload["tenant_id"] == "tenant-1"

    def test_tampered_rejected(self):
        from app.device_auth import TokenError, issue_token, verify_token
        tok = issue_token(self.KEY, "dev-1", "t", "dataset")
        body, _ = tok.split(".")
        import base64, json as j
        payload = j.loads(base64.urlsafe_b64decode(body + "=="))
        payload["device_id"] = "dev-evil"
        evil_body = base64.urlsafe_b64encode(
            j.dumps(payload).encode()).rstrip(b"=").decode()
        with pytest.raises(TokenError):
            verify_token(self.KEY, f"{evil_body}.{tok.split('.')[1]}",
                         "dataset")

    def test_expired_rejected(self):
        from app.device_auth import TokenError, issue_token, verify_token
        tok = issue_token(self.KEY, "dev-1", "t", "dataset",
                          lifetime_seconds=60, now=1000)
        with pytest.raises(TokenError):
            verify_token(self.KEY, tok, "dataset", now=2000)

    def test_wrong_scope_rejected(self):
        from app.device_auth import TokenError, issue_token, verify_token
        tok = issue_token(self.KEY, "dev-1", "t", "doh")
        with pytest.raises(TokenError):
            verify_token(self.KEY, tok, "dataset")

    def test_wrong_key_rejected(self):
        from app.device_auth import TokenError, issue_token, verify_token
        tok = issue_token(self.KEY, "dev-1", "t", "dataset")
        with pytest.raises(TokenError):
            verify_token(b"other-key", tok, "dataset")

    def test_lifetime_cap(self):
        from app.device_auth import issue_token
        with pytest.raises(ValueError):
            issue_token(self.KEY, "d", "t", "dataset",
                        lifetime_seconds=90000)

    def test_endpoints_require_credential_when_key_set(self):
        from app.server import create_app
        from app.device_auth import issue_token
        ds = build_dataset(sample_rules(), version=1)
        c = TestClient(create_app(ds, device_token_key=self.KEY))
        assert c.get("/v1/dataset/manifest").status_code == 401
        assert c.get("/v1/dataset/prefilter").status_code == 401
        assert c.get("/v1/dataset/shards/0").status_code == 401
        # Token in the URL query must NOT authenticate.
        tok = issue_token(self.KEY, "dev-1", "t", "dataset")
        assert c.get(f"/v1/dataset/manifest?token={tok}"
                     ).status_code == 401
        ok = c.get("/v1/dataset/manifest",
                   headers={"Authorization": f"Bearer {tok}"})
        assert ok.status_code == 200

    def test_dev_mode_open_without_key(self):
        from app.server import create_app
        ds = build_dataset(sample_rules(), version=1)
        c = TestClient(create_app(ds, device_token_key=None))
        assert c.get("/v1/dataset/manifest").status_code == 200


class TestDeviceAuthRevocationAndBinding:
    KEY = b"test-signing-key-32-bytes-padded!!!"

    def test_revoked_jti_rejected(self):
        from app.device_auth import TokenError, issue_token, verify_token
        tok = issue_token(self.KEY, "dev-1", "t", "dataset")
        payload = verify_token(self.KEY, tok, "dataset")
        with pytest.raises(TokenError):
            verify_token(self.KEY, tok, "dataset",
                         revoked_jtis={payload["jti"]})

    def test_unrevoked_still_accepted(self):
        from app.device_auth import issue_token, verify_token
        tok = issue_token(self.KEY, "dev-1", "t", "dataset")
        assert verify_token(self.KEY, tok, "dataset",
                            revoked_jtis={"other-jti"})

    def test_policy_binding_enforced(self):
        from app.device_auth import TokenError, issue_token, verify_token
        tok = issue_token(self.KEY, "dev-1", "t", "dataset",
                          policy_id="pol-9")
        assert verify_token(self.KEY, tok, "dataset",
                            required_policy_id="pol-9")
        with pytest.raises(TokenError):
            verify_token(self.KEY, tok, "dataset",
                         required_policy_id="pol-other")

    def test_unbound_token_fails_policy_requirement(self):
        from app.device_auth import TokenError, issue_token, verify_token
        tok = issue_token(self.KEY, "dev-1", "t", "dataset")
        with pytest.raises(TokenError):
            verify_token(self.KEY, tok, "dataset",
                         required_policy_id="pol-9")

    def test_every_token_has_unique_jti(self):
        from app.device_auth import issue_token, verify_token
        a = issue_token(self.KEY, "dev-1", "t", "dataset")
        b = issue_token(self.KEY, "dev-1", "t", "dataset")
        pa = verify_token(self.KEY, a, "dataset")
        pb = verify_token(self.KEY, b, "dataset")
        assert pa["jti"] != pb["jti"]

    def test_401_body_reveals_no_failure_reason(self):
        """Expired, tampered, wrong-scope, and missing tokens must all
        receive the identical generic 401 body: no oracle about which
        check failed."""
        from app.server import create_app
        from app.device_auth import issue_token
        ds = build_dataset(sample_rules(), version=1)
        c = TestClient(create_app(ds, device_token_key=self.KEY))
        bodies = set()
        r = c.get("/v1/dataset/manifest")
        assert r.status_code == 401
        bodies.add(r.text)
        tok = issue_token(self.KEY, "dev-1", "t", "dataset")
        r = c.get("/v1/dataset/manifest",
                  headers={"Authorization": f"Bearer {tok}x"})
        assert r.status_code == 401
        bodies.add(r.text)
        expired = issue_token(self.KEY, "dev-1", "t", "dataset",
                              lifetime_seconds=1, now=1000)
        r = c.get("/v1/dataset/manifest",
                  headers={"Authorization": f"Bearer {expired}"})
        assert r.status_code == 401
        bodies.add(r.text)
        wrong_scope = issue_token(self.KEY, "dev-1", "t", "doh")
        r = c.get("/v1/dataset/manifest",
                  headers={"Authorization": f"Bearer {wrong_scope}"})
        assert r.status_code == 401
        bodies.add(r.text)
        assert len(bodies) == 1, f"401 bodies differ by reason: {bodies}"
        assert "unauthorized" in bodies.pop()

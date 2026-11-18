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

from app.apple_prefilter import (FORMAT_ID, KOSHERGUARD_MURMUR_SEED,  # noqa: E402
                                 ApplePrefilter, fnv1a32, murmur3_32,
                                 to_punycode)
from app.dataset import SHARD_SIZE, URLRule, build_dataset  # noqa: E402
from app.server import create_app  # noqa: E402


class TestHashPrimitives:
    """Known-answer tests pinning the exact hash functions Apple
    documents for the URL Filter prefilter (FNV-1a 32, MurmurHash3 32).
    The Swift URLFilter prefilter code verifies the SAME vectors
    (tools/apple-prefilter-vectors.json) so both platforms compute
    identical bit arrays."""

    def test_fnv1a32_known_vectors(self):
        # Published FNV-1a 32 reference values.
        assert fnv1a32(b"") == 0x811C9DC5
        assert fnv1a32(b"a") == 0xE40C292C
        assert fnv1a32(b"foobar") == 0xBF9CF968

    def test_murmur3_32_known_vectors(self):
        # Published MurmurHash3 x86-32 reference values.
        assert murmur3_32(b"", 0) == 0
        assert murmur3_32(b"foo", 0) == 0xF6A5C420
        # Cross-checked against the reference mmh3 package.
        assert murmur3_32(b"hello world", 42) == 0xEA0C9BF9
        assert murmur3_32(b"abcde", 7) == 0xB5138433

    def test_punycode(self):
        assert to_punycode("Example.COM.") == "example.com"
        assert to_punycode("bücher.de") == "xn--bcher-kva.de"
        assert to_punycode("münchen.example/path") == \
            "xn--mnchen-3ya.example/path"


class TestBloom:
    def test_no_false_negatives(self):
        bf = ApplePrefilter(500)
        items = [f"blocked-{i}.example" for i in range(500)]
        for i in items:
            bf.add(i)
        assert all(bf.might_contain(i) for i in items)

    def test_false_positive_rate_bounded(self):
        bf = ApplePrefilter(2000, 0.001)
        for i in range(2000):
            bf.add(f"b{i}.example")
        fps = sum(bf.might_contain(f"clean-{i}.example")
                  for i in range(20000))
        # Generous bound: sizing targets 0.1%; require < 1%.
        assert fps / 20000 < 0.01

    def test_roundtrip(self):
        bf = ApplePrefilter(100)
        bf.add("a.example")
        bf.add("b.example")
        bf2 = ApplePrefilter.from_bytes(bf.to_bytes(), 100)
        assert bf2.might_contain("a.example")
        assert bf2.might_contain("b.example")
        assert not bf2.might_contain("c.example")

    def test_from_bytes_size_mismatch_rejected(self):
        bf = ApplePrefilter(100)
        with pytest.raises(ValueError, match="size mismatch"):
            ApplePrefilter.from_bytes(bf.to_bytes() + b"x", 100)

    def test_seed_changes_layout(self):
        a = ApplePrefilter(10, murmur_seed=1)
        b = ApplePrefilter(10, murmur_seed=2)
        a.add("same.example")
        b.add("same.example")
        assert a.to_bytes() != b.to_bytes()


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
        assert m["prefilter"]["format"] == FORMAT_ID
        assert m["prefilter"]["bit_count"] == ds.prefilter.bit_count
        assert m["prefilter"]["hash_count"] == ds.prefilter.hash_count
        assert m["prefilter"]["murmur_seed"] == ds.prefilter.murmur_seed
        assert len(m["shards_sha256"]) == m["shard_count"]
        for shard, digest in zip(ds.shards, m["shards_sha256"]):
            assert hashlib.sha256(shard).hexdigest() == digest

    def test_prefilter_holds_blocked_only(self):
        ds = build_dataset(sample_rules(), version=1)
        assert ds.prefilter.might_contain("bet365.com")
        assert ds.prefilter.might_contain("porn.example")
        assert not ds.prefilter.might_contain("wikipedia.org")

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
        assert r.headers["x-bloom-murmur-seed"] == \
            str(KOSHERGUARD_MURMUR_SEED)
        bf = ApplePrefilter.from_bytes(
            r.content, item_count=2, fp_rate=0.001)
        assert bf.might_contain("bet365.com")

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


class TestPIRDeviceExport:
    """The DEVICE (NEURLFilter) export. Security-critical semantics
    (NEURLFilterDataFormat.md in the pinned apple/pir-service-example):
    a keyword PRESENT in the device dataset is BLOCKED on device; the
    value is Apple's ignored placeholder. An allow row in this export
    would block the allowed site - these tests pin that invariant."""

    def test_block_rows_only_with_placeholder_value(self):
        from app.pir_export import export_device_textpb, parse_textpb
        rules = [URLRule("Bet365.COM", "block", "gambling"),
                 URLRule("allowed.example", "allow", "")]
        rows = parse_textpb(export_device_textpb(rules))
        assert rows == [("bet365.com", "1")]

    def test_allow_beats_block_exact_host(self):
        """SECURITY: a host with BOTH an explicit allow and a
        (category) block must not appear in the device dataset at all
        - presence means block, so emitting it would block the
        explicitly allowed site. Mirrors the on-device engine's
        explicit-allow-beats-block order."""
        from app.pir_export import export_device_textpb, parse_textpb
        rules = [URLRule("precedence.example", "block", "ads"),
                 URLRule("precedence.example", "allow", "")]
        assert parse_textpb(export_device_textpb(rules)) == []

    def test_allow_precedence_applies_after_normalization(self):
        """The allow matches the block regardless of case/trailing
        dot - a normalization gap would re-block the allowed host."""
        from app.pir_export import export_device_textpb, parse_textpb
        rules = [URLRule("Ads.EXAMPLE.", "block", "ads"),
                 URLRule("ads.example", "allow", "")]
        assert parse_textpb(export_device_textpb(rules)) == []

    def test_duplicate_blocks_collapse_and_sort(self):
        from app.pir_export import export_device_textpb, parse_textpb
        rules = [URLRule("b.example", "block", "ads"),
                 URLRule("a.example", "block", "adult"),
                 URLRule("B.EXAMPLE", "block", "ads")]
        rows = parse_textpb(export_device_textpb(rules))
        assert rows == [("a.example", "1"), ("b.example", "1")]

    def test_unknown_verdict_rejected(self):
        """A malformed row must fail the export, never be silently
        dropped (a dropped BLOCK silently weakens filtering)."""
        from app.pir_export import export_device_textpb
        with pytest.raises(ValueError):
            export_device_textpb([URLRule("x.example", "maybe")])

    def test_empty_keyword_rejected(self):
        from app.pir_export import export_device_textpb
        with pytest.raises(ValueError):
            export_device_textpb([URLRule(" . ", "block")])


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


class TestDeviceExportMarkerBinding:
    """The exclusive device-export binding: deploy/pir/prepare-dataset.sh
    refuses any input whose first line is not the device-export marker,
    so the generic allow-valued export can never be processed for the
    device dataset (its allow rows would BLOCK allowed sites under
    presence semantics). These tests pin that the marker distinguishes
    the two exporters and survives the round-trip parser."""

    def test_device_export_first_line_is_marker(self):
        from app.pir_export import (DEVICE_EXPORT_MARKER,
                                    export_device_textpb)
        out = export_device_textpb([URLRule("a.example", "block", "")])
        assert out.splitlines()[0] == DEVICE_EXPORT_MARKER
        # The marker must be a protobuf-text comment so Apple's parser
        # (SwiftProtobuf text format) accepts marked input.
        assert DEVICE_EXPORT_MARKER.startswith("# kosherguard-device-export-v1:")

    def test_generic_export_never_carries_marker(self):
        """GUARD DISCRIMINATION: the generic export must NOT pass the
        prepare-dataset marker check - this is the unsafe input the
        guard exists to refuse."""
        from app.pir_export import export_textpb
        out = export_textpb([URLRule("a.example", "block", "ads"),
                             URLRule("b.example", "allow", "")])
        first = out.splitlines()[0] if out.splitlines() else ""
        assert not first.startswith("# kosherguard-device-export-v1:")

    def test_marker_does_not_break_round_trip_parser(self):
        from app.pir_export import export_device_textpb, parse_textpb
        rows = parse_textpb(export_device_textpb(
            [URLRule("a.example", "block", "")]))
        assert rows == [("a.example", "1")]

    def test_empty_device_export_still_marked(self):
        """An all-allowed rule set exports zero rows but still carries
        the marker - an empty device dataset is a valid (block-nothing)
        input, not a guard failure."""
        from app.pir_export import (DEVICE_EXPORT_MARKER,
                                    export_device_textpb)
        out = export_device_textpb([URLRule("a.example", "allow", "")])
        assert out.splitlines()[0] == DEVICE_EXPORT_MARKER
        from app.pir_export import parse_textpb
        assert parse_textpb(out) == []


class TestDeviceExportWWWCanonicalization:
    """Apple's default ParsingConfiguration strips the www subdomain
    from requested URLs, so the device export canonicalizes
    www-prefixed rules to the stripped form Apple actually queries."""

    def test_www_prefix_stripped_from_block_key(self):
        from app.pir_export import export_device_textpb, parse_textpb
        rows = parse_textpb(export_device_textpb(
            [URLRule("WWW.Ads.EXAMPLE", "block", "ads")]))
        assert rows == [("ads.example", "1")]

    def test_www_allow_still_excludes_stripped_block(self):
        """Allow precedence applies AFTER www-canonicalization:
        allowing www.a.example must exclude a block of a.example."""
        from app.pir_export import export_device_textpb, parse_textpb
        rows = parse_textpb(export_device_textpb(
            [URLRule("a.example", "block", "ads"),
             URLRule("www.a.example", "allow", "")]))
        assert rows == []

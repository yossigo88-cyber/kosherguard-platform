"""DNS edge runner tests against synthetic generation fixtures.

These fixtures are built directly on disk - NOT through the control
plane's publication code - so the runner is verified independently of
the (currently held) publication path.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "filtering-engine", "src")))

import runner  # noqa: E402

POLICY_V1 = {"default_policy": "allow", "allowlist": [], "blocklist": ["bad.example"],
             "category_rules": {"allow": [], "block": []}}
POLICY_V2 = {"default_policy": "allow", "allowlist": [], "blocklist": ["bad.example", "worse.example"],
             "category_rules": {"allow": [], "block": []}}
CATS = {"_meta": {"note": "synthetic fixture"}, "domains": {}}


def make_generation(root, revision, policy, categories=CATS):
    """Create a complete generation dir and flip current/ at it,
    mimicking the publisher's on-disk layout (synthetic fixture)."""
    gen_dir = os.path.join(root, "generations", str(revision))
    os.makedirs(gen_dir, exist_ok=True)
    import hashlib
    pb = (json.dumps(policy, indent=2, sort_keys=True) + "\n").encode()
    cb = (json.dumps(categories, indent=2, sort_keys=True) + "\n").encode()
    manifest = {
        "revision": revision, "generation": str(revision),
        "policy_sha256": hashlib.sha256(pb).hexdigest(),
        "categories_sha256": hashlib.sha256(cb).hexdigest(),
        "files": ["policy.json", "categories.json"],
    }
    with open(os.path.join(gen_dir, "policy.json"), "wb") as fh:
        fh.write(pb)
    with open(os.path.join(gen_dir, "categories.json"), "wb") as fh:
        fh.write(cb)
    with open(os.path.join(gen_dir, "manifest.json"), "w") as fh:
        json.dump(manifest, fh)
    link = os.path.join(root, "current")
    tmp = link + ".tmp"
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    os.symlink(f"generations/{revision}", tmp)
    os.rename(tmp, link)


def test_generation_paths(tmp_path):
    make_generation(str(tmp_path), 3, POLICY_V1)
    policy, categories, revision = runner.generation_paths(str(tmp_path))
    assert revision == 3
    assert policy.endswith("policy.json")


def test_missing_manifest_fails_closed(tmp_path):
    with pytest.raises(runner.RunnerError):
        runner.generation_paths(str(tmp_path))


def test_runner_loads_and_decides(tmp_path):
    make_generation(str(tmp_path), 1, POLICY_V1)
    r = runner.DNSEdgeRunner(str(tmp_path))
    decision = r.service.engine.policy_for_client(None).decide("bad.example")
    assert decision.action == "block"
    assert r.service.engine.policy_for_client(None).decide("good.example").action == "allow"


def test_watch_picks_up_new_generation(tmp_path):
    make_generation(str(tmp_path), 1, POLICY_V1)
    r = runner.DNSEdgeRunner(str(tmp_path))
    assert r.service.engine.policy_for_client(None).decide("worse.example").action == "allow"
    make_generation(str(tmp_path), 2, POLICY_V2)
    assert r.check_for_update() is True
    assert r.service.engine.policy_for_client(None).decide("worse.example").action == "block"
    # Unchanged revision: no reload.
    assert r.check_for_update() is False


def test_broken_republication_keeps_previous_config(tmp_path):
    make_generation(str(tmp_path), 1, POLICY_V1)
    r = runner.DNSEdgeRunner(str(tmp_path))
    # Publish a broken generation 2 (bad policy doc) and flip current.
    broken = {"default_policy": "maybe", "allowlist": [], "blocklist": [],
              "category_rules": {"allow": [], "block": []}}
    make_generation(str(tmp_path), 2, broken)
    ok = r.check_for_update()
    assert ok is False
    # Old engine still serving.
    assert r.service.engine.policy_for_client(None).decide("bad.example").action == "block"
    assert r._revision == 1


def test_live_dns_query_against_runner(tmp_path):
    """Start the real service on a synthetic fixture and query it."""
    import socket
    import dnslib
    make_generation(str(tmp_path), 1, POLICY_V1)
    # Find a free port.
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    r = runner.DNSEdgeRunner(str(tmp_path), listen=f"127.0.0.1:{port}",
                             upstreams=[("127.0.0.1", 5399)],  # dead upstream
                             watch_interval=60)
    r.service.config.upstream_timeout = 0.3
    r.start()
    try:
        # Blocked domain: sinkhole answer, no upstream needed.
        q = dnslib.DNSRecord.question("bad.example")
        reply = q.send("127.0.0.1", port, timeout=3)
        parsed = dnslib.DNSRecord.parse(reply)
        assert parsed.rr, "expected a sinkhole answer"
        assert str(parsed.rr[0].rdata) == "0.0.0.0"
        # Blocked + nxdomain mode is a config choice; here sinkhole.
        # Allowed domain with a dead upstream: SERVFAIL (fail-closed,
        # never a silent allow-by-error).
        q2 = dnslib.DNSRecord.question("good.example")
        reply2 = dnslib.DNSRecord.parse(q2.send("127.0.0.1", port, timeout=3))
        assert reply2.header.rcode == dnslib.RCODE.SERVFAIL
    finally:
        r.stop()

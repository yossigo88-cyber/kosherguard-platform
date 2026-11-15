"""Stage 10 end-to-end acceptance test: dashboard -> publish -> real DNS.

The most important test of Stage 10. A REAL dashboard server (in
process, ephemeral port) and a REAL DNS filtering service subprocess
(run as a separate OS process with --watch) share a temporary
publication root. The test:

1. Creates categories, domains, and a policy through the dashboard API.
2. Selects the policy and publishes.
3. Waits (bounded polling on the engine status file and on the DNS
   answers themselves - never sleeps) for the running engine to load
   the new generation.
4. Verifies real DNS UDP and TCP answers reflect the published policy.
5. Changes the policy through the API, publishes again, and verifies
   the DNS answers change.
6. Rolls back the configuration and verifies the DNS answers revert,
   proving a rollback publishes a new working generation.
"""

import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "filtering-engine" / "src"))

from dnslib import A, QTYPE, DNSRecord, RR  # noqa: E402

UPSTREAM_A = "93.184.216.34"


class FakeUpstream(threading.Thread):
    """A tiny real DNS server standing in for the internet resolver."""

    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.start()

    def run(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(4096)
            except OSError:
                return
            try:
                query = DNSRecord.parse(data)
            except Exception:
                continue
            reply = query.reply()
            reply.add_answer(RR(str(query.q.qname), QTYPE.A, rdata=A(UPSTREAM_A), ttl=60))
            try:
                self.sock.sendto(reply.pack(), addr)
            except OSError:
                return


def query_udp(port, domain):
    q = DNSRecord.question(domain)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    try:
        sock.sendto(q.pack(), ("127.0.0.1", port))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    return DNSRecord.parse(data)


def query_tcp(port, domain):
    q = DNSRecord.question(domain)
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        payload = q.pack()
        sock.sendall(struct.pack(">H", len(payload)) + payload)
        header = sock.recv(2)
        length = struct.unpack(">H", header)[0]
        data = b""
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                raise ConnectionError("short read")
            data += chunk
    finally:
        sock.close()
    return DNSRecord.parse(data)


def answer_a(record):
    for rr in record.rr:
        if rr.rtype == QTYPE.A:
            return str(rr.rdata)
    return None


def wait_for(predicate, timeout=15.0, interval=0.05, description="condition"):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(interval)
    raise AssertionError(f"timed out waiting for {description}")


@pytest.mark.skipif(not hasattr(os, "fork"), reason="POSIX only")
def test_dashboard_to_dns_end_to_end(client, server, tmp_path):
    publish_root = Path(server.store.publisher.root)
    upstream = FakeUpstream()
    engine_src = Path(__file__).resolve().parents[2] / "filtering-engine" / "src"
    status_path = publish_root / "engine-status.json"  # the dashboard reads it from the shared root
    log_path = tmp_path / "engine.log"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(engine_src)

    # The engine starts with an empty allow-all configuration already
    # published by the dashboard layout (generation 0 written by hand is
    # not needed: the engine can start before the first publish because
    # we seed the pointer with an initial generation written through the
    # real Publisher).
    import publishing
    pub = publishing.Publisher(publish_root)
    with pub.locked():
        pub.publish(
            0,
            publishing.canonical_json({
                "default_policy": "allow", "allowlist": [], "blocklist": [],
                "category_rules": {"allow": [], "block": []}}),
            publishing.canonical_json({"_meta": {}, "domains": {}}),
            {"policy_name": "initial-empty", "published_by": "test-setup"})

    with open(log_path, "wb") as logf:
        proc = subprocess.Popen(
            [sys.executable, "-u",
             str(engine_src / "dns_service.py"),
             "--policy", str(publish_root / "current" / "policy.json"),
             "--categories", str(publish_root / "current" / "categories.json"),
             "--listen", "127.0.0.1:0",
             "--upstream", f"127.0.0.1:{upstream.port}",
             "--watch", "0.1",
             "--status-file", str(status_path)],
            stdout=logf, stderr=logf, env=env)
        try:
            wait_for(lambda: "Listening on 127.0.0.1:" in log_path.read_text(),
                     description="engine startup")
            line = [l for l in log_path.read_text().splitlines()
                    if "Listening on 127.0.0.1:" in l][0]
            port = int(line.split("Listening on 127.0.0.1:")[1].split()[0])

            # Baseline: nothing blocked yet.
            assert answer_a(query_udp(port, "social.test")) == UPSTREAM_A

            # Build the configuration through the dashboard API only.
            status, _ = client.post("/api/categories", {
                "name": "social-media", "display_name": "Social", "description": ""})
            assert status in (201, 409)  # builtin catalogue may already have it
            status, body = client.post("/api/domains", {
                "domain": "social.test", "categories": ["social-media"]})
            assert status == 201, body
            status, policy = client.post("/api/policies", {
                "name": "family", "description": "", "default_policy": "allow",
                "enabled": True, "allowlist": [], "blocklist": [],
                "category_allow": [], "category_block": ["social-media"]})
            assert status == 201, policy
            status, body = client.post(f"/api/policies/{policy['id']}/select")
            assert status == 200, body
            status, revision = client.post("/api/config/publish")
            assert status == 200, revision

            # The engine must report the new revision as active.
            def engine_on_revision(n):
                try:
                    s = json.loads(status_path.read_text())
                except (OSError, json.JSONDecodeError):
                    return False
                return s.get("revision") == n and s.get("state") == "active"
            wait_for(lambda: engine_on_revision(revision["revision"]),
                     description="engine to load the published generation")

            # Real DNS behavior now reflects the dashboard policy.
            wait_for(lambda: answer_a(query_udp(port, "social.test")) == "0.0.0.0",
                     description="UDP answer to become the sinkhole")
            assert answer_a(query_udp(port, "www.social.test")) == "0.0.0.0"  # subdomain
            assert answer_a(query_udp(port, "other.test")) == UPSTREAM_A
            assert answer_a(query_tcp(port, "social.test")) == "0.0.0.0"  # TCP too

            # The dashboard reports engine confirmation, not just files.
            status, cfg = client.get("/api/config/status")
            assert cfg["engine_matches_active_revision"] is True

            # Change the policy through the API and publish again.
            payload = dict(policy)
            payload.pop("id")
            payload["category_block"] = []
            payload["blocklist"] = ["games.test"]
            status, _ = client.put(f"/api/policies/{policy['id']}", payload)
            assert status == 200
            client.post("/api/domains", {"domain": "games.test", "categories": ["social-media"]})
            status, rev2 = client.post("/api/config/publish")
            assert status == 200
            wait_for(lambda: engine_on_revision(rev2["revision"]),
                     description="engine to load the second generation")
            wait_for(lambda: answer_a(query_udp(port, "social.test")) == UPSTREAM_A,
                     description="UDP answer for social.test to be forwarded again")
            assert answer_a(query_udp(port, "games.test")) == "0.0.0.0"

            # Roll back to the first published configuration.
            status, rev3 = client.post("/api/config/rollback",
                                       {"revision": revision["revision"]})
            assert status == 200
            assert rev3["status"] == "published"
            wait_for(lambda: engine_on_revision(rev3["revision"]),
                     description="engine to load the rollback generation")
            wait_for(lambda: answer_a(query_udp(port, "social.test")) == "0.0.0.0",
                     description="UDP answer to return to blocked after rollback")
            assert answer_a(query_udp(port, "games.test")) == UPSTREAM_A

            # The engine process is still healthy after all reloads.
            assert proc.poll() is None
        finally:
            proc.terminate()
            proc.wait(timeout=10)
            upstream.sock.close()

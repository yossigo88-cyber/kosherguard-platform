"""End-to-end DNS decision reporting: a REAL DNS query against the
real dns-edge runner flows through the DNSDecisionReporter into the
real control-plane ingestion route and lands in the tenant's log,
distinct from fixture-post tests. Harness is fully local: uvicorn
serving the app on loopback, dnslib query on loopback."""

import json
import os
import socket
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "dns-edge")))
sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "url-filter-server")))

from app.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402
from test_filter_logs import (  # noqa: E402
    TOKEN_KEY, make_client, make_default_policy, mint, mk_device)

TOKEN_KEY_LOCAL = TOKEN_KEY


def _free_udp_port():
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def _make_generation(root):
    import hashlib
    policy = {"default_policy": "allow", "allowlist": [],
              "blocklist": ["bad.example"],
              "category_rules": {"allow": [], "block": []}}
    cats = {"_meta": {"note": "synthetic fixture"}, "domains": {}}
    gen_dir = os.path.join(root, "generations", "0")
    os.makedirs(gen_dir, exist_ok=True)
    pb = (json.dumps(policy, indent=2, sort_keys=True) + "\n").encode()
    cb = (json.dumps(cats, indent=2, sort_keys=True) + "\n").encode()
    with open(os.path.join(gen_dir, "policy.json"), "wb") as fh:
        fh.write(pb)
    with open(os.path.join(gen_dir, "categories.json"), "wb") as fh:
        fh.write(cb)
    with open(os.path.join(gen_dir, "manifest.json"), "w") as fh:
        json.dump({"revision": 0, "generation": "0",
                   "policy_sha256": hashlib.sha256(pb).hexdigest(),
                   "categories_sha256": hashlib.sha256(cb).hexdigest(),
                   "files": ["policy.json", "categories.json"]}, fh)
    tmp = os.path.join(root, "current.tmp")
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    os.symlink("generations/0", tmp)
    os.rename(tmp, os.path.join(root, "current"))


def test_dns_query_lands_in_tenant_log(tmp_path, engine):
    import dnslib
    import uvicorn
    import reporter as dns_reporter
    import runner as dns_runner

    env = {"KG_DATABASE_URL": "postgresql://placeholder",
           "KG_PUBLICATIONS_ROOT": "/tmp/kg-pub-test",
           "KG_DEVICE_TOKEN_KEY": TOKEN_KEY_LOCAL}
    settings = Settings(env)
    app = create_app(settings, engine=engine)
    client = make_client(engine)
    make_default_policy(engine)
    dev = mk_device(client)
    token = mint(client, dev, scope="doh")

    httpd = uvicorn.Server(uvicorn.Config(
        app, host="127.0.0.1", port=0, log_level="error"))
    thread = threading.Thread(target=httpd.run, daemon=True)
    thread.start()
    end = time.time() + 10
    while not httpd.started and time.time() < end:
        time.sleep(0.05)
    port = httpd.servers[0].sockets[0].getsockname()[1]

    _make_generation(str(tmp_path))
    dns_port = _free_udp_port()
    rep = dns_reporter.DNSDecisionReporter(
        f"http://127.0.0.1:{port}", token, batch_size=1, timeout=3.0)
    r = dns_runner.DNSEdgeRunner(
        str(tmp_path), listen=f"127.0.0.1:{dns_port}",
        upstreams=[("127.0.0.1", 5399)], watch_interval=60,
        decision_reporter=rep)
    r.service.config.upstream_timeout = 0.3
    r.start()
    try:
        q = dnslib.DNSRecord.question("bad.example")
        reply = dnslib.DNSRecord.parse(q.send("127.0.0.1", dns_port,
                                              timeout=3))
        assert str(reply.rr[0].rdata) == "0.0.0.0"  # sinkholed
        rep.flush()
        assert rep.dropped == 0 and rep.sent == 1
        rows = client.get("/api/filter-logs").json()["decisions"]
        assert rows, "expected the DNS decision in the tenant log"
        row = rows[0]
        assert row["source"] == "dns"
        assert row["domain"] == "bad.example"
        assert row["action"] == "block"
        assert row["device"] == "phone-logs"
    finally:
        r.stop()
        httpd.should_exit = True
        thread.join(timeout=5)

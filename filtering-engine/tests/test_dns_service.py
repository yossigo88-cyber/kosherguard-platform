"""Automated tests for the DNS filtering service.

These tests run the real service over real UDP sockets against a fake
upstream resolver (a tiny in-test DNS server), so no internet access is
needed and results are deterministic. Covered: allowed domains, blocked
domains (sinkhole and NXDOMAIN), DNS responses, upstream failures,
malformed requests, non-A query types, and structured decision logs.
"""

import io
import json
import socket
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dnslib import A, QTYPE, RCODE, DNSRecord, RR

from category_db import CategoryDB
from dns_service import DNSFilteringService, DecisionLogger, ServiceConfig
from policy_engine import PolicyEngine

UPSTREAM_A = "93.184.216.34"  # canned answer the fake upstream returns


class FakeUpstream(threading.Thread):
    """A minimal DNS server that answers A queries with a fixed address
    and TXT queries with a fixed string."""

    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.running = True

    def run(self):
        while self.running:
            try:
                data, client = self.sock.recvfrom(4096)
            except OSError:
                return
            try:
                query = DNSRecord.parse(data)
            except Exception:
                continue
            reply = query.reply()
            name = str(query.q.qname)
            if query.q.qtype == QTYPE.A:
                reply.add_answer(RR(name, QTYPE.A, rdata=A(UPSTREAM_A), ttl=300))
            elif query.q.qtype == QTYPE.TXT:
                from dnslib import TXT
                reply.add_answer(RR(name, QTYPE.TXT, rdata=TXT("upstream-ok"), ttl=300))
            self.sock.sendto(reply.pack(), client)

    def stop(self):
        self.running = False
        self.sock.close()


@pytest.fixture()
def upstream():
    server = FakeUpstream()
    server.start()
    yield server
    server.stop()


def build_service(upstream_port, policy=None, block_mode="sinkhole", log_stream=None):
    db = CategoryDB({"adult-site.example": ["adult"]})
    engine = PolicyEngine(policy or {
        "default_policy": "allow",
        "allowlist": [],
        "blocklist": ["blocked.example"],
        "category_rules": {"allow": [], "block": ["adult"]},
    }, db)
    config = ServiceConfig(
        listen_host="127.0.0.1",
        listen_port=0,  # ephemeral
        upstreams=[("127.0.0.1", upstream_port)],
        upstream_timeout=1.0,
        block_mode=block_mode,
    )
    service = DNSFilteringService(engine, config, DecisionLogger(log_stream or io.StringIO()))
    service.start()
    return service


def query(domain, port, qtype="A", timeout=3):
    data = DNSRecord.question(domain, qtype).send("127.0.0.1", port, timeout=timeout)
    return DNSRecord.parse(data) if isinstance(data, (bytes, bytearray)) else data


# -- allowed domains --------------------------------------------------------

def test_allowed_domain_forwarded_to_upstream(upstream):
    service = build_service(upstream.port)
    try:
        reply = query("some-site.example", service.config.listen_port)
        assert reply.header.rcode == RCODE.NOERROR
        answers = [str(r.rdata) for r in reply.rr]
        assert UPSTREAM_A in answers
    finally:
        service.stop()


def test_txt_query_forwarded(upstream):
    service = build_service(upstream.port)
    try:
        reply = query("some-site.example", service.config.listen_port, qtype="TXT")
        assert reply.header.rcode == RCODE.NOERROR
        assert any("upstream-ok" in str(r.rdata) for r in reply.rr)
    finally:
        service.stop()


# -- blocked domains ----------------------------------------------------------

def test_blocked_domain_sinkhole_a_record(upstream):
    service = build_service(upstream.port)
    try:
        reply = query("blocked.example", service.config.listen_port)
        assert reply.header.rcode == RCODE.NOERROR
        assert [str(r.rdata) for r in reply.rr] == ["0.0.0.0"]
    finally:
        service.stop()


def test_blocked_domain_sinkhole_aaaa(upstream):
    service = build_service(upstream.port)
    try:
        reply = query("blocked.example", service.config.listen_port, qtype="AAAA")
        assert reply.header.rcode == RCODE.NOERROR
        assert [str(r.rdata) for r in reply.rr] == ["::"]
    finally:
        service.stop()


def test_blocked_domain_nxdomain_mode(upstream):
    service = build_service(upstream.port, block_mode="nxdomain")
    try:
        reply = query("blocked.example", service.config.listen_port)
        assert reply.header.rcode == RCODE.NXDOMAIN
        assert not reply.rr
    finally:
        service.stop()


def test_category_blocked_domain(upstream):
    service = build_service(upstream.port)
    try:
        reply = query("adult-site.example", service.config.listen_port)
        assert [str(r.rdata) for r in reply.rr] == ["0.0.0.0"]
    finally:
        service.stop()


def test_blocked_subdomain_of_blocked_parent(upstream):
    service = build_service(upstream.port)
    try:
        reply = query("ads.blocked.example", service.config.listen_port)
        assert [str(r.rdata) for r in reply.rr] == ["0.0.0.0"]
    finally:
        service.stop()


def test_default_block_policy_sinkholes_unknown(upstream):
    service = build_service(upstream.port, policy={
        "default_policy": "block", "allowlist": [], "blocklist": [],
        "category_rules": {"allow": [], "block": []},
    })
    try:
        reply = query("unknown.example", service.config.listen_port)
        assert [str(r.rdata) for r in reply.rr] == ["0.0.0.0"]
    finally:
        service.stop()


# -- upstream failure ---------------------------------------------------------

def test_upstream_failure_returns_servfail():
    # Port 9 (discard) is closed, so every upstream attempt times out.
    service = build_service(upstream_port=9)
    try:
        reply = query("some-site.example", service.config.listen_port)
        assert reply.header.rcode == RCODE.SERVFAIL
        assert not reply.rr
    finally:
        service.stop()


# -- malformed requests ---------------------------------------------------------

def test_malformed_packet_gets_formerr_and_service_survives(upstream):
    service = build_service(upstream.port)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.sendto(b"\x12\x34this-is-not-a-dns-packet",
                    ("127.0.0.1", service.config.listen_port))
        data, _ = sock.recvfrom(4096)
        reply = DNSRecord.parse(data)
        assert reply.header.id == 0x1234
        assert reply.header.rcode == RCODE.FORMERR
        # The service is still alive and answers real queries afterwards.
        ok = query("some-site.example", service.config.listen_port)
        assert ok.header.rcode == RCODE.NOERROR
    finally:
        service.stop()


# -- structured decision logs ---------------------------------------------------

def test_decision_log_fields_and_privacy(upstream):
    stream = io.StringIO()
    service = build_service(upstream.port, log_stream=stream)
    try:
        query("blocked.example", service.config.listen_port)
        query("some-site.example", service.config.listen_port)
    finally:
        service.stop()
    lines = [json.loads(x) for x in stream.getvalue().splitlines() if x.strip()]
    blocked = next(x for x in lines if x["domain"] == "blocked.example")
    allowed = next(x for x in lines if x["domain"] == "some-site.example")

    assert blocked["decision"] == "block"
    assert blocked["rule"] == "explicit_block"
    assert "blocked.example" in blocked["reason"]
    assert blocked["outcome"] == "answered_blocked"
    assert "ts" in blocked and "latency_ms" in blocked

    assert allowed["decision"] == "allow"
    assert allowed["outcome"] == "forwarded"
    assert allowed["upstream"] == "127.0.0.1"

    # Privacy: no client address anywhere in the log stream.
    assert "client" not in stream.getvalue()
    assert "127.0.0.1:" not in stream.getvalue()

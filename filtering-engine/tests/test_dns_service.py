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
import struct
import sys
import threading
import time
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
    upstream_ports = (upstream_port if isinstance(upstream_port, list)
                      else [upstream_port])
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
        upstreams=[("127.0.0.1", p) for p in upstream_ports],
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
    blocked = next(x for x in lines if x.get("decision") == "block")
    assert blocked["decision"] == "block"
    assert blocked["outcome"] == "answered_blocked"
    assert "ts" in blocked and "latency_ms" in blocked
    assert "domain" not in blocked and "reason" not in blocked
    assert "blocked.example" not in stream.getvalue()
    assert "some-site.example" not in stream.getvalue()
    assert "client" not in stream.getvalue()


# -- multiple upstreams ----------------------------------------------------

class SilentUpstream:
    """A fake upstream that receives queries, proves they arrived by
    signaling an event, and deliberately never answers - so the only
    possible client outcome is a genuine timeout."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.received = threading.Event()
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        while True:
            try:
                self.sock.recvfrom(4096)
            except OSError:
                return  # socket closed by stop()
            self.received.set()  # the query arrived; it is never answered

    def stop(self):
        try:
            self.sock.close()
        except OSError:
            pass
        if self._thread is not None:
            self._thread.join(timeout=2)


def test_first_upstream_timeout_fails_over_to_second(upstream):
    """Real timeout, proven: the first upstream receives the query (its
    event fires) and never answers, so the service's attempt on it runs
    to the full upstream timeout; the service then fails over to the
    second upstream and returns that upstream's answer."""
    silent = SilentUpstream()
    silent.start()
    service = build_service([silent.port, upstream.port])  # timeout 1.0s
    try:
        started = time.monotonic()
        reply = query("some-site.example", service.config.listen_port)
        elapsed = time.monotonic() - started
        # The first upstream got the query and never answered...
        assert silent.received.wait(1)
        # ...so the attempt genuinely timed out: an immediate error
        # (e.g. connection refused) would have failed over in
        # milliseconds, far under the 1s upstream timeout.
        assert elapsed >= 1.0
        assert reply.header.rcode == RCODE.NOERROR
        assert any(str(r.rdata) == UPSTREAM_A for r in reply.rr)
    finally:
        service.stop()
        silent.stop()


def test_first_upstream_refused_fails_over_to_second(upstream):
    # Port 9 (discard) is closed: the first upstream attempt gets an
    # immediate connection-refused error (NOT a timeout); the next
    # upstream must still get the query and answer it.
    service = build_service([9, upstream.port])
    try:
        reply = query("some-site.example", service.config.listen_port)
        assert reply.header.rcode == RCODE.NOERROR
        assert any(str(r.rdata) == UPSTREAM_A for r in reply.rr)
    finally:
        service.stop()


# -- malformed requests ------------------------------------------------------

def test_tiny_malformed_packet_dropped_and_service_survives(upstream):
    stream = io.StringIO()
    service = build_service(upstream.port, log_stream=stream)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        try:
            # One byte: not even a transaction ID is recoverable, so the
            # packet is dropped with no response (never a crash).
            sock.sendto(b"\x12", ("127.0.0.1", service.config.listen_port))
            with pytest.raises(socket.timeout):
                sock.recvfrom(4096)
        finally:
            sock.close()
        # The service is still alive and correct afterwards.
        ok = query("some-site.example", service.config.listen_port)
        assert ok.header.rcode == RCODE.NOERROR
        events = [json.loads(x) for x in stream.getvalue().splitlines()
                  if x.strip()]
        assert any(e.get("event") == "malformed_query"
                   and e.get("outcome") == "dropped_or_formerr"
                   for e in events)
    finally:
        service.stop()


def test_questionless_packet_refused_and_service_survives(upstream):
    """A parseable header with qdcount=0 carries no question to answer.
    dnslib supplies an empty (root-name) question, which normalizes to
    an empty domain, so the service answers REFUSED via the unusable-
    query-name path - an explicit error response, never a crash or a
    silently mis-filtered answer."""
    stream = io.StringIO()
    service = build_service(upstream.port, log_stream=stream)
    try:
        wire = struct.pack("!HHHHHH", 0xBEEF, 0, 0, 0, 0, 0)  # header, no question
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        try:
            sock.sendto(wire, ("127.0.0.1", service.config.listen_port))
            data, _ = sock.recvfrom(4096)
        finally:
            sock.close()
        reply = DNSRecord.parse(data)
        assert reply.header.id == 0xBEEF
        assert reply.header.rcode == RCODE.REFUSED
        # The service is still alive and correct afterwards.
        ok = query("some-site.example", service.config.listen_port)
        assert ok.header.rcode == RCODE.NOERROR
        events = [json.loads(x) for x in stream.getvalue().splitlines()
                  if x.strip()]
        assert any(e.get("outcome") == "answered_refused" for e in events)
    finally:
        service.stop()


def test_root_domain_query_refused(upstream):
    """The root name normalizes to an empty domain, which cannot be
    filtered: REFUSED, and the decision log records it honestly."""
    stream = io.StringIO()
    service = build_service(upstream.port, log_stream=stream)
    try:
        reply = query(".", service.config.listen_port)
        assert reply.header.rcode == RCODE.REFUSED
        events = [json.loads(x) for x in stream.getvalue().splitlines()
                  if x.strip()]
        refused = next(e for e in events
                       if e.get("outcome") == "answered_refused")
        assert refused["event"] == "dns_query"
    finally:
        service.stop()


# -- blocked domains: other query types --------------------------------------

def test_blocked_domain_other_qtypes_nxdomain_in_sinkhole_mode(upstream):
    # In sinkhole mode only A/AAAA queries get sinkhole answers; other
    # query types for blocked domains get NXDOMAIN.
    service = build_service(upstream.port)  # sinkhole mode
    try:
        reply = query("blocked.example", service.config.listen_port,
                      qtype="TXT")
        assert reply.header.rcode == RCODE.NXDOMAIN
        assert not reply.rr
    finally:
        service.stop()


# -- logging failures ----------------------------------------------------------

class RaisingStream:
    """A decision-log stream whose writes always fail (full disk, lost
    file, closed handle)."""

    def write(self, _s):
        raise OSError("log write failed")

    def flush(self):
        raise OSError("log write failed")


def test_logging_failure_does_not_crash_request_processing(upstream):
    # Every log write fails; the service must still answer correctly.
    service = build_service(upstream.port, log_stream=RaisingStream())
    try:
        blocked = query("blocked.example", service.config.listen_port)
        assert [str(r.rdata) for r in blocked.rr] == ["0.0.0.0"]
        allowed = query("some-site.example", service.config.listen_port)
        assert any(str(r.rdata) == UPSTREAM_A for r in allowed.rr)
    finally:
        service.stop()

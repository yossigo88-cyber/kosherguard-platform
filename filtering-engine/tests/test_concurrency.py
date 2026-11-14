"""Concurrency tests for the DNS filtering service.

Verifies the bounded worker pool: a slow or unreachable upstream must not
delay unrelated requests, the queue is bounded and saturates safely
(drop + log, never unbounded threads or memory), and shutdown closes
sockets and workers cleanly. Runs against an in-test slow fake upstream
over real UDP sockets; no internet access needed.
"""

import io
import json
import logging
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dnslib import A, QTYPE, DNSRecord, RR

from category_db import CategoryDB
from dns_service import DNSFilteringService, DecisionLogger, ServiceConfig
from policy_engine import PolicyEngine

UPSTREAM_A = "93.184.216.34"
SLOW_DELAY = 2.0  # seconds the slow upstream holds every response


class SlowUpstream(threading.Thread):
    """A fake upstream resolver that answers every A query with a fixed
    address, but only after `delay` seconds. Each request is answered on
    its own thread so concurrent slow queries do not serialize here."""

    def __init__(self, delay):
        super().__init__(daemon=True)
        self.delay = delay
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
            threading.Thread(target=self._answer_later, args=(data, client),
                             daemon=True).start()

    def _answer_later(self, data, client):
        time.sleep(self.delay)
        try:
            query = DNSRecord.parse(data)
            reply = query.reply()
            reply.add_answer(RR(str(query.q.qname), QTYPE.A,
                                rdata=A(UPSTREAM_A), ttl=300))
            self.sock.sendto(reply.pack(), client)
        except Exception:
            pass

    def stop(self):
        self.running = False
        self.sock.close()


@pytest.fixture()
def slow_upstream():
    server = SlowUpstream(SLOW_DELAY)
    server.start()
    yield server
    server.stop()


def build_service(upstream_port, max_workers=4, max_queued=16, log_stream=None):
    db = CategoryDB({"adult-site.example": ["adult"]})
    engine = PolicyEngine({
        "default_policy": "allow",
        "allowlist": [],
        "blocklist": ["blocked.example"],
        "category_rules": {"allow": [], "block": ["adult"]},
    }, db)
    config = ServiceConfig(
        listen_host="127.0.0.1",
        listen_port=0,  # ephemeral
        upstreams=[("127.0.0.1", upstream_port)],
        upstream_timeout=SLOW_DELAY + 3,
        max_workers=max_workers,
        max_queued=max_queued,
    )
    service = DNSFilteringService(engine, config,
                                  DecisionLogger(log_stream or io.StringIO()))
    service.start()
    return service


def query(domain, port, qtype="A", timeout=SLOW_DELAY + 5):
    data = DNSRecord.question(domain, qtype).send("127.0.0.1", port,
                                                  timeout=timeout)
    return DNSRecord.parse(data) if isinstance(data, (bytes, bytearray)) else data


# -- the required proof: a slow upstream must not block unrelated requests ---

def test_slow_upstream_does_not_delay_blocked_request(slow_upstream):
    service = build_service(slow_upstream.port)
    try:
        results = {}

        def slow_query():
            # Allowed domain: forwarded to the slow upstream, takes ~2s.
            results["slow"] = query("some-site.example",
                                    service.config.listen_port)

        t = threading.Thread(target=slow_query)
        t.start()
        time.sleep(0.3)  # let the slow query reach a worker + the upstream

        started = time.monotonic()
        reply = query("blocked.example", service.config.listen_port)
        elapsed = time.monotonic() - started

        # The blocked request is decided locally and must come back
        # promptly even though the upstream is still holding the other
        # request.
        assert [str(r.rdata) for r in reply.rr] == ["0.0.0.0"]
        assert elapsed < SLOW_DELAY / 2, (
            f"blocked request took {elapsed:.2f}s; a slow upstream delayed "
            f"an unrelated locally-decided request"
        )

        # The slow request still gets its real upstream answer afterwards.
        t.join(timeout=SLOW_DELAY + 5)
        assert not t.is_alive()
        assert any(str(r.rdata) == UPSTREAM_A for r in results["slow"].rr)
    finally:
        service.stop()


def test_multiple_slow_requests_run_concurrently(slow_upstream):
    service = build_service(slow_upstream.port, max_workers=4)
    try:
        results = {}
        threads = []
        for i in range(4):
            def worker(i=i):
                results[i] = query(f"site-{i}.example",
                                   service.config.listen_port)
            threads.append(threading.Thread(target=worker))
        started = time.monotonic()
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=SLOW_DELAY * 3 + 5)
        elapsed = time.monotonic() - started

        assert all(not t.is_alive() for t in threads)
        assert len(results) == 4
        for reply in results.values():
            assert any(str(r.rdata) == UPSTREAM_A for r in reply.rr)
        # Serial handling would take >= 4 * SLOW_DELAY; concurrency must
        # finish all four in well under twice one delay.
        assert elapsed < SLOW_DELAY * 2, (
            f"4 concurrent slow requests took {elapsed:.2f}s; "
            f"requests appear to be serialized"
        )
    finally:
        service.stop()


# -- saturation is safe: bounded queue, drop + log, service survives ---------

def test_saturation_drops_safely_and_service_survives(slow_upstream):
    stream = io.StringIO()
    # One worker, one queued slot: the tightest possible bound.
    service = build_service(slow_upstream.port, max_workers=1, max_queued=1,
                            log_stream=stream)
    try:
        results = {}
        t1 = threading.Thread(target=lambda: results.__setitem__(
            "first", query("one.example", service.config.listen_port)))
        t1.start()
        time.sleep(0.3)  # the single worker is now stuck on the slow upstream
        t2 = threading.Thread(target=lambda: results.__setitem__(
            "second", query("two.example", service.config.listen_port)))
        t2.start()
        time.sleep(0.2)  # the one queue slot now holds the second request

        # A third request exceeds the bound: it is dropped (no response),
        # not queued, and no extra thread is created for it.
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        sock.sendto(DNSRecord.question("three.example").pack(),
                    ("127.0.0.1", service.config.listen_port))
        with pytest.raises(socket.timeout):
            sock.recvfrom(4096)
        sock.close()

        t1.join(timeout=SLOW_DELAY + 5)
        t2.join(timeout=SLOW_DELAY + 5)
        assert not t1.is_alive() and not t2.is_alive()
        assert any(str(r.rdata) == UPSTREAM_A for r in results["first"].rr)
        assert any(str(r.rdata) == UPSTREAM_A for r in results["second"].rr)

        # The drop is visible in the structured log.
        events = [json.loads(line) for line in stream.getvalue().splitlines()
                  if line.strip()]
        assert any(e.get("event") == "queue_full"
                   and e.get("outcome") == "dropped" for e in events)

        # The service is still healthy: blocked domains are answered.
        reply = query("blocked.example", service.config.listen_port)
        assert [str(r.rdata) for r in reply.rr] == ["0.0.0.0"]
    finally:
        service.stop()


def test_shutdown_closes_workers_while_request_in_flight(slow_upstream):
    service = build_service(slow_upstream.port, max_workers=2)
    results = {}
    t = threading.Thread(target=lambda: results.__setitem__(
        "slow", query("some-site.example", service.config.listen_port)))
    t.start()
    time.sleep(0.3)  # request in flight against the slow upstream
    # Keep our own references: stop() prunes service._workers, so only
    # these saved threads can prove every worker really terminated.
    workers = list(service._workers)
    assert len(workers) == 2
    started = time.monotonic()
    survivors = service.stop()
    elapsed = time.monotonic() - started
    # Bounded wait: stop() lets the in-flight request (2s upstream delay)
    # finish and never hangs longer than the upstream-timeout bound.
    assert elapsed < SLOW_DELAY + 3
    # Clean shutdown: no survivors reported, and every worker thread we
    # saved has actually terminated.
    assert survivors == []
    for w in workers:
        assert not w.is_alive(), f"worker {w.name} still alive after stop()"
    assert service._sock.fileno() == -1  # socket closed
    t.join(timeout=5)
    assert not t.is_alive()
    # The in-flight request still received its response before shutdown
    # completed - clean, not dropped mid-flight.
    assert any(str(r.rdata) == UPSTREAM_A for r in results["slow"].rr)


def test_stop_reports_workers_that_fail_to_terminate(slow_upstream, caplog):
    """A worker stuck past the shutdown timeout must be reported, not
    silently discarded: stop() returns it, keeps it referenced, and logs
    the incomplete shutdown."""
    service = build_service(slow_upstream.port, max_workers=1)
    gate = threading.Event()

    def stuck(_data):
        gate.wait(30)  # stuck far past any shutdown timeout
        return None

    service.handle_packet = stuck
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(DNSRecord.question("blocked.example").pack(),
                ("127.0.0.1", service.config.listen_port))
    time.sleep(0.3)  # the single worker has the request and is stuck
    service.config.upstream_timeout = 0.1  # shutdown join bound ~2.1s
    try:
        with caplog.at_level(logging.WARNING, logger="kosherguard.dns"):
            survivors = service.stop()
        # Reported accurately, not claimed clean.
        assert len(survivors) == 1
        assert survivors[0].is_alive()
        assert service._workers == survivors  # still referenced, not discarded
        assert any("shutdown incomplete" in r.getMessage()
                   for r in caplog.records)
    finally:
        gate.set()  # release the stuck worker so nothing outlives the test
        sock.close()
    survivors[0].join(timeout=5)
    assert not survivors[0].is_alive()

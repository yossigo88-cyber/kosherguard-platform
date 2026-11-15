"""Stage 4 tests: DNS over TCP, upstream TCP fallback, EDNS0 and large
responses, bounded TCP resources, and shared-deadline shutdown.

All tests use local fake upstreams and real UDP/TCP sockets on
127.0.0.1; no internet access is needed.
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

from dnslib import A, EDNS0, QTYPE, RCODE, TXT, DNSRecord, RR

from category_db import CategoryDB
from dns_service import DNSFilteringService, DecisionLogger, ServiceConfig
from policy_engine import PolicyEngine

UPSTREAM_A = "93.184.216.34"
UPSTREAM_A2 = "93.184.216.99"


def tcp_query(domain, port, qtype="A", timeout=5, udp_size=None):
    """Send one DNS query over TCP (two-byte length framing) and return
    the parsed reply."""
    q = DNSRecord.question(domain, qtype)
    if udp_size:
        q.add_ar(EDNS0(udp_len=udp_size))
    data = q.pack()
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        sock.sendall(struct.pack("!H", len(data)) + data)
        header = _read_exact(sock, 2, timeout)
        length = struct.unpack("!H", header)[0]
        return DNSRecord.parse(_read_exact(sock, length, timeout))
    finally:
        sock.close()


def _read_exact(sock, n, timeout):
    sock.settimeout(timeout)
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return bytes(buf)


def udp_query(domain, port, qtype="A", timeout=5, udp_size=None):
    q = DNSRecord.question(domain, qtype)
    if udp_size:
        q.add_ar(EDNS0(udp_len=udp_size))
    data = q.send("127.0.0.1", port, timeout=timeout)
    return DNSRecord.parse(data) if isinstance(data, (bytes, bytearray)) else data


class FakeUpstream:
    """Combined UDP+TCP fake upstream on one port.

    delay:        seconds to hold every response (slow upstream).
    truncate_udp: answer UDP queries with a TC-flagged partial response;
                  TCP queries get the complete answer.
    large:        answer with a ~large_size-byte response (many TXT records).
    no_tcp:       do not run the TCP listener (TCP connects are refused).
    answer_ip:    A-record address returned for A queries.
    """

    def __init__(self, delay=0, truncate_udp=False, large=False,
                 large_size=1500, no_tcp=False, answer_ip=UPSTREAM_A):
        self.delay = delay
        self.truncate_udp = truncate_udp
        self.large = large
        self.large_size = large_size
        self.answer_ip = answer_ip
        self.running = True
        self.transports = []          # "udp"/"tcp" in arrival order
        self.queries = []             # parsed queries received
        self._lock = threading.Lock()

        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.bind(("127.0.0.1", 0))
        self.port = self.udp_sock.getsockname()[1]
        self.tcp_sock = None
        if not no_tcp:
            self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.tcp_sock.bind(("127.0.0.1", self.port))
            self.tcp_sock.listen(16)

        self._threads = [
            threading.Thread(target=self._serve_udp, daemon=True),
        ]
        if self.tcp_sock is not None:
            self._threads.append(
                threading.Thread(target=self._serve_tcp, daemon=True))
        for t in self._threads:
            t.start()

    # -- replies -----------------------------------------------------------

    def _reply(self, query, complete):
        reply = query.reply()
        # A real resolver echoes EDNS0 in its replies; copy the query's OPT.
        for rr in query.ar:
            if rr.rtype == QTYPE.OPT:
                reply.add_ar(rr)
        name = str(query.q.qname)
        if not complete:
            # TC-flagged partial answer: one record, flag set.
            reply.add_answer(RR(name, QTYPE.A, rdata=A(self.answer_ip), ttl=300))
            reply.header.tc = 1
            return reply
        if self.large:
            filler = "x" * 180
            while len(reply.pack()) < self.large_size:
                reply.add_answer(RR(name, QTYPE.TXT, rdata=TXT(filler), ttl=300))
        else:
            reply.add_answer(RR(name, QTYPE.A, rdata=A(self.answer_ip), ttl=300))
        return reply

    def _note(self, transport, query):
        with self._lock:
            self.transports.append(transport)
            self.queries.append(query)

    # -- serving -------------------------------------------------------------

    def _serve_udp(self):
        while self.running:
            try:
                data, client = self.udp_sock.recvfrom(4096)
            except OSError:
                return
            threading.Thread(target=self._answer_udp, args=(data, client),
                             daemon=True).start()

    def _answer_udp(self, data, client):
        if self.delay:
            time.sleep(self.delay)
        try:
            query = DNSRecord.parse(data)
            self._note("udp", query)
            reply = self._reply(query, complete=not self.truncate_udp)
            self.udp_sock.sendto(reply.pack(), client)
        except Exception:
            pass

    def _serve_tcp(self):
        try:
            self.tcp_sock.settimeout(0.2)
        except OSError:
            return  # stopped before the loop began
        while self.running:
            try:
                conn, _ = self.tcp_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._answer_tcp, args=(conn,),
                             daemon=True).start()

    def _answer_tcp(self, conn):
        try:
            if self.delay:
                time.sleep(self.delay)
            header = _read_exact(conn, 2, 5)
            length = struct.unpack("!H", header)[0]
            query = DNSRecord.parse(_read_exact(conn, length, 5))
            self._note("tcp", query)
            reply = self._reply(query, complete=True).pack()
            conn.sendall(struct.pack("!H", len(reply)) + reply)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self):
        self.running = False
        self.udp_sock.close()
        if self.tcp_sock is not None:
            self.tcp_sock.close()


@pytest.fixture()
def upstream():
    server = FakeUpstream()
    yield server
    server.stop()


def build_service(upstream_ports, log_stream=None, **config_overrides):
    db = CategoryDB({"adult-site.example": ["adult"]})
    engine = PolicyEngine({
        "default_policy": "allow",
        "allowlist": [],
        "blocklist": ["blocked.example"],
        "category_rules": {"allow": [], "block": ["adult"]},
    }, db)
    if not isinstance(upstream_ports, list):
        upstream_ports = [upstream_ports]
    config_overrides.setdefault("tcp_idle_timeout", 2.0)
    config_overrides.setdefault("upstream_timeout", 2.0)
    config = ServiceConfig(
        listen_host="127.0.0.1",
        listen_port=0,  # ephemeral
        upstreams=[("127.0.0.1", p) for p in upstream_ports],
        **config_overrides,
    )
    service = DNSFilteringService(engine, config,
                                  DecisionLogger(log_stream or io.StringIO()))
    service.start()
    return service


def log_events(stream):
    return [json.loads(line) for line in stream.getvalue().splitlines()
            if line.strip()]


# -- basic TCP behavior ------------------------------------------------------

def test_tcp_blocked_query(upstream):
    service = build_service(upstream.port)
    try:
        reply = tcp_query("blocked.example", service.config.listen_port)
        assert [str(r.rdata) for r in reply.rr] == ["0.0.0.0"]
    finally:
        service.stop()


def test_tcp_allowed_query(upstream):
    service = build_service(upstream.port)
    try:
        reply = tcp_query("some-site.example", service.config.listen_port)
        assert any(str(r.rdata) == UPSTREAM_A for r in reply.rr)
    finally:
        service.stop()


def test_tcp_multiple_messages_one_connection_in_order(upstream):
    service = build_service(upstream.port)
    try:
        sock = socket.create_connection(
            ("127.0.0.1", service.config.listen_port), timeout=5)
        try:
            for domain, expected in (
                ("blocked.example", "0.0.0.0"),
                ("some-site.example", UPSTREAM_A),
                ("blocked.example", "0.0.0.0"),
            ):
                data = DNSRecord.question(domain).pack()
                sock.sendall(struct.pack("!H", len(data)) + data)
                header = _read_exact(sock, 2, 5)
                reply = DNSRecord.parse(
                    _read_exact(sock, struct.unpack("!H", header)[0], 5))
                assert [str(r.rdata) for r in reply.rr] == [expected]
        finally:
            sock.close()
    finally:
        service.stop()


def test_tcp_partial_message_delivery(upstream):
    service = build_service(upstream.port)
    try:
        sock = socket.create_connection(
            ("127.0.0.1", service.config.listen_port), timeout=5)
        try:
            data = DNSRecord.question("blocked.example").pack()
            framed = struct.pack("!H", len(data)) + data
            for i in range(0, len(framed), 3):  # 3-byte trickle
                sock.sendall(framed[i:i + 3])
                time.sleep(0.01)
            header = _read_exact(sock, 2, 5)
            reply = DNSRecord.parse(
                _read_exact(sock, struct.unpack("!H", header)[0], 5))
            assert [str(r.rdata) for r in reply.rr] == ["0.0.0.0"]
        finally:
            sock.close()
    finally:
        service.stop()


def test_tcp_malformed_and_invalid_do_not_crash(upstream):
    service = build_service(upstream.port)
    try:
        # Framed garbage with a recoverable transaction ID: FORMERR.
        sock = socket.create_connection(
            ("127.0.0.1", service.config.listen_port), timeout=5)
        try:
            garbage = b"\x12\x34this-is-not-a-dns-packet"
            sock.sendall(struct.pack("!H", len(garbage)) + garbage)
            header = _read_exact(sock, 2, 5)
            reply = DNSRecord.parse(
                _read_exact(sock, struct.unpack("!H", header)[0], 5))
            assert reply.header.id == 0x1234
            assert reply.header.rcode == RCODE.FORMERR
        finally:
            sock.close()

        # Zero length is an invalid message length: connection closed.
        sock = socket.create_connection(
            ("127.0.0.1", service.config.listen_port), timeout=5)
        try:
            sock.sendall(struct.pack("!H", 0))
            sock.settimeout(5)
            assert sock.recv(64) == b""  # closed by the server
        finally:
            sock.close()

        # The service is still alive and correct afterwards.
        reply = tcp_query("blocked.example", service.config.listen_port)
        assert [str(r.rdata) for r in reply.rr] == ["0.0.0.0"]
    finally:
        service.stop()


def test_slow_tcp_client_does_not_block_unrelated_requests(upstream):
    service = build_service(upstream.port, tcp_workers=2)
    try:
        slow = socket.create_connection(
            ("127.0.0.1", service.config.listen_port), timeout=5)
        try:
            data = DNSRecord.question("some-site.example").pack()
            framed = struct.pack("!H", len(data)) + data
            slow.sendall(framed[:5])  # message half-sent: worker waits
            time.sleep(0.3)           # ensure the worker holds the partial read

            started = time.monotonic()
            reply = tcp_query("blocked.example", service.config.listen_port)
            elapsed = time.monotonic() - started
            assert [str(r.rdata) for r in reply.rr] == ["0.0.0.0"]
            assert elapsed < 1.0

            # The slow client still gets served once it finishes sending.
            slow.sendall(framed[5:])
            header = _read_exact(slow, 2, 5)
            ok = DNSRecord.parse(
                _read_exact(slow, struct.unpack("!H", header)[0], 5))
            assert any(str(r.rdata) == UPSTREAM_A for r in ok.rr)
        finally:
            slow.close()
    finally:
        service.stop()


# -- bounded TCP resources -----------------------------------------------------

def test_tcp_queue_full_closes_connection_and_logs(upstream):
    stream = io.StringIO()
    service = build_service(upstream.port, log_stream=stream,
                            tcp_workers=1, tcp_queued=1,
                            tcp_idle_timeout=5.0)
    held = socket.create_connection(
        ("127.0.0.1", service.config.listen_port), timeout=5)  # occupies the worker
    try:
        held.sendall(b"\x00")  # partial frame: worker is now stuck reading it
        time.sleep(0.3)  # worker has conn 1, queue empty
        queued = socket.create_connection(
            ("127.0.0.1", service.config.listen_port), timeout=5)  # fills the queue
        time.sleep(0.3)  # queue now holds conn 2
        third = socket.create_connection(
            ("127.0.0.1", service.config.listen_port), timeout=5)
        try:
            third.settimeout(5)
            assert third.recv(64) == b""  # closed safely, not answered
        finally:
            third.close()
        assert any(e.get("event") == "tcp_queue_full"
                   and e.get("outcome") == "connection_closed"
                   for e in log_events(stream))
    finally:
        held.close()
        queued.close()
        service.stop()


def test_idle_connection_closed_after_timeout(upstream):
    service = build_service(upstream.port, tcp_idle_timeout=0.5)
    try:
        sock = socket.create_connection(
            ("127.0.0.1", service.config.listen_port), timeout=5)
        try:
            started = time.monotonic()
            sock.settimeout(5)
            assert sock.recv(64) == b""  # server closed the idle connection
            assert time.monotonic() - started < 3
        finally:
            sock.close()
    finally:
        service.stop()


def test_max_messages_per_connection_enforced(upstream):
    # High idle timeout: the per-connection message cap is the only
    # mechanism that can close this connection. A third message is never
    # sent: the server closes after the cap without reading further
    # input, and unread client data in its buffer would turn the close
    # into a RST, making the assertion below a race.
    service = build_service(upstream.port, tcp_max_messages=2,
                            tcp_idle_timeout=30.0)
    try:
        sock = socket.create_connection(
            ("127.0.0.1", service.config.listen_port), timeout=5)
        try:
            data = DNSRecord.question("blocked.example").pack()
            framed = struct.pack("!H", len(data)) + data
            for _ in range(2):
                sock.sendall(framed)
                header = _read_exact(sock, 2, 5)
                _read_exact(sock, struct.unpack("!H", header)[0], 5)
            sock.settimeout(5)
            assert sock.recv(4096) == b""  # cap reached: closed promptly
        finally:
            sock.close()
    finally:
        service.stop()


# -- listener setup ------------------------------------------------------------

def test_port_zero_binds_both_transports_to_same_port(upstream):
    service = build_service(upstream.port)  # listen_port=0
    try:
        port = service.config.listen_port
        assert port != 0
        udp_reply = udp_query("blocked.example", port)
        tcp_reply = tcp_query("blocked.example", port)
        assert [str(r.rdata) for r in udp_reply.rr] == ["0.0.0.0"]
        assert [str(r.rdata) for r in tcp_reply.rr] == ["0.0.0.0"]
    finally:
        service.stop()


def test_tcp_bind_failure_cleans_up_udp_listener(upstream):
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    port = blocker.getsockname()[1]
    try:
        db = CategoryDB({})
        engine = PolicyEngine({"default_policy": "allow"}, db)
        config = ServiceConfig(listen_host="127.0.0.1", listen_port=port,
                               upstreams=[("127.0.0.1", upstream.port)])
        service = DNSFilteringService(engine, config,
                                      DecisionLogger(io.StringIO()))
        with pytest.raises(OSError):
            service.start()
        assert not service._running.is_set()
        assert not any(t.is_alive() for t in service._all_threads())
        # The UDP listener it had bound is released again.
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.bind(("127.0.0.1", port))
        finally:
            probe.close()
    finally:
        blocker.close()


# -- upstream TCP fallback -------------------------------------------------------

def test_truncated_udp_upstream_triggers_tcp_fallback():
    up = FakeUpstream(truncate_udp=True)
    stream = io.StringIO()
    service = build_service(up.port, log_stream=stream)
    try:
        reply = udp_query("some-site.example", service.config.listen_port)
        # Complete answer came back over the TCP fallback, not the
        # TC-flagged partial UDP answer.
        assert reply.header.rcode == RCODE.NOERROR
        assert any(str(r.rdata) == UPSTREAM_A for r in reply.rr)
        assert up.transports == ["udp", "tcp"]
        forwarded = next(e for e in log_events(stream)
                         if e.get("outcome") == "forwarded")
        assert forwarded["transport"] == "tcp"
    finally:
        service.stop()
        up.stop()


def test_failed_tcp_fallback_moves_to_next_upstream():
    up1 = FakeUpstream(truncate_udp=True, no_tcp=True)  # TCP refused
    up2 = FakeUpstream(answer_ip=UPSTREAM_A2)
    stream = io.StringIO()
    service = build_service([up1.port, up2.port], log_stream=stream)
    try:
        reply = udp_query("some-site.example", service.config.listen_port)
        assert any(str(r.rdata) == UPSTREAM_A2 for r in reply.rr)
        assert up1.transports == ["udp"]  # no TCP listener ever got a query
        assert up2.transports == ["udp"]
        events = log_events(stream)
        assert any(e.get("outcome") == "tcp_fallback_failed"
                   for e in events)
        forwarded = next(e for e in events if e.get("outcome") == "forwarded")
        assert forwarded["transport"] == "udp"
    finally:
        service.stop()
        up1.stop()
        up2.stop()


def test_all_upstreams_fail_returns_servfail_over_tcp_too():
    # Dead ports: UDP attempts time out.
    service = build_service(9)
    try:
        reply = tcp_query("some-site.example", service.config.listen_port)
        assert reply.header.rcode == RCODE.SERVFAIL
    finally:
        service.stop()


def test_edns0_preserved_when_forwarding(upstream):
    service = build_service(upstream.port)
    try:
        reply = udp_query("some-site.example", service.config.listen_port,
                          udp_size=2048)
        assert reply.header.rcode == RCODE.NOERROR
        assert upstream.queries, "upstream saw no query"
        opt = [rr for rr in upstream.queries[-1].ar if rr.rtype == QTYPE.OPT]
        assert opt, "upstream did not receive the client's OPT record"
        assert opt[0].rclass == 2048
    finally:
        service.stop()


# -- large responses and downstream size rules ----------------------------------

def test_large_response_truncated_at_512_without_opt():
    up = FakeUpstream(large=True, large_size=1500)
    service = build_service(up.port)
    try:
        q = DNSRecord.question("some-site.example")  # no OPT record
        data = q.send("127.0.0.1", service.config.listen_port, timeout=5)
        packet = bytes(data) if isinstance(data, (bytes, bytearray)) else data.pack()
        assert len(packet) <= 512
        reply = DNSRecord.parse(packet)
        assert reply.header.tc == 1
        assert 0 < len(reply.rr) < 20  # some whole records, not all
    finally:
        service.stop()
        up.stop()


def test_large_response_complete_with_sufficient_edns0():
    up = FakeUpstream(large=True, large_size=1500)
    service = build_service(up.port)
    try:
        q = DNSRecord.question("some-site.example")
        q.add_ar(EDNS0(udp_len=2048))
        data = q.send("127.0.0.1", service.config.listen_port, timeout=5)
        packet = bytes(data) if isinstance(data, (bytes, bytearray)) else data.pack()
        reply = DNSRecord.parse(packet)
        assert reply.header.tc == 0
        assert len(reply.rr) >= 5  # the full multi-record answer
        # The OPT record is preserved in the response.
        assert any(rr.rtype == QTYPE.OPT for rr in reply.ar)
    finally:
        service.stop()
        up.stop()


def test_max_udp_response_caps_even_when_client_allows_more():
    up = FakeUpstream(large=True, large_size=1500)
    service = build_service(up.port, max_udp_response=600)
    try:
        q = DNSRecord.question("some-site.example")
        q.add_ar(EDNS0(udp_len=4096))
        data = q.send("127.0.0.1", service.config.listen_port, timeout=5)
        packet = bytes(data) if isinstance(data, (bytes, bytearray)) else data.pack()
        assert len(packet) <= 600
        reply = DNSRecord.parse(packet)
        assert reply.header.tc == 1
    finally:
        service.stop()
        up.stop()


def test_tcp_downstream_gets_complete_large_response():
    up = FakeUpstream(large=True, large_size=3000)
    service = build_service(up.port)
    try:
        reply = tcp_query("some-site.example", service.config.listen_port)
        assert reply.header.tc == 0
        assert len(reply.rr) >= 10  # complete, untruncated, far over 512 bytes
    finally:
        service.stop()
        up.stop()


def test_truncated_udp_upstream_large_answer_complete_over_tcp_downstream():
    """Truncated upstream UDP -> TCP fallback -> downstream TCP client gets
    the complete large answer; downstream UDP client gets a valid
    TC-flagged truncation of it."""
    up = FakeUpstream(truncate_udp=True, large=True, large_size=2000)
    service = build_service(up.port)
    try:
        tcp_reply = tcp_query("some-site.example", service.config.listen_port)
        assert tcp_reply.header.tc == 0
        assert len(tcp_reply.rr) >= 8

        q = DNSRecord.question("some-site.example")
        q.add_ar(EDNS0(udp_len=1024))  # smaller than the 2000-byte answer
        data = q.send("127.0.0.1", service.config.listen_port, timeout=5)
        packet = bytes(data) if isinstance(data, (bytes, bytearray)) else data.pack()
        assert len(packet) <= 1024
        udp_reply = DNSRecord.parse(packet)
        assert udp_reply.header.tc == 1
        assert len(udp_reply.rr) < len(tcp_reply.rr)
        # The OPT record is preserved in the truncated response.
        assert any(rr.rtype == QTYPE.OPT for rr in udp_reply.ar)
    finally:
        service.stop()
        up.stop()




# -- per-message read deadline -------------------------------------------------

def test_message_fragmented_across_reads_within_deadline_succeeds(upstream):
    """Prefix and body each arrive in pieces; the complete frame lands
    well within the shared per-message deadline, so it is answered."""
    service = build_service(upstream.port, tcp_idle_timeout=3.0)
    try:
        sock = socket.create_connection(
            ("127.0.0.1", service.config.listen_port), timeout=5)
        try:
            data = DNSRecord.question("blocked.example").pack()
            framed = struct.pack("!H", len(data)) + data
            # Prefix in two pieces, body in two pieces, small pauses.
            sock.sendall(framed[:1])
            time.sleep(0.2)
            sock.sendall(framed[1:2])
            time.sleep(0.2)
            half = 2 + len(data) // 2
            sock.sendall(framed[2:half])
            time.sleep(0.2)
            sock.sendall(framed[half:])
            header = _read_exact(sock, 2, 5)
            reply = DNSRecord.parse(
                _read_exact(sock, struct.unpack("!H", header)[0], 5))
            assert [str(r.rdata) for r in reply.rr] == ["0.0.0.0"]
        finally:
            sock.close()
    finally:
        service.stop()


def test_prefix_and_body_each_fast_but_total_over_deadline_disconnects(upstream):
    """The prefix takes less than tcp_idle_timeout and the body takes less
    than tcp_idle_timeout, but together they exceed it: the connection
    must be closed without an answer, because one deadline covers the
    whole message."""
    service = build_service(upstream.port, tcp_idle_timeout=1.0)
    try:
        sock = socket.create_connection(
            ("127.0.0.1", service.config.listen_port), timeout=5)
        try:
            data = DNSRecord.question("blocked.example").pack()
            sock.sendall(struct.pack("!H", len(data))[:1])
            time.sleep(0.6)  # prefix complete at ~0.6s: under 1.0s alone
            sock.sendall(struct.pack("!H", len(data))[1:])
            time.sleep(0.6)  # body complete at ~1.2s: over the shared 1.0s
            sock.sendall(data)
            sock.settimeout(5)
            assert sock.recv(64) == b""  # closed at the deadline, unanswered
        finally:
            sock.close()
        # The service is healthy afterwards.
        reply = tcp_query("blocked.example", service.config.listen_port)
        assert [str(r.rdata) for r in reply.rr] == ["0.0.0.0"]
    finally:
        service.stop()


def test_shutdown_budget_covers_one_message_deadline(upstream):
    """The shutdown budget accounts for ONE tcp_idle_timeout, which is
    the longest a worker can wait on one incomplete message now that the
    length prefix and body share a single per-message deadline."""
    service = build_service(upstream.port, upstream_timeout=0.5,
                            tcp_idle_timeout=1.25)
    try:
        expected = 0.5 * len(service.config.upstreams) * 2 + 1.25 + 2.0
        assert service._shutdown_budget() == expected
    finally:
        service.stop()


# -- shutdown closes queued connections -----------------------------------------

def test_queued_connection_closed_during_shutdown(upstream):
    """One worker busy on a held connection, one connection waiting in
    the queue: stop() must close BOTH client sockets, leave the queue
    empty, and finish with no surviving TCP worker."""
    service = build_service(upstream.port, tcp_workers=1, tcp_queued=1,
                            tcp_idle_timeout=2.0, upstream_timeout=0.5)
    held = socket.create_connection(
        ("127.0.0.1", service.config.listen_port), timeout=5)
    try:
        held.sendall(b"\x00")  # partial frame: the one worker is busy reading
        time.sleep(0.3)
        queued = socket.create_connection(
            ("127.0.0.1", service.config.listen_port), timeout=5)
        time.sleep(0.3)  # queued connection is waiting in the queue
        try:
            survivors = service.stop()
            assert survivors == []  # clean shutdown, honestly reported
            for sock in (held, queued):
                sock.settimeout(5)
                assert sock.recv(64) == b""  # both closed by the service
            assert service._tcp_conn_queue.qsize() == 0
            assert not any(t.is_alive() and "tcp" in t.name
                           for t in service._all_threads())
        finally:
            queued.close()
    finally:
        held.close()
        service.stop()


def test_accept_during_shutdown_never_enqueues_untracked_connection(upstream):
    """Race guard: a connection accepted after _stopping is set is closed
    immediately instead of being enqueued where nobody would drain it."""
    service = build_service(upstream.port)
    try:
        service._stopping.set()  # shutdown begins while accept() runs
        time.sleep(0.1)
        sock = socket.create_connection(
            ("127.0.0.1", service.config.listen_port), timeout=5)
        try:
            sock.settimeout(5)
            assert sock.recv(64) == b""  # closed, never queued or served
            assert service._tcp_conn_queue.qsize() == 0
        finally:
            sock.close()
    finally:
        service._stopping.clear()  # let stop() run its normal path
        service.stop()


# -- listener startup failure cleanup -------------------------------------------

def test_udp_bind_failure_cleans_up(monkeypatch, upstream):
    """A failing UDP bind must close the created socket, clear the
    service references, and leave no threads running."""
    blocker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    blocker.bind(("127.0.0.1", 0))
    port = blocker.getsockname()[1]
    created = []
    real_socket = socket.socket

    def recording_socket(*args, **kwargs):
        sock = real_socket(*args, **kwargs)
        created.append(sock)
        return sock

    monkeypatch.setattr("dns_service.socket.socket", recording_socket)
    try:
        db = CategoryDB({})
        engine = PolicyEngine({"default_policy": "allow"}, db)
        config = ServiceConfig(listen_host="127.0.0.1", listen_port=port,
                               upstreams=[("127.0.0.1", upstream.port)])
        service = DNSFilteringService(engine, config,
                                      DecisionLogger(io.StringIO()))
        with pytest.raises(OSError):
            service.start()
        assert created, "the UDP socket was created before the bind failed"
        assert created[0].fileno() == -1  # explicitly closed
        assert service._sock is None
        assert service._tcp_sock is None
        assert not service._running.is_set()
        assert not any(t.is_alive() for t in service._all_threads())
    finally:
        blocker.close()


# -- UDP response-size guarantee -------------------------------------------------

def test_max_udp_response_below_minimum_rejected(upstream):
    """max_udp_response has a documented 512-byte minimum: below it the
    truncation guarantee (header + question always fit) could not hold."""
    with pytest.raises(ValueError):
        build_service(upstream.port, max_udp_response=511)
    with pytest.raises(ValueError):
        build_service(upstream.port, max_udp_response=0)
    service = build_service(upstream.port, max_udp_response=512)  # accepted
    service.stop()


def test_oversized_opt_dropped_to_fit_udp_limit():
    """An OPT record too large to fit is dropped rather than sent
    oversized: the UDP response never exceeds the effective limit and
    always carries TC when anything was removed."""
    up = FakeUpstream()
    service = build_service(up.port)
    try:
        query = DNSRecord.question("some-site.example")
        query.header.id = 0x2222
        base = query.pack()
        # Append an OPT RR advertising a 512-byte payload with ~600 bytes
        # of option data: header+question+OPT alone exceed 512 bytes.
        opt = struct.pack("!B H H I H", 0, 41, 512, 0, 600) + b"\x00" * 600
        wire = base[:10] + struct.pack("!H", 1) + base[12:] + opt
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        try:
            sock.sendto(wire, ("127.0.0.1", service.config.listen_port))
            packet, _ = sock.recvfrom(4096)
        finally:
            sock.close()
        reply = DNSRecord.parse(packet)  # valid wire data, no cut records
        assert len(packet) <= 512
        assert reply.header.tc == 1
        assert not any(rr.rtype == QTYPE.OPT for rr in reply.ar)
        # Retrying over TCP yields the complete answer.
        tcp_reply = tcp_query("some-site.example", service.config.listen_port)
        assert tcp_reply.header.tc == 0
        assert any(str(r.rdata) == UPSTREAM_A for r in tcp_reply.rr)
    finally:
        service.stop()
        up.stop()



def test_worker_closes_connection_dequeued_after_shutdown_began(upstream):
    """Race regression, fully synchronized: the TCP worker is gated
    BEFORE service.start() so it cannot reach the original queue read
    until the instrumentation is installed; it is then provably inside
    _tcp_conn_queue.get() (having passed its loop's shutdown check) when
    shutdown sets _stopping, and the get returns a queued connection.
    That connection was never genuinely served, so the worker must close
    it without calling _serve_tcp_conn()."""
    # Constructed directly (not via build_service) so the worker gate is
    # installed before any worker thread exists.
    db = CategoryDB({"adult-site.example": ["adult"]})
    engine = PolicyEngine({"default_policy": "allow", "allowlist": [],
                           "blocklist": ["blocked.example"],
                           "category_rules": {"allow": [], "block": ["adult"]}},
                          db)
    config = ServiceConfig(
        listen_host="127.0.0.1",
        listen_port=0,  # ephemeral
        upstreams=[("127.0.0.1", upstream.port)],
        upstream_timeout=2.0,
        tcp_idle_timeout=2.0,
        tcp_workers=1,
        tcp_queued=4,
    )
    service = DNSFilteringService(engine, config, DecisionLogger(io.StringIO()))

    served = []
    real_serve = service._serve_tcp_conn

    def spy(conn):
        served.append(conn)
        return real_serve(conn)

    service._serve_tcp_conn = spy

    # Gate installed before start(): each TCP worker signals when it
    # reaches the gate and is held there, before entering the original
    # _tcp_worker() loop, so no worker can call queue.get() until the
    # test has installed the instrumented get.
    reached_gate = threading.Event()
    open_gate = threading.Event()
    real_worker = service._tcp_worker

    def gated_worker():
        reached_gate.set()
        assert open_gate.wait(5), "test never released the worker gate"
        real_worker()

    service._tcp_worker = gated_worker

    entered_get = threading.Event()
    release_get = threading.Event()
    try:
        service.start()
        try:
            assert reached_gate.wait(5), "worker never started"
            # The worker is held before its loop: instrument the queue
            # read now, before any get() call can have happened.
            real_get = service._tcp_conn_queue.get

            def instrumented_get(*args, **kwargs):
                entered_get.set()
                assert release_get.wait(5), "test never released the read"
                return real_get(*args, **kwargs)

            service._tcp_conn_queue.get = instrumented_get
            open_gate.set()
            assert entered_get.wait(5), "worker never reached the queue read"
            assert service._tcp_workers[0].is_alive()

            # The worker is held inside get(). Begin shutdown, then
            # enqueue a tracked, never-served connection (socketpair:
            # the server end plays the accepted connection).
            server_end, client_end = socket.socketpair()
            with service._conns_lock:
                service._active_conns.add(server_end)
            service._stopping.set()
            service._tcp_conn_queue.put_nowait(server_end)
            release_get.set()  # worker's get() now returns the connection
            try:
                assert service._tcp_workers[0].join(5) is None
                assert not service._tcp_workers[0].is_alive()
                assert served == []  # never served after shutdown began
                client_end.settimeout(5)
                assert client_end.recv(64) == b""  # closed by the worker
                assert service._tcp_conn_queue.qsize() == 0
            finally:
                client_end.close()
        finally:
            # Never strand the worker at either gate, even on failure.
            open_gate.set()
            release_get.set()
    finally:
        survivors = service.stop()
    assert survivors == []  # clean shutdown, no surviving worker

# -- shutdown ---------------------------------------------------------

def test_shutdown_closes_listeners_connections_and_workers(upstream):
    service = build_service(upstream.port, tcp_idle_timeout=1.0)
    idle = socket.create_connection(
        ("127.0.0.1", service.config.listen_port), timeout=5)
    try:
        time.sleep(0.2)
        survivors = service.stop()
        assert survivors == []
        assert service._sock.fileno() == -1
        assert service._tcp_sock.fileno() == -1
        # The idle client connection was closed by the server.
        idle.settimeout(5)
        assert idle.recv(64) == b""
    finally:
        idle.close()

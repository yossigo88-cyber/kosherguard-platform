"""DNS filtering service for the KosherGuard core filtering engine (Stage 4).

A UDP + TCP DNS service that answers queries according to the central
policy engine:

- Allowed domains are forwarded to a configurable upstream resolver over
  UDP. If the upstream's UDP answer has the truncation (TC) flag set, the
  same query (EDNS0 included) is retried over TCP to the same upstream;
  if that fails, the next upstream is tried. When every upstream fails,
  the client gets SERVFAIL.
- Blocked domains are answered locally: by default a sinkhole answer
  (0.0.0.0 for A, :: for AAAA); NXDOMAIN for other query types, or for all
  types when block_mode is "nxdomain".
- Malformed packets get a FORMERR response when a transaction ID can be
  recovered, and are otherwise dropped (UDP) or the connection is closed
  (TCP). The service never crashes on bad input.

TCP transport (RFC 1035 section 4.2.2 framing): each DNS message is
prefixed with a two-byte unsigned big-endian length. TCP and UDP listen
on the same configured port; with port 0 the UDP socket binds first and
TCP takes its assigned port. If either listener fails to start, the
other is closed again - the service never runs half-started. Accepted
connections go to a fixed-size worker pool through a bounded queue; a
connection that arrives at a full queue is closed and logged. Per-read,
per-message, idle, and message-count limits keep one client from
occupying a worker indefinitely.

Downstream response sizes: UDP clients get at most their advertised
EDNS0 payload size (512 bytes without an OPT record), further capped by
the configurable max_udp_response safety limit. Oversized UDP responses
are truncated at DNS-record boundaries with the TC flag set - never cut
mid-record - with the OPT record preserved. TCP clients always get the
complete response (up to the protocol's 65535-byte frame limit).

Concurrency: incoming requests are handled by bounded worker pools
(separate pools for UDP requests and TCP connections; configurable
sizes and queue bounds). A slow or unreachable upstream or client
occupies at most one worker. When a queue is full, new work is dropped
(UDP) or the connection is closed (TCP) and the event is logged; both
are the standard overload answers and keep resource use strictly
bounded.

Shutdown: one overall monotonic deadline is shared by the receive
thread, accept thread, and all workers of both pools; every join only
gets the time remaining, so the total wait never multiplies by the
number of threads or connections. In-flight requests get a bounded
opportunity to finish; idle or slow TCP connections are then closed to
unblock their workers. Threads still alive at the deadline are logged by
name, kept referenced, and returned - an incomplete shutdown is never
reported as clean.

Scope, stated plainly: DNS filtering controls access to *domains*. It
cannot block individual URLs, pages, or paths, and it cannot see or filter
the contents of encrypted HTTPS traffic. See README.md.

Privacy by design: the client IP address is intentionally NOT recorded in
the decision log. Logs contain the requested domain, the decision, and why.
"""

from __future__ import annotations

import json
import logging
import queue
import socket
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from dnslib import AAAA, A, QTYPE, RCODE, DNSHeader, DNSRecord, RR

from policy_engine import PolicyEngine, normalize_domain

log = logging.getLogger("kosherguard.dns")

SINKHOLE_IPV4 = "0.0.0.0"
SINKHOLE_IPV6 = "::"

DNS_TCP_MAX_MESSAGE = 65535  # two-byte length prefix limits the frame
DNS_CLASSIC_UDP_SIZE = 512  # limit when the client sent no EDNS0 OPT
TCP_LISTEN_BACKLOG = 64  # kernel backlog behind the application queue


class DecisionLogger:
    """Structured JSON-lines decision log, suitable for future dashboard
    ingestion. One JSON object per line. No personal data is collected:
    the client address is never written."""

    def __init__(self, stream) -> None:
        self._stream = stream
        self._lock = threading.Lock()

    def log_decision(self, record: dict) -> None:
        record = dict(record)
        record["ts"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        line = json.dumps(record, sort_keys=True)
        with self._lock:
            self._stream.write(line + "\n")
            self._stream.flush()


@dataclass
class ServiceConfig:
    """Runtime configuration for the DNS filtering service."""

    listen_host: str = "127.0.0.1"
    listen_port: int = 5353  # 53 in production (needs privileges); 5353 for local dev
    upstreams: List[Tuple[str, int]] = field(
        default_factory=lambda: [("1.1.1.1", 53), ("8.8.8.8", 53)]
    )
    upstream_timeout: float = 3.0  # seconds per upstream attempt (UDP or TCP)
    block_mode: str = "sinkhole"  # "sinkhole" or "nxdomain"
    blocked_ttl: int = 60
    # Bounded concurrency, UDP: how many requests are processed in
    # parallel and how many may wait for a worker before being dropped.
    max_workers: int = 32
    max_queued: int = 128
    # Bounded concurrency, TCP: fixed worker pool for accepted
    # connections and a bounded queue of accepted connections waiting
    # for a worker.
    tcp_workers: int = 16
    tcp_queued: int = 64
    # Per-connection limits so one client cannot hold a worker forever:
    # every read and every complete message must arrive within
    # tcp_idle_timeout seconds, and a connection is closed after
    # tcp_max_messages DNS messages.
    tcp_idle_timeout: float = 10.0
    tcp_max_messages: int = 64
    # Safety cap on UDP responses to clients, on top of the client's own
    # advertised EDNS0 payload size (512 bytes without an OPT record).
    max_udp_response: int = 4096


class DNSFilteringService:
    """A policy-driven DNS filtering service (UDP + TCP)."""

    def __init__(
        self,
        engine: PolicyEngine,
        config: Optional[ServiceConfig] = None,
        decision_logger: Optional[DecisionLogger] = None,
    ) -> None:
        self.engine = engine
        self.config = config or ServiceConfig()
        if self.config.block_mode not in ("sinkhole", "nxdomain"):
            raise ValueError(f"unknown block_mode: {self.config.block_mode!r}")
        for name in ("max_workers", "max_queued", "tcp_workers", "tcp_queued",
                     "tcp_max_messages", "max_udp_response"):
            value = getattr(self.config, name)
            if not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer, got {value!r}")
        for name in ("upstream_timeout", "tcp_idle_timeout"):
            value = getattr(self.config, name)
            if not isinstance(value, (int, float)) or value <= 0:
                raise ValueError(f"{name} must be a positive number, got {value!r}")
        self.decisions = decision_logger
        self._sock: Optional[socket.socket] = None
        self._tcp_sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._accept_thread: Optional[threading.Thread] = None
        self._running = threading.Event()
        self._stopping = threading.Event()
        self._queue: Optional[queue.Queue] = None
        self._workers: List[threading.Thread] = []
        self._tcp_conn_queue: Optional[queue.Queue] = None
        self._tcp_workers: List[threading.Thread] = []
        self._active_conns: set = set()
        self._conns_lock = threading.Lock()

    # -- packet handling (pure, separately testable) -----------------------

    def handle_packet(self, data: bytes, downstream_udp: bool = False) -> Optional[bytes]:
        """Process one DNS query packet; returns the response packet to
        send back, or None when the input was unrecoverably malformed.

        downstream_udp=True applies the downstream UDP size rules (client
        EDNS0 payload size capped by max_udp_response, truncation with TC
        at record boundaries). TCP downstreams always get the complete
        response."""
        started = time.monotonic()
        try:
            query = DNSRecord.parse(data)
        except Exception:
            self._log({"event": "malformed_query", "outcome": "dropped_or_formerr"})
            return self._formerr(data)

        qname = normalize_domain(str(query.q.qname))
        qtype = query.q.qtype
        qtype_name = QTYPE.get(qtype, str(qtype))
        base = {
            "event": "dns_query",
            "domain": qname,
            "qtype": qtype_name,
        }
        try:
            decision = self.engine.decide(qname)
        except ValueError:
            reply = query.reply()
            reply.header.rcode = RCODE.REFUSED
            self._log({**base, "decision": "refused", "outcome": "answered_refused",
                       "reason": "unusable query name"})
            return self._finalize(query, reply, downstream_udp)[0]

        base.update({
            "decision": decision.action,
            "rule": decision.rule,
            "category": decision.category,
            "reason": decision.reason,
        })

        if decision.action == "block":
            reply = self._blocked_reply(query, qtype)
            packet, truncated = self._finalize(query, reply, downstream_udp)
            record = {**base, "outcome": "answered_blocked",
                      "block_mode": self.config.block_mode}
            if truncated:
                record["truncated"] = True
            self._log(record, started)
            return packet

        # Allowed: forward to upstream resolvers in order. UDP first; a
        # truncated (TC) UDP answer is retried over TCP to the same
        # upstream; if that fails, the next upstream gets the normal UDP
        # attempt plus its own truncation check.
        last_error = None
        for host, port in self.config.upstreams:
            try:
                packet = query.send(host, port, timeout=self.config.upstream_timeout)
                packet = bytes(packet) if isinstance(packet, (bytes, bytearray)) else packet.pack()
                try:
                    answer_rec = DNSRecord.parse(packet)
                except Exception as exc:
                    last_error = f"{host}: unparseable upstream response ({exc})"
                    continue
                transport = "udp"
                if answer_rec.header.tc:
                    try:
                        packet = query.send(host, port, tcp=True,
                                            timeout=self.config.upstream_timeout)
                        packet = bytes(packet) if isinstance(packet, (bytes, bytearray)) else packet.pack()
                        answer_rec = DNSRecord.parse(packet)
                        transport = "tcp"
                    except Exception as exc:
                        self._log({**base, "outcome": "tcp_fallback_failed",
                                   "upstream": host, "error": str(exc)})
                        last_error = f"{host}: tcp fallback failed: {exc}"
                        continue
                packet, truncated = self._finalize(query, answer_rec, downstream_udp)
                record = {**base, "outcome": "forwarded", "upstream": host,
                          "transport": transport}
                if truncated:
                    record["truncated"] = True
                self._log(record, started)
                return packet
            except (socket.timeout, OSError) as exc:
                last_error = f"{host}: {exc}"
                continue
        reply = query.reply()
        reply.header.rcode = RCODE.SERVFAIL
        self._log({**base, "outcome": "servfail", "error": last_error}, started)
        return self._finalize(query, reply, downstream_udp)[0]

    def _finalize(self, query: DNSRecord, reply: DNSRecord,
                  downstream_udp: bool) -> Tuple[bytes, bool]:
        """Pack the reply, applying the downstream UDP size rules when
        needed. Returns (packet, truncated)."""
        packet = reply.pack()
        if not downstream_udp:
            return packet, False
        max_size = min(self._client_udp_size(query), self.config.max_udp_response)
        if len(packet) <= max_size:
            return packet, False
        reply = self._truncate_reply(reply, max_size)
        return reply.pack(), True

    @staticmethod
    def _client_udp_size(query: DNSRecord) -> int:
        """The client's advertised EDNS0 UDP payload size, or the classic
        512-byte limit when no OPT record was sent."""
        for rr in query.ar:
            if rr.rtype == QTYPE.OPT:
                size = getattr(rr, "rclass", 0)
                if isinstance(size, int) and size >= 512:
                    return size
                return DNS_CLASSIC_UDP_SIZE
        return DNS_CLASSIC_UDP_SIZE

    @staticmethod
    def _truncate_reply(reply: DNSRecord, max_size: int) -> DNSRecord:
        """Truncate a response to max_size by dropping whole records from
        the end of the answer, then non-OPT additional, then authority
        sections - never cutting mid-record - and set the TC flag so the
        client retries over TCP. The OPT record is preserved."""
        removed = False
        while len(reply.pack()) > max_size:
            if reply.rr:
                reply.rr.pop()
                removed = True
            elif any(a.rtype != QTYPE.OPT for a in reply.ar):
                for i in range(len(reply.ar) - 1, -1, -1):
                    if reply.ar[i].rtype != QTYPE.OPT:
                        reply.ar.pop(i)
                        removed = True
                        break
            elif reply.auth:
                reply.auth.pop()
                removed = True
            else:
                break  # header+question+OPT alone exceed the limit
        if removed:
            reply.header.tc = 1
        return reply

    def _blocked_reply(self, query: DNSRecord, qtype: int) -> DNSRecord:
        reply = query.reply()
        if self.config.block_mode == "nxdomain":
            reply.header.rcode = RCODE.NXDOMAIN
            return reply
        name = str(query.q.qname)
        if qtype == QTYPE.A:
            reply.add_answer(RR(name, QTYPE.A, rdata=A(SINKHOLE_IPV4),
                                ttl=self.config.blocked_ttl))
        elif qtype == QTYPE.AAAA:
            reply.add_answer(RR(name, QTYPE.AAAA, rdata=AAAA(SINKHOLE_IPV6),
                                ttl=self.config.blocked_ttl))
        else:
            # No useful sinkhole record for other types; refuse existence.
            reply.header.rcode = RCODE.NXDOMAIN
        return reply

    @staticmethod
    def _formerr(data: bytes) -> Optional[bytes]:
        """FORMERR response when a transaction ID is recoverable."""
        if len(data) < 2:
            return None
        header = DNSHeader(id=int.from_bytes(data[:2], "big"))
        header.qr = 1
        header.rcode = RCODE.FORMERR
        return DNSRecord(header).pack()

    def _log(self, record: dict, started: Optional[float] = None) -> None:
        if started is not None:
            record["latency_ms"] = round((time.monotonic() - started) * 1000, 2)
        if self.decisions is not None:
            try:
                self.decisions.log_decision(record)
            except Exception:
                log.exception("failed to write decision log")
        log.info("%s", json.dumps(record, sort_keys=True))

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> None:
        """Bind both listeners (UDP first; TCP on the same port), start the
        bounded worker pools and the receive/accept threads. If anything
        fails, everything started so far is torn down again."""
        if self._running.is_set():
            raise RuntimeError("service already running")
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((self.config.listen_host, self.config.listen_port))
        # Lets the receive loop notice shutdown without closing the socket
        # out from under workers that are still sending responses.
        self._sock.settimeout(0.5)
        self.config.listen_port = self._sock.getsockname()[1]  # resolves port 0
        try:
            self._tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._tcp_sock.bind((self.config.listen_host, self.config.listen_port))
            self._tcp_sock.listen(TCP_LISTEN_BACKLOG)
            self._tcp_sock.settimeout(0.5)
        except Exception:
            # Never leave a partially running service.
            self._sock.close()
            self._sock = None
            if self._tcp_sock is not None:
                self._tcp_sock.close()
                self._tcp_sock = None
            raise
        try:
            self._queue = queue.Queue(maxsize=self.config.max_queued)
            self._tcp_conn_queue = queue.Queue(maxsize=self.config.tcp_queued)
            self._stopping.clear()
            self._workers = [
                threading.Thread(target=self._worker, name=f"dns-worker-{i + 1}",
                                 daemon=True)
                for i in range(self.config.max_workers)
            ]
            self._tcp_workers = [
                threading.Thread(target=self._tcp_worker,
                                 name=f"dns-tcp-worker-{i + 1}", daemon=True)
                for i in range(self.config.tcp_workers)
            ]
            for worker in self._workers + self._tcp_workers:
                worker.start()
            self._running.set()
            self._thread = threading.Thread(target=self._serve,
                                            name="dns-udp-receive", daemon=True)
            self._accept_thread = threading.Thread(target=self._accept,
                                                   name="dns-tcp-accept",
                                                   daemon=True)
            self._thread.start()
            self._accept_thread.start()
        except Exception:
            self._abort_start()
            raise
        log.info("DNS filtering service listening on %s:%s (UDP+TCP; "
                 "upstream: %s; udp workers: %d/%d queued; tcp workers: %d/%d queued)",
                 self.config.listen_host, self.config.listen_port,
                 ", ".join(h for h, _ in self.config.upstreams),
                 self.config.max_workers, self.config.max_queued,
                 self.config.tcp_workers, self.config.tcp_queued)

    def _abort_start(self) -> None:
        """Tear down a half-started service after a startup failure."""
        self._running.clear()
        self._stopping.set()
        for sock in (self._sock, self._tcp_sock):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        for t in [self._thread, self._accept_thread] + self._workers + self._tcp_workers:
            if t is not None:
                t.join(timeout=2)
        self._sock = self._tcp_sock = None
        self._thread = self._accept_thread = None
        self._workers = []
        self._tcp_workers = []

    # -- UDP side -----------------------------------------------------------

    def _serve(self) -> None:
        """Receive packets and hand them to the worker pool. The queue is
        bounded: when all workers are busy and the queue is full, the
        packet is dropped and logged (UDP clients retry)."""
        while self._running.is_set():
            try:
                data, client = self._sock.recvfrom(4096)
            except socket.timeout:
                continue  # periodic wake-up so shutdown is noticed
            except OSError:
                break
            try:
                self._queue.put_nowait((data, client))
            except queue.Full:
                self._log({"event": "queue_full", "outcome": "dropped",
                           "reason": "all workers busy and request queue full"})

    def _worker(self) -> None:
        """One bounded UDP worker: processes queued requests until
        shutdown. Its own request finishes even after stop() begins;
        requests still queued at shutdown are dropped (clients retry,
        per UDP)."""
        while not self._stopping.is_set():
            try:
                data, client = self._queue.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                response = self.handle_packet(data, downstream_udp=True)
            except Exception:
                log.exception("unexpected error handling query")
                continue
            if response is not None:
                try:
                    self._sock.sendto(response, client)
                except OSError:
                    log.warning("could not send response to client")

    # -- TCP side -----------------------------------------------------------

    def _accept(self) -> None:
        """Accept TCP connections into the bounded connection queue. A
        connection arriving at a full queue is closed and logged."""
        while self._running.is_set():
            try:
                conn, _addr = self._tcp_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self._tcp_conn_queue.put_nowait(conn)
            except queue.Full:
                self._log({"event": "tcp_queue_full",
                           "outcome": "connection_closed",
                           "reason": "all TCP workers busy and connection "
                                     "queue full"})
                try:
                    conn.close()
                except OSError:
                    pass

    def _tcp_worker(self) -> None:
        """One bounded TCP worker: serves accepted connections until
        shutdown."""
        while not self._stopping.is_set():
            try:
                conn = self._tcp_conn_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            with self._conns_lock:
                self._active_conns.add(conn)
            try:
                self._serve_tcp_conn(conn)
            except Exception:
                log.exception("unexpected error serving TCP connection")
            finally:
                with self._conns_lock:
                    self._active_conns.discard(conn)
                try:
                    conn.close()
                except OSError:
                    pass

    def _serve_tcp_conn(self, conn: socket.socket) -> None:
        """Serve one connection: length-prefixed messages in order, until
        the client closes, the read/idle timeout expires, the message
        limit is reached, or shutdown closes the connection."""
        for _ in range(self.config.tcp_max_messages):
            header = self._recv_exact(conn, 2)
            if header is None:
                return
            length = int.from_bytes(header, "big")
            if length == 0 or length > DNS_TCP_MAX_MESSAGE:
                self._log({"event": "tcp_invalid_length",
                           "outcome": "connection_closed",
                           "length": length})
                return
            data = self._recv_exact(conn, length)
            if data is None:
                return  # client gone, idle, or never finished the message
            response = self.handle_packet(data)
            if response is None:
                return  # unrecoverably malformed; close safely
            if len(response) > DNS_TCP_MAX_MESSAGE:
                self._log({"event": "tcp_oversized_response",
                           "outcome": "connection_closed"})
                return
            conn.sendall(len(response).to_bytes(2, "big") + response)

    def _recv_exact(self, conn: socket.socket, n: int) -> Optional[bytes]:
        """Read exactly n bytes, tolerating partial delivery. The whole
        read (not each chunk) must finish within tcp_idle_timeout, so a
        client trickling bytes cannot hold the worker. Returns None on
        timeout, close, or error."""
        buf = bytearray()
        deadline = time.monotonic() + self.config.tcp_idle_timeout
        while len(buf) < n:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            conn.settimeout(remaining)
            try:
                chunk = conn.recv(min(65536, n - len(buf)))
            except (socket.timeout, OSError):
                return None
            if not chunk:
                return None
            buf += chunk
        return bytes(buf)

    def _close_active_conns(self) -> None:
        with self._conns_lock:
            conns = list(self._active_conns)
        for conn in conns:
            try:
                conn.close()
            except OSError:
                pass

    def _all_threads(self) -> List[threading.Thread]:
        return ([t for t in (self._thread, self._accept_thread) if t is not None]
                + self._workers + self._tcp_workers)

    # -- shutdown -----------------------------------------------------------

    def stop(self) -> List[threading.Thread]:
        """Shut down: stop receiving and accepting, give in-flight
        requests a bounded opportunity to finish, close idle or slow TCP
        connections to unblock their workers, stop every worker, then
        close both listeners. Requests still queued at shutdown are
        dropped (clients retry).

        One overall monotonic deadline is shared by the receive thread,
        accept thread, and every worker of both transports; each join
        only gets the time remaining, so the total wait never multiplies
        by the number of threads or connections. The budget accounts for
        the maximum upstream attempts (UDP plus a TCP fallback per
        upstream), the configured connection-read timeout, and a margin.

        Returns the list of threads that were still alive after the
        deadline - empty on a clean shutdown. Survivors are logged by
        name and kept referenced, so an incomplete shutdown is reported
        accurately instead of being silently discarded and presented as
        clean."""
        self._running.clear()
        self._stopping.set()
        upstream_budget = (
            self.config.upstream_timeout * max(1, len(self.config.upstreams)) * 2
        )  # each upstream may get a UDP attempt plus a TCP fallback
        shutdown_budget = upstream_budget + self.config.tcp_idle_timeout + 2.0
        deadline = time.monotonic() + shutdown_budget

        def remaining() -> float:
            return max(0.0, deadline - time.monotonic())

        # 1. Stop the receive and accept loops (both wake within 0.5s).
        if self._thread is not None:
            self._thread.join(timeout=remaining())
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=remaining())

        # 2. Bounded opportunity for in-flight requests to finish.
        for worker in self._workers:
            worker.join(timeout=remaining())
        for worker in self._tcp_workers:
            worker.join(timeout=remaining())

        # 3. Force-unblock whatever is left: closing active connections
        #    breaks idle or slow TCP reads so their workers can exit.
        alive = [t for t in self._all_threads() if t.is_alive()]
        if alive:
            self._close_active_conns()
            for t in alive:
                t.join(timeout=remaining())

        # 4. Close both listeners.
        for sock in (self._sock, self._tcp_sock):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

        survivors = [t for t in self._all_threads() if t.is_alive()]
        if survivors:
            log.error(
                "shutdown incomplete: %d thread(s) still running after the "
                "%.1fs overall deadline: %s",
                len(survivors), shutdown_budget,
                ", ".join(t.name for t in survivors),
            )
        # Keep an accurate record: only threads that actually stopped are
        # discarded; survivors stay referenced and visible.
        self._workers = survivors
        return survivors


def main(argv: Optional[list] = None) -> int:
    import argparse

    from category_db import CategoryDB

    parser = argparse.ArgumentParser(description="KosherGuard DNS filtering service")
    parser.add_argument("--policy", required=True, help="policy JSON file")
    parser.add_argument("--categories", required=True, help="category database JSON file")
    parser.add_argument("--listen", default="127.0.0.1:5353", help="host:port to bind")
    parser.add_argument("--upstream", action="append",
                        help="upstream resolver host[:port]; repeatable")
    parser.add_argument("--block-mode", choices=["sinkhole", "nxdomain"],
                        default="sinkhole")
    parser.add_argument("--max-workers", type=int, default=32,
                        help="bounded UDP worker pool size (default: 32)")
    parser.add_argument("--max-queued", type=int, default=128,
                        help="max UDP requests waiting for a worker before new "
                             "packets are dropped (default: 128)")
    parser.add_argument("--tcp-workers", type=int, default=16,
                        help="bounded TCP worker pool size (default: 16)")
    parser.add_argument("--tcp-queued", type=int, default=64,
                        help="max accepted TCP connections waiting for a worker "
                             "before new connections are closed (default: 64)")
    parser.add_argument("--tcp-idle-timeout", type=float, default=10.0,
                        help="seconds a TCP read/message may take before the "
                             "connection is closed (default: 10)")
    parser.add_argument("--tcp-max-messages", type=int, default=64,
                        help="max DNS messages per TCP connection (default: 64)")
    parser.add_argument("--max-udp-response", type=int, default=4096,
                        help="safety cap on UDP response size to clients "
                             "(default: 4096)")
    parser.add_argument("--log", help="decision log file (JSON lines); default: stderr")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    policy = json.loads(open(args.policy, encoding="utf-8").read())
    engine = PolicyEngine(policy, CategoryDB.load(args.categories))

    host, _, port = args.listen.partition(":")
    upstreams = None
    if args.upstream:
        upstreams = []
        for u in args.upstream:
            h, _, p = u.partition(":")
            upstreams.append((h, int(p) if p else 53))
    config = ServiceConfig(listen_host=host, listen_port=int(port or 5353),
                           upstreams=upstreams or ServiceConfig().upstreams,
                           block_mode=args.block_mode,
                           max_workers=args.max_workers,
                           max_queued=args.max_queued,
                           tcp_workers=args.tcp_workers,
                           tcp_queued=args.tcp_queued,
                           tcp_idle_timeout=args.tcp_idle_timeout,
                           tcp_max_messages=args.tcp_max_messages,
                           max_udp_response=args.max_udp_response)

    import sys
    stream = open(args.log, "a", encoding="utf-8") if args.log else sys.stderr
    service = DNSFilteringService(engine, config, DecisionLogger(stream))
    service.start()
    print(f"Listening on {config.listen_host}:{config.listen_port} "
          f"(UDP+TCP) - Ctrl+C to stop")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        service.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

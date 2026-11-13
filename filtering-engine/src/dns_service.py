"""DNS filtering service for the KosherGuard core filtering engine (Stage 3).

A UDP DNS service that answers queries according to the central policy
engine:

- Allowed domains are forwarded to a configurable upstream resolver and
  the upstream answer is relayed to the client.
- Blocked domains are answered locally: by default a sinkhole answer
  (0.0.0.0 for A, :: for AAAA); NXDOMAIN for other query types, or for all
  types when block_mode is "nxdomain".
- Malformed packets get a FORMERR response when a transaction ID can be
  recovered, and are otherwise dropped. The service never crashes on bad
  input.
- When every upstream fails (timeout or error), the client gets SERVFAIL.

Scope, stated plainly: DNS filtering controls access to *domains*. It
cannot block individual URLs, pages, or paths, and it cannot see or filter
the contents of encrypted HTTPS traffic. See README.md.

Privacy by design: the client IP address is intentionally NOT recorded in
the decision log. Logs contain the requested domain, the decision, and why.
"""

from __future__ import annotations

import json
import logging
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
    upstream_timeout: float = 3.0  # seconds per upstream attempt
    block_mode: str = "sinkhole"  # "sinkhole" or "nxdomain"
    blocked_ttl: int = 60


class DNSFilteringService:
    """A policy-driven DNS filtering service (UDP)."""

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
        self.decisions = decision_logger
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = threading.Event()

    # -- packet handling (pure, separately testable) -----------------------

    def handle_packet(self, data: bytes) -> Optional[bytes]:
        """Process one DNS query packet; returns the response packet to
        send back, or None when the input was unrecoverably malformed."""
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
            return reply.pack()

        base.update({
            "decision": decision.action,
            "rule": decision.rule,
            "category": decision.category,
            "reason": decision.reason,
        })

        if decision.action == "block":
            reply = self._blocked_reply(query, qtype)
            self._log({**base, "outcome": "answered_blocked",
                       "block_mode": self.config.block_mode},
                      started)
            return reply.pack()

        # Allowed: forward to upstream resolvers in order.
        last_error = None
        for host, port in self.config.upstreams:
            try:
                answer = query.send(host, port, timeout=self.config.upstream_timeout)
                packet = bytes(answer) if isinstance(answer, (bytes, bytearray)) else answer.pack()
                self._log({**base, "outcome": "forwarded", "upstream": host},
                          started)
                return packet
            except (socket.timeout, OSError) as exc:
                last_error = f"{host}: {exc}"
                continue
        reply = query.reply()
        reply.header.rcode = RCODE.SERVFAIL
        self._log({**base, "outcome": "servfail", "error": last_error}, started)
        return reply.pack()

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

    # -- socket server ------------------------------------------------------

    def start(self) -> None:
        """Bind the UDP socket and serve in a background thread."""
        if self._running.is_set():
            raise RuntimeError("service already running")
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((self.config.listen_host, self.config.listen_port))
        self.config.listen_port = self._sock.getsockname()[1]  # resolves port 0
        self._running.set()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        log.info("DNS filtering service listening on %s:%s (upstream: %s)",
                 self.config.listen_host, self.config.listen_port,
                 ", ".join(h for h, _ in self.config.upstreams))

    def _serve(self) -> None:
        while self._running.is_set():
            try:
                data, client = self._sock.recvfrom(4096)
            except OSError:
                break
            try:
                response = self.handle_packet(data)
            except Exception:
                log.exception("unexpected error handling query")
                continue
            if response is not None:
                try:
                    self._sock.sendto(response, client)
                except OSError:
                    log.warning("could not send response to client")

    def stop(self) -> None:
        self._running.clear()
        if self._sock is not None:
            self._sock.close()
        if self._thread is not None:
            self._thread.join(timeout=2)


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
                           block_mode=args.block_mode)

    import sys
    stream = open(args.log, "a", encoding="utf-8") if args.log else sys.stderr
    service = DNSFilteringService(engine, config, DecisionLogger(stream))
    service.start()
    print(f"Listening on {config.listen_host}:{config.listen_port} - Ctrl+C to stop")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        service.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

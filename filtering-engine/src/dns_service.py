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
connections are tracked from the moment they are accepted and go to a
fixed-size worker pool through a bounded queue; a connection that
arrives at a full queue is closed and logged. Each complete message
(length prefix plus body) must arrive within one shared deadline of
tcp_idle_timeout, and a per-connection message count limit keeps one
client from occupying a worker indefinitely.

Downstream response sizes: UDP clients get at most their advertised
EDNS0 payload size (512 bytes without an OPT record), further capped by
the configurable max_udp_response safety limit. Oversized UDP responses
are truncated at DNS-record boundaries with the TC flag set - never cut
mid-record - with the OPT record preserved when it fits (an OPT record
that itself cannot fit is dropped, never sent oversized). TCP clients
always get the complete response (up to the protocol's 65535-byte frame
limit).

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
opportunity to finish; connections still waiting in the accept queue
are drained and closed, and idle or slow active connections are then
closed to unblock their workers. Threads still alive at the deadline are
logged by name, kept referenced, and returned - an incomplete shutdown
is never reported as clean.

Configuration hot reload (Stage 10): the running service NEVER modifies
its PolicyEngine or CategoryDB in place. A reload (SIGHUP, or the
optional --watch poll) builds a complete replacement engine from the
configuration files - validating the policy with validate_policy(),
building a fresh CategoryDB, and verifying the generation manifest's
content hashes when one exists - and only then swaps one immutable
reference. Every DNS query reads that reference exactly once at the
start of its handling, so each query evaluates against ONE complete
engine instance; in-flight queries simply finish against the previous
engine object. An invalid, incomplete, missing, or corrupted new
configuration is rejected loudly: the service keeps answering with the
last valid configuration, the rejection is logged, the failed
configuration is never reported as active, and the service stays
healthy. The SIGHUP handler itself only sets a flag; all file I/O and
validation happen in the service's normal execution flow. When
--status-file is given, the service atomically writes its active
configuration identity (paths, hashes, generation, reload count, last
error) after every load attempt, so the dashboard can show what the
engine is actually enforcing.

Scope, stated plainly: DNS filtering controls access to *domains*. It
cannot block individual URLs, pages, or paths, and it cannot see or filter
the contents of encrypted HTTPS traffic. See README.md.

Privacy by design: the client IP address is intentionally NOT recorded in
the decision log. Logs contain the requested domain, the decision, and why.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import queue
import re
import socket
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

from dnslib import AAAA, A, QTYPE, RCODE, DNSHeader, DNSRecord, RR

from category_db import CategoryDB, CategoryDBError
from policy_engine import PolicyConfigError, PolicyEngine, normalize_domain

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


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


def _validate_generation_manifest(manifest, policy_path, categories_path,
                                  policy_sha256, categories_sha256):
    """Fail-closed validation of a generation manifest.

    When a manifest.json exists it MUST be complete, well-formed, and
    internally consistent with the generation being loaded; anything
    less is a corrupted or tampered publication and is rejected rather
    than silently falling back to unverified file loading. Required:
    a JSON object; both content hashes present and each a 64-character
    lowercase SHA-256 hexadecimal string; a non-negative-integer revision;
    a non-empty generation string equal to str(revision) AND to the
    resolved generation directory name; and both hashes matching the
    actual file bytes exactly. Raises PolicyConfigError on any defect.
    """
    manifest_path = Path(policy_path).parent / "manifest.json"
    if not isinstance(manifest, dict):
        raise PolicyConfigError(
            f"generation manifest {manifest_path} is not a JSON object; "
            "refusing to load")
    for key, path in (("policy_sha256", policy_path),
                      ("categories_sha256", categories_path)):
        value = manifest.get(key)
        if not isinstance(value, str) or not _SHA256_HEX.fullmatch(value):
            raise PolicyConfigError(
                f"generation manifest {manifest_path}: {key} is missing or "
                "not a valid 64-character SHA-256 hexadecimal value; "
                "refusing to load")
    revision = manifest.get("revision")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        raise PolicyConfigError(
            f"generation manifest {manifest_path}: revision is missing or "
            "not a non-negative integer; refusing to load")
    generation = manifest.get("generation")
    if not isinstance(generation, str) or not generation:
        raise PolicyConfigError(
            f"generation manifest {manifest_path}: generation is missing or "
            "not a non-empty string; refusing to load")
    if generation != str(revision):
        raise PolicyConfigError(
            f"generation manifest {manifest_path}: generation {generation!r} "
            f"is inconsistent with revision {revision}; refusing to load")
    directory = os.path.basename(os.path.dirname(os.path.realpath(policy_path)))
    if generation != directory:
        raise PolicyConfigError(
            f"generation manifest {manifest_path}: generation {generation!r} "
            f"does not match its directory {directory!r} (mixed-generation "
            "or relocated file set); refusing to load")
    if manifest["policy_sha256"] != policy_sha256:
        raise PolicyConfigError(
            f"{policy_path} does not match its generation manifest "
            "(corrupted or mixed-generation file); refusing to load")
    if manifest["categories_sha256"] != categories_sha256:
        raise PolicyConfigError(
            f"{categories_path} does not match its generation manifest "
            "(corrupted or mixed-generation file); refusing to load")


def load_validated_engine(policy_path, categories_path):
    """Build a COMPLETE replacement engine from configuration files.

    Both files are read, parsed, validated with the engine's own
    validators, and - when a generation manifest.json sits next to the
    policy file (the dashboard's Stage 10 publication layout) - their
    content hashes are verified against it, so a corrupted or
    mixed-generation file set is rejected rather than loaded. Returns
    (engine, info); raises OSError, PolicyConfigError, CategoryDBError,
    or ValueError on any problem. Nothing is mutated anywhere: the
    caller decides whether to activate the result.
    """
    policy_path = str(policy_path)
    categories_path = str(categories_path)
    policy_bytes = Path(policy_path).read_bytes()
    categories_bytes = Path(categories_path).read_bytes()
    info = {
        "policy_path": policy_path,
        "categories_path": categories_path,
        "policy_sha256": _sha256(policy_bytes),
        "categories_sha256": _sha256(categories_bytes),
    }
    manifest_path = Path(policy_path).parent / "manifest.json"
    if os.path.lexists(manifest_path):
        # lexists, not is_file: a manifest path that EXISTS as anything
        # other than a regular readable file (a directory, a broken
        # symlink, an unreadable entry) is a present-but-invalid
        # manifest and must be rejected, never silently treated as "no
        # manifest". Only a genuinely absent manifest path loads
        # unverified (the legacy pre-publication layout).
        if not manifest_path.is_file():
            raise PolicyConfigError(
                f"generation manifest {manifest_path} exists but is not "
                "a regular readable file (directory, broken symlink, or "
                "unusable entry); refusing to load")
        try:
            manifest = json.loads(manifest_path.read_text("utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PolicyConfigError(
                f"unreadable generation manifest {manifest_path}: {exc}")
        _validate_generation_manifest(
            manifest, policy_path, categories_path,
            info["policy_sha256"], info["categories_sha256"])
        info["generation"] = manifest["generation"]
        info["manifest_revision"] = manifest["revision"]
    try:
        policy = json.loads(policy_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PolicyConfigError(f"{policy_path}: invalid JSON: {exc}")
    try:
        categories_raw = json.loads(categories_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CategoryDBError(f"{categories_path}: invalid JSON: {exc}")
    if not isinstance(categories_raw, dict) or not isinstance(categories_raw.get("domains"), dict):
        raise CategoryDBError(
            f"{categories_path}: expected an object with a 'domains' object")
    engine = PolicyEngine(
        policy, CategoryDB(categories_raw["domains"], meta=categories_raw.get("_meta", {})))
    return engine, info


def config_identity(policy_path, categories_path):
    """A cheap fingerprint of the configuration file set, used by the
    --watch poll to notice a new publication: resolved paths (the
    dashboard's 'current' symlink makes a new generation resolve to a
    new path) plus size and mtime of both files. None when either file
    is unreadable."""
    try:
        resolved_policy = os.path.realpath(policy_path)
        resolved_categories = os.path.realpath(categories_path)
        ps = os.stat(resolved_policy)
        cs = os.stat(resolved_categories)
        return (resolved_policy, resolved_categories,
                ps.st_size, ps.st_mtime_ns, cs.st_size, cs.st_mtime_ns)
    except OSError:
        return None


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
                     "tcp_max_messages"):
            value = getattr(self.config, name)
            if not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer, got {value!r}")
        # 512 is the classic DNS UDP message limit: a header plus the
        # echoed question always fits in it, which is what makes the
        # truncation guarantee below possible.
        value = self.config.max_udp_response
        if not isinstance(value, int) or value < DNS_CLASSIC_UDP_SIZE:
            raise ValueError(
                f"max_udp_response must be an integer >= {DNS_CLASSIC_UDP_SIZE}, "
                f"got {value!r}")
        for name in ("upstream_timeout", "tcp_idle_timeout"):
            value = getattr(self.config, name)
            if not isinstance(value, (int, float)) or value <= 0:
                raise ValueError(f"{name} must be a positive number, got {value!r}")
        self.decisions = decision_logger
        # Stage 10 hot reload: self.engine is one immutable reference,
        # replaced wholesale by reload_from_paths and never mutated.
        # handle_packet reads it exactly once per query, so every query
        # sees one complete engine instance.
        self.active_config: Optional[dict] = None
        self.reload_count = 0
        self.last_reload_error: Optional[dict] = None
        self._status_path: Optional[str] = None
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
        # Read the engine reference ONCE: even if a reload swaps it
        # mid-query, this query completes against one complete engine.
        engine = self.engine
        try:
            decision = engine.decide(qname)
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
        client retries over TCP. The OPT record is preserved when it
        fits; when the OPT record itself prevents the response from
        fitting, it is dropped instead (OPT is advisory) rather than
        sending an oversized message. TC is set whenever anything was
        removed."""
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
            elif reply.ar:
                # Only the OPT record is left and it does not fit. OPT is
                # advisory: drop it so the response fits, rather than
                # returning an oversized message. The client retrying
                # over TCP gets the complete response.
                reply.ar.pop()
                removed = True
            else:
                # Header plus question alone exceed the limit. max_size
                # is always >= 512 and a legal DNS message header plus
                # question is far smaller, so this cannot happen in
                # practice; set TC so the client retries over TCP rather
                # than trusting an oversized UDP message.
                reply.header.tc = 1
                break
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

    # -- hot reload (Stage 10) ----------------------------------------------

    def reload_from_paths(self, policy_path, categories_path,
                          trigger: str = "manual") -> bool:
        """Build and activate a replacement engine, fail-safe.

        The replacement is fully loaded and validated BEFORE anything
        changes; the swap is a single reference assignment. On ANY
        failure the previous engine keeps serving, the rejection is
        logged loudly, the failed configuration is never reported as
        active, and the method returns False. In-flight queries are
        never interrupted: they already hold their own reference to the
        previous engine object, which is never mutated.
        """
        try:
            engine, info = load_validated_engine(policy_path, categories_path)
        except Exception as exc:
            self.last_reload_error = {
                "error": str(exc),
                "trigger": trigger,
                "at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            }
            log.error(
                "configuration reload REJECTED (%s): %s - keeping the previous "
                "valid configuration (policy=%s, categories=%s)",
                trigger, exc, policy_path, categories_path)
            self._write_status(trigger)
            return False
        self.engine = engine  # the one atomic step
        self.active_config = info
        self.reload_count += 1
        self.last_reload_error = None
        log.info(
            "configuration reload accepted (%s): generation=%s revision=%s "
            "policy_sha256=%s categories_sha256=%s",
            trigger, info.get("generation"), info.get("manifest_revision"),
            info["policy_sha256"][:12], info["categories_sha256"][:12])
        self._write_status(trigger)
        return True

    def set_status_path(self, path) -> None:
        self._status_path = str(path)

    def _write_status(self, trigger: str) -> None:
        """Atomically record what the engine is enforcing right now.

        Written temp-file-plus-rename so a reader (the dashboard) never
        sees a partial file. Contains the ACTIVE configuration identity
        only; a rejected reload updates last_error but never the active
        fields."""
        if not self._status_path:
            return
        status = {
            "pid": os.getpid(),
            "state": "active",
            "trigger": trigger,
            "reload_count": self.reload_count,
            "loaded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "last_error": self.last_reload_error,
        }
        if self.active_config:
            status.update({
                "policy_path": self.active_config["policy_path"],
                "categories_path": self.active_config["categories_path"],
                "policy_sha256": self.active_config["policy_sha256"],
                "categories_sha256": self.active_config["categories_sha256"],
                "generation": self.active_config.get("generation"),
                "revision": self.active_config.get("manifest_revision"),
            })
        path = Path(self._status_path)
        try:
            tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
            tmp.write_text(json.dumps(status, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
            os.replace(str(tmp), str(path))
        except OSError:
            log.exception("could not write engine status file %s", path)

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> None:
        """Bind both listeners (UDP first; TCP on the same port), start the
        bounded worker pools and the receive/accept threads. If anything
        fails, everything started so far is torn down again."""
        if self._running.is_set():
            raise RuntimeError("service already running")
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.bind((self.config.listen_host, self.config.listen_port))
            # Lets the receive loop notice shutdown without closing the
            # socket out from under workers still sending responses.
            self._sock.settimeout(0.5)
            self.config.listen_port = self._sock.getsockname()[1]  # resolves port 0
            self._tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._tcp_sock.bind((self.config.listen_host, self.config.listen_port))
            self._tcp_sock.listen(TCP_LISTEN_BACKLOG)
            self._tcp_sock.settimeout(0.5)
        except Exception:
            # Any listener-setup failure (UDP bind included) closes every
            # socket created so far and clears the references: the
            # service is never left partially started.
            for sock in (self._sock, self._tcp_sock):
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
            self._sock = None
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
            # Account for the connection from the moment it is accepted,
            # so shutdown can always find and close it - whether it is
            # waiting in the queue or being served by a worker.
            with self._conns_lock:
                self._active_conns.add(conn)
            if self._stopping.is_set():
                # Accepted just as shutdown began: never enqueue a
                # connection nobody will drain.
                self._close_tracked_conn(conn)
                continue
            try:
                self._tcp_conn_queue.put_nowait(conn)
            except queue.Full:
                self._log({"event": "tcp_queue_full",
                           "outcome": "connection_closed",
                           "reason": "all TCP workers busy and connection "
                                     "queue full"})
                self._close_tracked_conn(conn)

    def _tcp_worker(self) -> None:
        """One bounded TCP worker: serves accepted connections until
        shutdown."""
        while not self._stopping.is_set():
            try:
                conn = self._tcp_conn_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            if self._stopping.is_set():
                # Shutdown began while this worker was waiting inside
                # get(): the connection was still waiting in the queue,
                # never genuinely served. Close it like a drained one;
                # stop() only drains what is still queued, so a
                # dequeued-but-unserved connection is this worker's job.
                self._close_tracked_conn(conn)
                continue
            try:
                self._serve_tcp_conn(conn)
            except Exception:
                log.exception("unexpected error serving TCP connection")
            finally:
                self._close_tracked_conn(conn)

    def _close_tracked_conn(self, conn: socket.socket) -> None:
        """Close one tracked connection and drop it from the active set."""
        with self._conns_lock:
            self._active_conns.discard(conn)
        try:
            conn.close()
        except OSError:
            pass

    def _drain_queued_conns(self) -> None:
        """Close every accepted connection still waiting in the TCP
        connection queue. Queued connections are not being served, so
        closing them at shutdown cannot interrupt in-flight work."""
        if self._tcp_conn_queue is None:
            return
        while True:
            try:
                conn = self._tcp_conn_queue.get_nowait()
            except queue.Empty:
                return
            self._close_tracked_conn(conn)

    def _serve_tcp_conn(self, conn: socket.socket) -> None:
        """Serve one connection: length-prefixed messages in order, until
        the client closes, the read/idle timeout expires, the message
        limit is reached, or shutdown closes the connection."""
        for _ in range(self.config.tcp_max_messages):
            # One absolute deadline per complete message: the two-byte
            # length prefix and the message body share it, so one message
            # can never take almost twice tcp_idle_timeout to arrive.
            deadline = time.monotonic() + self.config.tcp_idle_timeout
            header = self._recv_exact(conn, 2, deadline)
            if header is None:
                return
            length = int.from_bytes(header, "big")
            # A two-byte prefix can hold at most 65535, which is exactly
            # the supported maximum; zero is the only invalid length.
            if length == 0:
                self._log({"event": "tcp_invalid_length",
                           "outcome": "connection_closed",
                           "length": length})
                return
            data = self._recv_exact(conn, length, deadline)
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

    def _recv_exact(self, conn: socket.socket, n: int,
                    deadline: float) -> Optional[bytes]:
        """Read exactly n bytes, tolerating partial delivery, finishing
        before the caller's absolute monotonic deadline. One deadline
        covers a complete message (length prefix plus body), so a client
        trickling bytes cannot hold the worker. Returns None on timeout,
        close, or error."""
        buf = bytearray()
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

    def _shutdown_budget(self) -> float:
        """The one overall shutdown budget: the maximum upstream work
        (each upstream may get a UDP attempt plus a TCP fallback), plus
        ONE tcp_idle_timeout - the longest a TCP worker can spend waiting
        for a single incomplete message, because the length prefix and
        body share one per-message deadline - plus a margin."""
        upstream_budget = (
            self.config.upstream_timeout * max(1, len(self.config.upstreams)) * 2
        )
        return upstream_budget + self.config.tcp_idle_timeout + 2.0

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
        shutdown_budget = self._shutdown_budget()
        deadline = time.monotonic() + shutdown_budget

        def remaining() -> float:
            return max(0.0, deadline - time.monotonic())

        # 1. Stop the receive and accept loops (both wake within 0.5s).
        if self._thread is not None:
            self._thread.join(timeout=remaining())
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=remaining())

        # 2. Close accepted connections still waiting in the queue: the
        #    accept thread has stopped, so nothing new can be enqueued,
        #    and queued connections are not being served yet.
        self._drain_queued_conns()

        # 3. Bounded opportunity for in-flight requests to finish.
        for worker in self._workers:
            worker.join(timeout=remaining())
        for worker in self._tcp_workers:
            worker.join(timeout=remaining())

        # 4. Force-unblock whatever is left: closing active connections
        #    breaks idle or slow TCP reads so their workers can exit.
        alive = [t for t in self._all_threads() if t.is_alive()]
        if alive:
            self._close_active_conns()
            for t in alive:
                t.join(timeout=remaining())

        # 5. Close both listeners.
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
    parser.add_argument("--watch", type=float, default=0.0, metavar="SECONDS",
                        help="poll the configuration files every SECONDS and "
                             "reload when they change (0 = disabled; SIGHUP "
                             "always triggers a reload)")
    parser.add_argument("--status-file",
                        help="atomically write the active configuration identity "
                             "here after every load attempt (JSON)")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    # Startup load is validation-first too: an invalid or corrupted
    # initial configuration stops the service instead of mis-filtering.
    engine, info = load_validated_engine(args.policy, args.categories)

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
    service.active_config = info
    if args.status_file:
        service.set_status_path(args.status_file)
    service.start()
    service._write_status("startup")
    print(f"Listening on {config.listen_host}:{config.listen_port} "
          f"(UDP+TCP) - Ctrl+C to stop")

    # SIGHUP only sets a flag: signal handlers must never do file I/O or
    # validation. The loop below performs the reload in the service's
    # normal execution flow. The --watch poll additionally notices a new
    # published generation on its own (the dashboard cannot signal this
    # process across service boundaries).
    import signal

    reload_requested = threading.Event()

    def _on_sighup(_signum, _frame):
        reload_requested.set()

    signal.signal(signal.SIGHUP, _on_sighup)

    active_identity = config_identity(args.policy, args.categories)
    rejected_identity = None  # do not retry the same rejected file set
    watch = args.watch if args.watch > 0 else None
    try:
        while True:
            reload_requested.wait(timeout=watch or 3600)
            if reload_requested.is_set():
                reload_requested.clear()
                if service.reload_from_paths(args.policy, args.categories,
                                             trigger="sighup"):
                    active_identity = config_identity(args.policy, args.categories)
                    rejected_identity = None
            elif watch:
                identity = config_identity(args.policy, args.categories)
                if (identity is not None and identity != active_identity
                        and identity != rejected_identity):
                    if service.reload_from_paths(args.policy, args.categories,
                                                 trigger="watch"):
                        active_identity = identity
                        rejected_identity = None
                    else:
                        rejected_identity = identity
    except KeyboardInterrupt:
        service.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

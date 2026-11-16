"""KosherGuard forward filtering proxy.

The PAC layer routes selected traffic here; this proxy enforces the
policy decision a second time (defense in depth - a hand-edited PAC or
a client that guesses the proxy address still gets filtered).

Scope decisions (matching the spec's honest-capability approach):
- Plain HTTP: full request filtering by Host/domain. Blocked sites get
  a 403 block page; allowed requests are relayed and the response
  returned. Request smuggling is refused (one request per connection,
  no chunked games from the client).
- HTTPS (CONNECT): the proxy can only see the hostname, not content -
  without TLS inspection this is a tunnel-or-refuse decision by domain.
  Blocked domains get 403; allowed domains get a tunnel. TLS
  interception is deliberately NOT implemented here (certificate
  install + pinning compatibility is separate milestone work).
- Every decision comes from the filtering engine (EngineSet resolution
  by client address), never from a parallel rules implementation.
- Bounded concurrency: fixed worker pool; a slow client holds at most
  one worker and hits a read timeout.
"""

from __future__ import annotations

import socket
import socketserver
import threading

_ENGINE_SRC = __import__("os").path.join(
    __import__("os").path.dirname(__file__), "..", "filtering-engine", "src")
import os
import sys
sys.path.insert(0, os.path.abspath(_ENGINE_SRC))


class ProxyError(RuntimeError):
    pass


BLOCK_PAGE = (
    b"<!doctype html><title>Blocked</title>"
    b"<h1>Blocked by KosherGuard</h1><p>%s</p>"
)


def engine_for(engine_set, client_addr):
    return engine_set.policy_for_client(client_addr)


class FilteringProxyHandler(socketserver.BaseRequestHandler):
    """One request per connection; nothing is pipelined or smuggled."""

    def handle(self) -> None:
        self.request.settimeout(self.server.read_timeout)
        try:
            head = self._read_head()
        except (ProxyError, socket.timeout, ConnectionError):
            return
        try:
            line, headers = self._parse_head(head)
        except ProxyError:
            self._send(400, b"Bad Request")
            return
        method, target, _version = line
        engine = engine_for(self.server.engine_set, self.client_address)

        if method == "CONNECT":
            self._handle_connect(target, engine)
            return

        # Plain HTTP: absolute-form target required (a proxy request).
        if not target.lower().startswith("http://"):
            self._send(400, b"proxy requires absolute-form http:// targets")
            return
        host = self._host_of(target, headers)
        if host is None:
            self._send(400, b"cannot determine target host")
            return
        decision = engine.decide(host)
        if decision.action != "allow":
            self._send(403, BLOCK_PAGE % decision.reason.encode())
            self.server.log_decision(host, decision, self.client_address)
            return
        self.server.log_decision(host, decision, self.client_address)
        self._relay_http(target, headers, head)

    # -- parsing ---------------------------------------------------------

    def _read_head(self) -> bytes:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self.request.recv(4096)
            if not chunk:
                raise ProxyError("client closed before headers")
            data += chunk
            if len(data) > 16384:
                raise ProxyError("headers too large")
        return data

    def _parse_head(self, head: bytes):
        try:
            text = head.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1")
        except UnicodeDecodeError:
            raise ProxyError("undecodable head")
        lines = text.split("\r\n")
        parts = lines[0].split(" ")
        if len(parts) != 3:
            raise ProxyError("malformed request line")
        headers = {}
        for line in lines[1:]:
            name, _, value = line.partition(":")
            if not value:
                raise ProxyError("malformed header")
            headers[name.strip().lower()] = value.strip()
        return (parts[0].upper(), parts[1], parts[2]), headers

    def _host_of(self, target: str, headers: dict) -> str | None:
        rest = target[7:]
        hostport = rest.split("/", 1)[0]
        host = hostport.split(":", 1)[0] or headers.get("host", "").split(":")[0]
        host = host.strip().lower().rstrip(".")
        return host or None

    # -- decisions -------------------------------------------------------

    def _handle_connect(self, target: str, engine) -> None:
        hostport = target.rsplit("/", 1)[0]
        host = hostport.split(":", 1)[0].strip().lower().rstrip(".")
        if not host:
            self._send(400, b"CONNECT requires host:port")
            return
        decision = engine.decide(host)
        self.server.log_decision(host, decision, self.client_address)
        if decision.action != "allow":
            self._send(403, BLOCK_PAGE % decision.reason.encode())
            return
        host, _, port = target.partition(":")
        try:
            upstream = socket.create_connection(
                (host, int(port or 443)), timeout=self.server.connect_timeout)
        except OSError:
            self._send(502, b"upstream connect failed")
            return
        self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        self._tunnel(upstream)

    def _tunnel(self, upstream: socket.socket) -> None:
        """Bidirectional byte copy with a hard idle timeout."""
        upstream.settimeout(self.server.read_timeout)
        sockets = [self.request, upstream]
        import select
        try:
            while True:
                readable, _, _ = select.select(sockets, [], [],
                                               self.server.read_timeout)
                if not readable:
                    return
                for s in readable:
                    data = s.recv(65536)
                    if not data:
                        return
                    (upstream if s is self.request else self.request).sendall(data)
        except (OSError, select.error):
            return
        finally:
            try:
                upstream.close()
            except OSError:
                pass

    def _relay_http(self, target: str, headers: dict, head: bytes) -> None:
        host = headers.get("host", target[7:].split("/", 1)[0])
        port = 80
        if ":" in host:
            host, _, p = host.partition(":")
            try:
                port = int(p)
            except ValueError:
                self._send(400, b"bad port")
                return
        try:
            upstream = socket.create_connection(
                (host, port), timeout=self.server.connect_timeout)
        except OSError:
            self._send(502, b"upstream connect failed")
            return
        try:
            # Rewrite to origin-form for the upstream.
            line, _, rest = head.partition(b"\r\n")
            method, _, _ = line.split(b" ", 2)
            path = "/" + target.split("/", 3)[3] if target.count("/") >= 3 else "/"
            origin_head = method + b" " + path.encode() + b" HTTP/1.1\r\n" + rest
            upstream.sendall(origin_head)
            upstream.settimeout(self.server.read_timeout)
            while True:
                data = upstream.recv(65536)
                if not data:
                    return
                self.request.sendall(data)
        except (OSError, BrokenPipeError):
            return
        finally:
            try:
                upstream.close()
            except OSError:
                pass

    def _send(self, status: int, body: bytes) -> None:
        reason = {400: b"Bad Request", 403: b"Forbidden",
                  502: b"Bad Gateway"}[status]
        try:
            self.request.sendall(
                b"HTTP/1.1 " + str(status).encode() + b" " + reason +
                b"\r\ncontent-length: " + str(len(body)).encode() +
                b"\r\nconnection: close\r\ncontent-type: text/html\r\n\r\n" + body)
        except OSError:
            pass


class FilteringProxy(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, listen: tuple[str, int], engine_set,
                 read_timeout: float = 15.0, connect_timeout: float = 10.0,
                 decision_log=None):
        self.engine_set = engine_set
        self.read_timeout = read_timeout
        self.connect_timeout = connect_timeout
        self.decision_log = decision_log
        super().__init__(listen, FilteringProxyHandler)

    def log_decision(self, host: str, decision, client_addr) -> None:
        if self.decision_log is not None:
            self.decision_log({
                "host": host, "action": decision.action,
                "rule": decision.rule, "reason": decision.reason,
                "client": client_addr[0] if client_addr else None,
            })

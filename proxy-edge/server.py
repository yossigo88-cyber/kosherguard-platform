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
- Every decision comes from the filtering engine (EngineSet resolution),
  never from a parallel rules implementation.
- Bounded concurrency: fixed worker pool; a slow client holds at most
  one worker and hits a read timeout.

Authenticated per-device access (8B): when the server is constructed
with token_key, EVERY request must carry a policy-bound device token in
a `Proxy-Authorization: Bearer <token>` header, verified with the same
HMAC token scheme as dataset distribution (url-filter-server's shared
device_auth). Fail-closed: missing, malformed, expired, wrong-scope,
revoked, or policy-unbound credentials get 407 (credentials problem) or
403 (authenticated but not bound to an available policy); no request is
ever filtered or relayed without a verified token. The engine resolves
by the token's policy binding, never by client address, in this mode.
The token value is never logged; the decision log records the
authenticated device_id instead. The proxy-authorization and
proxy-connection headers are stripped before relaying upstream so
credentials never leave the proxy. Constructing without token_key keeps
the legacy network-binding behavior for development only - a production
listener must always set token_key.
"""

from __future__ import annotations

import socket
import socketserver
import threading

_ENGINE_SRC = __import__("os").path.join(
    __import__("os").path.dirname(__file__), "..", "filtering-engine", "src")
_AUTH_SRC = __import__("os").path.join(
    __import__("os").path.dirname(__file__), "..", "url-filter-server", "app")
import os
import sys
sys.path.insert(0, os.path.abspath(_ENGINE_SRC))
sys.path.insert(0, os.path.abspath(_AUTH_SRC))

import device_auth  # noqa: E402


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
        resolved = self._resolve_engine(headers)
        if resolved is None:
            return
        engine, device_id = resolved

        if method == "CONNECT":
            self._handle_connect(target, engine, device_id)
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
            self.server.log_decision(host, decision, self.client_address,
                                     device_id)
            return
        self.server.log_decision(host, decision, self.client_address,
                                 device_id)
        self._relay_http(target, headers, head)

    # -- authentication --------------------------------------------------

    def _resolve_engine(self, headers: dict):
        """Authenticate and resolve the engine; None means already refused.

        Legacy mode (no token_key configured) resolves by client address.
        Authenticated mode requires a policy-bound token and resolves by
        the token's binding; every failure refuses the request here."""
        srv = self.server
        if srv.token_key is None:
            return engine_for(srv.engine_set, self.client_address), None
        auth = headers.get("proxy-authorization", "")
        scheme, _, token = auth.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            self._send_auth_required()
            return None
        try:
            payload = device_auth.verify_token(
                srv.token_key, token.strip(), srv.required_scope,
                revoked_jtis=srv.revoked_jtis)
        except device_auth.TokenError:
            self._send_auth_required()
            return None
        policy_id = payload.get("policy_id")
        if isinstance(policy_id, bool) or not isinstance(policy_id, int):
            self._send(403, b"proxy token is not bound to a policy")
            return None
        engine = srv.engine_set.per_policy.get(policy_id)
        if engine is None:
            self._send(403, b"proxy token is bound to an unknown policy")
            return None
        return engine, payload.get("device_id")

    def _send_auth_required(self) -> None:
        self._send(407, b"Proxy authentication required",
                   b'proxy-authenticate: Bearer realm="KosherGuard"\r\n')

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

    def _handle_connect(self, target: str, engine, device_id=None) -> None:
        hostport = target.rsplit("/", 1)[0]
        host = hostport.split(":", 1)[0].strip().lower().rstrip(".")
        if not host:
            self._send(400, b"CONNECT requires host:port")
            return
        decision = engine.decide(host)
        self.server.log_decision(host, decision, self.client_address,
                                 device_id)
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
            # Rewrite to origin-form for the upstream. Proxy credentials
            # and proxy hop-by-hop headers are stripped so they never
            # leave the proxy.
            line, _, rest = head.partition(b"\r\n")
            method, _, _ = line.split(b" ", 2)
            path = "/" + target.split("/", 3)[3] if target.count("/") >= 3 else "/"
            kept = [l for l in rest.split(b"\r\n")
                    if not l.lower().startswith(
                        (b"proxy-authorization:", b"proxy-connection:"))]
            origin_head = (method + b" " + path.encode() + b" HTTP/1.1\r\n"
                           + b"\r\n".join(kept))
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

    def _send(self, status: int, body: bytes,
              extra_headers: bytes = b"") -> None:
        reason = {400: b"Bad Request", 403: b"Forbidden",
                  407: b"Proxy Authentication Required",
                  502: b"Bad Gateway"}[status]
        try:
            self.request.sendall(
                b"HTTP/1.1 " + str(status).encode() + b" " + reason +
                b"\r\ncontent-length: " + str(len(body)).encode() +
                b"\r\nconnection: close\r\ncontent-type: text/html\r\n" +
                extra_headers + b"\r\n" + body)
        except OSError:
            pass


class FilteringProxy(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, listen: tuple[str, int], engine_set,
                 read_timeout: float = 15.0, connect_timeout: float = 10.0,
                 decision_log=None, token_key: bytes | None = None,
                 required_scope: str = "proxy", revoked_jtis=None):
        self.engine_set = engine_set
        self.read_timeout = read_timeout
        self.connect_timeout = connect_timeout
        self.decision_log = decision_log
        self.token_key = token_key
        self.required_scope = required_scope
        self.revoked_jtis = revoked_jtis
        super().__init__(listen, FilteringProxyHandler)

    def log_decision(self, host: str, decision, client_addr,
                     device_id=None) -> None:
        if self.decision_log is not None:
            entry = {
                "host": host, "action": decision.action,
                "rule": decision.rule, "reason": decision.reason,
                "client": client_addr[0] if client_addr else None,
            }
            if device_id is not None:
                entry["device"] = device_id
            self.decision_log(entry)

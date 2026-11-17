"""Dedicated TLS listener for native device-channel MDM.

Run explicitly, never imported/started by the web app. Public TLS with optional
client auth allows initial profile download; check-in/command paths REQUIRE
getpeercert from CA-verified socket, then DB pinning. No proxy identity headers.
No access logs, URL/token echoes, request bodies or certificate dumps.
"""
from __future__ import annotations

import argparse
import json
import ssl
import threading
import time
from collections import OrderedDict, deque
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import urlsplit

from sqlalchemy.exc import IntegrityError

from .db import session_scope
from .native_mdm import download_profile, device_message, TransportError
from mdm.identity import ProvisioningError


def tls_context(*, cert_file, key_file, identity_ca_file):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_file, key_file)
    context.load_verify_locations(cafile=identity_ca_file)
    context.verify_mode = ssl.CERT_OPTIONAL
    context.set_alpn_protocols(["http/1.1"])
    return context


def handler_for(engine, runtime):
    class Handler(BaseHTTPRequestHandler):
        server_version = "KosherGuardMDM"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass  # Default logs include sensitive one-time URLs.

        def reply(self, status, body=b"", content_type="application/xml"):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Pragma", "no-cache")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def do_GET(self):
            parsed = urlsplit(self.path)
            if parsed.query or parsed.fragment:
                return self.reply(400)
            if parsed.path == "/MDMServiceConfig":
                # dep_enrollment_url intentionally absent until the ADE device
                # activation handoff is implemented and separately configured.
                return self.reply(503)  # No generic Configurator ADE discovery without per-device handoff.
            if not parsed.path.startswith("/enroll/"):
                return self.reply(404)
            token = parsed.path[len("/enroll/"):]
            try:
                with session_scope(engine) as session:
                    result = download_profile(session, runtime, token)
                self.reply(200, result, "application/x-apple-aspen-config")
            except TransportError as exc:
                self.reply(exc.status)
            except (ValueError, ProvisioningError, IntegrityError):
                self.reply(409)
            except Exception:
                self.reply(503)

        def do_POST(self):
            # Generic CMS-only server-generated PKCS12 delivery is not an
            # authenticated fresh activation. Use attended control-plane
            # configuration_web_url with fresh guardian session instead.
            self.reply(410)

        def do_PUT(self):
            parsed = urlsplit(self.path)
            if parsed.path not in {"/mdm", "/checkin"} or parsed.query or parsed.fragment:
                return self.reply(404)
            if self.headers.get("Transfer-Encoding") or self.headers.get("Content-Encoding"):
                return self.reply(400)
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return self.reply(400)
            if not 1 <= length <= 1024*1024:
                return self.reply(413)
            peer = self.connection.getpeercert(binary_form=True)
            if not peer:
                return self.reply(403)
            self.connection.settimeout(3)
            data = self.rfile.read(length)
            if len(data) != length:
                return self.reply(400)
            try:
                with session_scope(engine) as session:
                    result = device_message(session, runtime, peer, parsed.path, data)
                self.reply(200, result)
            except TransportError as exc:
                self.reply(exc.status)
            except Exception:
                self.reply(503)

    return Handler


class TLSServer(ThreadingMixIn, HTTPServer):
    """Bound workers BEFORE TLS handshake and limit unauthenticated ingress.

    No unbounded threads or per-IP memory. These are local service limits,
    not a claim of Internet-scale DDoS resistance. Front-door volumetric
    controls still needed before public deployment (not deployed here).
    """
    daemon_threads = True
    block_on_close = False
    request_queue_size = 16

    def __init__(self, address, handler, context, *, max_workers=16,
                 requests_per_minute=60, handshake_timeout=3):
        if not 1 <= max_workers <= 128 or not 1 <= requests_per_minute <= 600:
            raise ValueError("bounded worker/rate configuration required")
        self.context = context
        self.handshake_timeout = handshake_timeout
        self._admission = threading.BoundedSemaphore(max_workers)
        self._rate_lock = threading.Lock()
        self._rate = OrderedDict()
        self._requests_per_minute = requests_per_minute
        super().__init__(address, handler)

    def _rate_allowed(self, ip):
        now = time.monotonic()
        with self._rate_lock:
            timestamps = self._rate.get(ip)
            if timestamps is None:
                if len(self._rate) >= 1024:
                    self._rate.popitem(last=False)
                timestamps = deque()
                self._rate[ip] = timestamps
            while timestamps and timestamps[0] <= now-60:
                timestamps.popleft()
            self._rate.move_to_end(ip)
            if len(timestamps) >= self._requests_per_minute:
                return False
            timestamps.append(now)
            return True

    def process_request(self, request, client_address):
        if not self._rate_allowed(client_address[0]):
            self.shutdown_request(request)
            return
        if not self._admission.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._admission.release()
            self.shutdown_request(request)
            raise

    def process_request_thread(self, request, client_address):
        try:
            request.settimeout(self.handshake_timeout)
            request = self.context.wrap_socket(request, server_side=True)
            request.settimeout(3)
            self.finish_request(request, client_address)
        except (OSError, ssl.SSLError):
            pass  # No certificate/token/body echo in error logs.
        except Exception:
            pass  # Request handler has closed generic error responses.
        finally:
            self.shutdown_request(request)
            self._admission.release()


def main():
    parser = argparse.ArgumentParser(description="Native MDM TLS service; explicit configuration only")
    parser.add_argument("--config-factory", required=True, help="Python module:function returning (engine, runtime, TLS context); secrets from external store")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args()
    import importlib
    module, function = args.config_factory.split(":", 1)
    engine, runtime, context = getattr(importlib.import_module(module), function)()
    if runtime is None or not isinstance(context, ssl.SSLContext) or context.verify_mode != ssl.CERT_OPTIONAL:
        raise RuntimeError("explicit runtime and client-verifying TLS context required")
    TLSServer((args.bind, args.port), handler_for(engine, runtime), context).serve_forever()


if __name__ == "__main__":
    main()

"""DecisionForwarder: batching, auth header, best-effort failure handling."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from forwarder import DecisionForwarder  # noqa: E402


class Receiver(BaseHTTPRequestHandler):
    batches = []
    fail = False

    def do_POST(self):
        body = json.loads(self.rfile.read(
            int(self.headers["Content-Length"])))
        Receiver.batches.append({
            "path": self.path,
            "auth": self.headers.get("Authorization"),
            "body": body})
        if Receiver.fail:
            self.send_response(500)
        else:
            self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"accepted": %d}' % len(body["decisions"]))

    def log_message(self, *a):
        pass


@pytest.fixture()
def receiver():
    Receiver.batches = []
    Receiver.fail = False
    srv = HTTPServer(("127.0.0.1", 0), Receiver)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


class TestForwarder:
    def test_batches_at_threshold_with_auth(self, receiver):
        f = DecisionForwarder(receiver, "tok123", batch_size=3)
        for i in range(3):
            f({"host": f"d{i}.example.com", "action": "block",
               "rule": "r", "reason": "x"})
        assert len(Receiver.batches) == 1
        b = Receiver.batches[0]
        assert b["path"] == "/api/filter-logs"
        assert b["auth"] == "Bearer tok123"
        assert [d["domain"] for d in b["body"]["decisions"]] == \
            ["d0.example.com", "d1.example.com", "d2.example.com"]
        assert f.sent == 3 and f.dropped == 0

    def test_no_send_below_threshold_until_flush(self, receiver):
        f = DecisionForwarder(receiver, "tok123", batch_size=10)
        f({"host": "a.example.com", "action": "allow", "rule": "",
           "reason": ""})
        assert Receiver.batches == []
        f.flush()
        assert len(Receiver.batches) == 1
        assert f.sent == 1

    def test_failures_are_dropped_not_raised(self, receiver):
        Receiver.fail = True
        f = DecisionForwarder(receiver, "tok123", batch_size=2)
        f({"host": "a.example.com", "action": "allow", "rule": "",
           "reason": ""})
        f({"host": "b.example.com", "action": "block", "rule": "",
           "reason": ""})
        assert f.dropped == 2 and f.sent == 0
        # the proxy keeps working: next entries still buffer cleanly
        Receiver.fail = False
        f({"host": "c.example.com", "action": "allow", "rule": "",
           "reason": ""})
        f.flush()
        assert f.sent == 1

    def test_unreachable_host_drops_silently(self):
        f = DecisionForwarder("http://127.0.0.1:1", "tok", batch_size=1,
                              timeout=0.5)
        f({"host": "a.example.com", "action": "allow", "rule": "",
           "reason": ""})
        assert f.dropped == 1

    def test_from_env_requires_both(self):
        assert DecisionForwarder.from_env({}) is None
        assert DecisionForwarder.from_env(
            {"KG_CONTROL_PLANE_URL": "http://x"}) is None
        f = DecisionForwarder.from_env(
            {"KG_CONTROL_PLANE_URL": "http://x", "KG_DEVICE_TOKEN": "t"})
        assert f is not None

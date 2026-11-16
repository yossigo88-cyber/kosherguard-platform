"""DNS decision reporting: the reporter batches real decisions, stamps
source "dns", authenticates with the doh credential, and never lets a
control-plane outage delay a filtering decision."""

import http.server
import json
import os
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import reporter  # noqa: E402

KEY = b"doh-report-test-key"


class _Sink(http.server.BaseHTTPRequestHandler):
    posts = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        type(self).posts.append((self.headers.get("Authorization"),
                                 json.loads(body)))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


def _server():
    _Sink.posts = []
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Sink)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_batches_and_stamps_dns_source():
    srv = _server()
    r = reporter.DNSDecisionReporter(
        f"http://127.0.0.1:{srv.server_address[1]}", "tok-1",
        batch_size=2)
    r.log_decision({"domain": "a.example", "outcome": "answered_blocked",
                    "rule": "blocked", "reason": "policy blocked domain"})
    assert len(_Sink.posts) == 1  # immediate blocked-only, no history buffer
    r.log_decision({"domain": "b.example", "outcome": "forwarded"})
    assert len(_Sink.posts) == 1
    auth, body = _Sink.posts[0]
    assert auth == "Bearer tok-1"
    assert body["decisions"][0] == {
        "domain": "a.example", "action": "block", "source": "dns",
        "rule": "blocked", "reason": "policy blocked domain"}
    assert len(body["decisions"]) == 1
    assert r.sent == 1
    assert r._pending == []
    srv.shutdown()
    srv.server_close()


def test_flush_and_best_effort_drop():
    srv = _server()
    r = reporter.DNSDecisionReporter(
        f"http://127.0.0.1:{srv.server_address[1]}", "tok-1",
        batch_size=100)
    r.log_decision({"domain": "a.example", "outcome": "answered_blocked"})
    r.flush()
    assert r.sent == 1
    srv.shutdown()
    srv.server_close()
    # Unreachable control plane: dropped, counted, never raised.
    r2 = reporter.DNSDecisionReporter("http://127.0.0.1:1", "tok-1",
                                      batch_size=1, timeout=0.2)
    r2.log_decision({"domain": "x.example", "outcome": "answered_blocked"})
    assert r2.dropped == 1


def test_from_env_only_when_configured():
    assert reporter.DNSDecisionReporter.from_env({}) is None
    r = reporter.DNSDecisionReporter.from_env({
        "KG_CONTROL_PLANE_URL": "http://x", "KG_DOH_DEVICE_TOKEN": "t"})
    assert r is not None


def test_runner_installs_reporter(tmp_path):
    """Runtime wiring: the runner hands the reporter to the DNS
    service as its decision logger."""
    from test_runner import POLICY_V1, make_generation
    root = tmp_path / "gen"
    root.mkdir()
    make_generation(str(root), 0, POLICY_V1)
    import runner
    rep = reporter.DNSDecisionReporter("http://127.0.0.1:1", "tok-1")
    r = runner.DNSEdgeRunner(str(root), decision_reporter=rep)
    assert r.service.decisions is rep


def test_runner_starts_and_stops_revocation_loop(tmp_path):
    """The DNS edge entrypoint starts the revocation refresh loop with
    the service and stops it on stop()."""
    import time
    from test_runner import POLICY_V1, make_generation
    root = tmp_path / "gen"
    root.mkdir()
    make_generation(str(root), 0, POLICY_V1)
    import runner
    import threading as _th

    class StubFeed:
        def __init__(self):
            self.shared_set = set()
            self.started = 0
            self._stop = _th.Event()

        def start_refresh_loop(self, interval=60.0):
            self.started += 1
            return self._stop

    feed = StubFeed()
    r = runner.DNSEdgeRunner(str(root), listen="127.0.0.1:0",
                             revocation_feed=feed,
                             refresh_interval=0.05)
    r.start()
    try:
        assert feed.started == 1
        assert not feed._stop.is_set()
    finally:
        r.stop()
    assert feed._stop.is_set()

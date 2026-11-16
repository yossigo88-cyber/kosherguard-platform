"""Revocation distribution tests: the control-plane feed client and
its consumption by the edge verifier. The feed is pulled with a scoped
bearer token; consumption is the in-place set the verifier refuses
against, so a refresh takes effect without restarting the edge."""

import http.server
import json
import os
import sys
import threading

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.dataset import URLRule, build_dataset  # noqa: E402
from app.device_auth import issue_token, verify_token  # noqa: E402
from app.revocations import RevocationFeed  # noqa: E402
from app.server import create_app  # noqa: E402

KEY = b"revocation-feed-test-key"


class _FeedHandler(http.server.BaseHTTPRequestHandler):
    body = b'{"revoked_jtis": []}'
    seen_auth = []

    def do_GET(self):
        type(self).seen_auth.append(self.headers.get("Authorization"))
        if not self.path.endswith("/api/credential-revocations"):
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(type(self).body)

    def log_message(self, *args):
        pass


@pytest.fixture
def feed_server():
    srv = http.server.HTTPServer(("127.0.0.1", 0), _FeedHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()
    srv.server_close()


def test_feed_refresh_sends_scoped_bearer(feed_server):
    _FeedHandler.body = json.dumps(
        {"revoked_jtis": ["jti-1", "jti-2"]}).encode()
    _FeedHandler.seen_auth = []
    token = issue_token(KEY, "dev-1", "tenant-1", "dataset")
    feed = RevocationFeed(
        f"http://127.0.0.1:{feed_server.server_address[1]}",
        token_provider=lambda: token)
    assert feed.refresh() == 2
    assert feed.jtis == {"jti-1", "jti-2"}
    assert _FeedHandler.seen_auth == [f"Bearer {token}"]


def test_feed_refresh_replaces_not_accumulates(feed_server):
    token = issue_token(KEY, "dev-1", "tenant-1", "dataset")
    feed = RevocationFeed(
        f"http://127.0.0.1:{feed_server.server_address[1]}",
        token_provider=lambda: token)
    _FeedHandler.body = json.dumps({"revoked_jtis": ["a"]}).encode()
    feed.refresh()
    _FeedHandler.body = json.dumps({"revoked_jtis": ["b"]}).encode()
    assert feed.refresh() == 1
    assert feed.jtis == {"b"}


def test_failed_refresh_keeps_prior_set(feed_server):
    token = issue_token(KEY, "dev-1", "tenant-1", "dataset")
    feed = RevocationFeed(
        f"http://127.0.0.1:{feed_server.server_address[1]}",
        token_provider=lambda: token)
    _FeedHandler.body = json.dumps({"revoked_jtis": ["a"]}).encode()
    feed.refresh()
    feed_server.shutdown()  # next refresh fails to connect
    with pytest.raises(Exception):
        feed.refresh()
    assert feed.jtis == {"a"}


def test_consumption_end_to_end(feed_server):
    """A dataset token passes until its jti appears in the pulled
    feed; the shared set makes the refresh visible to the running
    verifier without rewiring."""
    ds = build_dataset([URLRule("bet365.com", "block", "gambling")],
                       version=1, provenance="test")
    _FeedHandler.body = b'{"revoked_jtis": []}'
    token = issue_token(KEY, "dev-1", "tenant-1", "dataset")
    feed = RevocationFeed(
        f"http://127.0.0.1:{feed_server.server_address[1]}",
        token_provider=lambda: token)
    feed.refresh()
    app = create_app(ds, device_token_key=KEY,
                     revoked_jtis=feed.shared_set)
    c = TestClient(app)
    hdr = {"Authorization": f"Bearer {token}"}
    assert c.get("/v1/dataset/manifest", headers=hdr).status_code == 200
    jti = verify_token(KEY, token, "dataset")["jti"]
    _FeedHandler.body = json.dumps({"revoked_jtis": [jti]}).encode()
    assert feed.refresh() == 1
    r = c.get("/v1/dataset/manifest", headers=hdr)
    assert r.status_code == 401
    # An unrevoked token for the same tenant is unaffected.
    other = issue_token(KEY, "dev-2", "tenant-1", "dataset")
    assert c.get("/v1/dataset/manifest",
                 headers={"Authorization": f"Bearer {other}"}
                 ).status_code == 200

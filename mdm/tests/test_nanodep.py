"""Contract tests for the NanoDEP depserver client.

A local in-process HTTP fixture implements the documented depserver
contract (HTTP Basic auth as depserver:<api-key>, /v1/assigner,
/proxy/{name}/... to the Apple DEP API). NO external service is
contacted: the fixture binds 127.0.0.1 only. These tests prove our
client speaks the documented wire contract correctly; they are not
evidence of Apple-side operation, which remains blocked on the missing
Apple Business organization.
"""

import base64
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from mdm.ade import build_sync_plan  # noqa: E402
from mdm.nanodep import NanoDEPClient, NanoDEPError, NanoDEPSyncer  # noqa: E402

API_KEY = "test-key"
EXPECTED_AUTH = "Basic " + base64.b64encode(
    f"depserver:{API_KEY}".encode()).decode()


class Fixture(BaseHTTPRequestHandler):
    calls: list = []

    def log_message(self, *a):  # silence
        pass

    def _record(self, body=None):
        Fixture.calls.append({
            "method": self.command, "path": self.path,
            "auth": self.headers.get("Authorization"), "body": body})

    def _json(self, code, payload):
        data = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n)) if n else None

    def _auth_ok(self):
        return self.headers.get("Authorization") == EXPECTED_AUTH

    def do_GET(self):
        self._record()
        if not self._auth_ok():
            return self._json(401, {"error": "unauthorized"})
        if self.path == "/version":
            return self._json(200, {"version": "v0.7.0"})
        if self.path == "/v1/dep_names":
            return self._json(200, {"dep_names": ["mdmserver1"]})
        if self.path == "/v1/assigner/mdmserver1":
            return self._json(200, {"profile_uuid": "UUID-1"})
        if self.path == "/proxy/mdmserver1/account":
            return self._json(200, {"server_name": "KosherGuard",
                                    "server_uuid": "S-UUID"})
        return self._json(404, {"error": "not found"})

    def do_PUT(self):
        body = self._body()
        self._record(body)
        if not self._auth_ok():
            return self._json(401, {"error": "unauthorized"})
        if self.path.startswith("/v1/assigner/mdmserver1?profile_uuid="):
            return self._json(200, {})
        return self._json(404, {"error": "not found"})

    def do_POST(self):
        body = self._body()
        self._record(body)
        if not self._auth_ok():
            return self._json(401, {"error": "unauthorized"})
        if self.path == "/proxy/mdmserver1/devices":
            cursor = (body or {}).get("cursor")
            if not cursor:
                return self._json(200, {
                    "devices": [{"serial_number": "S1"},
                                {"serial_number": "S2"}],
                    "cursor": "PAGE2", "more_to_follow": True})
            return self._json(200, {
                "devices": [{"serial_number": "S3"}],
                "cursor": "PAGE2", "more_to_follow": False})
        if self.path == "/proxy/mdmserver1/profile/devices":
            return self._json(200, {"profile_uuid": body["profile_uuid"],
                                    "devices": {s: "SUCCESS"
                                                for s in body["devices"]}})
        return self._json(404, {"error": "not found"})


@pytest.fixture()
def server():
    Fixture.calls = []
    httpd = HTTPServer(("127.0.0.1", 0), Fixture)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_port}"
    httpd.shutdown()


@pytest.fixture()
def client(server):
    return NanoDEPClient(server, API_KEY)


class TestConfigAPI:
    def test_version_and_auth(self, client):
        assert client.version()["version"] == "v0.7.0"
        assert Fixture.calls[0]["auth"] == EXPECTED_AUTH

    def test_wrong_key_rejected(self, server):
        bad = NanoDEPClient(server, "wrong")
        with pytest.raises(NanoDEPError) as exc:
            bad.version()
        assert exc.value.status == 401

    def test_dep_names(self, client):
        assert client.dep_names() == ["mdmserver1"]

    def test_assigner_roundtrip(self, client):
        client.set_assigner("mdmserver1", "UUID-9")
        put = [c for c in Fixture.calls if c["method"] == "PUT"][0]
        assert put["path"] == "/v1/assigner/mdmserver1?profile_uuid=UUID-9"
        assert client.get_assigner("mdmserver1") == "UUID-1"

    def test_empty_profile_uuid_rejected(self, client):
        with pytest.raises(NanoDEPError):
            client.set_assigner("mdmserver1", "")


class TestProxy:
    def test_account(self, client):
        assert client.account("mdmserver1")["server_uuid"] == "S-UUID"

    def test_iter_devices_follows_cursor(self, client):
        serials = [d["serial_number"]
                   for d in client.iter_devices("mdmserver1")]
        assert serials == ["S1", "S2", "S3"]
        posts = [c for c in Fixture.calls
                 if c["path"] == "/proxy/mdmserver1/devices"]
        # First page request omits the cursor; the second carries it.
        assert "cursor" not in (posts[0]["body"] or {})
        assert posts[1]["body"]["cursor"] == "PAGE2"
        assert len(posts) == 2

    def test_assign_profile(self, client):
        result = client.assign_profile("mdmserver1", "UUID-9", ["S1", "S2"])
        assert result["devices"] == {"S1": "SUCCESS", "S2": "SUCCESS"}
        post = [c for c in Fixture.calls
                if c["path"] == "/proxy/mdmserver1/profile/devices"][0]
        assert post["body"] == {"profile_uuid": "UUID-9",
                                "devices": ["S1", "S2"]}

    def test_assign_requires_serials(self, client):
        with pytest.raises(NanoDEPError):
            client.assign_profile("mdmserver1", "UUID-9", [])


class TestSyncer:
    def test_execute_plan_end_to_end(self, client):
        plan = build_sync_plan(1, "UUID-9", ["S1"], {"S1"})
        result = NanoDEPSyncer(client, "mdmserver1").execute(plan)
        assert result["devices"] == {"S1": "SUCCESS"}
        paths = [c["path"] for c in Fixture.calls]
        assert "/v1/assigner/mdmserver1?profile_uuid=UUID-9" in paths
        assert "/proxy/mdmserver1/profile/devices" in paths

    def test_syncer_requires_dep_name(self, client):
        with pytest.raises(NanoDEPError):
            NanoDEPSyncer(client, "")

    def test_unreachable_server_raises(self):
        dead = NanoDEPClient("http://127.0.0.1:1", "k", timeout=0.5)
        with pytest.raises(NanoDEPError, match="unreachable"):
            dead.version()

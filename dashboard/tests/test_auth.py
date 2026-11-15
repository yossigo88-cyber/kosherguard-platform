"""Authentication and session tests: login, logout, session checks,
password change, login lockout, cookie flags."""

from conftest import ADMIN_PASSWORD, ADMIN_USERNAME, Client


def test_protected_endpoints_require_session(anon_client):
    for path in ("/api/overview", "/api/policies", "/api/categories",
                 "/api/domains", "/api/audit", "/api/me", "/api/config"):
        status, body = anon_client.get(path)
        assert status == 401, path
        assert "error" in body


def test_protected_mutations_require_session(anon_client):
    status, _ = anon_client.post("/api/policies", {"name": "x", "default_policy": "allow"})
    assert status == 401
    status, _ = anon_client.post("/api/categories", {"name": "x", "display_name": "X"})
    assert status == 401
    status, _ = anon_client.post("/api/domains", {"domain": "x.example", "categories": ["news"]})
    assert status == 401


def test_wrong_password_rejected(anon_client):
    status, _ = anon_client.login(ADMIN_USERNAME, "wrong-password")
    assert status == 401


def test_unknown_user_rejected(anon_client):
    status, _ = anon_client.login("nobody", "whatever-123")
    assert status == 401


def test_login_me_logout_flow(anon_client):
    status, body = anon_client.login()
    assert status == 200
    assert body == {"username": ADMIN_USERNAME}
    status, body = anon_client.get("/api/me")
    assert status == 200
    assert body["username"] == ADMIN_USERNAME
    status, _ = anon_client.post("/api/logout", {})
    assert status == 200
    status, _ = anon_client.get("/api/me")
    assert status == 401


def test_session_cookie_flags(server):
    c = Client(server.server_address[1])
    status, body, _, set_cookie = c.request(
        "POST", "/api/login", {"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}
    )
    assert status == 200
    assert "HttpOnly" in set_cookie
    assert "SameSite=Strict" in set_cookie
    assert "kg_session=" in set_cookie


def test_change_password(client, server):
    status, _ = client.post("/api/change-password",
                            {"current_password": "wrong", "new_password": "new-password-1"})
    assert status == 401
    status, _ = client.post("/api/change-password",
                            {"current_password": ADMIN_PASSWORD, "new_password": "short"})
    assert status == 400
    status, _ = client.post(
        "/api/change-password",
        {"current_password": ADMIN_PASSWORD, "new_password": "new-password-1"},
    )
    assert status == 200
    # All existing sessions are invalidated.
    status, _ = client.get("/api/me")
    assert status == 401
    # Old password no longer works; the new one does.
    other = Client(server.server_address[1])
    status, _ = other.login(ADMIN_USERNAME, ADMIN_PASSWORD)
    assert status == 401
    status, _ = other.login(ADMIN_USERNAME, "new-password-1")
    assert status == 200


def test_login_lockout(limited_server):
    c = Client(limited_server.server_address[1])
    for _ in range(2):
        status, _ = c.login(ADMIN_USERNAME, "bad-password")
        assert status == 401
    # Third attempt is locked out even with the CORRECT password.
    status, _ = c.login(ADMIN_USERNAME, ADMIN_PASSWORD)
    assert status == 429


def test_password_never_appears_in_responses(client):
    for path in ("/api/me", "/api/overview", "/api/policies", "/api/audit"):
        status, body = client.get(path)
        assert status == 200
        assert ADMIN_PASSWORD not in str(body)
        assert "password_hash" not in str(body)

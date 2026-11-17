"""Database read must not yield bearer sessions; untrusted hash costs bounded."""
import sqlite3

import pytest

import auth


@pytest.fixture
def conn():
    c = sqlite3.connect(':memory:')
    c.row_factory = sqlite3.Row
    c.executescript('''
        CREATE TABLE admins (id INTEGER PRIMARY KEY, username TEXT);
        INSERT INTO admins VALUES (1, 'admin');
        CREATE TABLE sessions (token TEXT PRIMARY KEY, admin_id INTEGER,
                               created_at TEXT, expires_at TEXT);
    ''')
    yield c
    c.close()


def test_database_session_value_is_not_replayable(conn):
    token = auth.create_session(conn, 1)
    stored = conn.execute('SELECT token FROM sessions').fetchone()[0]
    assert stored != token
    assert stored == auth.hash_session_token(token)
    assert auth.resolve_session(conn, token)['username'] == 'admin'
    with pytest.raises(auth.AuthError):
        auth.resolve_session(conn, stored)
    auth.destroy_session(conn, token)
    assert conn.execute('SELECT count(*) FROM sessions').fetchone()[0] == 0


def test_expired_digest_session_removed(conn):
    token = auth.create_session(conn, 1)
    conn.execute("UPDATE sessions SET expires_at='2000-01-01T00:00:00+00:00'")
    with pytest.raises(auth.AuthError, match='session expired'):
        auth.resolve_session(conn, token)
    assert conn.execute('SELECT count(*) FROM sessions').fetchone()[0] == 0


def test_legacy_plaintext_sessions_invalidated_and_purged(conn):
    conn.execute("INSERT INTO sessions VALUES ('legacy-token',1,'2000','2999')")
    with pytest.raises(auth.AuthError):
        auth.resolve_session(conn, 'legacy-token')
    fresh = auth.create_session(conn, 1)
    assert conn.execute('SELECT count(*) FROM sessions').fetchone()[0] == 1
    assert auth.resolve_session(conn, fresh)['id'] == 1


@pytest.mark.parametrize('rounds', [-1, 0, 9999, 2000001, 2147483648])
def test_reject_bad_hash_cost_before_kdf(monkeypatch, rounds):
    def forbidden(*args, **kwargs):
        pytest.fail('untrusted cost reached KDF')
    monkeypatch.setattr(auth.hashlib, 'pbkdf2_hmac', forbidden)
    assert not auth.verify_password('password', f'pbkdf2${rounds}$' + '00'*16 + '$' + '00'*32)


def test_valid_existing_password_still_verifies():
    hashed = auth.hash_password('long test password')
    assert auth.verify_password('long test password', hashed)
    assert not auth.verify_password('wrong', hashed)

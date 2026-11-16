"""Executable DoH app: uvicorn asgi:create_runtime --factory.

All credentials come from deployment configuration; none are hardcoded.
The feed bearer is reread from a mode0600 file on every refresh, so an
operator can rotate it by atomic rename. No unattended minting is claimed.
"""
import os
import stat
from contextlib import asynccontextmanager
from doh_server import create_app


def create_runtime():
    key = os.environ.get('KG_DEVICE_TOKEN_KEY', '').encode()
    root = os.environ.get('KG_PUBLICATIONS_ROOT', '')
    if not root or not key:
        raise ValueError('KG_PUBLICATIONS_ROOT and KG_DEVICE_TOKEN_KEY required')
    control = os.environ.get('KG_CONTROL_PLANE_URL', '')
    token_file = os.environ.get('KG_REVOCATION_TOKEN_FILE', '')
    feed = None
    expected_tenant = None
    if bool(control) != bool(token_file):
        raise ValueError('feed URL and token file must be configured together')
    if control:
        import sys
        sys.path.insert(0, os.path.abspath(os.path.join(
            os.path.dirname(__file__), '..', 'url-filter-server', 'app')))
        from revocations import RevocationFeed
        def provider():
            fd = os.open(token_file, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd) as f:
                mode = os.fstat(f.fileno()).st_mode
                if not stat.S_ISREG(mode) or stat.S_IMODE(mode) & 0o077:
                    raise ValueError('feed credential requires private regular file')
                return f.read(16384).strip()
        from doh_identity import authenticate_doh_request
        expected_tenant = authenticate_doh_request(
            'Bearer '+provider(), key)['tenant_id']
        feed = RevocationFeed(control, provider)
    app = create_app(root, key, revoked_jtis=feed.shared_set if feed else None,
                     expected_tenant=expected_tenant)
    @asynccontextmanager
    async def lifespan(app):
        stop = feed.start_refresh_loop(interval=60) if feed else None
        try:
            yield
        finally:
            if stop: stop.set()
    app.router.lifespan_context = lifespan
    return app

"""Code-only proxy process entrypoint: python proxy-edge/runtime.py.

Requires a tenant generation root and private key file. Does not provision
Apple profiles, deploy listeners or mint credentials. TLS/network ingress is
operator-managed and untested here.
"""
import os
import signal
import stat
import threading
from server import build_published_proxy


def private_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        mode = os.fstat(stream.fileno()).st_mode
        if not stat.S_ISREG(mode) or stat.S_IMODE(mode) & 0o077:
            raise ValueError('credential requires private regular file')
        value = stream.read(16385)
        if not value or len(value) > 16384:
            raise ValueError('invalid credential file size')
        return value.strip()


def build_runtime(env=None):
    env = os.environ if env is None else env
    root = env.get('KG_TENANT_PUBLICATIONS_ROOT', '')
    keyfile = env.get('KG_DEVICE_TOKEN_KEY_FILE', '')
    if not root or not keyfile:
        raise ValueError('tenant publication root and private key file required')
    host = env.get('KG_PROXY_HOST', '127.0.0.1')
    port = int(env.get('KG_PROXY_PORT', '8080'))
    key = private_file(keyfile)
    control = env.get('KG_CONTROL_PLANE_URL', '')
    tokenfile = env.get('KG_REVOCATION_TOKEN_FILE', '')
    if bool(control) != bool(tokenfile):
        raise ValueError('revocation URL and token file required together')
    proxy = build_published_proxy((host, port), root, key,
        watch_interval=float(env.get('KG_POLICY_REFRESH_SECONDS', '5')))
    if control:
        from server import device_auth
        import revocations
        def provider():
            value = private_file(tokenfile).decode()
            claims = device_auth.verify_token(key, value, required_scope='proxy')
            if str(claims['tenant_id']) != str(proxy.policy_bundle.tenant_id):
                raise ValueError('revocation credential belongs to another tenant')
            return value
        try:
            provider()  # validate initial file without an external call
            feed = revocations.RevocationFeed(control, provider)
            proxy.revoked_jtis = feed.shared_set
            proxy.revocation_stop = feed.start_refresh_loop(interval=60)
        except Exception:
            proxy.server_close()
            raise
    return proxy


def main():
    proxy = build_runtime()
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    thread = threading.Thread(target=proxy.serve_forever)
    thread.start()
    try:
        stop.wait()
    finally:
        proxy.shutdown()
        proxy.server_close()
        thread.join(timeout=10)


if __name__ == '__main__':
    main()

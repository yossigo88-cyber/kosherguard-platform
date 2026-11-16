"""Authenticated DNS-over-HTTPS endpoint backed by immutable policy bundles.

Serve with TLS at the configured ingress; loopback HTTP is test-only.
Identity and tenant come only from a verified short-lived header token.
No decision/history reporting is added by this endpoint.
"""
from __future__ import annotations
import base64
import os
import threading
from fastapi import FastAPI, Request
from fastapi.responses import Response
from doh_identity import authenticate_doh_request, tenant_root_for_token, IdentityError
from policy_bundle import load_bundle
import dns_service


def create_app(publications_root, token_key, revoked_jtis=None,
               now=None, upstreams=None, expected_tenant=None):
    if not token_key:
        raise ValueError('DoH requires a device verification key')
    app = FastAPI(docs_url=None, redoc_url=None)
    lock = threading.Lock()
    bundles = {}

    def bundle_for(root):
        # Full validation on reload, last-known-good on a corrupt update.
        # Root comes solely from an authenticated tenant identity.
        with lock:
            try:
                current = os.readlink(os.path.join(root, 'current'))
                old = bundles.get(root)
                if old is not None and old[0] == current:
                    return old[1]
                loaded = load_bundle(root, now=now)
                bundles[root] = (current, loaded)
                return loaded
            except Exception:
                if root in bundles:
                    return bundles[root][1]
                raise

    @app.api_route('/dns-query', methods=['GET', 'POST'])
    async def query(request: Request):
        try:
            claims = authenticate_doh_request(
                request.headers.get('authorization'), token_key,
                revoked_jtis=revoked_jtis)
            if expected_tenant is not None and str(claims["tenant_id"]) != str(expected_tenant):
                return Response(status_code=403)
            root = tenant_root_for_token(publications_root, claims)
        except IdentityError:
            return Response(status_code=401)
        # URL-transported credentials are never accepted.
        if set(request.query_params) - {'dns'}:
            return Response(status_code=400)
        if request.method == 'POST':
            if request.headers.get('content-type', '').split(';')[0] != 'application/dns-message':
                return Response(status_code=415)
            data = bytearray()
            async for chunk in request.stream():
                data.extend(chunk)
                if len(data) > 65535:
                    return Response(status_code=413)
            data = bytes(data)
        else:
            encoded = request.query_params.get('dns', '')
            if len(encoded) > 87380:
                return Response(status_code=413)
            try:
                data = base64.b64decode(encoded + '=' * (-len(encoded) % 4),
                                        altchars=b'-_', validate=True)
            except ValueError:
                return Response(status_code=400)
        if not data or len(data) > 65535:
            return Response(status_code=400)
        try:
            bundle = bundle_for(root)
            if str(bundle.tenant_id) != str(claims["tenant_id"]):
                return Response(status_code=403)
            config = dns_service.ServiceConfig()
            if upstreams:
                config.upstreams = list(upstreams)
            # A request-local service holds exactly one already-validated
            # engine; there is no shared mutable request policy switch.
            service = dns_service.DNSFilteringService(
                bundle.for_device(claims['device_id']), config)
            import asyncio
            answer = await asyncio.to_thread(service.handle_packet, data)
        except Exception:
            return Response(status_code=503)
        if answer is None:
            return Response(status_code=400)
        return Response(bytes(answer), media_type='application/dns-message',
                        headers={'Cache-Control': 'no-store',
                                 'X-Policy-Revision': str(bundle.revision)})
    return app

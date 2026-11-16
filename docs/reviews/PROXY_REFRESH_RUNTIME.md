# Proxy generation-refresh runtime

Code-only increment after64daa131. Nothing deployed or run against devices.

`python proxy-edge/runtime.py` requires KG_TENANT_PUBLICATIONS_ROOT and a
mode0600 regular non-symlink KG_DEVICE_TOKEN_KEY_FILE. Loopback host default,
KG_PROXY_PORT default8080; KG_POLICY_REFRESH_SECONDS default5. This watches
local publication files, not remote accounts. Service example is configuration
only. TLS ingress, PAC/device auth transport and production network behavior
still need separate authorized setup and verification.

The published-proxy constructor starts its local watch loop. Every candidate
bundle is hash/schema/schedule validated; only advancing revisions for the
original tenant replace the last-known-good reference. Bad/foreign/stale
revisions retain the old bundle. Each request snapshots that reference before
checking tenant/current assignment. server_close signals and joins the watch.
No device acknowledges application here; an existing CONNECT tunnel is not
re-evaluated midstream. This closes the explicit-reload-only code gap, not
real-device enforcement.

Optional KG_CONTROL_PLANE_URL plus KG_REVOCATION_TOKEN_FILE enables the real
60second revocation feed. Both required together. Provider rereads private
regular token file every refresh, verifies proxy scope/tenant/expiry, and
supports atomic credential-file replacement. No automatic minting is claimed.
Without this pair there is no remote revocation feed; credentials still expire,
but runtime startup alone proves no feed is current. Runtime closes the feed
stop event on exit; in-flight HTTP timeout may delay its daemon's final exit.

Tests: six policy-bundle control-plane integration tests cover automatic valid
reload, foreign/corrupt LKG, recovery and stopped thread; private-file/no-config
and actual subprocess socket-request/SIGTERM tests in proxy runtime suite.
Production deployment, upstream/Apple transport and long-lived connection
cutover remain unverified. Other original-plan gaps remain open, including
secure sole-owner recovery, groups/exceptions/five-role/support/onboarding,
enrollment tickets, offboarding/migration and website/legal matrices.

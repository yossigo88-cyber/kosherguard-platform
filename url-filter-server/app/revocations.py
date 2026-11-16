"""Revocation feed client for edge verifiers.

Edges pull the tenant's revoked, not-yet-expired jtis from the control
plane's GET /api/credential-revocations and refuse listed tokens during
verification. The feed is tenant-scoped by the presented scoped token
itself: the caller needs a dataset/proxy/doh token for its own tenant
and can never read another tenant's revocations.

Tokens are short-lived by design; the caller supplies a token_provider
callable (e.g. the app's credential controller) so refresh can re-mint
as needed. Revocation is best-effort between refreshes: unlisted tokens
still expire on their short lifetime, which bounds the window.
"""

from __future__ import annotations

import json
import threading
import urllib.request


class RevocationFeed:
    def __init__(self, control_plane_url: str, token_provider,
                 timeout: float = 10.0) -> None:
        self._url = control_plane_url.rstrip("/") + \
            "/api/credential-revocations"
        self._token_provider = token_provider
        self._timeout = timeout
        self._jtis: set[str] = set()
        self._lock = threading.Lock()

    def refresh(self) -> int:
        """Pull the feed; returns the number of revoked jtis now known.
        The set is updated in place so verifiers holding a reference
        see the refresh without rewiring."""
        token = self._token_provider()
        req = urllib.request.Request(
            self._url, headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:
            data = json.loads(resp.read().decode())
        jtis = set(data.get("revoked_jtis") or [])
        with self._lock:
            self._jtis.clear()
            self._jtis.update(jtis)
        return len(jtis)

    @property
    def jtis(self) -> set[str]:
        with self._lock:
            return set(self._jtis)

    def start_refresh_loop(self, interval: float = 60.0,
                           stop_event: threading.Event | None = None
                           ) -> threading.Event:
        """Refresh now and then every interval seconds on a daemon
        thread; returns the stop event (set it to stop). A failed
        refresh keeps the prior set, so a control-plane outage degrades
        to bounded staleness (unlisted tokens still expire on their
        short lifetime). The token provider is called on EVERY refresh,
        so a renewed credential is picked up without rewiring."""
        stop = stop_event or threading.Event()

        def loop():
            while not stop.is_set():
                try:
                    self.refresh()
                except Exception:
                    pass
                stop.wait(interval)

        threading.Thread(target=loop, name="revocation-feed",
                         daemon=True).start()
        return stop

    @property
    def shared_set(self) -> set[str]:
        """The live set reference for in-place consumption: pass this
        to a verifier's revoked_jtis so each refresh is visible without
        rewiring. Reads outside the feed's own refresh are unsynchronized;
        verifiers only test membership, which a clear+update keeps safe
        between refreshes."""
        return self._jtis

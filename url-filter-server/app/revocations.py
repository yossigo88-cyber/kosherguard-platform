"""Revocation feed client for edge verifiers.

Edges pull the tenant's revoked, not-yet-expired jtis from the control
plane's GET /api/credential-revocations and refuse listed tokens during
verification. The feed is tenant-scoped by the presented scoped token
itself: the caller needs a dataset/proxy/doh token for its own tenant
and can never read another tenant's revocations.

Tokens are short-lived by design; the caller supplies a token_provider
callable (e.g. the app's credential controller) so refresh can re-mint
as needed.

Consistency: verifiers always see a COMPLETE revocation set - either
the previous one or the newly fetched one, never a partially applied
one. A refresh builds the new set first and swaps it in as one
immutable snapshot (a single atomic reference assignment); a failed
fetch or parse changes nothing, so the old set keeps protecting until
a good fetch lands.

Staleness bound, precisely: while the control plane is reachable the
set is at most one refresh interval stale (default 60s loop). If
refreshes fail, the last good set persists and the true bound is each
token's own remaining lifetime - minted as
min(KG_SESSION_LIFETIME_SECONDS, 86400), i.e. up to 12 hours with the
default session lifetime. Operators shrinking that window lower the
session lifetime, not the feed interval.
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
        # Immutable snapshot, swapped atomically on each successful
        # refresh: a verifier's membership read always sees one
        # COMPLETE set, never a clear+update in progress (the race
        # that briefly accepted revoked tokens). The lock serializes
        # concurrent refreshes; reads need no lock.
        self._snapshot: frozenset[str] = frozenset()
        self._lock = threading.Lock()

    def refresh(self) -> int:
        """Pull the feed; returns the number of revoked jtis now known.
        On success the new set replaces the old as ONE atomic snapshot;
        on any failure the previous set is preserved unchanged."""
        token = self._token_provider()
        req = urllib.request.Request(
            self._url, headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:
            data = json.loads(resp.read().decode())
        new = frozenset(data.get("revoked_jtis") or [])
        with self._lock:
            self._snapshot = new
        return len(new)

    @property
    def jtis(self) -> set[str]:
        return set(self._snapshot)

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
    def shared_set(self) -> frozenset[str]:
        """The current COMPLETE revocation set (immutable). Reading it
        is one atomic reference load: verifiers see either the whole
        previous set or the whole new set, never a refresh in flight.
        Callers that want every refresh read it per verification (the
        server does); the value must never be mutated by callers."""
        return self._snapshot

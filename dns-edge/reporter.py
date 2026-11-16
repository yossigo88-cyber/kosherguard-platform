"""Best-effort reporting of real DNS decisions to the control plane
(spec Part 10: Filtering logs, "dns" source).

Wire-up: pass DNSDecisionReporter(...) as the runner's
decision_reporter; it is installed as the DNS service's decision
logger. Only blocked domains are sent immediately to POST /api/filter-logs
with a doh-scoped credential. Allowed decisions are ignored. No history queue
or on-disk spool exists; failures are counted and dropped. The configured
request timeout bounds synchronous reporting delay. Detailed blocked activity
is retained only by the central retention-controlled ingestion route.
"""

from __future__ import annotations

import json
import threading
import urllib.request


class DNSDecisionReporter:
    def __init__(self, control_plane_url: str, token: str,
                 batch_size: int = 25, timeout: float = 3.0) -> None:
        self._url = control_plane_url.rstrip("/") + "/api/filter-logs"
        self._token = token
        self._batch_size = batch_size
        self._timeout = timeout
        self._lock = threading.Lock()
        self._pending: list[dict] = []
        self.dropped = 0
        self.sent = 0

    @classmethod
    def from_env(cls, env) -> "DNSDecisionReporter | None":
        """Configured only when both settings are present; otherwise the
        service keeps deciding without reporting (the panel then
        honestly shows no rows)."""
        url = (env.get("KG_CONTROL_PLANE_URL") or "").strip()
        token = (env.get("KG_DOH_DEVICE_TOKEN") or "").strip()
        if not url or not token:
            return None
        return cls(url, token)

    def log_decision(self, record: dict) -> None:
        if not (record.get("action") == "block" or str(record.get("outcome", "")).startswith("answered_blocked")):
            return
        # No history cache. Submit only a blocked domain, immediately; failure
        # drops it rather than spooling sensitive records to disk/memory.
        self._post([{"domain": record.get("domain"), "action": "block",
                     "source": "dns", "rule": "blocked",
                     "reason": "policy blocked domain"}])

    def flush(self) -> None:
        with self._lock:
            batch, self._pending = self._pending, []
        if batch:
            self._post(batch)

    def _post(self, batch: list[dict]) -> None:
        body = json.dumps({"decisions": batch}).encode()
        req = urllib.request.Request(
            self._url, data=body,
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self._token}"})
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as r:
                if 200 <= r.status < 300:
                    self.sent += len(batch)
                    return
        except Exception:
            pass
        self.dropped += len(batch)

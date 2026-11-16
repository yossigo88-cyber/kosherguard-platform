"""Best-effort forwarding of real proxy decisions to the control plane.

Wire-up: pass DecisionForwarder(...) as the server's decision_log
callback. Entries the proxy actually decided are buffered and POSTed in
batches to POST /api/filter-logs with the device's scoped credential
(scope "proxy"). Forwarding is strictly best-effort: the proxy's job is
filtering, so a control-plane outage must never delay or break a
decision - failures are counted and the batch is dropped, never
retried into a queue that could grow without bound.
"""

from __future__ import annotations

import json
import threading
import urllib.request


class DecisionForwarder:
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
    def from_env(cls, env) -> "DecisionForwarder | None":
        """Configured only when both settings are present; otherwise the
        proxy keeps deciding without reporting (the panel then honestly
        shows no rows)."""
        url = (env.get("KG_CONTROL_PLANE_URL") or "").strip()
        token = (env.get("KG_DEVICE_TOKEN") or "").strip()
        if not url or not token:
            return None
        return cls(url, token)

    def __call__(self, entry: dict) -> None:
        batch = None
        with self._lock:
            self._pending.append({
                "domain": entry.get("host"),
                "action": entry.get("action"),
                "rule": entry.get("rule") or "",
                "reason": entry.get("reason") or "",
            })
            if len(self._pending) >= self._batch_size:
                batch = self._pending
                self._pending = []
        if batch is not None:
            self._post(batch)

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

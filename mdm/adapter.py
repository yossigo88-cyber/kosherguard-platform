"""MDM adapter interface and implementations.

Command lifecycle (spec Part 5/6): queued -> delivered ->
acknowledged | error | not_now. A command is only ever reported as
successful when the device itself returns an Acknowledged status -
never because the server managed to send it.
"""

from __future__ import annotations

import abc
import json
import urllib.error
import urllib.request

# Commands KosherGuard supports. EraseDevice and any other destructive
# command are deliberately absent from this build.
SUPPORTED_COMMANDS = frozenset({
    "DeviceInformation",
    "InstalledApplicationList",
    "ProfileList",
    "InstallProfile",
    "RemoveProfile",
    "InstallApplication",
    "RemoveApplication",
    "ManagedApplicationList",
    "DeviceLock",
    "RestartDevice",
    # Activates Declarative Device Management on the device; after this
    # the device starts sending DeclarativeManagement check-ins, which
    # NanoMDM (-dm flag) forwards to the control plane's /api/ddm/
    # endpoints. Verified sources: NanoMDM operations guide "-dm"
    # (main branch) and MicroMDM's WWDC21 declarative-management post
    # (micromdm.io/blog/wwdc21-declarative-management), which shows
    # exactly this command enqueued via cmdr.py.
    "DeclarativeManagement",
})


class MDMAdapterError(RuntimeError):
    pass


class CommandResult:
    """Outcome of delivering one command to one enrollment."""

    def __init__(self, status: str, detail: str = "") -> None:
        if status not in ("acknowledged", "error", "not_now"):
            raise ValueError(f"unknown device status: {status}")
        self.status = status
        self.detail = detail

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"CommandResult({self.status!r}, {self.detail!r})"


class MDMAdapter(abc.ABC):
    """Narrow interface between the control plane and the MDM server."""

    @abc.abstractmethod
    def deliver_command(self, enrollment_id: str, command: str,
                        payload: dict) -> CommandResult:
        """Send one command to one enrollment and return its device status."""

    @abc.abstractmethod
    def push(self, enrollment_id: str) -> None:
        """Send an APNs push to wake the device for a check-in."""


class NanoMDMAdapter(MDMAdapter):
    """Classic MDM commands only. DDM declarations are NOT delivered
    through this adapter: NanoMDM v0.3.0+ forwards DeclarativeManagement
    check-ins to the DM server named by its -dm flag (operations guide,
    docs/operations-guide.md), which for this platform is the control
    plane's /api/ddm/ endpoints (control-plane/app/ddm_ops.py). Delivery
    of a declaration therefore requires NanoMDM to be run with
    -dm https://<control-plane>/api/ddm/ - that is deployment config,
    not code in this class."""
    """HTTP client for a NanoMDM server's API.

    NanoMDM exposes command enqueueing and push over HTTP; device
    statuses are reconciled from its PostgreSQL storage by the control
    plane's reconciler. This client performs no retries and no
    credential handling beyond a caller-supplied API key header.
    """

    def __init__(self, base_url: str, api_key: str = "",
                 timeout: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _request(self, method: str, path: str, body: dict | None) -> bytes:
        req = urllib.request.Request(
            self.base_url + path,
            method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Content-Type": "application/json",
                     **({"Authorization": f"Bearer {self.api_key}"}
                        if self.api_key else {})})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.read()
        except (urllib.error.URLError, OSError) as exc:
            raise MDMAdapterError(f"nanomdm request failed: {exc}") from exc

    def deliver_command(self, enrollment_id: str, command: str,
                        payload: dict) -> CommandResult:
        if command not in SUPPORTED_COMMANDS:
            raise MDMAdapterError(f"unsupported command: {command}")
        raw = self._request("POST", f"/v1/enrollments/{enrollment_id}/commands",
                            {"command": command, "payload": payload})
        # NanoMDM enqueue confirms the queue write only; the device has
        # not answered yet. Until status reconciliation reads a real
        # device status, the honest result is not_now (pending).
        _ = raw
        return CommandResult("not_now", "enqueued; awaiting device check-in")

    def push(self, enrollment_id: str) -> None:
        self._request("POST", f"/v1/enrollments/{enrollment_id}/push", None)


class SimulatedMDMAdapter(MDMAdapter):
    """Deterministic in-process fake for tests and local development.

    Records every call and returns scripted per-command results so the
    control plane's lifecycle handling can be tested without any Apple
    infrastructure.
    """

    def __init__(self, results: dict | None = None) -> None:
        self.results = results or {}
        self.calls: list[tuple[str, str, dict]] = []
        self.pushes: list[str] = []

    def deliver_command(self, enrollment_id: str, command: str,
                        payload: dict) -> CommandResult:
        if command not in SUPPORTED_COMMANDS:
            raise MDMAdapterError(f"unsupported command: {command}")
        self.calls.append((enrollment_id, command, payload))
        scripted = self.results.get(command)
        if scripted is not None:
            return scripted
        return CommandResult("acknowledged")

    def push(self, enrollment_id: str) -> None:
        self.pushes.append(enrollment_id)

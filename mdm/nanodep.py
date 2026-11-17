"""NanoDEP depserver client: the real execution path for ADE work.

Implements the documented NanoDEP HTTP contract (micromdm/nanodep
docs/operations-guide.md):

- HTTP Basic auth: username "depserver", password = the -api key.
- Config API: GET/PUT /v1/assigner/{name} (assigner profile UUID),
  GET /version, GET /v1/dep_names.
- Transparent-auth reverse proxy: /proxy/{name}/{apple-endpoint}
  forwards to https://mdmenrollment.apple.com/{endpoint} with NanoDEP
  handling session tokens. Apple DEP endpoints used here: POST
  /devices (fetch/sync, cursor-paginated), POST /profile/devices
  (assign a profile UUID to device serials), GET /account.

This module is IMPLEMENTED but UNVERIFIED against Apple: no Apple
Business org, no DEP tokens, and no NanoDEP server exist yet, so the
only executions so far are against the local fixture server in
mdm/tests. That distinction is stated wherever coverage is reported.
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request


class NanoDEPError(RuntimeError):
    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class NanoDEPClient:
    """HTTP client for one NanoDEP depserver."""

    def __init__(self, base_url: str, api_key: str,
                 timeout: float = 15.0) -> None:
        if not base_url.startswith(("https://", "http://")):
            raise NanoDEPError("base_url must be an http(s) URL")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _request(self, method: str, path: str,
                 body: dict | None = None,
                 query: dict | None = None) -> dict:
        url = self.base_url + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        auth = base64.b64encode(
            f"depserver:{self.api_key}".encode()).decode()
        req = urllib.request.Request(
            url, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": f"Basic {auth}",
                     "Accept": "application/json",
                     **({"Content-Type": "application/json"}
                        if body is not None else {})})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            raise NanoDEPError(
                f"depserver {method} {path} -> HTTP {exc.code}",
                status=exc.code) from exc
        except (urllib.error.URLError, OSError) as exc:
            raise NanoDEPError(f"depserver unreachable: {exc}") from exc
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise NanoDEPError(
                f"depserver {method} {path} returned non-JSON") from exc

    # -- config API ---------------------------------------------------
    def version(self) -> dict:
        return self._request("GET", "/version")

    def dep_names(self) -> list[str]:
        return self._request("GET", "/v1/dep_names").get("dep_names", [])

    def get_assigner(self, dep_name: str) -> str:
        body = self._request("GET", f"/v1/assigner/{dep_name}")
        return body.get("profile_uuid", "")

    def set_assigner(self, dep_name: str, profile_uuid: str) -> None:
        if not profile_uuid:
            raise NanoDEPError("profile_uuid is required")
        self._request("PUT", f"/v1/assigner/{dep_name}",
                      query={"profile_uuid": profile_uuid})

    # -- transparent-auth proxy to the Apple DEP API -------------------
    def _proxy(self, dep_name: str, method: str, apple_endpoint: str,
               body: dict | None = None) -> dict:
        return self._request(
            method, f"/proxy/{dep_name}/{apple_endpoint.lstrip('/')}",
            body=body)

    def account(self, dep_name: str) -> dict:
        return self._proxy(dep_name, "GET", "account")

    def fetch_devices(self, dep_name: str,
                      cursor: str = "") -> dict:
        """One Apple DEP device fetch/sync page. The first request of a
        sync omits the cursor (per the godep contract)."""
        body: dict = {}
        if cursor:
            body["cursor"] = cursor
        return self._proxy(dep_name, "POST", "server/devices", body=body)

    def iter_devices(self, dep_name: str):
        """Yield device dicts across all cursor pages until Apple says
        the sync is complete."""
        cursor = ""
        while True:
            page = self.fetch_devices(dep_name, cursor=cursor)
            for device in page.get("devices", []):
                yield device
            next_cursor = page.get("cursor", cursor)
            if page.get("more_to_follow") and (not next_cursor or next_cursor == cursor):
                raise NanoDEPError("pagination cursor did not advance")
            cursor = next_cursor
            # Apple's contract: more_to_follow while pages remain.
            if not page.get("more_to_follow"):
                return

    def assign_profile(self, dep_name: str, profile_uuid: str,
                       serials: list[str]) -> dict:
        """Assign an enrollment profile to device serials (Apple DEP
        POST /profile/devices)."""
        if not profile_uuid:
            raise NanoDEPError("profile_uuid is required")
        if not serials:
            raise NanoDEPError("at least one serial is required")
        return self._proxy(dep_name, "POST", "profile/devices",
                           body={"profile_uuid": profile_uuid,
                                 "devices": list(serials)})


class NanoDEPSyncer:
    """Executes ADESyncPlans through a NanoDEPClient.

    This is the bridge between our declarative plan (mdm.ade) and the
    real depserver: validate against our tenant's records, set the
    assigner, then assign the profile to the planned serials.
    """

    def __init__(self, client: NanoDEPClient, dep_name: str) -> None:
        if not dep_name:
            raise NanoDEPError("dep_name is required")
        self.client = client
        self.dep_name = dep_name

    def execute(self, plan) -> dict:
        """Run one validated plan. Returns the Apple DEP assignment
        response per serial. Raises NanoDEPError on any failure - a
        partial assignment is reported, never hidden."""
        self.client.set_assigner(self.dep_name, plan.profile_name)
        return self.client.assign_profile(
            self.dep_name, plan.profile_name, plan.serials)

    # Defined below as a standalone function to keep the existing client API
    # stable for existing users.


def define_profile(client: NanoDEPClient, dep_name: str, profile: dict) -> dict:
    """Apple Define Profile API through NanoDEP's authenticated proxy.

    This registers with Apple only when explicitly invoked with authorized
    credentials. No test invokes Apple. A response must be checked before
    assignment; request JSON alone is not registration.
    """
    from .identity import https_url
    https_url(profile.get("url", ""))
    if profile.get("is_mdm_removable") is False and profile.get("is_supervised") is not True:
        raise NanoDEPError("Prevent Unenrollment requires supervision")
    if profile.get("await_device_configured") is True:
        raise NanoDEPError("await_device_configured requires an implemented DeviceConfigured flow")
    response = client._proxy(dep_name, "POST", "profile", body=profile)
    if not response.get("profile_uuid"):
        raise NanoDEPError("Apple did not return a profile UUID")
    return response


class CurrentAssignmentLookup:
    """Real customer-specific NanoDEP Device Details lookup, no cached allow.

    Apple returns serial/profile assignment, not UDID. The UDID association is
    separately approved inventory supplied by the customer instance. Every
    lookup checks current assigned profile/status under that tenant's server.
    """
    def __init__(self, *, client, tenant_id, dep_name, profile_uuid, inventory_lookup):
        if type(tenant_id) is not int or tenant_id<1 or not dep_name or not profile_uuid or not callable(inventory_lookup):
            raise NanoDEPError("tenant/server/profile and approved inventory required")
        self.client,self.tenant_id,self.dep_name,self.profile_uuid=client,tenant_id,dep_name,profile_uuid
        self.inventory_lookup=inventory_lookup

    def __call__(self,tenant_id,serial):
        if tenant_id!=self.tenant_id or not isinstance(serial,str) or not 1<=len(serial)<=120:
            raise NanoDEPError("assignment lookup tenant/serial mismatch")
        response=self.client._proxy(self.dep_name,"POST","devices",body={"devices":[serial]})
        devices=response.get("devices")
        if not isinstance(devices,dict):raise NanoDEPError("malformed Apple Device Details response")
        device=devices.get(serial)
        if (not isinstance(device,dict) or device.get("serial_number")!=serial
                or device.get("profile_uuid")!=self.profile_uuid
                or device.get("profile_status") not in {"assigned","pushed"}
                or device.get("op_type")=="deleted" or device.get("released_by_replacement") is True):
            raise NanoDEPError("device is not currently assigned to expected server/profile")
        inventory=self.inventory_lookup(tenant_id,serial)
        if not isinstance(inventory,str) or not 8<=len(inventory)<=120:
            raise NanoDEPError("device has no approved UDID inventory")
        return {"assigned":True,"udid":inventory}

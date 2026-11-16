"""DNS edge runner: serve the reviewed filtering engine's DNS service
from a published generation directory.

The runner owns NO policy logic. It points the Stage-4-reviewed
DNSFilteringService at <root>/current/policy.json and
<root>/current/categories.json, and polls the publication manifest for
a new revision; on change it asks the service for its fail-safe
reload (full re-validation before swap, previous config kept on any
failure).

The runner never writes into the publication tree - it is a reader.
Per-tenant isolation is the publisher's job; the runner serves exactly
the root it is configured with.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time

_ENGINE_SRC = os.path.join(os.path.dirname(__file__), "..",
                           "filtering-engine", "src")
sys.path.insert(0, os.path.abspath(_ENGINE_SRC))

import dns_service  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import schedules as _schedules  # noqa: E402


class RunnerError(RuntimeError):
    pass


def generation_paths(root: str) -> tuple[str, str, int]:
    """Resolve (policy_path, categories_path, revision) for the current
    generation under root. Fails closed: anything wrong is an error,
    never a guess."""
    current = os.path.join(root, "current")
    manifest_path = os.path.join(current, "manifest.json")
    try:
        with open(manifest_path, encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise RunnerError(f"cannot read current manifest: {exc}")
    revision = manifest.get("revision")
    if not isinstance(revision, int) or revision < 0:
        raise RunnerError("current manifest has no valid revision")
    return (os.path.join(current, "policy.json"),
            os.path.join(current, "categories.json"), revision)


class DNSEdgeRunner:
    """Runs the DNS service against a generation root with watch reload."""

    def __init__(self, root: str, listen: str = "127.0.0.1:5353",
                 upstreams=None, watch_interval: float = 5.0,
                 block_mode: str = "sinkhole",
                 decision_reporter=None,
                 revocation_feed=None,
                 refresh_interval: float = 60.0):
        self.root = root
        self.watch_interval = watch_interval
        policy_path, categories_path, revision = generation_paths(root)
        host, _, port = listen.partition(":")
        config = dns_service.ServiceConfig(
            listen_host=host or "127.0.0.1",
            listen_port=int(port or 5353),
            block_mode=block_mode,
        )
        if upstreams:
            config.upstreams = list(upstreams)
        engine, _info = dns_service.load_validated_engine_set(
            policy_path, categories_path)
        # Filtering schedules (spec 8F): when the policy document
        # carries _schedules, the default engine becomes a
        # ScheduledPolicyEngine. Without schedules this returns the
        # reviewed set unchanged. A malformed schedule raises here,
        # which is the engine's fail-clearly startup behavior.
        engine = _schedules.wrap_default_engine(
            engine, policy_path, categories_path)
        self.service = dns_service.DNSFilteringService(
            engine, config,
            decision_logger=decision_reporter)
        self._policy_path = policy_path
        self._categories_path = categories_path
        self._revision = revision
        self._stop = threading.Event()
        self._watch_thread = None
        # Revocation distribution for the DoH front: the feed's shared
        # set is handed to doh_identity.authenticate_doh_request so a
        # revoked device credential is refused without a restart. The
        # loop starts with the service and stops with it.
        self._revocation_feed = revocation_feed
        self._refresh_interval = refresh_interval
        self._revocation_stop = None

    def check_for_update(self) -> bool:
        """Poll the manifest; reload if the revision advanced.
        Returns True when a reload was accepted."""
        try:
            _, _, revision = generation_paths(self.root)
        except RunnerError:
            return False
        if revision == self._revision:
            return False
        # Pre-validate the incoming generation's schedules BEFORE the
        # service swaps engines: a bad schedule rejects the reload while
        # the previous (scheduled) engine is still active. Without this,
        # a schedule error discovered after the swap would leave the
        # fresh engine running unscheduled - silently looser filtering.
        try:
            with open(self._policy_path, encoding="utf-8") as fh:
                incoming = json.load(fh)
            _schedules.validate_schedules(incoming.get("_schedules"))
        except (OSError, ValueError) as exc:
            return False
        ok = self.service.reload_from_paths(
            self._policy_path, self._categories_path, trigger="watch")
        if ok:
            # reload_from_paths rebuilt the set from files; re-apply the
            # schedule wrapper to the fresh set. Our generations are
            # single-policy, and the schedule list was just validated,
            # so this wrap cannot fail for our publication pipeline.
            self.service.engine = _schedules.wrap_default_engine(
                self.service.engine, self._policy_path,
                self._categories_path)
            self._revision = revision
        return ok

    def start(self) -> None:
        self.service.start()
        if self._revocation_feed is not None:
            self._revocation_stop = self._revocation_feed\
                .start_refresh_loop(interval=self._refresh_interval)
        self._watch_thread = threading.Thread(
            target=self._watch_loop, name="dns-edge-watch", daemon=True)
        self._watch_thread.start()

    def _watch_loop(self) -> None:
        while not self._stop.wait(self.watch_interval):
            self.check_for_update()

    def stop(self) -> None:
        self._stop.set()
        if self._revocation_stop is not None:
            self._revocation_stop.set()
        if self._watch_thread is not None:
            self._watch_thread.join(timeout=5)
        self.service.stop()

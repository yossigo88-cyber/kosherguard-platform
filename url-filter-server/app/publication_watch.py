"""Automatic publish -> rebuild -> serve chain for the URL Filter
dataset (B5). The control plane's Publisher atomically activates each
tenant generation (`current` symlink -> generations/<N>, verified
manifest); this watcher polls that per-tenant publication root,
rebuilds the dataset when the generation changes, and swaps it into
the serving DatasetRef - no human POST, no process restart.

Scope and isolation:
- ONE watcher serves ONE tenant's publication root; it never reads
  outside that root, so tenant datasets stay isolated by
  construction.
- The dataset carries the tenant's BASELINE policy only. Per-device
  assignments ride the per-device rule feed (the device-map /
  assigned-policy documents); they never enter this global dataset.
- Atomicity: build_dataset produces Bloom prefilter + shards +
  manifest as ONE object and the swap is a single reference
  assignment, so the served artifacts can never mix generations.
- Last good: a failed read/build leaves the serving dataset
  untouched (the failure is recorded for status, never served).
"""

import json
import os
import threading
import time
from pathlib import Path

from .dataset import Dataset, URLRule, build_dataset
from .server import DatasetRef


class WatchError(Exception):
    pass


def _norm(host) -> str:
    return str(host).lower().rstrip(".")


def rules_from_generation(generation_dir) -> list[URLRule]:
    """Derive the dataset rule set from one published generation.

    Mirrors the device filter-rules endpoint's semantics
    (control-plane main.py): blocklist -> block, allowlist overlays
    -> allow. Categories expand through the SAME generation's
    categories.json (domains -> [categories]): category_block marks
    each listed domain block, category_allow overlays allow.
    """
    generation_dir = Path(generation_dir)
    try:
        policy = json.loads((generation_dir / "policy.json")
                            .read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WatchError(f"unreadable policy document: {exc}") from exc
    if not isinstance(policy, dict) or "blocklist" not in policy:
        raise WatchError("policy document has no blocklist")
    categories_path = generation_dir / "categories.json"
    domains: dict = {}
    if categories_path.exists():
        try:
            cat_doc = json.loads(categories_path.read_bytes()
                                 .decode("utf-8"))
            domains = cat_doc.get("domains", {})
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WatchError(f"unreadable categories document: {exc}") \
                from exc
    rules: dict[str, URLRule] = {}
    for host in policy.get("blocklist", []):
        rules[_norm(host)] = URLRule(_norm(host), "block", "")
    for category in policy.get("category_block", []):
        for host, cats in domains.items():
            if category in cats:
                rules[_norm(host)] = URLRule(_norm(host), "block",
                                             str(category))
    # Allows overlay blocks, exactly like the device feed.
    for host in policy.get("allowlist", []):
        rules[_norm(host)] = URLRule(_norm(host), "allow", "")
    for category in policy.get("category_allow", []):
        for host, cats in domains.items():
            if category in cats:
                rules[_norm(host)] = URLRule(_norm(host), "allow",
                                             str(category))
    return list(rules.values())


class PublicationWatcher:
    """Polls one tenant's publication root and keeps the serving
    dataset on the current generation."""

    def __init__(self, tenant_root: str, ref: DatasetRef,
                 build=build_dataset, on_swap=None):
        self.tenant_root = tenant_root
        self.ref = ref
        self._build = build
        # Optional post-swap hook (new Dataset) -> None, invoked after
        # every successful swap. The deployment entrypoint uses it to
        # write the device PIR export and trigger PIR regeneration.
        self._on_swap = on_swap
        # Seed from the serving dataset: a restart with the same
        # current generation does not rebuild it.
        self._loaded_generation = ref.current.version
        self.last_built_at: float | None = None
        self.last_error: str | None = None
        self.hook_error: str | None = None
        self.build_count = 0
        self._lock = threading.Lock()

    def _current_generation_dir(self):
        return self.current_dir_static(self.tenant_root)

    @staticmethod
    def current_dir_static(tenant_root: str):
        """The generation directory `current` points at, or None when
        the symlink is missing. Raises WatchError when it escapes the
        tenant root."""
        link = os.path.join(tenant_root, "current")
        try:
            target = os.readlink(link)
        except OSError:
            return None
        path = target if os.path.isabs(target) else os.path.join(
            tenant_root, target)
        # Confinement: never follow the link outside the tenant root.
        root_real = os.path.realpath(tenant_root)
        if not os.path.realpath(path).startswith(root_real + os.sep):
            raise WatchError("current points outside the tenant root")
        return path

    def check_once(self) -> str:
        """One poll: 'updated', 'unchanged' or 'failed' (last good
        kept). Never raises for content problems."""
        with self._lock:
            try:
                generation_dir = self._current_generation_dir()
                if generation_dir is None:
                    return "unchanged"
                generation_dir = Path(generation_dir)
                manifest = json.loads(
                    (generation_dir / "manifest.json").read_bytes()
                    .decode("utf-8"))
                generation = int(manifest["generation"])
                # Same-generation identity: the generation directory
                # name is the identity; a manifest that disagrees is
                # corruption, not a new dataset.
                if os.path.basename(
                        os.path.realpath(generation_dir)) \
                        != str(generation):
                    raise WatchError("manifest generation mismatch")
                if generation == self._loaded_generation:
                    return "unchanged"
                rules = rules_from_generation(generation_dir)
                # Build FULLY before swap: a build failure (including
                # the device key-set refusal of unexpressible
                # ancestor exceptions) never disturbs the serving
                # dataset.
                dataset = self._build(
                    rules, version=generation,
                    provenance=f"publication:{self.tenant_root}")
                self.ref.swap(dataset)
                self._loaded_generation = generation
                self.last_built_at = time.time()
                self.build_count += 1
                self.last_error = None
                if self._on_swap is not None:
                    # The swap already happened: a hook failure (PIR
                    # regeneration) is recorded separately and never
                    # rolls back the served dataset.
                    try:
                        self._on_swap(dataset)
                        self.hook_error = None
                    except Exception as exc:
                        self.hook_error = str(exc)
                return "updated"
            except Exception as exc:
                self.last_error = str(exc)
                return "failed"

    def start_refresh_loop(self, interval: float = 60.0,
                           stop_event: threading.Event | None = None
                           ) -> threading.Event:
        """Poll now and then every interval seconds on a daemon
        thread; returns the stop event. A failed poll keeps the prior
        dataset, so a control-plane outage degrades to bounded
        staleness (status() exposes last_built_at/last_error)."""
        stop = stop_event or threading.Event()

        def loop():
            while not stop.is_set():
                self.check_once()
                stop.wait(interval)

        threading.Thread(target=loop, name="publication-watch",
                         daemon=True).start()
        return stop

    def status(self) -> dict:
        with self._lock:
            return {"generation": self._loaded_generation,
                    "last_built_at": self.last_built_at,
                    "build_count": self.build_count,
                    "last_error": self.last_error,
                    "hook_error": self.hook_error}

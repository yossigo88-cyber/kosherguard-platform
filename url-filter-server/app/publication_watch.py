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

    The input contract is the control plane's canonical published
    policy (publication_ops.export_policy_documents): top-level
    default_policy / allowlist / blocklist plus NESTED
    category_rules:{allow, block}, engine-validated before publish.
    Anything off that contract - unknown keys, wrong types, the
    API-shaped top-level category_block/category_allow, or
    default_policy other than 'allow' - is refused loudly: a policy
    misread as empty is a fail-open filter. default_policy 'block'
    can never be expressed as a membership dataset (the dataset's
    presence means block; there is no block-everything-else member),
    so it is refused rather than silently degraded.

    Categories expand through the SAME generation's categories.json
    (domains -> [categories]): category_rules.block marks each listed
    domain block, category_rules.allow overlays allow. Allows overlay
    blocks, exactly like the device feed. Filtering _schedules are
    engine-time metadata; a membership dataset cannot express time
    windows, so a scheduled block applies for the whole publication
    (over-blocks, never under-blocks).
    """
    generation_dir = Path(generation_dir)
    try:
        policy = json.loads((generation_dir / "policy.json")
                            .read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WatchError(f"unreadable policy document: {exc}") from exc
    if not isinstance(policy, dict):
        raise WatchError("policy document is not an object")
    allowed_keys = {"default_policy", "allowlist", "blocklist",
                    "category_rules", "_schedules", "_meta"}
    unknown = sorted(set(policy) - allowed_keys)
    if unknown:
        raise WatchError(f"policy document has unknown keys: {unknown}")
    if policy.get("default_policy") != "allow":
        raise WatchError(
            "default_policy {!r} is not expressible as a URL Filter "
            "membership dataset (presence = block only); refusing "
            "rather than degrading it into an allow-default blocklist"
            .format(policy.get("default_policy")))

    def str_list(value, field):
        if not isinstance(value, list) or not all(
                isinstance(v, str) for v in value):
            raise WatchError(f"policy document {field} must be a list "
                             "of strings")
        return value

    blocklist = str_list(policy.get("blocklist", []), "blocklist")
    allowlist = str_list(policy.get("allowlist", []), "allowlist")
    category_rules = policy.get("category_rules", {})
    if not isinstance(category_rules, dict) or \
            set(category_rules) - {"allow", "block"}:
        raise WatchError("policy document category_rules must be an "
                         "object with only allow/block lists")
    category_block = str_list(category_rules.get("block", []),
                              "category_rules.block")
    category_allow = str_list(category_rules.get("allow", []),
                              "category_rules.allow")
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
        if not isinstance(domains, dict):
            raise WatchError("categories document domains is not an "
                             "object")
    _refuse_per_device_divergence(generation_dir)
    rules: dict[str, URLRule] = {}
    for host in blocklist:
        rules[_norm(host)] = URLRule(_norm(host), "block", "")
    for category in category_block:
        for host, cats in domains.items():
            if category in cats:
                rules[_norm(host)] = URLRule(_norm(host), "block",
                                             str(category))
    # Allows overlay blocks, exactly like the device feed.
    for host in allowlist:
        rules[_norm(host)] = URLRule(_norm(host), "allow", "")
    for category in category_allow:
        for host, cats in domains.items():
            if category in cats:
                rules[_norm(host)] = URLRule(_norm(host), "allow",
                                             str(category))
    return list(rules.values())


def _refuse_per_device_divergence(generation_dir) -> None:
    """The published generation can carry PER-DEVICE policy: the
    device map binds devices to assigned policy documents and
    exceptions.json carries per-device exception overlays. One
    membership dataset (Bloom/prefilter + one PIR processed database)
    expresses exactly one policy. Serving the tenant default while a
    generation assigns different policies or exceptions per device
    would enforce the WRONG policy on those devices - so any
    divergence is refused loudly (last good keeps serving) instead of
    merged. A generation where every device is assigned the default
    policy is not divergent and serves normally."""
    generation_dir = Path(generation_dir)
    device_map_path = generation_dir / "device-map.json"
    if device_map_path.exists():
        try:
            device_map = json.loads(device_map_path.read_bytes()
                                    .decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WatchError(f"unreadable device map: {exc}") from exc
        default_pid = device_map.get("default_policy_id")
        devices = device_map.get("devices", {})
        if not isinstance(devices, dict):
            raise WatchError("device map devices is not an object")
        divergent = [dev for dev, entry in devices.items()
                     if isinstance(entry, dict)
                     and entry.get("policy_id") != default_pid]
        if divergent:
            raise WatchError(
                "generation assigns non-default policies to devices "
                f"{sorted(divergent)}; a single membership dataset "
                "cannot express per-device policy, refusing to merge "
                "them into one global dataset")
    exceptions_path = generation_dir / "exceptions.json"
    if exceptions_path.exists():
        try:
            overlay = json.loads(exceptions_path.read_bytes()
                                 .decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WatchError(f"unreadable exceptions overlay: {exc}")                 from exc
        if overlay:
            raise WatchError(
                "generation carries per-device exception overlays for "
                f"devices {sorted(overlay)}; a single membership "
                "dataset cannot express per-device exceptions, "
                "refusing to merge them into one global dataset")


class PublicationWatcher:
    """Polls one tenant's publication root and keeps the serving
    dataset on the current generation."""

    def __init__(self, tenant_root: str, ref: DatasetRef,
                 build=build_dataset, on_swap=None):
        self.tenant_root = tenant_root
        self.ref = ref
        self._build = build
        # Optional staged-activation hook (new Dataset) -> None,
        # invoked BEFORE every swap: it must finish preparing the
        # generation's other artifacts (device PIR export +
        # regeneration). A hook failure aborts the activation: last
        # good keeps serving and the poll retries.
        self._on_swap = on_swap
        # Seed from the serving dataset: a restart with the same
        # current generation does not rebuild it.
        self._loaded_generation = ref.current.version
        # Latest generation the publication root ADVERTISES, tracked on
        # every poll even when loading it fails: the difference between
        # published and loaded is the staleness a status consumer
        # (app/dashboard) needs, not just an operator log line.
        self._published_generation: int | None = None
        self.last_built_at: float | None = None
        self.last_error: str | None = None
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
                self._published_generation = generation
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
                # Staged activation: the activation hook (device PIR
                # export + regeneration command) runs BEFORE the
                # serving swap. If it fails, the generation is NOT
                # marked loaded - the last good dataset keeps serving
                # (functional policy preserved) and the next poll
                # retries the same generation. Bloom/prefilter and the
                # PIR data therefore never serve different committed
                # generations: the new PIR data exists before the new
                # Bloom/prefilter becomes visible, and a failed
                # activation changes nothing.
                if self._on_swap is not None:
                    self._on_swap(dataset)
                self.ref.swap(dataset)
                self._loaded_generation = generation
                self.last_built_at = time.time()
                self.build_count += 1
                self.last_error = None
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
                    "published_generation": self._published_generation,
                    "behind": (self._published_generation is not None
                               and self._published_generation
                               != self._loaded_generation),
                    "last_built_at": self.last_built_at,
                    "build_count": self.build_count,
                    "last_error": self.last_error}

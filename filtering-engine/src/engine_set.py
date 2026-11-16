"""Multi-policy engine set for the KosherGuard filtering engine (Stage 11C).

One running DNS service chooses the correct policy for each query using
the published device/network binding map. The unit of activation is one
complete, immutable ENGINE SET:

- default:    the default PolicyEngine (every unmatched client).
- per_policy: policy ID -> PolicyEngine, one validated instance per
              published policy (the default policy's ID included).
- bindings:   canonical network-binding key ("ipv4:<dotted-quad>" or
              "ipv6:<canonical /64>") -> validated BindingRecord.
- credentials: RESERVED for a future authenticated-identity stage. It is
              always empty in Stage 11C: there is no token issuance, no
              token storage, no token authentication, and no
              credential-based request routing, so no query can ever be
              attributed to a credential.

Validation is all-or-nothing: load_validated_engine_set() reads and
validates every document and verifies every manifest hash BEFORE
returning, and rejects the entire generation on any defect. Nothing is
ever silently skipped: a valid default policy must not hide an invalid
assigned policy. A query therefore can never observe a partially loaded
or mixed engine configuration.

Policy resolution order for each DNS query (strict; plan section 7.2):

1. Authenticated credential - RESERVED extension point only; Stage 11C
   has no authenticated channel, credentials is empty, and
   policy_for_client accepts no credential input, so this step can
   never fire and never pretends a credential was authenticated.
2. Exact IPv4 network binding of the observed client address.
3. IPv6 /64 network/group binding of the observed client address.
4. The default policy.

A network binding is a ROUTING HINT, never authenticated device
identity: a shared IPv4 address or IPv6 /64 applies the same policy to
every client observed behind it, and nothing here claims one physical
device was identified. The mandatory tighten-only rule (plan 4.5) is
enforced by the dashboard at assignment/publication time; the engine
only enforces published documents.

Multi-document generation format (produced by the Stage 11D publisher;
the engine is ready to load it today):

    generations/<revision>/
        policies/<policy_id>.json   one validated policy document each
        categories.json             the shared category database
        devices.json                default policy pointer + binding map
        manifest.json               revision/generation identity and the
                                    SHA-256 of EVERY file above

devices.json contract (strict schema; unknown keys are rejected):

    {
      "default_policy_id": 3,                      required, positive int
      "bindings": {                                required, may be empty
        "ipv4:192.168.1.50":    {"device_id": 1, "policy_id": 5,
                                 "class": "network_binding"},
        "ipv6:2001:db8:1:2::/64": {"device_id": 2, "policy_id": 7,
                                 "class": "network_binding"}
      },
      "credentials": {},                           required, MUST be empty
      "_meta": {"source": "...", "revision": 12}   optional; a revision
                                                   here must match the
                                                   manifest's revision
    }

The schema is exactly these four keys (Stage 11 plan 7.1); any other
key is rejected as unknown. There is no device inventory: the device
registry lives in the dashboard and request processing never touches
it, so each binding carries its device reference inline (device_id).
A binding with missing, null, or malformed device metadata rejects the
whole generation; whether a well-formed device_id exists in the
dashboard registry is NOT verifiable from this generation format, and
no registry lookup is performed; enforcing registry existence is a
requirement on the future Stage 11D publisher, which does not exist yet.
The policy set is exactly the default policy plus the policies
referenced by bindings (the future publisher is required to emit exactly
that set, plan 7.3): a manifest listing a policy document nothing
references, or a reference to a policy with no document, is an
inconsistent generation and is rejected fail-closed - silently
accepting it could mask a binding lost from devices.json.

The manifest must also cover every file on disk: an unmanifested file
inside the generation directory (a stray policies/*.json, a second
top-level document, anything) is unverified content in a verified
generation and rejects it, just like a missing or corrupt listed file.

Every binding key is the canonical string produced by the Stage 11A
canonicalizer; any other spelling is malformed and rejected. The engine
canonicalizes every observed source address with the SAME canonicalizer
before lookup, so lookups are plain string dict lookups with no parsing
ambiguity - and no per-query database, file, or network access for
policy resolution. Normal DNS forwarding of allowed queries to upstream
resolvers is unchanged and is not what this claim covers.

Path contract (the command line is unchanged): for a multi-document
generation, --policy names the GENERATION DIRECTORY (typically the
publisher's atomically switched "current" symlink) and --categories
must name that same generation's categories.json. A legacy generation
(policy.json + categories.json + an optional legacy manifest) keeps
loading exactly as before: its single policy becomes the default and
every client is treated as unregistered. A directory without
devices.json is not a valid multi-document generation, and a legacy
file set WITH a devices.json sibling is an ambiguous mixed layout:
both are rejected loudly rather than guessed at.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from address_canonicalization import (
    BindingValidationError,
    canonical_source_key,
    canonicalize_ipv4,
    canonicalize_ipv6_prefix,
)
from category_db import CategoryDB, CategoryDBError
from generation_io import (
    _read_manifest_fd,
    _safe_open_manifest,
    _sha256,
    _validate_generation_manifest,
    load_json_strict,
    read_fd_bytes,
    safe_open_generation_file,
    validate_multidoc_manifest,
)
from policy_engine import PolicyConfigError, PolicyEngine


class EngineSetError(PolicyConfigError):
    """A multi-document generation, devices.json, or engine-set input is
    invalid; the ENTIRE generation is rejected (never partially loaded).
    The message names the exact offending file or field. Subclasses
    PolicyConfigError: a defective engine-set generation IS a policy
    configuration error, so existing reload/startup paths that catch
    PolicyConfigError handle it unchanged."""


@dataclass(frozen=True)
class BindingRecord:
    """One validated network binding: which registry entry and policy a
    canonical binding key routes to. identity_class is ALWAYS
    "network_binding" in Stage 11C - a routing hint, never an
    authenticated identity (credential kinds are reserved for a future
    stage and cannot appear here)."""

    device_id: int
    policy_id: int
    identity_class: str = "network_binding"


class EngineSet:
    """One complete immutable multi-policy engine configuration.

    Instances are built by load_validated_engine_set() (fully validated
    from files) or directly in tests. All mappings are exposed read-only
    (MappingProxyType): nothing about an active engine set can be
    mutated while the service is running. The DNS service holds ONE
    reference to the active set and swaps it wholesale on reload; each
    query reads that reference exactly once and resolves its policy
    from that single snapshot.
    """

    __slots__ = ("_default", "_per_policy", "_bindings", "_credentials",
                 "_default_policy_id")

    def __init__(self, default, per_policy=None, bindings=None,
                 credentials=None, default_policy_id=None) -> None:
        if not isinstance(default, PolicyEngine):
            raise EngineSetError(
                f"default must be a PolicyEngine, got {type(default).__name__}")
        per_policy = dict(per_policy or {})
        bindings = dict(bindings or {})
        credentials = dict(credentials or {})
        for policy_id, engine in per_policy.items():
            if isinstance(policy_id, bool) or not isinstance(policy_id, int) or policy_id < 1:
                raise EngineSetError(
                    f"per_policy key must be a positive integer policy ID, "
                    f"got {policy_id!r}")
            if not isinstance(engine, PolicyEngine):
                raise EngineSetError(
                    f"per_policy[{policy_id}] must be a PolicyEngine, got "
                    f"{type(engine).__name__}")
        for key, binding in bindings.items():
            if not isinstance(key, str):
                raise EngineSetError(
                    f"binding key must be a canonical string, got {key!r}")
            if not isinstance(binding, BindingRecord):
                raise EngineSetError(
                    f"bindings[{key!r}] must be a BindingRecord, got "
                    f"{type(binding).__name__}")
        if credentials:
            raise EngineSetError(
                "credentials is a reserved extension point and must be "
                "empty in Stage 11C (no token issuance, storage, or "
                "authentication exists)")
        if default_policy_id is not None:
            if (isinstance(default_policy_id, bool)
                    or not isinstance(default_policy_id, int)
                    or default_policy_id < 1):
                raise EngineSetError(
                    f"default_policy_id must be a positive integer, got "
                    f"{default_policy_id!r}")
            if default_policy_id not in per_policy:
                raise EngineSetError(
                    f"default_policy_id {default_policy_id} has no engine in "
                    "per_policy")
        self._default = default
        self._per_policy = MappingProxyType(per_policy)
        self._bindings = MappingProxyType(bindings)
        self._credentials = MappingProxyType(credentials)
        self._default_policy_id = default_policy_id

    @property
    def default(self):
        """The default PolicyEngine: every client with no binding match."""
        return self._default

    @property
    def per_policy(self):
        """Read-only policy ID -> PolicyEngine map (default ID included)."""
        return self._per_policy

    @property
    def bindings(self):
        """Read-only canonical binding key -> BindingRecord map."""
        return self._bindings

    @property
    def credentials(self):
        """Reserved credential map; always empty in Stage 11C."""
        return self._credentials

    @property
    def default_policy_id(self):
        """The default policy's ID, or None for a legacy single-policy set."""
        return self._default_policy_id

    def policy_for_client(self, client_addr=None):
        """Resolve the PolicyEngine for one observed client address.

        client_addr is whatever the socket layer produced: an AF_INET
        (host, port) tuple, an AF_INET6 (host, port, flowinfo, scope_id)
        tuple, a bare address string, or None for callers with no client
        address (the historical behavior). Resolution order is exactly
        the documented one (credential - reserved and never firing -
        then IPv4 exact binding, then IPv6 /64 group binding, then
        default). An invalid, unsupported, or absent address, and any
        canonicalization failure, safely selects the default policy;
        this method never raises and never crashes request processing.
        """
        # Step 1 (reserved): authenticated credential resolution. There
        # is no authenticated channel in Stage 11C: credentials is
        # always empty and no credential is accepted as input, so no
        # query can ever be attributed to a credential here.
        key = binding_key_for_client(client_addr)
        if key is not None:
            binding = self._bindings.get(key)
            if binding is not None:
                engine = self._per_policy.get(binding.policy_id)
                if engine is not None:  # always true after validation
                    return engine
        return self._default


def binding_key_for_client(client_addr):
    """The canonical binding-lookup key for an observed client, or None.

    Unpacks the socket address tuple (host is element 0 for both AF_INET
    and AF_INET6) and delegates ALL canonicalization to the shared
    Stage 11A canonicalizer (canonical_source_key): IPv4 maps to its
    dotted-quad key, IPv6 to its /64 network key, IPv4-mapped IPv6 forms
    to the IPv4 key, and IPv6 scope/zone information is stripped (an
    interface marker, never a different network identity). Returns None
    for absent, malformed, or unsupported input - the caller then serves
    the default policy. Never raises.
    """
    if client_addr is None:
        return None
    host = client_addr
    if isinstance(client_addr, (tuple, list)):
        # A real socket address is (host, port[, flowinfo, scope_id]);
        # anything shorter is malformed input, not a client identity.
        if len(client_addr) < 2:
            return None
        host = client_addr[0]
    if not isinstance(host, str):
        return None
    try:
        return canonical_source_key(host)
    except (ValueError, TypeError, AttributeError):
        return None


# -- devices.json validation ----------------------------------------------

# The strict devices.json schema is exactly the four documented keys
# (Stage 11 plan 7.1). FORMAT LIMITATION, stated explicitly: the engine
# has no device inventory to cross-check against (the device registry
# lives in the dashboard, and request processing never touches it), so
# it can only validate the SHAPE of each binding's inline device
# metadata - a missing, null, or malformed device_id rejects the whole
# generation - it CANNOT verify that a positive device_id actually
# exists in the dashboard registry, and no registry lookup is performed
# at load time or per query. Enforcing registry existence is a
# requirement on the future Stage 11D publisher (plan 7.1: it must
# export only associations of active devices with an active
# assignment); no publisher implements that today.
_DEVICES_KEYS = {"default_policy_id", "bindings", "credentials", "_meta"}
_BINDING_KEYS = {"device_id", "policy_id", "class"}
_BINDING_KEY_RE = re.compile(r"^(ipv4|ipv6):(.+)$")
_DECIMAL_RE = re.compile(r"[0-9]+")


def _require_positive_int(value, field):
    """A real positive integer ID; booleans are NOT integers here."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise EngineSetError(
            f"devices.json: {field} must be a positive integer, got {value!r}")
    return value


def _validate_binding_key(key):
    """A binding key must be the CANONICAL string the Stage 11A
    canonicalizer produces: 'ipv4:<dotted-quad>' or 'ipv6:<canonical
    /64>'. Any other spelling (non-canonical addresses, unknown kinds)
    is malformed published data and rejects the generation - keys are
    never silently re-canonicalized, because a non-canonical published
    key means the publisher and the engine disagree."""
    if not isinstance(key, str):
        raise EngineSetError(f"devices.json: binding key must be a string, "
                             f"got {key!r}")
    match = _BINDING_KEY_RE.fullmatch(key)
    if not match:
        raise EngineSetError(
            f"devices.json: binding key {key!r} is not in 'ipv4:<address>' "
            "or 'ipv6:</64-prefix>' form")
    kind, value = match.group(1), match.group(2)
    try:
        canonical = (canonicalize_ipv4(value) if kind == "ipv4"
                     else canonicalize_ipv6_prefix(value))
    except BindingValidationError as exc:
        raise EngineSetError(f"devices.json: binding key {key!r} is not a "
                             f"valid canonical binding: {exc}")
    if canonical != value:
        raise EngineSetError(
            f"devices.json: binding key {key!r} is not in canonical form "
            f"(canonical form is '{kind}:{canonical}'); only canonical keys "
            "produced by the shared canonicalizer may appear in a generation")
    return key


def _validate_devices_json(doc, manifest_revision):
    """Validate devices.json; return (default_policy_id, bindings,
    device_count). Raises EngineSetError on the first defect."""
    if not isinstance(doc, dict):
        raise EngineSetError(
            f"devices.json: must be a JSON object, got "
            f"{type(doc).__name__}")
    unknown = set(doc) - _DEVICES_KEYS
    if unknown:
        raise EngineSetError(
            f"devices.json: unknown keys {sorted(unknown)} "
            f"(valid keys: {sorted(_DEVICES_KEYS)})")

    default_policy_id = _require_positive_int(
        doc.get("default_policy_id"), "default_policy_id")

    bindings_doc = doc.get("bindings")
    if not isinstance(bindings_doc, dict):
        raise EngineSetError("devices.json: bindings is missing or not an "
                             "object")

    credentials = doc.get("credentials")
    if not isinstance(credentials, dict):
        raise EngineSetError("devices.json: credentials is missing or not an "
                             "object")
    if credentials:
        raise EngineSetError(
            "devices.json: credentials is a reserved extension point and "
            "MUST be empty in Stage 11C (no token issuance, storage, or "
            "authentication exists)")

    meta = doc.get("_meta")
    if meta is not None:
        if not isinstance(meta, dict):
            raise EngineSetError("devices.json: _meta must be an object")
        meta_revision = meta.get("revision")
        if meta_revision is not None:
            if (isinstance(meta_revision, bool)
                    or not isinstance(meta_revision, int) or meta_revision < 0):
                raise EngineSetError(
                    "devices.json: _meta.revision must be a non-negative "
                    "integer")
            if meta_revision != manifest_revision:
                raise EngineSetError(
                    f"devices.json: _meta.revision {meta_revision} does not "
                    f"match the manifest revision {manifest_revision} "
                    "(mixed-generation documents)")

    bindings = {}
    for key, value in bindings_doc.items():
        _validate_binding_key(key)
        if not isinstance(value, dict):
            raise EngineSetError(
                f"devices.json: bindings[{key!r}] must be an object")
        unknown_fields = set(value) - _BINDING_KEYS
        if unknown_fields:
            raise EngineSetError(
                f"devices.json: bindings[{key!r}] has unknown fields "
                f"{sorted(unknown_fields)} (valid fields: "
                f"{sorted(_BINDING_KEYS)})")
        if value.get("class") != "network_binding":
            raise EngineSetError(
                f"devices.json: bindings[{key!r}].class must be "
                f"'network_binding', got {value.get('class')!r} (credential "
                "classes are reserved for a future authenticated-identity "
                "stage)")
        if "device_id" not in value:
            raise EngineSetError(
                f"devices.json: bindings[{key!r}] carries no device metadata "
                "(device_id is missing); a binding must reference a device")
        if "policy_id" not in value:
            raise EngineSetError(
                f"devices.json: bindings[{key!r}] references no policy "
                "(policy_id is missing)")
        device_id = _require_positive_int(
            value.get("device_id"), f"bindings[{key!r}].device_id")
        policy_id = _require_positive_int(
            value.get("policy_id"), f"bindings[{key!r}].policy_id")
        bindings[key] = BindingRecord(device_id=device_id, policy_id=policy_id)

    # No device inventory exists in this format; the count derives from
    # the bindings themselves (distinct referenced devices).
    device_count = len({b.device_id for b in bindings.values()})
    return default_policy_id, bindings, device_count


_POLICY_PATH_RE = re.compile(r"^policies/([0-9]+)\.json$")


def load_validated_engine(policy_path, categories_path):
    """Build a COMPLETE replacement engine from configuration files
    (the legacy Stage 10 single-policy layout).

    Both files are read, parsed, validated with the engine's own
    validators, and - when a generation manifest.json sits next to the
    policy file (the dashboard's Stage 10 publication layout) - their
    content hashes are verified against it, so a corrupted or
    mixed-generation file set is rejected rather than loaded. Returns
    (engine, info); raises OSError, PolicyConfigError, CategoryDBError,
    or ValueError on any problem. Nothing is mutated anywhere: the
    caller decides whether to activate the result.

    This function lives next to the multi-policy loader so all
    generation loading is in one module; dns_service re-exports it for
    the existing callers and tests.
    """
    policy_path = str(policy_path)
    categories_path = str(categories_path)
    policy_bytes = Path(policy_path).read_bytes()
    categories_bytes = Path(categories_path).read_bytes()
    info = {
        "policy_path": policy_path,
        "categories_path": categories_path,
        "policy_sha256": _sha256(policy_bytes),
        "categories_sha256": _sha256(categories_bytes),
    }
    manifest_path = Path(policy_path).parent / "manifest.json"
    manifest_fd = _safe_open_manifest(manifest_path)
    if manifest_fd is not None:
        # Verified regular on the opened descriptor inside
        # _safe_open_manifest; the bytes come from that SAME
        # descriptor. A present-but-invalid manifest is NEVER ignored;
        # only a genuinely absent path (None) loads unverified.
        manifest = _read_manifest_fd(manifest_fd, manifest_path)
        _validate_generation_manifest(
            manifest, policy_path, categories_path,
            info["policy_sha256"], info["categories_sha256"])
        info["generation"] = manifest["generation"]
        info["manifest_revision"] = manifest["revision"]
    try:
        policy = json.loads(policy_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PolicyConfigError(f"{policy_path}: invalid JSON: {exc}")
    try:
        categories_raw = json.loads(categories_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CategoryDBError(f"{categories_path}: invalid JSON: {exc}")
    if not isinstance(categories_raw, dict) or not isinstance(categories_raw.get("domains"), dict):
        raise CategoryDBError(
            f"{categories_path}: expected an object with a 'domains' object")
    engine = PolicyEngine(
        policy, CategoryDB(categories_raw["domains"], meta=categories_raw.get("_meta", {})))
    return engine, info


# -- the loader -------------------------------------------------------------

def _load_multidoc_engine_set(generation_dir, categories_path):
    """Load and validate one complete multi-document generation.

    generation_dir is the generation directory path as given (typically
    through the publisher's "current" symlink); categories_path is the
    --categories argument, which must name THIS generation's
    categories.json. Returns (EngineSet, info); raises EngineSetError,
    PolicyConfigError, CategoryDBError, or OSError on any defect. Every
    listed file's bytes are read through a descriptor-based safe open
    and verified against the manifest BEFORE any document is used.
    """
    given_dir = str(generation_dir)
    real_dir = os.path.realpath(given_dir)
    if not os.path.isdir(real_dir):
        raise EngineSetError(
            f"{given_dir}: not a generation directory; refusing to load")
    dir_name = os.path.basename(real_dir)

    categories_path = str(categories_path)
    expected_categories = os.path.join(real_dir, "categories.json")
    # Compare the DIRECTORY fully resolved but the final component as
    # given: a symlinked categories.json inside this directory must flow
    # through to the descriptor-based safe open (O_NOFOLLOW) and be
    # rejected there as an unsafe file, not misreported as a
    # mixed-generation file set.
    given_categories = os.path.join(
        os.path.realpath(os.path.dirname(categories_path) or "."),
        os.path.basename(categories_path))
    if given_categories != expected_categories:
        raise EngineSetError(
            f"--categories {categories_path} does not name this generation's "
            f"categories.json ({expected_categories}); a generation's "
            "documents must come from ONE directory (mixed-generation "
            "file sets are rejected)")

    # The multi-document format REQUIRES a manifest: without one there
    # is no verified file set, and unverified multi-policy loading is
    # never silently attempted.
    manifest_path = os.path.join(real_dir, "manifest.json")
    fd = safe_open_generation_file(manifest_path, "generation manifest")
    manifest = load_json_strict(read_fd_bytes(
        fd, f"generation manifest {manifest_path}"),
        f"generation manifest {manifest_path}")
    files = validate_multidoc_manifest(manifest, dir_name, manifest_path)

    # Classify the manifest entries BEFORE opening anything: exactly
    # the known generation files, so an unknown or malformed entry is
    # reported as what it is (a bad manifest), not as a hash mismatch.
    policy_entries = {}  # policy_id -> relative path
    for rel_path in files:
        if rel_path in ("categories.json", "devices.json"):
            continue
        match = _POLICY_PATH_RE.fullmatch(rel_path)
        if not match:
            raise EngineSetError(
                f"generation manifest {manifest_path}: files entry "
                f"{rel_path!r} is not a known generation file "
                "(categories.json, devices.json, or policies/<id>.json)")
        digits = match.group(1)
        policy_id = int(digits)
        if policy_id < 1 or str(policy_id) != digits:
            raise EngineSetError(
                f"generation manifest {manifest_path}: files entry "
                f"{rel_path!r} does not name a canonical positive policy ID")
        policy_entries[policy_id] = rel_path
    for required in ("categories.json", "devices.json"):
        if required not in files:
            raise EngineSetError(
                f"generation manifest {manifest_path}: required file "
                f"{required!r} is not listed; refusing to load")

    # The manifest covers EVERY file in the generation (plan 7.1): a
    # file on disk that the manifest does not list is unverified content
    # in a verified generation and rejects it, exactly like a missing
    # file. (manifest.json itself is the verifier, never listed.)
    on_disk = set()
    for entry in os.listdir(real_dir):
        if entry == "manifest.json":
            continue
        full = os.path.join(real_dir, entry)
        if entry == "policies" and os.path.isdir(full):
            for sub in os.listdir(full):
                on_disk.add(f"policies/{sub}")
        else:
            on_disk.add(entry)
    unlisted = sorted(on_disk - set(files))
    if unlisted:
        raise EngineSetError(
            f"generation directory {real_dir}: file(s) {unlisted} exist "
            "on disk but are not listed in the generation manifest "
            "(unverified content in a verified generation); refusing to "
            "load")

    # Read and hash-verify EVERY listed file before using any of them.
    contents = {}
    for rel_path, expected_hash in files.items():
        fd = safe_open_generation_file(os.path.join(real_dir, rel_path),
                                       f"generation file {rel_path!r}")
        data = read_fd_bytes(fd, f"generation file {rel_path!r}")
        actual = _sha256(data)
        if actual != expected_hash:
            raise EngineSetError(
                f"{os.path.join(real_dir, rel_path)} does not match its "
                "generation manifest (corrupted or mixed-generation file); "
                "refusing to load")
        contents[rel_path] = data

    # devices.json defines the required policy set.
    devices_doc = load_json_strict(contents["devices.json"], "devices.json")
    default_policy_id, bindings, device_count = _validate_devices_json(
        devices_doc, manifest["revision"])
    referenced = {default_policy_id} | {b.policy_id for b in bindings.values()}
    listed = set(policy_entries)
    missing = sorted(referenced - listed)
    if missing:
        raise EngineSetError(
            f"devices.json references policy ID(s) {missing} with no "
            "policy document in the manifest (a missing default or assigned "
            "policy rejects the whole generation)")
    extra = sorted(listed - referenced)
    if extra:
        raise EngineSetError(
            f"generation manifest {manifest_path}: policy document(s) "
            f"{extra} are listed but referenced by neither the default "
            "policy pointer nor any binding (the manifest must list exactly "
            "the referenced policy set)")

    # Categories: one shared validated database for every policy engine.
    categories_raw = load_json_strict(contents["categories.json"],
                                      "categories.json")
    if not isinstance(categories_raw, dict) or not isinstance(
            categories_raw.get("domains"), dict):
        raise CategoryDBError(
            "categories.json: expected an object with a 'domains' object")
    try:
        category_db = CategoryDB(categories_raw["domains"],
                                 meta=categories_raw.get("_meta", {}))
    except CategoryDBError as exc:
        raise CategoryDBError(f"categories.json: {exc}")

    # Every policy document is independently validated by the engine's
    # own validator; one invalid policy rejects the ENTIRE generation.
    per_policy = {}
    for policy_id in sorted(referenced):
        rel_path = policy_entries[policy_id]
        document = load_json_strict(contents[rel_path],
                                    f"policies/{policy_id}.json")
        try:
            per_policy[policy_id] = PolicyEngine(document, category_db)
        except PolicyConfigError as exc:
            raise EngineSetError(
                f"policies/{policy_id}.json: invalid policy: {exc}")

    engine_set = EngineSet(
        default=per_policy[default_policy_id],
        per_policy=per_policy,
        bindings=bindings,
        credentials={},
        default_policy_id=default_policy_id,
    )
    info = {
        "format": "multi-policy",
        "policy_path": given_dir,
        "categories_path": categories_path,
        "policy_sha256": files[policy_entries[default_policy_id]],
        "categories_sha256": files["categories.json"],
        "devices_sha256": files["devices.json"],
        "generation": manifest["generation"],
        "manifest_revision": manifest["revision"],
        "default_policy_id": default_policy_id,
        "policy_count": len(per_policy),
        "binding_count": len(bindings),
        "device_count": device_count,
    }
    return engine_set, info


def load_validated_engine_set(policy_path, categories_path):
    """Build a COMPLETE, fully validated engine set from configuration.

    Two layouts are supported, distinguished by what --policy names:

    - A DIRECTORY: a multi-document generation (the Stage 11 format
      above). The manifest is required; every file is hash-verified;
      every policy, binding, ID, and reference is validated; the whole
      generation is rejected on any defect.
    - A FILE (policy.json): the legacy Stage 10 layout, loaded exactly
      as before via dns_service.load_validated_engine (including its
      optional legacy manifest verification). The single policy becomes
      the engine set's default and every client is treated as
      unregistered. A devices.json next to the policy file means an
      ambiguous half-migrated layout and is REJECTED: a valid default
      policy must never silently hide a multi-policy generation.

    Returns (EngineSet, info). Raises EngineSetError, PolicyConfigError,
    CategoryDBError, OSError, or ValueError on any problem. Nothing is
    mutated anywhere: the caller decides whether to activate the result.
    """
    policy_path = str(policy_path)
    categories_path = str(categories_path)
    if os.path.isdir(policy_path):
        return _load_multidoc_engine_set(policy_path, categories_path)

    devices_candidate = os.path.join(
        os.path.dirname(os.path.realpath(policy_path)), "devices.json")
    if os.path.lexists(devices_candidate):
        raise EngineSetError(
            f"{devices_candidate} exists next to {policy_path}: this looks "
            "like a multi-policy generation, but those are loaded by naming "
            "the generation DIRECTORY as --policy (a top-level policy.json "
            "plus devices.json is an ambiguous mixed layout); refusing to "
            "load")

    # Legacy single-policy generation: the existing loader, unchanged.
    engine, info = load_validated_engine(policy_path, categories_path)
    info = dict(info)
    info["format"] = "single-policy"
    return EngineSet(default=engine), info

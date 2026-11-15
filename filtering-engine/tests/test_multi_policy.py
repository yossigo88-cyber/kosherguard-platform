"""Tests for Stage 11C multi-policy engine support.

Covers the immutable engine set (load_validated_engine_set), the
multi-document generation format and its manifest, client-address
threading and policy resolution, backward compatibility with Stage 10
legacy generations, atomic reload with engine sets, concurrency, and
the privacy requirements (no client addresses in logs or status).

Every test runs real components: real files on disk, the real loader,
real DNS packets, and (for the service tests) real UDP/TCP sockets
against in-test fake upstream resolvers. No internet access is needed.
Tests prove BEHAVIOR (real DNS answers, real decisions), never source
text. No sleeps are used for synchronization: tests poll observable
state with a deadline or gate on threading Events.
"""

import hashlib
import inspect
import io
import json
import os
import signal
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dnslib import A, AAAA, EDNS0, QTYPE, RCODE, DNSRecord, RR

import dns_service
from category_db import CategoryDB
from dns_service import DNSFilteringService, DecisionLogger, ServiceConfig
from engine_set import (
    BindingRecord,
    EngineSet,
    EngineSetError,
    binding_key_for_client,
    load_validated_engine_set,
)
from policy_engine import PolicyConfigError, PolicyEngine, normalize_domain

UPSTREAM_A = "93.184.216.34"

# The default policy allows everything; the per-binding policies each
# block something distinct so the policy that answered is identifiable
# from the DNS answer alone.
DEFAULT_POLICY = {
    "default_policy": "allow", "allowlist": [], "blocklist": [],
    "category_rules": {"allow": [], "block": []},
}
STRICT_POLICY = {
    "default_policy": "allow", "allowlist": [],
    "blocklist": ["blocked-a.test"],
    "category_rules": {"allow": [], "block": []},
}
V6_POLICY = {
    "default_policy": "allow", "allowlist": [],
    "blocklist": ["blocked-v6.test"],
    "category_rules": {"allow": [], "block": []},
}
CAT_POLICY = {
    "default_policy": "allow", "allowlist": [], "blocklist": [],
    "category_rules": {"allow": [], "block": ["social"]},
}
CATEGORIES = {"_meta": {"dataset": "test"},
              "domains": {"social.example": ["social"]}}

POLICIES = {1: DEFAULT_POLICY, 5: STRICT_POLICY, 7: V6_POLICY, 9: CAT_POLICY}
BINDINGS = {
    "ipv4:192.168.1.50": {"device_id": 1, "policy_id": 5,
                          "class": "network_binding"},
    "ipv4:192.168.1.60": {"device_id": 3, "policy_id": 9,
                          "class": "network_binding"},
    "ipv6:2001:db8:1:2::/64": {"device_id": 2, "policy_id": 7,
                               "class": "network_binding"},
    "ipv6:fe80::/64": {"device_id": 2, "policy_id": 7,
                       "class": "network_binding"},
}
def build_generation(gen_dir, policies=None, default_policy_id=1,
                     bindings=None, categories=None,
                     credentials=None, write_manifest=True,
                     devices_overrides=None, manifest_overrides=None,
                     extra_files=(), omit_files=()):
    """Write a complete multi-document generation to disk, with correct
    hashes, and return its Path. Generation directories must be named by
    their revision (the manifest ties generation == str(revision) ==
    directory name).

    With policies=None the generation lists exactly the policy documents
    referenced by default_policy_id and the bindings, as the publisher
    contract requires. Passing an explicit policies dict writes exactly
    those documents (used by rejection tests that need an unreferenced
    or invalid document listed)."""
    gen = Path(gen_dir)
    revision = int(gen.name)
    # The publisher writes each generation into a FRESH directory; an
    # in-place rewrite that leaves stale documents behind is exactly
    # what the loader's unmanifested-file check rejects.
    shutil.rmtree(gen, ignore_errors=True)
    if policies is None:
        referenced = {default_policy_id}
        for binding in (bindings if bindings is not None else BINDINGS).values():
            referenced.add(binding["policy_id"])
        # Unknown referenced IDs are simply not written: the loader's
        # missing-policy rejection is what those generations exercise.
        policies = {policy_id: POLICIES[policy_id]
                    for policy_id in sorted(referenced)
                    if policy_id in POLICIES}
    (gen / "policies").mkdir(parents=True, exist_ok=True)
    files = {}
    for policy_id, document in sorted(policies.items()):
        rel = f"policies/{policy_id}.json"
        data = json.dumps(document).encode()
        (gen / rel).write_bytes(data)
        files[rel] = hashlib.sha256(data).hexdigest()
    cat_data = json.dumps(
        categories if categories is not None else CATEGORIES).encode()
    (gen / "categories.json").write_bytes(cat_data)
    files["categories.json"] = hashlib.sha256(cat_data).hexdigest()
    devices_doc = {
        "default_policy_id": default_policy_id,
        "bindings": bindings if bindings is not None else BINDINGS,
        "credentials": credentials if credentials is not None else {},
        "_meta": {"source": "test", "revision": revision},
    }
    if devices_overrides:
        devices_doc.update(devices_overrides)
    dev_data = json.dumps(devices_doc).encode()
    (gen / "devices.json").write_bytes(dev_data)
    files["devices.json"] = hashlib.sha256(dev_data).hexdigest()
    for rel, content in extra_files:
        (gen / rel).write_bytes(content if isinstance(content, bytes)
                               else json.dumps(content).encode())
    for rel in omit_files:
        os.remove(gen / rel)
        files.pop(rel, None)
    if write_manifest:
        manifest = {"revision": revision, "generation": str(revision),
                    "files": files}
        for key, value in (manifest_overrides or {}).items():
            if value is None:
                manifest.pop(key, None)
            else:
                manifest[key] = value
        (gen / "manifest.json").write_text(json.dumps(manifest),
                                           encoding="utf-8")
    return gen


def load(gen):
    """Load a generation directory the way the service does."""
    gen = Path(gen)
    return load_validated_engine_set(str(gen), str(gen / "categories.json"))


def corrupt(path):
    """Flip content without updating the manifest hash."""
    path = Path(path)
    path.write_bytes(path.read_bytes() + b" ")


class FakeUpstream(threading.Thread):
    """Answers every A query with UPSTREAM_A; AAAA with a fixed address."""

    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.start()

    def run(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(4096)
            except OSError:
                return
            try:
                query = DNSRecord.parse(data)
            except Exception:
                continue
            reply = query.reply()
            if query.q.qtype == QTYPE.AAAA:
                reply.add_answer(RR(str(query.q.qname), QTYPE.AAAA,
                                    rdata=AAAA("2001:db8::55"), ttl=60))
            else:
                reply.add_answer(RR(str(query.q.qname), QTYPE.A,
                                    rdata=A(UPSTREAM_A), ttl=60))
            try:
                self.sock.sendto(reply.pack(), addr)
            except OSError:
                return


class BigUpstream(threading.Thread):
    """Answers with 40 A records, large enough to force UDP truncation
    for a client advertising a small EDNS0 payload size."""

    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.start()

    def run(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(4096)
            except OSError:
                return
            try:
                query = DNSRecord.parse(data)
            except Exception:
                continue
            reply = query.reply()
            for i in range(40):
                reply.add_answer(RR(str(query.q.qname), QTYPE.A,
                                    rdata=A(f"93.184.216.{i}"), ttl=60))
            try:
                self.sock.sendto(reply.pack(), addr)
            except OSError:
                return


@pytest.fixture
def upstream():
    up = FakeUpstream()
    yield up
    up.sock.close()


def make_service(tmp_path, upstream, bindings=None, gen_name="1"):
    """A real running service loaded from a real multi-document
    generation on disk. The real local client address 127.0.0.1 is
    bound to STRICT_POLICY so real-socket queries exercise the binding
    path end to end."""
    # The generation must reference every policy document it lists, so
    # the service fixture binds all four policies: the full BINDINGS set
    # plus the real local client address.
    service_bindings = dict(BINDINGS)
    service_bindings["ipv4:127.0.0.1"] = {"device_id": 1, "policy_id": 5,
                                          "class": "network_binding"}
    service_bindings.update(bindings or {})
    gen = build_generation(tmp_path / gen_name, bindings=service_bindings)
    engine_set, info = load(gen)
    config = ServiceConfig(listen_host="127.0.0.1", listen_port=0,
                           upstreams=[("127.0.0.1", upstream.port)])
    svc = DNSFilteringService(engine_set, config)
    svc.active_config = info
    svc.start()
    return svc, gen


@pytest.fixture
def service(tmp_path, upstream):
    svc, gen = make_service(tmp_path, upstream)
    yield svc, gen
    svc.stop()


def query_udp(port, domain, qtype="A", edns_payload=None):
    q = DNSRecord.question(domain, qtype)
    if edns_payload is not None:
        q.add_ar(EDNS0(udp_len=edns_payload))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    try:
        sock.sendto(q.pack(), ("127.0.0.1", port))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    return DNSRecord.parse(data)


def query_tcp(port, domain):
    q = DNSRecord.question(domain)
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        payload = q.pack()
        sock.sendall(struct.pack(">H", len(payload)) + payload)
        header = sock.recv(2)
        length = struct.unpack(">H", header)[0]
        data = b""
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                raise ConnectionError("short read")
            data += chunk
    finally:
        sock.close()
    return DNSRecord.parse(data)


def answer_a(record):
    for rr in record.rr:
        if rr.rtype == QTYPE.A:
            return str(rr.rdata)
    return None


def wait_for(predicate, timeout=10.0, interval=0.02, description="condition"):
    """Bounded polling on an observable result; never a bare sleep."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    raise AssertionError(f"timed out waiting for {description}")


def handle(service, domain, client_addr=None):
    """Run a real DNS packet through the real decision path with an
    explicit client address (exactly what the socket workers pass)."""
    packet = DNSRecord.question(domain).pack()
    response = service.handle_packet(packet, client_addr=client_addr)
    return DNSRecord.parse(response)


# ======================================================================
# Engine-set loading
# ======================================================================

def test_load_default_only_multi_policy_set(tmp_path):
    """A valid generation with only a default policy and no bindings
    loads; every client gets the default policy."""
    gen = build_generation(tmp_path / "1", policies={1: DEFAULT_POLICY},
                           bindings={})
    engine_set, info = load(gen)
    assert isinstance(engine_set, EngineSet)
    assert engine_set.default_policy_id == 1
    assert engine_set.per_policy.keys() == {1}
    assert engine_set.bindings == {}
    assert engine_set.credentials == {}
    for addr in (None, ("192.0.2.9", 5353), ("2001:db8:9:9::1", 53, 0, 0)):
        assert engine_set.policy_for_client(addr) is engine_set.default
    assert info["format"] == "multi-policy"
    assert info["default_policy_id"] == 1
    assert info["policy_count"] == 1
    assert info["binding_count"] == 0
    assert info["generation"] == "1"
    assert info["manifest_revision"] == 1


def test_load_multiple_policy_set(tmp_path):
    """A valid generation with several policies and bindings loads;
    the full binding map routes to the right engines."""
    engine_set, info = load(build_generation(tmp_path / "1"))
    assert engine_set.per_policy.keys() == {1, 5, 7, 9}
    assert len(engine_set.bindings) == 4
    assert info["policy_count"] == 4
    assert info["binding_count"] == 4
    assert info["device_count"] == 3
    assert engine_set.policy_for_client(("192.168.1.50", 1)) is \
        engine_set.per_policy[5]
    assert engine_set.policy_for_client(("192.168.1.60", 1)) is \
        engine_set.per_policy[9]


def test_every_policy_independently_validated(tmp_path):
    """Each policy document passes through the engine's own validator:
    per-policy rules are enforced independently, and validator
    normalization (e.g. uppercase entries) applies to each document."""
    policies = dict(POLICIES)
    policies[11] = {"default_policy": "allow", "allowlist": [],
                    "blocklist": ["Shouty-Example.TEST"],
                    "category_rules": {"allow": [], "block": []}}
    bindings = dict(BINDINGS)
    bindings["ipv4:192.168.1.70"] = {"device_id": 1, "policy_id": 11,
                                     "class": "network_binding"}
    engine_set, _ = load(build_generation(tmp_path / "1", policies=policies,
                                          bindings=bindings))
    assert engine_set.per_policy[5].decide("blocked-a.test").action == "block"
    assert engine_set.per_policy[7].decide("blocked-a.test").action == "allow"
    assert engine_set.per_policy[7].decide("blocked-v6.test").action == "block"
    assert engine_set.per_policy[9].decide("social.example").action == "block"
    # Validator normalization applied to the 4th policy's document.
    assert engine_set.per_policy[11].decide("shouty-example.test").action == "block"


def test_missing_default_policy_rejected(tmp_path):
    """devices.json pointing at a policy with no document rejects the
    entire generation."""
    gen = build_generation(tmp_path / "1", policies={5: STRICT_POLICY},
                           default_policy_id=1,
                           bindings={"ipv4:192.168.1.50": {
                               "device_id": 1, "policy_id": 5,
                               "class": "network_binding"}})
    with pytest.raises(EngineSetError, match="policy"):
        load(gen)


def test_invalid_policy_among_valid_rejects_entire_set(tmp_path):
    """One semantically invalid policy (correctly hashed and published)
    rejects the WHOLE generation: a valid default must never hide an
    invalid assigned policy."""
    policies = dict(POLICIES)
    policies[7] = {"default_policy": "explode"}
    gen = build_generation(tmp_path / "1", policies=policies)
    with pytest.raises(EngineSetError, match="policies/7"):
        load(gen)


def test_invalid_categories_rejects_entire_set(tmp_path):
    gen = build_generation(tmp_path / "1",
                           categories={"domains": {"bad_domain": []}})
    with pytest.raises(Exception, match="categories"):
        load(gen)


def test_duplicate_policy_ids_rejected(tmp_path):
    """A manifest smuggling two entries for one policy file (duplicate
    JSON key) is rejected at parse time."""
    gen = build_generation(tmp_path / "1")
    manifest_path = gen / "manifest.json"
    text = manifest_path.read_text()
    entry = f'"policies/5.json": "{hashlib.sha256(json.dumps(STRICT_POLICY).encode()).hexdigest()}"'
    text = text.replace(entry, entry + ",\n    " + entry)
    manifest_path.write_text(text)
    with pytest.raises(PolicyConfigError, match="duplicate key"):
        load(gen)


@pytest.mark.parametrize("field,value", [
    ("default_policy_id", True),
    ("policy_id", False),
    ("device_id", True),
])
def test_boolean_ids_rejected(tmp_path, field, value):
    """Booleans masquerading as integer IDs are rejected everywhere."""
    if field == "default_policy_id":
        overrides = {"default_policy_id": value}
    else:
        overrides = {"bindings": {"ipv4:192.168.1.50": {
            "device_id": 1, "policy_id": 5, "class": "network_binding",
            field: value}}}
    gen = build_generation(tmp_path / "1", devices_overrides=overrides)
    with pytest.raises(EngineSetError, match="positive integer"):
        load(gen)


@pytest.mark.parametrize("bad_id", [0, -3, "2", 2.5, None])
def test_invalid_device_ids_rejected(tmp_path, bad_id):
    gen = build_generation(tmp_path / "1", devices_overrides={"bindings": {
        "ipv4:192.168.1.50": {"device_id": bad_id, "policy_id": 5,
                              "class": "network_binding"}}})
    with pytest.raises(EngineSetError, match="positive integer"):
        load(gen)


def test_binding_nonexistent_policy_rejected(tmp_path):
    gen = build_generation(tmp_path / "1", devices_overrides={"bindings": {
        "ipv4:192.168.1.50": {"device_id": 1, "policy_id": 99,
                              "class": "network_binding"}}})
    with pytest.raises(EngineSetError, match="99"):
        load(gen)


@pytest.mark.parametrize("bad_binding", [
    {},
    {"policy_id": 5, "class": "network_binding"},
    {"device_id": None, "policy_id": 5, "class": "network_binding"},
])
def test_binding_nonexistent_device_metadata_rejected(tmp_path,
                                                      bad_binding):
    """The format has no device inventory (the registry lives in the
    dashboard; the engine never touches it), so each binding must CARRY
    its device metadata inline: a binding with a missing or null
    device_id references nonexistent device metadata and rejects the
    whole generation. FORMAT LIMITATION (explicit): this proves only
    that inline metadata is present and well-formed - whether a
    positive device_id exists in the dashboard registry is NOT
    verifiable from the generation format, and no registry lookup is
    performed; the publisher enforces registry existence upstream."""
    gen = build_generation(tmp_path / "1", devices_overrides={"bindings": {
        "ipv4:192.168.1.50": bad_binding}})
    with pytest.raises(EngineSetError, match="device"):
        load(gen)


def test_unmanifested_file_on_disk_rejected(tmp_path):
    """The manifest covers EVERY file in the generation: a policy file
    written to disk without a manifest entry is unverified content and
    rejects the generation, exactly like a missing or corrupt listed
    file."""
    gen = build_generation(tmp_path / "1")
    (gen / "policies" / "8.json").write_text(json.dumps(STRICT_POLICY))
    with pytest.raises(EngineSetError, match="not listed in the generation"):
        load(gen)
    gen2 = build_generation(tmp_path / "2")
    (gen2 / "extra.json").write_text("{}")
    with pytest.raises(EngineSetError, match="not listed in the generation"):
        load(gen2)


@pytest.mark.parametrize("bad_class", ["credential", "identity", "token_hash",
                                       "network", "NETWORK_BINDING", ""])
def test_unsupported_binding_class_rejected(tmp_path, bad_class):
    gen = build_generation(tmp_path / "1", devices_overrides={"bindings": {
        "ipv4:192.168.1.50": {"device_id": 1, "policy_id": 5,
                              "class": bad_class}}})
    with pytest.raises(EngineSetError, match="network_binding"):
        load(gen)


def test_duplicate_binding_keys_rejected(tmp_path):
    """Two JSON entries for one binding key are rejected at parse time;
    two spellings of one network are rejected as non-canonical."""
    gen = build_generation(tmp_path / "1")
    devices_path = gen / "devices.json"
    doc = json.loads(devices_path.read_text())
    entry = '"ipv4:192.168.1.50": ' + json.dumps(doc["bindings"]["ipv4:192.168.1.50"])
    text = devices_path.read_text().replace(entry, entry + ", " + entry)
    devices_path.write_text(text)
    build_manifest_only(gen)
    with pytest.raises(PolicyConfigError, match="duplicate key"):
        load(gen)
    # A second spelling of the same /64 is not canonical: rejected, so
    # two spellings of one network can never coexist.
    gen2 = build_generation(tmp_path / "2", devices_overrides={"bindings": {
        "ipv6:2001:DB8:1:2::/64": {"device_id": 2, "policy_id": 7,
                                   "class": "network_binding"}}})
    with pytest.raises(EngineSetError, match="canonical"):
        load(gen2)


def build_manifest_only(gen):
    """Recompute just the manifest of an existing generation directory."""
    gen = Path(gen)
    files = {}
    for rel in sorted(os.listdir(gen)):
        if rel in ("manifest.json", "policies") or not (gen / rel).is_file():
            continue
        files[rel] = hashlib.sha256((gen / rel).read_bytes()).hexdigest()
    for name in sorted(os.listdir(gen / "policies")):
        rel = f"policies/{name}"
        files[rel] = hashlib.sha256((gen / rel).read_bytes()).hexdigest()
    revision = int(gen.name)
    (gen / "manifest.json").write_text(json.dumps(
        {"revision": revision, "generation": str(revision), "files": files}))


@pytest.mark.parametrize("overrides,match", [
    ({"bindings": [1, 2]}, "bindings"),
    ({"unknown_key": 1}, "unknown keys"),
    ({"default_policy_id": None}, "default_policy_id"),
    ({"credentials": None}, "credentials"),
    ({"devices": [1]}, "devices"),
    ({"_meta": "x"}, "_meta"),
])
def test_malformed_devices_json_rejected(tmp_path, overrides, match):
    if overrides.get("default_policy_id") is None and "default_policy_id" in overrides:
        # Remove the required key entirely.
        gen = build_generation(tmp_path / "1")
        doc = json.loads((gen / "devices.json").read_text())
        doc.pop("default_policy_id")
        (gen / "devices.json").write_text(json.dumps(doc))
        build_manifest_only(gen)
    else:
        gen = build_generation(tmp_path / "1", devices_overrides=overrides)
    with pytest.raises(EngineSetError, match=match):
        load(gen)


def test_devices_json_not_an_object_rejected(tmp_path):
    gen = build_generation(tmp_path / "1")
    (gen / "devices.json").write_text("[1, 2, 3]")
    build_manifest_only(gen)
    with pytest.raises(EngineSetError, match="JSON object"):
        load(gen)


def test_nonempty_credentials_rejected(tmp_path):
    """The reserved credentials collection must be EMPTY in Stage 11C:
    no token issuance, storage, or authentication exists."""
    gen = build_generation(tmp_path / "1",
                           credentials={"tok123": {"device_id": 1}})
    with pytest.raises(EngineSetError, match="reserved"):
        load(gen)


@pytest.mark.parametrize("omitted", ["policies/5.json", "devices.json",
                                     "categories.json"])
def test_missing_required_files_rejected(tmp_path, omitted):
    """A generation missing any manifest-listed file is rejected (the
    stale manifest still lists the deleted file)."""
    gen = build_generation(tmp_path / "1")
    os.remove(gen / omitted)
    with pytest.raises(PolicyConfigError, match="cannot open safely"):
        load(gen)


def test_multidoc_generation_requires_manifest(tmp_path):
    """A multi-document generation WITHOUT a manifest is rejected:
    unverified multi-policy loading is never silently attempted."""
    gen = build_generation(tmp_path / "1")
    os.remove(gen / "manifest.json")
    with pytest.raises(PolicyConfigError, match="cannot open safely"):
        load(gen)


@pytest.mark.parametrize("extra_entry,match", [
    ("extra.txt", "not a known generation file"),
    ("policies/abc.json", "not a known generation file"),
    ("policies/05.json", "canonical positive policy ID"),
    ("manifest.json", "not a known generation file"),
])
def test_extra_or_malformed_manifest_entries_rejected(tmp_path,
                                                      extra_entry, match):
    gen = build_generation(tmp_path / "1")
    manifest = json.loads((gen / "manifest.json").read_text())
    manifest["files"][extra_entry] = "0" * 64
    (gen / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(EngineSetError, match=match):
        load(gen)


def test_manifest_missing_devices_entry_rejected(tmp_path):
    """devices.json exists on disk but is not listed in the manifest:
    the required set is incomplete."""
    gen = build_generation(tmp_path / "1")
    manifest = json.loads((gen / "manifest.json").read_text())
    del manifest["files"]["devices.json"]
    (gen / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(EngineSetError, match="devices.json"):
        load(gen)


def test_every_file_hash_is_checked(tmp_path):
    """Positive control: a correct manifest loads; swapping two listed
    hashes is detected (each file is verified against ITS OWN entry)."""
    gen = build_generation(tmp_path / "1")
    engine_set, info = load(gen)
    assert info["devices_sha256"]
    manifest = json.loads((gen / "manifest.json").read_text())
    files = manifest["files"]
    files["devices.json"], files["categories.json"] = \
        files["categories.json"], files["devices.json"]
    (gen / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(EngineSetError, match="does not match"):
        load(gen)


@pytest.mark.parametrize("target", ["policies/5.json", "policies/1.json"])
def test_corrupting_one_policy_file_rejected(tmp_path, target):
    """Corrupting ANY one policy file (default or assigned) rejects the
    entire generation."""
    gen = build_generation(tmp_path / "1")
    corrupt(gen / target)
    with pytest.raises(EngineSetError, match="does not match"):
        load(gen)


def test_corrupting_categories_rejected(tmp_path):
    gen = build_generation(tmp_path / "1")
    corrupt(gen / "categories.json")
    with pytest.raises(EngineSetError, match="does not match"):
        load(gen)


def test_corrupting_devices_rejected(tmp_path):
    gen = build_generation(tmp_path / "1")
    corrupt(gen / "devices.json")
    with pytest.raises(EngineSetError, match="does not match"):
        load(gen)


def test_revision_generation_mismatch_rejected(tmp_path):
    gen = build_generation(tmp_path / "1", manifest_overrides={"generation": "2"})
    with pytest.raises(PolicyConfigError, match="inconsistent"):
        load(gen)
    gen2 = build_generation(tmp_path / "2", manifest_overrides={"revision": 1,
                                                                "generation": "1"})
    with pytest.raises(PolicyConfigError, match="does not match its directory"):
        load(gen2)
    gen3 = build_generation(tmp_path / "3", manifest_overrides={"revision": True})
    with pytest.raises(PolicyConfigError, match="revision"):
        load(gen3)


@pytest.mark.parametrize("bad_key", [
    "../evil.json", "policies/../../etc/passwd", "/etc/passwd",
    "policies//3.json", "policies/./3.json", "policies/../devices.json",
    "a\\b.json", "policies/3.json ", ".hidden/x.json", "policies/",
])
def test_unsafe_manifest_paths_rejected(tmp_path, bad_key):
    gen = build_generation(tmp_path / "1")
    manifest = json.loads((gen / "manifest.json").read_text())
    manifest["files"][bad_key] = "0" * 64
    (gen / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(PolicyConfigError):
        load(gen)


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="POSIX symlinks")
@pytest.mark.parametrize("target", ["policies/5.json", "devices.json",
                                    "categories.json"])
def test_symlinked_generation_files_rejected(tmp_path, target):
    """A symlinked generation file is rejected even when it points at a
    file with the right content (O_NOFOLLOW on the opened descriptor)."""
    gen = build_generation(tmp_path / "1")
    real = tmp_path / "real-copy"  # outside the generation directory
    real.write_bytes((gen / target).read_bytes())
    os.remove(gen / target)
    os.symlink(real, gen / target)
    assert (gen / target).is_file()  # a path-based check would pass
    with pytest.raises(PolicyConfigError, match="cannot open safely"):
        load(gen)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFOs")
def test_non_regular_files_rejected(tmp_path):
    gen = build_generation(tmp_path / "1")
    os.remove(gen / "policies" / "5.json")
    os.mkfifo(gen / "policies" / "5.json")
    with pytest.raises(PolicyConfigError, match="cannot open safely|not a regular"):
        load(gen)
    gen2 = build_generation(tmp_path / "2")
    os.remove(gen2 / "devices.json")
    (gen2 / "devices.json").mkdir()
    with pytest.raises(PolicyConfigError, match="not a regular"):
        load(gen2)


def test_legacy_stage10_generation_still_loads(tmp_path):
    """A legacy Stage 10 generation (policy.json + categories.json,
    optional legacy manifest, no devices.json) loads exactly as before:
    the single policy becomes the default and every client is
    unregistered."""
    gen = tmp_path / "1"
    gen.mkdir()
    (gen / "policy.json").write_text(json.dumps(STRICT_POLICY))
    (gen / "categories.json").write_text(json.dumps(CATEGORIES))
    policy_path, categories_path = gen / "policy.json", gen / "categories.json"
    engine_set, info = load_validated_engine_set(str(policy_path),
                                                 str(categories_path))
    assert info["format"] == "single-policy"
    assert engine_set.default_policy_id is None
    assert engine_set.bindings == {}
    for addr in (None, ("192.168.1.50", 1), ("2001:db8:1:2::1", 1, 0, 0)):
        assert engine_set.policy_for_client(addr) is engine_set.default
    # The legacy policy is really enforced (behavior, not structure).
    assert engine_set.policy_for_client(
        ("192.168.1.50", 1)).decide("blocked-a.test").action == "block"
    # With a valid legacy manifest, identity is reported as before.
    manifest = {"revision": 1, "generation": "1",
                "policy_sha256": hashlib.sha256(
                    (gen / "policy.json").read_bytes()).hexdigest(),
                "categories_sha256": hashlib.sha256(
                    (gen / "categories.json").read_bytes()).hexdigest()}
    (gen / "manifest.json").write_text(json.dumps(manifest))
    engine_set2, info2 = load_validated_engine_set(str(policy_path),
                                                   str(categories_path))
    assert info2["generation"] == "1"
    assert info2["manifest_revision"] == 1


# ======================================================================
# Address resolution
# ======================================================================

@pytest.fixture
def engine_set(tmp_path):
    resolved, _ = load(build_generation(tmp_path / "1"))
    return resolved


def test_ipv4_exact_binding_selects_policy(engine_set):
    for addr in (("192.168.1.50", 5353), "192.168.1.50",
                 ("192.168.1.50", 0)):
        engine = engine_set.policy_for_client(addr)
        assert engine is engine_set.per_policy[5]
        # Behavior: the selected policy actually blocks its domain.
        assert engine.decide("blocked-a.test").action == "block"


def test_ipv4_source_without_binding_selects_default(engine_set):
    engine = engine_set.policy_for_client(("192.168.1.51", 5353))
    assert engine is engine_set.default
    assert engine.decide("blocked-a.test").action == "allow"


def test_ipv6_within_registered_64_selects_group_policy(engine_set):
    engine = engine_set.policy_for_client(("2001:db8:1:2::1234", 53, 0, 0))
    assert engine is engine_set.per_policy[7]
    assert engine.decide("blocked-v6.test").action == "block"


def test_ipv6_outside_every_registered_64_selects_default(engine_set):
    engine = engine_set.policy_for_client(("2001:db8:1:3::1234", 53, 0, 0))
    assert engine is engine_set.default


def test_ipv6_canonical_spellings_resolve(engine_set):
    """Full, uppercase, and compressed spellings of one address all map
    to the same canonical /64 binding."""
    for spelling in ("2001:0DB8:0001:0002:0000:0000:0000:1234",
                     "2001:DB8:1:2::1234",
                     "2001:db8:1:2:0:0:0:1234"):
        assert engine_set.policy_for_client(spelling) is \
            engine_set.per_policy[7]


def test_ipv6_scope_identifiers_never_change_identity(engine_set):
    """A zone/scope marks the receiving interface, not a different
    network identity: every scoped spelling of an address resolves to
    the same binding as the bare address, and a scope can never pull a
    query into a DIFFERENT binding."""
    bare = engine_set.policy_for_client("fe80::1234")
    assert bare is engine_set.per_policy[7]  # fe80::/64 binding
    assert engine_set.policy_for_client("fe80::1234%eth0") is bare
    assert engine_set.policy_for_client("fe80::1234%eth1") is bare
    assert engine_set.policy_for_client(("fe80::1234", 53, 0, 2)) is bare
    # Same scope trick against the other registered prefix.
    assert engine_set.policy_for_client("2001:db8:1:2::5%eth0") is \
        engine_set.per_policy[7]


def test_invalid_client_address_safely_selects_default(engine_set):
    for garbage in ("not-an-ip", "999.999.1.1", "", ("999.1.1.1", 53),
                    12345, object(), (), ("192.168.1.50",), b"bytes"):
        assert engine_set.policy_for_client(garbage) is engine_set.default


def test_missing_client_address_selects_default(engine_set):
    assert engine_set.policy_for_client(None) is engine_set.default
    assert engine_set.policy_for_client() is engine_set.default


def test_shared_binding_applies_same_policy_to_many_clients(engine_set):
    """One shared address/prefix is a GROUP: two clients behind it get
    the very same policy engine (never a per-device claim)."""
    a = engine_set.policy_for_client(("192.168.1.50", 1111))
    b = engine_set.policy_for_client(("192.168.1.50", 2222))
    assert a is b
    c = engine_set.policy_for_client(("2001:db8:1:2::aa", 1, 0, 0))
    d = engine_set.policy_for_client(("2001:db8:1:2::bb", 2, 0, 0))
    assert c is d


def test_binding_is_never_authenticated_identity(engine_set):
    """No network binding is ever reported as authenticated identity:
    the records carry identity_class 'network_binding', the credentials
    collection is empty, and the resolver accepts no credential input."""
    for binding in engine_set.bindings.values():
        assert binding.identity_class == "network_binding"
    assert dict(engine_set.credentials) == {}
    assert "credential" not in inspect.signature(
        engine_set.policy_for_client).parameters
    assert "token" not in inspect.signature(
        engine_set.policy_for_client).parameters


def test_ipv4_mapped_source_matches_plain_ipv4_binding(engine_set):
    """A dual-stack socket reporting an IPv4 client in mapped form
    ('::ffff:192.168.1.50') resolves to the SAME IPv4 binding - the
    identity cannot be dodged or lost through the mapped spelling."""
    assert engine_set.policy_for_client(("::ffff:192.168.1.50", 53, 0, 0)) is \
        engine_set.per_policy[5]


def test_binding_key_for_client_socket_forms(engine_set):
    """The key builder understands real Python socket address tuples."""
    assert binding_key_for_client(("192.168.1.50", 5353)) == "ipv4:192.168.1.50"
    assert binding_key_for_client(("2001:db8:1:2::9", 53, 0, 0)) == \
        "ipv6:2001:db8:1:2::/64"
    assert binding_key_for_client(None) is None
    assert binding_key_for_client(("garbage", 1)) is None


# ======================================================================
# DNS behavior (real service, real sockets and packets)
# ======================================================================

def test_two_clients_different_bindings_get_different_answers(service):
    """End to end: the real UDP/TCP client (127.0.0.1, bound to the
    strict policy) gets the blocked answer; a client with no binding
    gets the default policy's forwarded answer for the same domain."""
    svc, _gen = service
    port = svc.config.listen_port
    # Real socket path (UDP and TCP): 127.0.0.1 is bound to policy 5.
    assert answer_a(query_udp(port, "blocked-a.test")) == "0.0.0.0"
    assert answer_a(query_tcp(port, "blocked-a.test")) == "0.0.0.0"
    # An unbound source for the same domain: default policy forwards.
    forwarded = handle(svc, "blocked-a.test", ("192.0.2.9", 5353))
    assert answer_a(forwarded) == UPSTREAM_A


def test_policy_block_allow_matrix_per_client(service):
    """A domain blocked under one client's policy is NOT blocked under
    another's, and vice versa - the matrix is fully crossed."""
    svc, _gen = service
    strict_client = ("192.168.1.50", 1111)   # policy 5: blocks blocked-a
    v6_client = ("2001:db8:1:2::7", 53, 0, 0)  # policy 7: blocks blocked-v6
    assert answer_a(handle(svc, "blocked-a.test", strict_client)) == "0.0.0.0"
    assert answer_a(handle(svc, "blocked-a.test", v6_client)) == UPSTREAM_A
    assert answer_a(handle(svc, "blocked-v6.test", v6_client)) == "0.0.0.0"
    assert answer_a(handle(svc, "blocked-v6.test", strict_client)) == UPSTREAM_A


def test_default_policy_behavior_for_unknown_clients(service):
    svc, _gen = service
    unknown = ("192.0.2.200", 9999)
    assert answer_a(handle(svc, "blocked-a.test", unknown)) == UPSTREAM_A
    assert answer_a(handle(svc, "blocked-v6.test", unknown)) == UPSTREAM_A
    assert answer_a(handle(svc, "social.example", unknown)) == UPSTREAM_A
    assert answer_a(handle(svc, "anything.test", unknown)) == UPSTREAM_A


def test_udp_behavior_remains_intact(service):
    svc, _gen = service
    port = svc.config.listen_port
    assert answer_a(query_udp(port, "other.test")) == UPSTREAM_A
    assert answer_a(query_udp(port, "blocked-a.test")) == "0.0.0.0"
    # Blocked AAAA sinks to :: under the bound strict policy.
    reply = query_udp(port, "blocked-a.test", qtype="AAAA")
    assert str(reply.rr[0].rdata) == "::"


def test_tcp_behavior_remains_intact(service):
    svc, _gen = service
    port = svc.config.listen_port
    assert answer_a(query_tcp(port, "other.test")) == UPSTREAM_A
    assert answer_a(query_tcp(port, "blocked-a.test")) == "0.0.0.0"


def test_upstream_fallback_remains_intact(tmp_path, upstream):
    """A dead first upstream still fails over to the next one for a
    binding-routed client."""
    dead = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dead.bind(("127.0.0.1", 0))
    dead_port = dead.getsockname()[1]
    dead.close()  # the port now refuses: the attempt fails fast
    gen = build_generation(tmp_path / "1", bindings={"ipv4:127.0.0.1": {
        "device_id": 1, "policy_id": 5, "class": "network_binding"}})
    engine_set, info = load(gen)
    config = ServiceConfig(listen_host="127.0.0.1", listen_port=0,
                           upstreams=[("127.0.0.1", dead_port),
                                      ("127.0.0.1", upstream.port)],
                           upstream_timeout=1.0)
    svc = DNSFilteringService(engine_set, config)
    svc.active_config = info
    svc.start()
    try:
        assert answer_a(query_udp(svc.config.listen_port, "other.test")) == \
            UPSTREAM_A
    finally:
        svc.stop()


def test_edns0_and_truncation_remain_intact(tmp_path):
    """EDNS0 size negotiation and TC truncation apply unchanged for a
    binding-routed client."""
    big = BigUpstream()
    try:
        gen = build_generation(tmp_path / "1", bindings={"ipv4:127.0.0.1": {
            "device_id": 1, "policy_id": 5, "class": "network_binding"}})
        engine_set, info = load(gen)
        config = ServiceConfig(listen_host="127.0.0.1", listen_port=0,
                               upstreams=[("127.0.0.1", big.port)])
        svc = DNSFilteringService(engine_set, config)
        svc.active_config = info
        svc.start()
        try:
            # Advertise a 512-byte payload: the large upstream answer
            # must come back truncated with TC, within the limit.
            reply = query_udp(svc.config.listen_port, "other.test",
                              edns_payload=512)
            assert reply.header.tc == 1
            assert len(reply.pack()) <= 512
            # Without an OPT record the classic 512 rule applies too.
            reply = query_udp(svc.config.listen_port, "other.test")
            assert reply.header.tc == 1
            assert len(reply.pack()) <= 512
            # TCP always gets the complete answer.
            reply = query_tcp(svc.config.listen_port, "other.test")
            assert reply.header.tc == 0
            assert len(reply.rr) == 40
        finally:
            svc.stop()
    finally:
        big.sock.close()


def test_malformed_packet_behavior_remains_intact(service):
    svc, _gen = service
    bound = ("192.168.1.50", 5353)
    # Unrecoverable garbage: dropped (None).
    assert svc.handle_packet(b"", client_addr=bound) is None
    # Recoverable transaction ID: FORMERR, exactly as for any client.
    response = svc.handle_packet(b"\x12\x34garbage", client_addr=bound)
    assert DNSRecord.parse(response).header.rcode == RCODE.FORMERR
    assert DNSRecord.parse(response).header.id == 0x1234
    # And over a real socket the service survives and answers.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    try:
        sock.sendto(b"\xab\xcdnot-a-dns-packet",
                    ("127.0.0.1", svc.config.listen_port))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    assert DNSRecord.parse(data).header.rcode == RCODE.FORMERR


# ======================================================================
# Reload and concurrency (real service, real on-disk generations)
# ======================================================================

def reload_gen(svc, gen):
    return svc.reload_from_paths(str(gen), str(Path(gen) / "categories.json"),
                                 trigger="test")


def test_successful_reload_changes_policy_resolution(tmp_path, upstream):
    """Generation 1 has no binding for the local client; generation 2
    (same directory name/revision, republished content) binds it to the
    strict policy. A reload changes the REAL UDP answer."""
    gen = build_generation(tmp_path / "1", bindings={})
    engine_set, info = load(gen)
    config = ServiceConfig(listen_host="127.0.0.1", listen_port=0,
                           upstreams=[("127.0.0.1", upstream.port)])
    svc = DNSFilteringService(engine_set, config)
    svc.active_config = info
    svc.start()
    try:
        port = svc.config.listen_port
        assert answer_a(query_udp(port, "blocked-a.test")) == UPSTREAM_A
        build_generation(gen, bindings={"ipv4:127.0.0.1": {
            "device_id": 1, "policy_id": 5, "class": "network_binding"}})
        assert reload_gen(svc, gen) is True
        assert svc.reload_count == 1
        assert answer_a(query_udp(port, "blocked-a.test")) == "0.0.0.0"
        assert answer_a(query_tcp(port, "blocked-a.test")) == "0.0.0.0"
    finally:
        svc.stop()


def _republish(gen, **overrides):
    """Rewrite one document of an existing generation (manifest
    regenerated unless the point is a stale/corrupt hash)."""
    build_generation(gen, **overrides)


def test_invalid_default_policy_rejects_reload(tmp_path, upstream):
    gen = build_generation(tmp_path / "1", bindings={"ipv4:127.0.0.1": {
        "device_id": 1, "policy_id": 5, "class": "network_binding"}})
    engine_set, info = load(gen)
    svc = DNSFilteringService(engine_set, ServiceConfig(
        listen_host="127.0.0.1", listen_port=0,
        upstreams=[("127.0.0.1", upstream.port)]))
    svc.active_config = info
    svc.start()
    try:
        port = svc.config.listen_port
        assert answer_a(query_udp(port, "blocked-a.test")) == "0.0.0.0"
        bad = dict(POLICIES)
        bad[1] = {"default_policy": "explode"}
        _republish(gen, policies=bad)
        assert reload_gen(svc, gen) is False
        assert answer_a(query_udp(port, "blocked-a.test")) == "0.0.0.0"
        assert answer_a(query_udp(port, "other.test")) == UPSTREAM_A
    finally:
        svc.stop()


def test_invalid_assigned_policy_rejects_reload(service):
    svc, gen = service
    port = svc.config.listen_port
    bad = dict(POLICIES)
    bad[5] = {"default_policy": "allow", "allowlist": "not-a-list"}
    _republish(gen, policies=bad)
    assert reload_gen(svc, gen) is False
    assert answer_a(query_udp(port, "blocked-a.test")) == "0.0.0.0"


def test_invalid_binding_rejects_reload(service):
    svc, gen = service
    port = svc.config.listen_port
    _republish(gen, bindings={"ipv4:127.0.0.1": {
        "device_id": 1, "policy_id": 99, "class": "network_binding"}})
    assert reload_gen(svc, gen) is False
    assert answer_a(query_udp(port, "blocked-a.test")) == "0.0.0.0"


def test_corrupted_policy_hash_rejects_reload(service):
    svc, gen = service
    port = svc.config.listen_port
    # Valid JSON, valid policy, but the manifest hash no longer matches.
    (gen / "policies" / "5.json").write_text(json.dumps(STRICT_POLICY) + " ")
    assert reload_gen(svc, gen) is False
    assert answer_a(query_udp(port, "blocked-a.test")) == "0.0.0.0"


def test_corrupted_devices_hash_rejects_reload(service):
    svc, gen = service
    port = svc.config.listen_port
    doc = json.loads((gen / "devices.json").read_text())
    doc["_meta"]["note"] = "tampered"
    (gen / "devices.json").write_text(json.dumps(doc))
    assert reload_gen(svc, gen) is False
    assert answer_a(query_udp(port, "blocked-a.test")) == "0.0.0.0"


def test_failed_reload_retains_entire_previous_set(tmp_path, upstream):
    """After a rejected reload BOTH the bound client's policy and the
    default policy provably remain the previous generation's."""
    full_bindings = dict(BINDINGS)
    full_bindings["ipv4:127.0.0.1"] = {"device_id": 1, "policy_id": 5,
                                       "class": "network_binding"}
    gen = build_generation(tmp_path / "1", bindings=full_bindings)
    engine_set, info = load(gen)
    svc = DNSFilteringService(engine_set, ServiceConfig(
        listen_host="127.0.0.1", listen_port=0,
        upstreams=[("127.0.0.1", upstream.port)]))
    svc.active_config = info
    svc.start()
    try:
        port = svc.config.listen_port
        assert answer_a(query_udp(port, "blocked-a.test")) == "0.0.0.0"
        assert answer_a(handle(svc, "blocked-v6.test",
                               ("2001:db8:1:2::7", 1, 0, 0))) == "0.0.0.0"
        # New generation: stricter default AND a corrupt assigned policy.
        bad = dict(POLICIES)
        bad[1] = {"default_policy": "block", "allowlist": [],
                  "blocklist": [], "category_rules": {"allow": [], "block": []}}
        bad[7] = {"broken": True}
        _republish(gen, policies=bad)
        assert reload_gen(svc, gen) is False
        # Everything still the OLD set: old default allows, old binding
        # policies apply, no partial activation of the stricter default.
        assert answer_a(query_udp(port, "blocked-a.test")) == "0.0.0.0"
        assert answer_a(query_udp(port, "other.test")) == UPSTREAM_A
        assert answer_a(handle(svc, "blocked-v6.test",
                               ("2001:db8:1:2::7", 1, 0, 0))) == "0.0.0.0"
        assert svc.reload_count == 0
        assert svc.last_reload_error is not None
    finally:
        svc.stop()


class _GatedEngine(PolicyEngine):
    """A PolicyEngine whose decide() blocks on a gate for one marked
    domain, so a test can hold a query in flight mid-decision."""

    def __init__(self, policy, db, entered, gate):
        super().__init__(policy, db)
        self._entered = entered
        self._gate = gate

    def decide(self, domain):
        if normalize_domain(domain) == "gate.test":
            self._entered.set()
            assert self._gate.wait(10), "test never released the gate"
        return super().decide(domain)


def test_inflight_request_finishes_on_one_consistent_snapshot(upstream):
    """A query that already resolved its policy from engine set A
    finishes against A even when the service swaps to set B
    mid-decision: the reference is read exactly once."""
    entered, gate = threading.Event(), threading.Event()
    old_bound = _GatedEngine({"default_policy": "allow", "allowlist": [],
                              "blocklist": ["gate.test"],
                              "category_rules": {"allow": [], "block": []}},
                             CategoryDB({}), entered, gate)
    old_default = PolicyEngine(DEFAULT_POLICY, CategoryDB({}))
    set_a = EngineSet(default=old_default,
                      per_policy={1: old_default, 5: old_bound},
                      bindings={"ipv4:192.168.1.50": BindingRecord(1, 5)},
                      default_policy_id=1)
    new_bound = PolicyEngine(DEFAULT_POLICY, CategoryDB({}))  # allows gate.test
    set_b = EngineSet(default=old_default,
                      per_policy={1: old_default, 5: new_bound},
                      bindings={"ipv4:192.168.1.50": BindingRecord(1, 5)},
                      default_policy_id=1)
    config = ServiceConfig(listen_host="127.0.0.1", listen_port=0,
                           upstreams=[("127.0.0.1", upstream.port)])
    svc = DNSFilteringService(set_a, config)
    answers = []

    def query():
        packet = DNSRecord.question("gate.test").pack()
        response = svc.handle_packet(packet, client_addr=("192.168.1.50", 7))
        answers.append(answer_a(DNSRecord.parse(response)))

    thread = threading.Thread(target=query)
    thread.start()
    try:
        assert entered.wait(5), "query never reached the gated decide"
        svc.engine = set_b  # the atomic swap, mid-decision
        assert thread.is_alive()
        gate.set()
        thread.join(5)
        assert not thread.is_alive()
    finally:
        gate.set()
        thread.join(5)
    # The in-flight query finished on set A (blocked), even though the
    # service now serves set B (which allows gate.test).
    assert answers == ["0.0.0.0"]
    followup = svc.handle_packet(DNSRecord.question("gate.test").pack(),
                                 client_addr=("192.168.1.50", 7))
    assert answer_a(DNSRecord.parse(followup)) == UPSTREAM_A


def test_concurrent_queries_during_repeated_reloads_never_mixed(tmp_path,
                                                                upstream):
    """Real UDP hammering across 40 real reloads flipping the local
    client's binding on and off: every single answer is one complete
    generation's answer, never an error or a third value."""
    gen = build_generation(tmp_path / "1", bindings={"ipv4:127.0.0.1": {
        "device_id": 1, "policy_id": 5, "class": "network_binding"}})
    engine_set, info = load(gen)
    svc = DNSFilteringService(engine_set, ServiceConfig(
        listen_host="127.0.0.1", listen_port=0,
        upstreams=[("127.0.0.1", upstream.port)]))
    svc.active_config = info
    svc.start()
    errors = []
    stop = threading.Event()

    def hammer():
        while not stop.is_set():
            try:
                answer = answer_a(query_udp(svc.config.listen_port,
                                            "blocked-a.test"))
                if answer not in ("0.0.0.0", UPSTREAM_A):
                    errors.append(f"unexpected answer {answer!r}")
            except Exception as exc:
                errors.append(str(exc))

    threads = [threading.Thread(target=hammer, daemon=True)
               for _ in range(4)]
    for t in threads:
        t.start()
    try:
        for _ in range(20):
            build_generation(gen, bindings={})
            svc.reload_from_paths(str(gen), str(gen / "categories.json"))
            build_generation(gen, bindings={"ipv4:127.0.0.1": {
                "device_id": 1, "policy_id": 5, "class": "network_binding"}})
            svc.reload_from_paths(str(gen), str(gen / "categories.json"))
    finally:
        stop.set()
        for t in threads:
            t.join(timeout=5)
        svc.stop()
    assert not errors
    assert svc.reload_count == 40


def _read_status(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError):
        return None


@pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="POSIX only")
def test_sighup_reload_with_engine_set_format(tmp_path, upstream):
    """The real service process, started on a multi-document generation
    through the publisher-style 'current' symlink (directory mode),
    reloads the WHOLE engine set on SIGHUP after an atomic symlink
    switch - and reports the multi-policy identity in its status file."""
    gens = tmp_path / "gens"
    build_generation(gens / "1", bindings={"ipv4:127.0.0.1": {
        "device_id": 1, "policy_id": 5, "class": "network_binding"}})
    build_generation(gens / "2", bindings={})
    current = tmp_path / "current"
    os.symlink("gens/1", str(current))
    status_path = tmp_path / "status.json"
    log_path = tmp_path / "service.log"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    with open(log_path, "wb") as logf:
        proc = subprocess.Popen(
            [sys.executable, "-u", "-m", "dns_service",
             "--policy", str(current),
             "--categories", str(current / "categories.json"),
             "--listen", "127.0.0.1:0",
             "--upstream", f"127.0.0.1:{upstream.port}",
             "--status-file", str(status_path)],
            stdout=logf, stderr=logf, env=env)
        try:
            wait_for(lambda: "Listening on 127.0.0.1:" in log_path.read_text(),
                     description="service startup line")
            line = [l for l in log_path.read_text().splitlines()
                    if "Listening on 127.0.0.1:" in l][0]
            port = int(line.split("Listening on 127.0.0.1:")[1].split()[0])
            # Generation 1 binds the local client to the strict policy.
            assert answer_a(query_udp(port, "blocked-a.test")) == "0.0.0.0"
            status = _read_status(status_path)
            assert status["format"] == "multi-policy"
            assert status["generation"] == "1"
            assert status["revision"] == 1
            # Only the referenced policies are published (1 and 5).
            assert status["policy_count"] == 2
            assert status["binding_count"] == 1
            assert status["default_policy_id"] == 1

            # Atomic publisher-style switch to generation 2 (no binding).
            tmp_link = tmp_path / ".current.tmp"
            os.symlink("gens/2", str(tmp_link))
            os.replace(str(tmp_link), str(current))
            proc.send_signal(signal.SIGHUP)
            wait_for(lambda: answer_a(query_udp(port, "blocked-a.test"))
                     == UPSTREAM_A,
                     description="SIGHUP engine-set reload to take effect")
            status = _read_status(status_path)
            assert status["generation"] == "2"
            assert status["trigger"] == "sighup"
            assert status["reload_count"] == 1
            assert status["binding_count"] == 0
            assert proc.poll() is None
        finally:
            proc.terminate()
            proc.wait(timeout=10)


@pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="POSIX only")
def test_watch_reload_with_engine_set_format(tmp_path, upstream):
    """--watch notices the symlink switch to a new multi-document
    generation with no signal at all."""
    gens = tmp_path / "gens"
    build_generation(gens / "1", bindings={"ipv4:127.0.0.1": {
        "device_id": 1, "policy_id": 5, "class": "network_binding"}})
    build_generation(gens / "2", bindings={})
    current = tmp_path / "current"
    os.symlink("gens/1", str(current))
    status_path = tmp_path / "status.json"
    log_path = tmp_path / "service.log"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    with open(log_path, "wb") as logf:
        proc = subprocess.Popen(
            [sys.executable, "-u", "-m", "dns_service",
             "--policy", str(current),
             "--categories", str(current / "categories.json"),
             "--listen", "127.0.0.1:0",
             "--upstream", f"127.0.0.1:{upstream.port}",
             "--watch", "0.1",
             "--status-file", str(status_path)],
            stdout=logf, stderr=logf, env=env)
        try:
            wait_for(lambda: "Listening on 127.0.0.1:" in log_path.read_text(),
                     description="service startup line")
            line = [l for l in log_path.read_text().splitlines()
                    if "Listening on 127.0.0.1:" in l][0]
            port = int(line.split("Listening on 127.0.0.1:")[1].split()[0])
            assert answer_a(query_udp(port, "blocked-a.test")) == "0.0.0.0"
            tmp_link = tmp_path / ".current.tmp"
            os.symlink("gens/2", str(tmp_link))
            os.replace(str(tmp_link), str(current))
            wait_for(lambda: answer_a(query_udp(port, "blocked-a.test"))
                     == UPSTREAM_A,
                     description="watch reload of generation 2")
            status = _read_status(status_path)
            assert status["trigger"] == "watch"
            assert status["generation"] == "2"
            assert status["format"] == "multi-policy"
        finally:
            proc.terminate()
            proc.wait(timeout=10)


def test_legacy_reload_behavior_remains_intact(tmp_path, upstream):
    """A service started on a legacy Stage 10 generation (loaded through
    the engine-set path) reloads legacy generations exactly as before;
    every client stays on the single default policy."""
    gen = tmp_path / "1"
    gen.mkdir()
    (gen / "policy.json").write_text(json.dumps(STRICT_POLICY))
    (gen / "categories.json").write_text(json.dumps(CATEGORIES))
    engine_set, info = load_validated_engine_set(
        str(gen / "policy.json"), str(gen / "categories.json"))
    svc = DNSFilteringService(engine_set, ServiceConfig(
        listen_host="127.0.0.1", listen_port=0,
        upstreams=[("127.0.0.1", upstream.port)]))
    svc.active_config = info
    svc.start()
    try:
        port = svc.config.listen_port
        assert answer_a(query_udp(port, "blocked-a.test")) == "0.0.0.0"
        (gen / "policy.json").write_text(json.dumps(DEFAULT_POLICY))
        assert svc.reload_from_paths(str(gen / "policy.json"),
                                     str(gen / "categories.json"),
                                     trigger="test") is True
        assert answer_a(query_udp(port, "blocked-a.test")) == UPSTREAM_A
        assert svc.active_config["format"] == "single-policy"
        # No binding appeared: the engine set still has none.
        assert svc.engine.bindings == {}
    finally:
        svc.stop()


# ======================================================================
# Privacy: client addresses never reach logs or status output
# ======================================================================

@pytest.fixture
def logged_service(tmp_path, upstream):
    stream = io.StringIO()
    svc, gen = make_service(tmp_path, upstream)
    svc.decisions = DecisionLogger(stream)
    yield svc, gen, stream
    svc.stop()


def test_decision_log_never_includes_client_ipv4(logged_service):
    svc, _gen, stream = logged_service
    # Bound client (synthesized address), blocked AND forwarded queries.
    handle(svc, "blocked-a.test", ("192.168.1.50", 5353))
    handle(svc, "other.test", ("192.168.1.50", 5353))
    # Real-socket client too.
    query_udp(svc.config.listen_port, "other.test")
    text = stream.getvalue()
    assert "192.168.1.50" not in text
    lines = [json.loads(l) for l in text.splitlines() if l.strip()]
    assert lines, "expected decision log entries"
    for record in lines:
        assert not ({"client", "client_addr", "client_ip", "source",
                     "source_addr", "src", "ip"} & set(record))


def test_decision_log_never_includes_client_ipv6(logged_service):
    svc, _gen, stream = logged_service
    handle(svc, "blocked-v6.test", ("2001:db8:1:2::1234", 53, 0, 0))
    handle(svc, "other.test", ("2001:db8:1:2::1234", 53, 0, 0))
    handle(svc, "other.test", ("fe80::77%eth0", 53, 0, 2))
    text = stream.getvalue()
    assert "2001:db8" not in text
    assert "fe80" not in text
    assert "::1234" not in text


def test_status_file_never_includes_client_addresses(tmp_path, upstream):
    svc, gen = make_service(tmp_path, upstream)
    try:
        status_path = tmp_path / "engine-status.json"
        svc.set_status_path(status_path)
        svc._write_status("startup")
        # Exercise binding-routed traffic before writing status.
        handle(svc, "blocked-a.test", ("192.168.1.50", 5353))
        query_udp(svc.config.listen_port, "blocked-a.test")
        svc._write_status("test")
        text = status_path.read_text()
        assert "192.168.1.50" not in text
        assert "2001:db8" not in text
        assert "ipv4:" not in text  # binding keys embed addresses
        assert "ipv6:" not in text
        status = json.loads(text)
        assert status["format"] == "multi-policy"
        assert status["policy_count"] == 4
        assert status["binding_count"] >= 1
    finally:
        svc.stop()


def test_status_file_never_includes_credentials(tmp_path, upstream):
    svc, _gen = make_service(tmp_path, upstream)
    try:
        status_path = tmp_path / "engine-status.json"
        svc.set_status_path(status_path)
        svc._write_status("startup")
        status = json.loads(status_path.read_text())
        assert "credentials" not in status
        assert "tokens" not in status
        assert "credential_count" not in status
    finally:
        svc.stop()


# ======================================================================
# Format detection and the directory path contract
# ======================================================================

def test_categories_must_belong_to_the_same_generation(tmp_path):
    """In directory mode, --categories naming another generation's file
    is a mixed-generation file set: rejected."""
    gen1 = build_generation(tmp_path / "1")
    gen2 = build_generation(tmp_path / "2")
    with pytest.raises(EngineSetError, match="does not name this generation"):
        load_validated_engine_set(str(gen1), str(gen2 / "categories.json"))


def test_ambiguous_legacy_plus_devices_layout_rejected(tmp_path):
    """A top-level policy.json WITH a devices.json sibling is an
    ambiguous half-migrated layout: rejected loudly, never silently
    loaded as default-only (which would hide the assigned policies)."""
    gen = build_generation(tmp_path / "1")
    (gen / "policy.json").write_text(json.dumps(DEFAULT_POLICY))
    with pytest.raises(EngineSetError, match="ambiguous mixed layout"):
        load_validated_engine_set(str(gen / "policy.json"),
                                  str(gen / "categories.json"))


def test_directory_without_devices_json_rejected(tmp_path):
    """A directory named as --policy that has no devices.json is not a
    multi-document generation."""
    gen = tmp_path / "1"
    gen.mkdir()
    (gen / "categories.json").write_text(json.dumps(CATEGORIES))
    with pytest.raises(PolicyConfigError, match="cannot open safely"):
        load(gen)


def test_devices_meta_revision_mismatch_rejected(tmp_path):
    """devices.json claiming a different revision than the manifest is
    a mixed-generation document set."""
    gen = build_generation(tmp_path / "1")
    doc = json.loads((gen / "devices.json").read_text())
    doc["_meta"]["revision"] = 99
    (gen / "devices.json").write_text(json.dumps(doc))
    build_manifest_only(gen)
    with pytest.raises(EngineSetError, match="revision"):
        load(gen)


def test_manifest_unknown_top_level_key_rejected(tmp_path):
    gen = build_generation(tmp_path / "1", manifest_overrides={"surprise": {}})
    with pytest.raises(PolicyConfigError, match="unknown keys"):
        load(gen)


def test_noncanonical_binding_keys_rejected(tmp_path):
    """Published binding keys must already be canonical: the engine
    never re-canonicalizes published data."""
    for bad_key in ("ipv4:192.168.001.50", "ipv6:2001:DB8::/64",
                    "ipv4:192.168.1.50/32", "ipv6:2001:db8::1/64",
                    "ipv6:::1/64", "ip:192.168.1.50"):
        gen = build_generation(tmp_path / "1", devices_overrides={"bindings": {
            bad_key: {"device_id": 1, "policy_id": 5,
                      "class": "network_binding"}}})
        with pytest.raises(EngineSetError):
            load(gen)
        for child in sorted(tmp_path.iterdir()):
            if child.is_dir():
                import shutil
                shutil.rmtree(child)

"""Tests for Stage 10 fail-safe hot reload in the DNS filtering service.

Every test runs the REAL service over real sockets against a fake
upstream resolver - no in-process simulation of the network path.
Covered: successful reload, rejection of invalid/missing/corrupted
configurations with last-known-good retained, UDP and TCP queries
before and after reloads, in-flight query safety during reload, a real
subprocess SIGHUP test, and watch-mode pickup of a new generation.

No sleeps are used for synchronization: tests poll observable state
(the DNS answer itself, or the engine status file) with a deadline.
"""

import hashlib
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dnslib import A, QTYPE, RCODE, DNSRecord, RR

from category_db import CategoryDB
from dns_service import (
    DNSFilteringService,
    DecisionLogger,
    ServiceConfig,
    config_identity,
    load_validated_engine,
)
from policy_engine import PolicyConfigError, PolicyEngine

UPSTREAM_A = "93.184.216.34"

POLICY_V1 = {
    "default_policy": "allow",
    "allowlist": [],
    "blocklist": ["blocked-one.test"],
    "category_rules": {"allow": [], "block": []},
}
POLICY_V2 = {
    "default_policy": "allow",
    "allowlist": [],
    "blocklist": ["blocked-two.test"],
    "category_rules": {"allow": [], "block": []},
}
CATEGORIES = {"_meta": {"dataset": "test"}, "domains": {}}


def write_config(directory, policy, categories):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "policy.json").write_text(json.dumps(policy), encoding="utf-8")
    (directory / "categories.json").write_text(json.dumps(categories), encoding="utf-8")
    return directory / "policy.json", directory / "categories.json"


class FakeUpstream(threading.Thread):
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
            reply.add_answer(RR(str(query.q.qname), QTYPE.A, rdata=A(UPSTREAM_A), ttl=60))
            try:
                self.sock.sendto(reply.pack(), addr)
            except OSError:
                return


@pytest.fixture
def upstream():
    up = FakeUpstream()
    yield up
    up.sock.close()


@pytest.fixture
def service(tmp_path, upstream):
    policy_path, categories_path = write_config(tmp_path / "cfg", POLICY_V1, CATEGORIES)
    engine, info = load_validated_engine(policy_path, categories_path)
    config = ServiceConfig(listen_host="127.0.0.1", listen_port=0,
                           upstreams=[("127.0.0.1", upstream.port)])
    svc = DNSFilteringService(engine, config)
    svc.active_config = info
    svc.start()
    yield svc, policy_path, categories_path
    svc.stop()


def query_udp(port, domain):
    q = DNSRecord.question(domain)
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


# -- successful reload ------------------------------------------------

def test_successful_reload_changes_behavior_udp_and_tcp(service):
    svc, policy_path, categories_path = service
    port = svc.config.listen_port
    assert answer_a(query_udp(port, "blocked-one.test")) == "0.0.0.0"
    assert answer_a(query_udp(port, "other.test")) == UPSTREAM_A
    assert answer_a(query_tcp(port, "blocked-one.test")) == "0.0.0.0"

    write_config(Path(policy_path).parent, POLICY_V2, CATEGORIES)
    assert svc.reload_from_paths(policy_path, categories_path, trigger="test") is True
    assert svc.reload_count == 1

    # New policy is enforced on both transports; the old block is gone.
    assert answer_a(query_udp(port, "blocked-two.test")) == "0.0.0.0"
    assert answer_a(query_udp(port, "blocked-one.test")) == UPSTREAM_A
    assert answer_a(query_tcp(port, "blocked-two.test")) == "0.0.0.0"


# -- rejection paths ----------------------------------------------------

def test_invalid_policy_rejected_last_good_kept(service):
    svc, policy_path, categories_path = service
    port = svc.config.listen_port
    Path(policy_path).write_text('{"default_policy": "explode"}', encoding="utf-8")
    assert svc.reload_from_paths(policy_path, categories_path, trigger="test") is False
    assert svc.reload_count == 0
    assert svc.last_reload_error is not None
    # The last valid configuration keeps answering.
    assert answer_a(query_udp(port, "blocked-one.test")) == "0.0.0.0"


def test_invalid_categories_rejected(service):
    svc, policy_path, categories_path = service
    port = svc.config.listen_port
    Path(categories_path).write_text('{"domains": {"bad_domain": []}}', encoding="utf-8")
    assert svc.reload_from_paths(policy_path, categories_path, trigger="test") is False
    assert answer_a(query_udp(port, "blocked-one.test")) == "0.0.0.0"


def test_missing_file_rejected(service, tmp_path):
    svc, policy_path, _ = service
    port = svc.config.listen_port
    assert svc.reload_from_paths(
        policy_path, tmp_path / "nonexistent.json", trigger="test") is False
    assert answer_a(query_udp(port, "blocked-one.test")) == "0.0.0.0"


def _write_manifest(gen, **overrides):
    """Write a structurally valid manifest for the generation in `gen`
    (named after its revision), with any fields overridden or removed
    (pass None to remove). Returns the manifest as written."""
    gen = Path(gen)
    policy_bytes = (gen / "policy.json").read_bytes()
    categories_bytes = (gen / "categories.json").read_bytes()
    manifest = {
        "revision": int(gen.name),
        "generation": gen.name,
        "policy_sha256": hashlib.sha256(policy_bytes).hexdigest(),
        "categories_sha256": hashlib.sha256(categories_bytes).hexdigest(),
    }
    for key, value in overrides.items():
        if value is None:
            manifest.pop(key, None)
        else:
            manifest[key] = value
    (gen / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return manifest


def test_corrupted_generation_rejected(tmp_path):
    """A manifest whose hashes do not match the files is refused."""
    gen = tmp_path / "1"
    policy_path, categories_path = write_config(gen, POLICY_V1, CATEGORIES)
    _write_manifest(gen, policy_sha256="0" * 64)
    with pytest.raises(PolicyConfigError):
        load_validated_engine(policy_path, categories_path)


def test_manifest_missing_policy_hash_rejected(tmp_path):
    gen = tmp_path / "1"
    policy_path, categories_path = write_config(gen, POLICY_V1, CATEGORIES)
    _write_manifest(gen, policy_sha256=None)
    with pytest.raises(PolicyConfigError):
        load_validated_engine(policy_path, categories_path)


def test_manifest_missing_categories_hash_rejected(tmp_path):
    gen = tmp_path / "1"
    policy_path, categories_path = write_config(gen, POLICY_V1, CATEGORIES)
    _write_manifest(gen, categories_sha256=None)
    with pytest.raises(PolicyConfigError):
        load_validated_engine(policy_path, categories_path)


def test_manifest_empty_hashes_rejected(tmp_path):
    gen = tmp_path / "1"
    policy_path, categories_path = write_config(gen, POLICY_V1, CATEGORIES)
    _write_manifest(gen, policy_sha256="", categories_sha256="")
    with pytest.raises(PolicyConfigError):
        load_validated_engine(policy_path, categories_path)


def test_manifest_malformed_hashes_rejected(tmp_path):
    gen = tmp_path / "1"
    policy_path, categories_path = write_config(gen, POLICY_V1, CATEGORIES)
    _write_manifest(gen, policy_sha256="not-a-hash",
                    categories_sha256="z" * 64)
    with pytest.raises(PolicyConfigError):
        load_validated_engine(policy_path, categories_path)


def test_manifest_inconsistent_metadata_rejected(tmp_path):
    """Generation/revision metadata that disagrees with itself or with
    the actual directory is refused."""
    gen = tmp_path / "1"
    policy_path, categories_path = write_config(gen, POLICY_V1, CATEGORIES)
    # generation != str(revision)
    _write_manifest(gen, generation="2")
    with pytest.raises(PolicyConfigError):
        load_validated_engine(policy_path, categories_path)
    # revision missing
    _write_manifest(gen, revision=None)
    with pytest.raises(PolicyConfigError):
        load_validated_engine(policy_path, categories_path)
    # revision not a positive integer
    _write_manifest(gen, revision="1")
    with pytest.raises(PolicyConfigError):
        load_validated_engine(policy_path, categories_path)
    # manifest consistent internally but not with the real directory
    _write_manifest(gen, revision=7, generation="7")
    with pytest.raises(PolicyConfigError):
        load_validated_engine(policy_path, categories_path)


def test_manifest_valid_accepted(tmp_path):
    """A complete, correct manifest loads and reports its identity."""
    gen = tmp_path / "3"
    policy_path, categories_path = write_config(gen, POLICY_V1, CATEGORIES)
    _write_manifest(gen)
    engine, info = load_validated_engine(policy_path, categories_path)
    assert isinstance(engine, PolicyEngine)
    assert info["generation"] == "3"
    assert info["manifest_revision"] == 3


def test_legacy_config_without_manifest_accepted(tmp_path):
    """A plain file set with no manifest.json at all keeps loading
    unverified (the pre-publication legacy layout)."""
    gen = tmp_path / "plain"
    policy_path, categories_path = write_config(gen, POLICY_V1, CATEGORIES)
    engine, info = load_validated_engine(policy_path, categories_path)
    assert isinstance(engine, PolicyEngine)
    assert "generation" not in info
    assert "manifest_revision" not in info


def test_invalid_manifest_reload_keeps_last_known_good(service):
    """A reload whose files carry a defective manifest is rejected and
    the service keeps answering with the last valid configuration."""
    svc, policy_path, categories_path = service
    port = svc.config.listen_port
    gen = Path(policy_path).parent
    write_config(gen, POLICY_V2, CATEGORIES)
    (gen / "manifest.json").write_text(
        json.dumps({"revision": 1, "generation": "1"}), encoding="utf-8")
    assert svc.reload_from_paths(policy_path, categories_path, trigger="test") is False
    assert svc.reload_count == 0
    assert answer_a(query_udp(port, "blocked-one.test")) == "0.0.0.0"
    assert answer_a(query_tcp(port, "blocked-one.test")) == "0.0.0.0"


def test_failed_reload_does_not_stop_service(service):
    svc, policy_path, categories_path = service
    port = svc.config.listen_port
    Path(policy_path).write_text("not json at all", encoding="utf-8")
    for _ in range(3):
        assert svc.reload_from_paths(policy_path, categories_path) is False
    # Service still healthy on UDP and TCP after repeated failures.
    assert answer_a(query_udp(port, "other.test")) == UPSTREAM_A
    assert answer_a(query_tcp(port, "blocked-one.test")) == "0.0.0.0"


# -- in-flight safety ----------------------------------------------------

def test_queries_safe_during_repeated_reloads(service):
    """Hammer real UDP queries while reloading back and forth; every
    query gets a coherent answer from one complete engine generation."""
    svc, policy_path, categories_path = service
    port = svc.config.listen_port
    errors = []
    stop = threading.Event()

    def hammer():
        while not stop.is_set():
            try:
                answer = answer_a(query_udp(port, "blocked-one.test"))
                if answer not in ("0.0.0.0", UPSTREAM_A):
                    errors.append(f"unexpected answer {answer}")
            except Exception as exc:
                errors.append(str(exc))

    threads = [threading.Thread(target=hammer, daemon=True) for _ in range(4)]
    for t in threads:
        t.start()
    for _ in range(20):
        write_config(Path(policy_path).parent, POLICY_V2, CATEGORIES)
        svc.reload_from_paths(policy_path, categories_path)
        write_config(Path(policy_path).parent, POLICY_V1, CATEGORIES)
        svc.reload_from_paths(policy_path, categories_path)
    stop.set()
    for t in threads:
        t.join(timeout=5)
    assert not errors
    assert svc.reload_count == 40


# -- status file ---------------------------------------------------------

def test_status_file_reflects_active_and_rejected(service, tmp_path):
    svc, policy_path, categories_path = service
    status_path = tmp_path / "engine-status.json"
    svc.set_status_path(status_path)
    svc._write_status("startup")
    status = json.loads(status_path.read_text())
    assert status["state"] == "active"
    assert status["reload_count"] == 0
    assert status["policy_sha256"] == svc.active_config["policy_sha256"]

    Path(policy_path).write_text("{broken", encoding="utf-8")
    assert svc.reload_from_paths(policy_path, categories_path, trigger="test") is False
    status = json.loads(status_path.read_text())
    # Rejection is visible but the ACTIVE identity is unchanged.
    assert status["last_error"] is not None
    assert status["policy_sha256"] == svc.active_config["policy_sha256"]
    assert status["reload_count"] == 0


# -- real subprocess: SIGHUP ---------------------------------------------

def _read_status(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError):
        return None


@pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="POSIX only")
def test_sighup_real_subprocess(tmp_path, upstream):
    """The real service process reloads on SIGHUP: flag-only handler,
    validation in normal flow, observable over real DNS answers on UDP
    and TCP against a real (fake) upstream resolver."""
    root = tmp_path / "pub"
    policy_path, categories_path = write_config(root, POLICY_V1, CATEGORIES)
    status_path = tmp_path / "status.json"
    log_path = tmp_path / "service.log"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    with open(log_path, "wb") as logf:
        proc = subprocess.Popen(
            [sys.executable, "-u", "-m", "dns_service",
             "--policy", str(policy_path), "--categories", str(categories_path),
             "--listen", "127.0.0.1:0", "--status-file", str(status_path),
             "--upstream", f"127.0.0.1:{upstream.port}"],
            stdout=logf, stderr=logf, env=env)
        try:
            # The listen port lands in the log; poll for it.
            def port_ready():
                text = log_path.read_text()
                return "Listening on 127.0.0.1:" in text
            wait_for(port_ready, description="service startup line")
            line = [l for l in log_path.read_text().splitlines()
                    if "Listening on 127.0.0.1:" in l][0]
            port = int(line.split("Listening on 127.0.0.1:")[1].split()[0])

            assert answer_a(query_udp(port, "blocked-one.test")) == "0.0.0.0"
            assert answer_a(query_udp(port, "other.test")) == UPSTREAM_A

            # Publish new content in place and signal.
            write_config(root, POLICY_V2, CATEGORIES)
            proc.send_signal(signal.SIGHUP)
            wait_for(lambda: answer_a(query_udp(port, "blocked-two.test")) == "0.0.0.0",
                     description="SIGHUP reload to take effect")
            # Real DNS proof of the reload on both transports: the new
            # block sinks, the old block is forwarded to the upstream.
            assert answer_a(query_udp(port, "blocked-two.test")) == "0.0.0.0"
            assert answer_a(query_tcp(port, "blocked-two.test")) == "0.0.0.0"
            assert answer_a(query_udp(port, "blocked-one.test")) == UPSTREAM_A
            assert answer_a(query_tcp(port, "blocked-one.test")) == UPSTREAM_A
            assert proc.poll() is None  # still healthy
            status = _read_status(status_path)
            assert status is not None
            assert status["trigger"] == "sighup"
            assert status["reload_count"] == 1

            # A broken configuration after SIGHUP is rejected; the
            # service stays up with POLICY_V2 as the last known-good.
            Path(policy_path).write_text("{oops", encoding="utf-8")
            proc.send_signal(signal.SIGHUP)
            wait_for(lambda: (_read_status(status_path) or {}).get("last_error") is not None,
                     description="rejection to appear in the status file")
            assert _read_status(status_path)["reload_count"] == 1
            assert answer_a(query_udp(port, "blocked-two.test")) == "0.0.0.0"
            assert answer_a(query_tcp(port, "blocked-two.test")) == "0.0.0.0"
            assert answer_a(query_udp(port, "blocked-one.test")) == UPSTREAM_A
            assert proc.poll() is None  # still running
        finally:
            proc.terminate()
            proc.wait(timeout=10)


@pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="POSIX only")
def test_watch_mode_picks_up_new_generation(tmp_path):
    """--watch notices a new published generation through the 'current'
    symlink without any signal."""
    gens = tmp_path / "gens"
    p1, c1 = write_config(gens / "1", POLICY_V1, CATEGORIES)
    current = tmp_path / "current"
    os.symlink("gens/1", str(current))
    policy_path = current / "policy.json"
    categories_path = current / "categories.json"
    status_path = tmp_path / "status.json"
    log_path = tmp_path / "service.log"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    with open(log_path, "wb") as logf:
        proc = subprocess.Popen(
            [sys.executable, "-u", "-m", "dns_service",
             "--policy", str(policy_path), "--categories", str(categories_path),
             "--listen", "127.0.0.1:0", "--watch", "0.1",
             "--status-file", str(status_path)],
            stdout=logf, stderr=logf, env=env)
        try:
            def port_ready():
                return "Listening on 127.0.0.1:" in log_path.read_text()
            wait_for(port_ready, description="service startup line")
            line = [l for l in log_path.read_text().splitlines()
                    if "Listening on 127.0.0.1:" in l][0]
            port = int(line.split("Listening on 127.0.0.1:")[1].split()[0])
            assert answer_a(query_udp(port, "blocked-one.test")) == "0.0.0.0"

            # New generation + atomic pointer switch, exactly like the
            # dashboard's publisher.
            write_config(gens / "2", POLICY_V2, CATEGORIES)
            tmp_link = tmp_path / ".current.tmp"
            os.symlink("gens/2", str(tmp_link))
            os.replace(str(tmp_link), str(current))

            wait_for(lambda: answer_a(query_udp(port, "blocked-two.test")) == "0.0.0.0",
                     description="watch reload of generation 2")
            status = _read_status(status_path)
            assert status["trigger"] == "watch"
            assert status["reload_count"] == 1
        finally:
            proc.terminate()
            proc.wait(timeout=10)


# -- manifest path edge cases: present-but-unusable is never "absent" -----

def test_manifest_path_is_directory_rejected(tmp_path):
    """A manifest.json that exists as a DIRECTORY is a present-but-
    invalid manifest: rejected, never treated as legacy no-manifest."""
    gen = tmp_path / "1"
    policy_path, categories_path = write_config(gen, POLICY_V1, CATEGORIES)
    (gen / "manifest.json").mkdir()
    with pytest.raises(PolicyConfigError):
        load_validated_engine(policy_path, categories_path)


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="POSIX symlinks")
def test_manifest_path_broken_symlink_rejected(tmp_path):
    """A manifest.json that is a broken symlink: Path.is_file() is False
    (it follows the link) but the entry exists, so this must be rejected
    rather than silently falling back to legacy unverified loading."""
    gen = tmp_path / "1"
    policy_path, categories_path = write_config(gen, POLICY_V1, CATEGORIES)
    os.symlink(gen / "does-not-exist.json", gen / "manifest.json")
    with pytest.raises(PolicyConfigError):
        load_validated_engine(policy_path, categories_path)


def test_manifest_path_directory_reload_keeps_last_known_good(service):
    """A reload whose manifest path is unusable is rejected by the
    running service, which keeps answering UDP and TCP with the last
    valid configuration."""
    svc, policy_path, categories_path = service
    port = svc.config.listen_port
    gen = Path(policy_path).parent
    write_config(gen, POLICY_V2, CATEGORIES)
    (gen / "manifest.json").mkdir()
    assert svc.reload_from_paths(policy_path, categories_path, trigger="test") is False
    assert svc.reload_count == 0
    assert answer_a(query_udp(port, "blocked-one.test")) == "0.0.0.0"
    assert answer_a(query_tcp(port, "blocked-one.test")) == "0.0.0.0"

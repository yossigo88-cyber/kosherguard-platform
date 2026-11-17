#!/usr/bin/env python3
"""Bounded, entirely local synthetic policy-propagation benchmark.

python tools/benchmark_propagation.py --rounds 10 --output /tmp/prop.json

Measures the one Answer-23 policy-update segment that exists in this
environment: publishing a new DNS policy generation (atomic 'current'
symlink flip) until the running DNS edge serves the new verdict. APNs
delivery, MDM command queues to real devices, PAC/proxy refresh on managed
networks, native filter updates and URL-filter database updates have no
live integration here and are NOT measured - see docs/reviews/LOAD_TEST.md.
No production-capacity or update-speed promise is made (Answers 6 and 23
describe measurement goals, not guarantees).
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import statistics
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "dns-edge"))
from runner import DNSEdgeRunner  # noqa: E402
import dnslib  # noqa: E402


def write_generation(root, revision, blocked):
    generation = Path(root) / "generations" / str(revision)
    generation.mkdir(parents=True)
    policy = {"default_policy": "allow", "allowlist": [],
              "blocklist": [blocked],
              "category_rules": {"allow": [], "block": []}}
    p = (json.dumps(policy, sort_keys=True) + "\n").encode()
    c = b'{"domains": {}}\n'
    (generation / "policy.json").write_bytes(p)
    (generation / "categories.json").write_bytes(c)
    (generation / "manifest.json").write_text(json.dumps({
        "revision": revision, "generation": str(revision),
        "policy_sha256": hashlib.sha256(p).hexdigest(),
        "categories_sha256": hashlib.sha256(c).hexdigest(),
        "files": ["policy.json", "categories.json"]}))
    tmp = Path(root) / ".current.tmp"
    if tmp.exists() or tmp.is_symlink():
        tmp.unlink()
    os.symlink(f"generations/{revision}", tmp)
    os.replace(tmp, Path(root) / "current")


def verdict(name, port):
    q = dnslib.DNSRecord.question(name)
    answer = dnslib.DNSRecord.parse(q.send("127.0.0.1", port, timeout=3))
    return bool(answer.rr and str(answer.rr[0].rdata) == "0.0.0.0")


def run(rounds=10, watch_interval=0.1):
    if not 1 <= rounds <= 1000:
        raise ValueError("rounds 1-1000")
    samples = []
    with tempfile.TemporaryDirectory(prefix="kg-prop-load-") as root:
        write_generation(root, 1, "rev1.example")
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        runner = DNSEdgeRunner(root, listen=f"127.0.0.1:{port}",
                               watch_interval=watch_interval)
        runner.start()
        try:
            for revision in range(2, rounds + 2):
                name = f"rev{revision}.example"
                write_generation(root, revision, name)
                published_at = time.perf_counter()
                deadline = published_at + 15
                while True:
                    try:
                        if verdict(name, port):
                            break
                    except Exception:
                        pass
                    if time.perf_counter() > deadline:
                        raise RuntimeError(
                            f"revision {revision} never served")
                    time.sleep(0.01)
                samples.append((time.perf_counter() - published_at) * 1000)
        finally:
            runner.stop()
    lat = sorted(samples)
    percentile = lambda p: lat[min(len(lat) - 1, int((len(lat) - 1) * p))]
    return {
        "scope": ("local loopback: generation symlink flip to the running "
                  "DNS edge serving the new block verdict, watch-poll "
                  f"interval {watch_interval}s; no APNs, MDM-device, "
                  "PAC/proxy, native-filter or URL-filter segment exists "
                  "in this environment"),
        "rounds": rounds,
        "all_propagated": len(samples) == rounds,
        "propagation_ms": {"median": round(statistics.median(lat), 3),
                           "p95": round(percentile(.95), 3),
                           "p99": round(percentile(.99), 3),
                           "max": round(max(lat), 3)},
        "environment": {"python": platform.python_version(),
                        "platform": platform.system(),
                        "cpus": os.cpu_count()},
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rounds", type=int, default=10)
    parser.add_argument("--output")
    args = parser.parse_args()
    report = run(args.rounds)
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(text + "\n")
    print(text)


if __name__ == "__main__":
    main()

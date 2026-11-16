#!/usr/bin/env python3
"""Bounded, entirely local synthetic DNS benchmark. No real domains/devices.

python tools/benchmark_dns.py --queries 1000 --clients 8 --output /tmp/report.json
This measures a loopback blocked-query path, NOT upstream/network/Apple
capacity, production availability or a promised customer/device count.
"""
import argparse
import concurrent.futures
import hashlib
import json
import logging
import os
from pathlib import Path
import platform
import socket
import statistics
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'dns-edge'))
from runner import DNSEdgeRunner
import dnslib


def run(queries=1000, clients=8):
    if not 1 <= queries <= 100000 or not 1 <= clients <= 64:
        raise ValueError('queries 1-100000; clients 1-64')
    logging.disable(logging.CRITICAL)
    with tempfile.TemporaryDirectory(prefix='kg-synthetic-load-') as root:
        generation = Path(root) / 'generations' / '1'
        generation.mkdir(parents=True)
        policy = {'default_policy': 'block', 'allowlist': [], 'blocklist': [],
                  'category_rules': {'allow': [], 'block': []}}
        p = (json.dumps(policy, sort_keys=True)+'\n').encode()
        c = b'{"domains": {}}\n'
        (generation/'policy.json').write_bytes(p)
        (generation/'categories.json').write_bytes(c)
        (generation/'manifest.json').write_text(json.dumps({
            'revision': 1, 'generation': '1',
            'policy_sha256': hashlib.sha256(p).hexdigest(),
            'categories_sha256': hashlib.sha256(c).hexdigest(),
            'files': ['policy.json', 'categories.json']}))
        os.symlink('generations/1', Path(root)/'current')
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]; probe.close()
        runner = DNSEdgeRunner(root, listen=f'127.0.0.1:{port}', watch_interval=60)
        runner.start()
        def one(n):
            started = time.perf_counter()
            try:
                q = dnslib.DNSRecord.question(f'synthetic-{n}.example')
                answer = dnslib.DNSRecord.parse(q.send('127.0.0.1', port, timeout=3))
                good = bool(answer.rr and str(answer.rr[0].rdata) == '0.0.0.0')
            except Exception:
                good = False
            return (time.perf_counter()-started)*1000, good
        try:
            started = time.perf_counter()
            with concurrent.futures.ThreadPoolExecutor(max_workers=clients) as pool:
                values = list(pool.map(one, range(queries)))
            seconds = time.perf_counter()-started
        finally:
            runner.stop()
        latencies = sorted(v[0] for v in values)
        percentile = lambda p: latencies[min(len(latencies)-1, int((len(latencies)-1)*p))]
        return {
            'scope': 'local loopback UDP DNS, all blocked, no upstream or Apple traffic',
            'queries': queries, 'concurrent_clients': clients,
            'correct_answers': sum(v[1] for v in values),
            'errors': sum(not v[1] for v in values),
            'elapsed_seconds': round(seconds, 4),
            'throughput_queries_per_second': round(queries/seconds, 2),
            'latency_ms': {'median': round(statistics.median(latencies), 3),
                           'p95': round(percentile(.95), 3),
                           'p99': round(percentile(.99), 3)},
            'environment': {'python': platform.python_version(),
                            'platform': platform.system(), 'cpus': os.cpu_count()},
            'limits': 'Not a production capacity estimate or SLA. Excludes upstream DNS, TLS/DoH, database, MDM, APNs, iOS, device counts and internet latency.'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--queries', type=int, default=1000)
    p.add_argument('--clients', type=int, default=8)
    p.add_argument('--output', required=True)
    args = p.parse_args()
    report = run(args.queries, args.clients)
    Path(args.output).write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
    return int(bool(report['errors']))


if __name__ == '__main__':
    raise SystemExit(main())

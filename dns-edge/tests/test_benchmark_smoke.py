"""The committed DNS load-test harness stays runnable (Answer 6:
synthetic load testing in small internal environments; Answer 23:
measure the policy-propagation segments that exist). Tiny bounded runs
only - the documented numbers live in docs/reviews/LOAD_TEST.md."""

import json
import os
import subprocess
import sys

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
TOOLS = os.path.join(ROOT, "tools")


def test_benchmark_dns_smoke(tmp_path):
    out = tmp_path / "dns.json"
    r = subprocess.run(
        [sys.executable, os.path.join(TOOLS, "benchmark_dns.py"),
         "--queries", "40", "--clients", "2", "--output", str(out)],
        capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    report = json.loads(out.read_text())
    assert report["correct_answers"] == 40 and report["errors"] == 0


def test_benchmark_propagation_smoke():
    r = subprocess.run(
        [sys.executable, os.path.join(TOOLS, "benchmark_propagation.py"),
         "--rounds", "2"],
        capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    report = json.loads(r.stdout)
    assert report["all_propagated"] is True
    assert report["propagation_ms"]["max"] > 0

"""The committed load-test harness stays runnable (Answer 6: synthetic
load testing in small internal environments). Tiny bounded runs only -
the documented numbers live in docs/reviews/LOAD_TEST.md."""

import os
import subprocess
import sys

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")


def test_benchmark_api_smoke():
    r = subprocess.run(
        [sys.executable, os.path.join(ROOT, "tools", "benchmark_api.py"),
         "--requests", "12", "--clients", "2"],
        capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    import json
    report = json.loads(r.stdout)
    reads = report["results"][1]
    assert reads["ok"] == 12 and reads["errors"] == 0
    assert report["results"][0]["ok"] >= 1

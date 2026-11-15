"""Stage 11B frontend checks: static guarantees plus the Node UI suite.

Static checks always run (pure Python file reads): the mandated honest
UI wording is present in app.js, the responsive/overflow CSS rules exist,
and no backend file was needed by these tests (they assert on the
frontend artifacts only).

When Node.js is available, this also runs `node --check` on app.js and
the full node:test UI suite (tests/test_devices_ui.mjs), which drives the
real app.js against a DOM/fetch shim. When Node is not installed these
two tests skip explicitly; the suite output records the skip.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

DASHBOARD = Path(__file__).resolve().parents[1]
APP_JS = DASHBOARD / "static" / "app.js"
STYLES = DASHBOARD / "static" / "styles.css"
INDEX = DASHBOARD / "static" / "index.html"
UI_SUITE = DASHBOARD / "tests" / "test_devices_ui.mjs"

NODE = shutil.which("node")

MANDATED_STRINGS = [
    # Exact wording required for every binding field.
    "Network/group binding — routing hint only, not verified device identity.",
    # Exact wording shown while no engine has confirmed enforcement.
    "Enforcement unavailable — no connected filtering engine has confirmed this policy.",
]


def test_mandated_honest_wording_present():
    src = APP_JS.read_text()
    for text in MANDATED_STRINGS:
        assert text in src, f"mandated UI string missing from app.js: {text!r}"


def test_ui_never_sends_identity_class():
    src = APP_JS.read_text()
    # The client must never attempt to set identity_class; the server
    # derives it from kind and rejects client-supplied values.
    assert "identity_class" not in src


def test_ui_has_no_token_or_mdm_offers():
    src = APP_JS.read_text()
    for forbidden in ("token_hash", "enroll device", "remote wipe", "push profile"):
        assert forbidden not in src


def test_responsive_css_rules_present():
    css = STYLES.read_text()
    assert "@media (max-width: 900px)" in css
    assert ".responsive-table" in css
    assert "overflow-x: auto" in css  # .table-wrap fallback
    # The mobile table-card pattern labels cells instead of overflowing.
    assert "attr(data-label)" in css


def test_index_html_unchanged_shell():
    # Stage 11B needed no index.html changes: the shell still loads the
    # same two static assets and keeps the modal host.
    html = INDEX.read_text()
    assert '<script src="/app.js"></script>' in html
    assert 'href="/styles.css"' in html
    assert 'id="modal-backdrop"' in html


@pytest.mark.skipif(NODE is None, reason="Node.js not installed; JS checks skipped")
def test_app_js_parses_under_node():
    result = subprocess.run(
        [NODE, "--check", str(APP_JS)], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(NODE is None, reason="Node.js not installed; UI suite skipped")
def test_devices_ui_suite():
    result = subprocess.run(
        [NODE, "--test", str(UI_SUITE)],
        capture_output=True, text=True, timeout=120, cwd=str(DASHBOARD))
    assert result.returncode == 0, result.stdout[-4000:] + result.stderr[-2000:]

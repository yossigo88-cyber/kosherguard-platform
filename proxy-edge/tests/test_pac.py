"""PAC generation tests."""

import os
import subprocess
import shutil
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pac  # noqa: E402

POLICY = {"default_policy": "allow", "allowlist": ["good.example"],
          "blocklist": ["bad.example"],
          "category_rules": {"allow": [], "block": ["gambling"]}}
CATS = {"domains": {"bet365.com": ["gambling"],
                    "wikipedia.org": ["education"]}}
STRICT = {"default_policy": "block", "allowlist": ["school.example"],
          "blocklist": [], "category_rules": {"allow": [], "block": []}}


def test_reference_evaluator():
    assert pac.evaluate_pac(POLICY, CATS, "bad.example").startswith("PROXY")
    assert pac.evaluate_pac(POLICY, CATS, "sub.bad.example").startswith("PROXY")
    assert pac.evaluate_pac(POLICY, CATS, "bet365.com").startswith("PROXY")
    assert pac.evaluate_pac(POLICY, CATS, "good.example") == "DIRECT"
    assert pac.evaluate_pac(POLICY, CATS, "wikipedia.org") == "DIRECT"
    assert pac.evaluate_pac(POLICY, CATS, "other.com") == "DIRECT"
    assert pac.evaluate_pac(POLICY, CATS, "localhost") == "DIRECT"


def test_strict_default_routes_unknown_to_proxy():
    assert pac.evaluate_pac(STRICT, None, "anything.com").startswith("PROXY")
    assert pac.evaluate_pac(STRICT, None, "school.example") == "DIRECT"


def test_allowlist_beats_category_block():
    policy = dict(POLICY, allowlist=["bet365.com"])
    assert pac.evaluate_pac(policy, CATS, "bet365.com") == "DIRECT"


def test_deterministic_output():
    a = pac.generate_pac(POLICY, CATS, "proxy.kg.example", 8080)
    b = pac.generate_pac(POLICY, CATS, "proxy.kg.example", 8080)
    assert a == b


def test_invalid_inputs_rejected():
    with pytest.raises(pac.PACError):
        pac.generate_pac(POLICY, CATS, "", 8080)
    with pytest.raises(pac.PACError):
        pac.generate_pac(POLICY, CATS, "proxy.example", 0)
    with pytest.raises(pac.PACError):
        pac.generate_pac({"default_policy": "maybe"}, CATS, "p.example", 8080)


def test_generated_javascript_matches_reference():
    """Run the real generated PAC under node and compare against the
    reference evaluator for every test host."""
    if shutil.which("node") is None:
        pytest.skip("node not available")
    generated = pac.generate_pac(POLICY, CATS, "proxy.kg.example", 8080)
    hosts = ["bad.example", "sub.bad.example", "bet365.com",
             "good.example", "wikipedia.org", "other.com", "localhost"]
    harness = generated + """
function dnsDomainIs(h, d) { return h.endsWith(d); }
function isPlainHostName(h) { return !h.includes('.'); }
const hosts = %s;
for (const h of hosts) {
  console.log(h + '=' + FindProxyForURL('http://' + h + '/', h));
}
""" % (__import__("json").dumps(hosts))
    out = subprocess.run(["node", "-e", harness], capture_output=True,
                         text=True, check=True).stdout
    actual = dict(line.split("=", 1) for line in out.strip().split("\n"))
    for host in hosts:
        expected = pac.evaluate_pac(POLICY, CATS, host,
                                    proxy_host="proxy.kg.example",
                                    proxy_port=8080)
        assert actual[host] == expected, f"{host}: PAC says {actual[host]!r}, reference says {expected!r}"

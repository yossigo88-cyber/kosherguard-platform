"""Domain-test evaluation: rule precedence and engine integration.

The documented precedence (identical to the filtering engine's, which
performs the actual evaluation):

1. explicit allowlist  -> allow
2. explicit blocklist  -> block
3. blocked category    -> block
4. allowed category    -> allow
5. default policy
"""


def setup_data(client):
    """Seed domains and a policy exercising every precedence level."""
    client.post("/api/domains", {"domain": "allowed-over-blocked.example",
                                 "categories": ["gambling"]})
    client.post("/api/domains", {"domain": "blocked-site.example",
                                 "categories": ["news"]})
    client.post("/api/domains", {"domain": "casino.example",
                                 "categories": ["gambling"]})
    client.post("/api/domains", {"domain": "school.example",
                                 "categories": ["news"]})
    client.post("/api/domains", {"domain": "plain.example",
                                 "categories": ["shopping"]})
    status, policy = client.post("/api/policies", {
        "name": "Precedence policy",
        "default_policy": "allow",
        "allowlist": ["allowed-over-blocked.example"],
        "blocklist": ["blocked-site.example"],
        "category_allow": ["news"],
        "category_block": ["gambling"],
    })
    assert status == 201, policy
    return policy


def run_decision(client, policy, domain):
    status, result = client.post(f"/api/policies/{policy['id']}/test", {"domain": domain})
    assert status == 200, result
    return result


def test_explicit_allow_beats_blocked_category(client):
    policy = setup_data(client)
    result = run_decision(client, policy, "allowed-over-blocked.example")
    assert result["action"] == "allow"
    assert result["rule"] == "explicit_allow"


def test_explicit_block_beats_allowed_category(client):
    policy = setup_data(client)
    result = run_decision(client, policy, "blocked-site.example")
    assert result["action"] == "block"
    assert result["rule"] == "explicit_block"


def test_category_block_beats_category_allow(client):
    policy = setup_data(client)
    result = run_decision(client, policy, "casino.example")
    assert result["action"] == "block"
    assert result["rule"] == "category_block"
    assert result["category"] == "gambling"


def test_category_allow(client):
    policy = setup_data(client)
    result = run_decision(client, policy, "school.example")
    assert result["action"] == "allow"
    assert result["rule"] == "category_allow"
    assert result["category"] == "news"


def test_default_policy_applies(client):
    policy = setup_data(client)
    result = run_decision(client, policy, "plain.example")
    assert result["action"] == "allow"
    assert result["rule"] == "default"


def test_default_policy_block(client):
    status, policy = client.post("/api/policies", {
        "name": "Strict", "default_policy": "block",
    })
    assert status == 201
    result = run_decision(client, policy, "anything.example")
    assert result["action"] == "block"
    assert result["rule"] == "default"


def test_subdomain_matching(client):
    policy = setup_data(client)
    # A listed domain covers all of its subdomains.
    result = run_decision(client, policy, "www.casino.example")
    assert result["action"] == "block"
    assert result["rule"] == "category_block"
    result = run_decision(client, policy, "deep.www.casino.example")
    assert result["action"] == "block"
    result = run_decision(client, policy, "www.blocked-site.example")
    assert result["action"] == "block"
    assert result["rule"] == "explicit_block"
    # ...but a different domain sharing a suffix is not a subdomain.
    result = run_decision(client, policy, "notcasino.example")
    assert result["action"] == "allow"
    assert result["rule"] == "default"


def test_malformed_test_domain_rejected(client):
    policy = setup_data(client)
    status, body = client.post(f"/api/policies/{policy['id']}/test", {"domain": "not a domain"})
    assert status == 400
    assert "error" in body


def test_unknown_policy_rejected(client):
    status, _ = client.post("/api/policies/9999/test", {"domain": "a.example"})
    assert status == 404


def test_disabled_category_excluded_from_evaluation(client):
    policy = setup_data(client)
    status, _ = client.post("/api/categories/gambling/enabled", {"enabled": False})
    assert status == 200
    result = run_decision(client, policy, "casino.example")
    # With gambling disabled, the category no longer blocks.
    assert result["action"] == "allow"
    assert result["rule"] == "default"


def test_domain_record_returned_with_decision(client):
    policy = setup_data(client)
    result = run_decision(client, policy, "casino.example")
    assert result["domain_record"]["categories"] == ["gambling"]
    result = run_decision(client, policy, "unknown.example")
    assert result["domain_record"] is None


def test_domain_record_explicit_rule_does_not_change_engine_decision(client):
    # An explicit "allow" designation on the record is administrative
    # intent only; the engine decision still comes from the policy.
    client.post("/api/domains", {"domain": "marked.example",
                                 "categories": ["gambling"], "rule": "allow"})
    policy = setup_data(client)
    result = run_decision(client, policy, "marked.example")
    assert result["domain_record"]["rule"] == "allow"
    assert result["action"] == "block"
    assert result["rule"] == "category_block"


def test_reason_is_human_readable(client):
    policy = setup_data(client)
    result = run_decision(client, policy, "casino.example")
    assert "gambling" in result["reason"]
    assert result["policy_name"] == "Precedence policy"

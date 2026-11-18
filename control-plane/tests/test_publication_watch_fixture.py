"""The url-filter-server watcher's real-format regression fixture must
stay byte-identical to what THIS control plane publishes. If
export_policy_documents' shape ever changes, this test fails before
the watcher silently misreads the new policy (fail-open risk)."""

import json
import os
import types

from app import policy_ops, publication_ops

FIXTURE_DIR = os.path.normpath(os.path.join(
    os.path.dirname(__file__), "..", "..", "url-filter-server",
    "tests", "fixtures", "published"))

_POLICY = {
    "default_policy": "allow",
    "blocklist": ["blocked.example"],
    "allowlist": ["allowed.example"],
    "category_block": ["gambling"],
    "category_allow": ["news"],
}
_CATEGORIES = {"domains": {"casino.example": ["gambling"],
                           "news.example": ["news"]}}


def test_published_fixture_matches_current_export(tmp_path):
    doc = policy_ops.normalize_engine_doc(_POLICY)
    version = types.SimpleNamespace(engine_doc=json.dumps(doc))
    cats = tmp_path / "categories.json"
    cats.write_text(json.dumps(_CATEGORIES))
    policy_json, categories_json = \
        publication_ops.export_policy_documents(
            version, categories_path=str(cats))
    for name, actual in (("policy.json", policy_json),
                         ("categories.json", categories_json)):
        with open(os.path.join(FIXTURE_DIR, name), "rb") as fh:
            assert fh.read() == actual, (
                f"published {name} drifted from the watcher fixture; "
                "regenerate url-filter-server/tests/fixtures/published "
                "and re-verify rules_from_generation")

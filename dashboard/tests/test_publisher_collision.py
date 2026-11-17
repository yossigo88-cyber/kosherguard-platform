"""A replay/collision must never delete a complete existing generation."""
import pytest

from publishing import Publisher, canonical_json


def test_existing_generation_survives_replayed_revision(tmp_path):
    p = Publisher(tmp_path / 'published')
    policy = canonical_json({'default_policy':'block', 'allowlist':[],
                             'blocklist':[], 'category_rules':{'allow':[], 'block':[]}})
    categories = canonical_json({'domains':{}})
    with p.locked():
        p.publish(1, policy, categories, {})
    before = {f.name: f.read_bytes() for f in (p.generations_dir / '1').iterdir()}
    with p.locked():
        with pytest.raises(FileExistsError):
            p.publish(1, policy, categories, {})
    assert p.current_link.resolve().is_dir()
    after = {f.name: f.read_bytes() for f in (p.generations_dir / '1').iterdir()}
    assert after == before
    assert p.current()['generation'] == '1'

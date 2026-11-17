"""The category pipeline's real domain-to-categories schema reaches URL rules."""
import json
import pytest
from app.dataset import load_categories


def test_pipeline_output_is_not_silently_empty(tmp_path):
    p = tmp_path / 'categories.json'
    p.write_text(json.dumps({'_meta': {'sources': {}}, 'domains': {
        'EXAMPLE.COM': ['news', 'reference'], 'bad.example': ['blocked']}}))
    rules = load_categories(str(p))
    assert {(r.url, r.category, r.verdict) for r in rules} == {
        ('example.com', 'news', 'block'),
        ('example.com', 'reference', 'block'),
        ('bad.example', 'blocked', 'block')}


@pytest.mark.parametrize('doc', [{}, {'categories': {}}, {'domains': []},
    {'domains': {'bad.example': []}}, {'domains': {'https://example.com': ['news']}},
    {'domains': {'bad.example': ['not a slug']}}])
def test_malformed_pipeline_input_fails_closed(tmp_path, doc):
    p = tmp_path / 'bad.json'
    p.write_text(json.dumps(doc))
    with pytest.raises(ValueError):
        load_categories(str(p))

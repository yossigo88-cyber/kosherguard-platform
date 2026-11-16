"""Category pipeline tests."""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import build  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TAXONOMY = os.path.join(ROOT, "taxonomy.json")


def write_source(directory, name, records):
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    return path


def test_real_seed_builds_and_loads():
    doc = build.build(os.path.join(ROOT, "sources"), TAXONOMY)
    assert len(doc["domains"]) > 100
    assert "NOT A COMPLETE" in doc["_meta"]["dataset"]
    assert doc["_meta"]["sources"]["seed-manual"]["records"] > 100
    # Spot-check categories from the spec's required list.
    for cat in ("adult", "gambling", "social-media", "video-streaming",
                "music", "gaming", "shopping", "news", "forums",
                "dating", "proxy-vpn"):
        assert any(cat in cats for cats in doc["domains"].values()), cat


def test_union_categories_across_sources(tmp_path):
    write_source(str(tmp_path), "a.jsonl", [
        {"domain": "x.example", "categories": ["news"], "source": "a"}])
    write_source(str(tmp_path), "b.jsonl", [
        {"domain": "x.example", "categories": ["forums"], "source": "b"}])
    doc = build.build(str(tmp_path), TAXONOMY)
    assert doc["domains"]["x.example"] == ["forums", "news"]


def test_unknown_category_rejected(tmp_path):
    write_source(str(tmp_path), "a.jsonl", [
        {"domain": "x.example", "categories": ["no-such-cat"], "source": "a"}])
    with pytest.raises(Exception, match="not in the taxonomy"):
        build.build(str(tmp_path), TAXONOMY)


def test_provenance_mismatch_rejected(tmp_path):
    write_source(str(tmp_path), "a.jsonl", [
        {"domain": "x.example", "categories": ["news"], "source": "b"}])
    with pytest.raises(Exception, match="provenance mismatch"):
        build.build(str(tmp_path), TAXONOMY)


def test_bad_domain_rejected(tmp_path):
    write_source(str(tmp_path), "a.jsonl", [
        {"domain": "not a domain!", "categories": ["news"], "source": "a"}])
    with pytest.raises(Exception):
        build.build(str(tmp_path), TAXONOMY)


def test_empty_sources_rejected(tmp_path):
    with pytest.raises(Exception, match="no .jsonl sources"):
        build.build(str(tmp_path), TAXONOMY)

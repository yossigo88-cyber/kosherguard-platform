"""Automated tests for the category database and the import process.

Covers: loading the shipped test dataset, multi-category domains,
lookup semantics, import merging, and import validation.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from category_db import (
    CategoryDB,
    CategoryDBError,
    main as db_tool_main,
    validate_domain,
)

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "data" / "categories.test.json"


# -- shipped dataset -----------------------------------------------------------

def test_test_dataset_loads_and_is_labeled():
    db = CategoryDB.load(DATASET)
    assert db.known_domain_count() >= 15
    assert "TEST DATA" in db.meta.get("dataset", "")
    assert "NOT A COMPLETE" in db.meta["dataset"]


def test_multi_category_domain():
    db = CategoryDB.load(DATASET)
    cats = db.categories_for("youtube.com")
    assert cats == {"video", "entertainment"}


def test_unknown_domain_has_no_categories():
    assert CategoryDB.load(DATASET).categories_for("not-listed.example") == set()


def test_subdomain_uses_parent_entry():
    db = CategoryDB.load(DATASET)
    assert db.categories_for("en.wikipedia.org") == {"education", "reference"}


# -- validation -----------------------------------------------------------------

def test_invalid_domain_rejected():
    with pytest.raises(CategoryDBError):
        CategoryDB({"not a domain!!": ["news"]})


def test_invalid_category_rejected():
    with pytest.raises(CategoryDBError):
        CategoryDB({"ok.example": ["Bad Category!"]})


def test_empty_category_list_rejected():
    with pytest.raises(CategoryDBError):
        CategoryDB({"ok.example": []})


# -- import process ---------------------------------------------------------------

def test_import_merges_and_unions_categories(tmp_path):
    db = CategoryDB.load(DATASET)
    added, updated = db.merge_records([
        {"domain": "new-site.example", "categories": ["news"]},
        {"domain": "youtube.com", "categories": ["video", "kids"]},
    ])
    assert (added, updated) == (1, 1)
    assert db.categories_for("new-site.example") == {"news"}
    assert db.categories_for("youtube.com") == {"video", "entertainment", "kids"}


def test_import_rejects_bad_record_with_line_number():
    db = CategoryDB.load(DATASET)
    with pytest.raises(CategoryDBError) as exc:
        db.merge_records([
            {"domain": "fine.example", "categories": ["news"]},
            {"domain": "not a domain", "categories": ["news"]},
        ])
    assert "line 2" in str(exc.value)


def test_import_cli_end_to_end(tmp_path):
    records = tmp_path / "new.jsonl"
    records.write_text(
        '{"domain": "imported.example", "categories": ["education"]}\n'
        '{"domain": "youtube.com", "categories": ["music"]}\n',
        encoding="utf-8",
    )
    out = tmp_path / "merged.json"
    rc = db_tool_main([str(DATASET), "import", str(records), "--out", str(out)])
    assert rc == 0
    merged = CategoryDB.load(out)
    assert merged.categories_for("imported.example") == {"education"}
    assert merged.categories_for("youtube.com") == {"video", "entertainment", "music"}
    # Round-trip: the merged file is valid JSON in the documented format.
    raw = json.loads(out.read_text(encoding="utf-8"))
    assert set(raw) == {"_meta", "domains"}


def test_import_cli_rejects_invalid_json(tmp_path, capsys):
    records = tmp_path / "bad.jsonl"
    records.write_text("{not json}\n", encoding="utf-8")
    rc = db_tool_main([str(DATASET), "import", str(records), "--out", str(tmp_path / "x.json")])
    assert rc == 1
    assert "line 1" in capsys.readouterr().err


# -- loading invalid or unavailable data ---------------------------------------

def test_load_requires_domains_key(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"_meta": {}}', encoding="utf-8")
    with pytest.raises(CategoryDBError):
        CategoryDB.load(bad)


def test_load_rejects_non_object_top_level(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('["not", "an", "object"]', encoding="utf-8")
    with pytest.raises(CategoryDBError):
        CategoryDB.load(bad)


def test_load_rejects_non_object_domains(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"domains": ["not-a-dict"]}', encoding="utf-8")
    with pytest.raises(CategoryDBError):
        CategoryDB.load(bad)


def test_load_missing_file_raises_oserror(tmp_path):
    # Unavailable data fails loudly with the underlying OS error; the
    # service cannot start on a database that does not exist.
    with pytest.raises(OSError):
        CategoryDB.load(tmp_path / "does-not-exist.json")


# -- import edge cases -----------------------------------------------------------

def test_import_same_domain_twice_unions_in_one_file():
    db = CategoryDB.load(DATASET)
    added, updated = db.merge_records([
        {"domain": "brand-new.example", "categories": ["news"]},
        {"domain": "brand-new.example", "categories": ["education"]},
    ])
    assert (added, updated) == (1, 1)
    assert db.categories_for("brand-new.example") == {"news", "education"}


# -- type validation (non-string values must be hard errors) ---------------------

def test_non_string_category_rejected():
    # A non-string category must be a clear CategoryDBError, never an
    # unhandled AttributeError from calling .strip() on it.
    with pytest.raises(CategoryDBError, match="category must be a string"):
        CategoryDB({"ok.example": [123]})


def test_load_rejects_non_string_category(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"domains": {"ok.example": ["news", 5]}}',
                   encoding="utf-8")
    with pytest.raises(CategoryDBError, match="category must be a string"):
        CategoryDB.load(bad)


def test_import_rejects_non_string_category_with_line_number():
    db = CategoryDB.load(DATASET)
    before = db.to_dict()
    with pytest.raises(CategoryDBError) as exc:
        db.merge_records([
            {"domain": "fine.example", "categories": ["news"]},
            {"domain": "other.example", "categories": [7]},
        ])
    assert "line 2" in str(exc.value)
    assert "category must be a string" in str(exc.value)
    assert db.to_dict() == before  # atomicity preserved


def test_import_cli_rejects_non_string_category_cleanly(tmp_path, capsys):
    records = tmp_path / "bad.jsonl"
    records.write_text(
        '{"domain": "fine.example", "categories": ["news"]}\n'
        '{"domain": "other.example", "categories": [7]}\n',
        encoding="utf-8")
    out = tmp_path / "merged.json"
    rc = db_tool_main([str(DATASET), "import", str(records), "--out", str(out)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "line 2" in err
    assert "category must be a string" in err
    assert "Traceback" not in err  # clean error, no unhandled traceback
    assert not out.exists()  # no partially updated database written


def test_non_string_domain_rejected():
    with pytest.raises(CategoryDBError, match="domain must be a string"):
        validate_domain(123)
    # In an import record: rejected with its line number, never silently
    # stringified, and the database is left unchanged.
    db = CategoryDB.load(DATASET)
    before = db.to_dict()
    with pytest.raises(CategoryDBError) as exc:
        db.merge_records([{"domain": 42, "categories": ["news"]}])
    assert "line 1" in str(exc.value)
    assert "domain must be a string" in str(exc.value)
    assert db.to_dict() == before


def test_failed_import_leaves_database_unchanged():
    """Regression: a malformed record must abort the import BEFORE any
    record is applied - a partially applied import is a silently wrong
    database, and the documented abort guarantee must hold for the
    in-memory merge too, not only for the CLI's file write."""
    db = CategoryDB.load(DATASET)
    before = db.to_dict()
    with pytest.raises(CategoryDBError, match="line 2"):
        db.merge_records([
            {"domain": "fine.example", "categories": ["news"]},
            {"domain": "not a domain", "categories": ["news"]},
        ])
    assert db.to_dict() == before
    assert db.categories_for("fine.example") == set()

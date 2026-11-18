"""Regression tests for the OpenStep plist parser gate in
tools/validate-ios-project.py. The parser exists because a hand edit
once dropped a comma between pbxproj array items: the textual checks
passed, xcodebuild rejected the file as damaged (CI run 44223017300).
These tests pin THAT mutant and other malformed shapes so the gate
cannot silently weaken."""

import importlib.util
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "validate_ios_project", TOOLS / "validate-ios-project.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

parse = module.parse_pbxproj
PbxParseError = module.PbxParseError
PBX_TEXT = (TOOLS.parent / "ios" / "KosherGuard.xcodeproj"
            / "project.pbxproj").read_text()


def test_current_project_parses():
    root = parse(PBX_TEXT)
    objects = root.get("objects")
    assert isinstance(objects, dict) and len(objects) > 100
    assert objects[root["rootObject"]]["isa"] == "PBXProject"


def test_the_actual_missing_comma_regression_is_rejected():
    # The exact mutant that broke the Xcode build.
    bad = PBX_TEXT.replace(
        "/* URLFilterControlProvider.swift */, KG6a",
        "/* URLFilterControlProvider.swift */ KG6a")
    assert bad != PBX_TEXT
    with pytest.raises(PbxParseError, match="missing ','"):
        parse(bad)


@pytest.mark.parametrize("mutant", [
    # Missing dict semicolon.
    PBX_TEXT.replace("isa = PBXProject;", "isa = PBXProject", 1),
    # Unbalanced brace.
    PBX_TEXT.rstrip()[:-1],
    # Trailing garbage after the root.
    PBX_TEXT + "junk",
    # Empty file.
    "",
])
def test_malformed_mutants_are_rejected(mutant):
    with pytest.raises(PbxParseError):
        parse(mutant)


def test_arrays_and_comments_parse():
    root = parse('{ a = (one, "two", /* c */ three,); b = { c = d; }; }')
    assert root["a"] == ["one", "two", "three"]
    assert root["b"] == {"c": "d"}

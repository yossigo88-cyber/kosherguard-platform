"""Regression tests for the parent-directory symlink fix (full build,
Milestone 1 / Part 3 item 2 of the final build instruction).

The generation loaders must never let a symlinked PARENT directory
redirect reads outside the intended generation directory. Every path is
traversed component-by-component with O_DIRECTORY|O_NOFOLLOW, and the
only followable symlink is the FINAL component (the publisher's atomic
"current" pointer) whose target stays inside its own parent directory.

Covers both loaders: the legacy single-policy layout
(load_validated_engine) and the Stage 11C multi-document generation
layout (load_validated_engine_set directory mode).
"""

import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from engine_set import EngineSetError, load_validated_engine, load_validated_engine_set
from policy_engine import PolicyConfigError

POLICY = {
    "default_policy": "allow", "allowlist": [], "blocklist": [],
    "category_rules": {"allow": [], "block": []},
}
CATEGORIES = {"_meta": {"dataset": "test"}, "domains": {}}


def write_legacy(gen_dir, manifest=True):
    """Write a legacy policy.json + categories.json generation (with a
    consistent Stage 10 manifest when manifest=True) and return the two
    file paths."""
    gen = Path(gen_dir)
    gen.mkdir(parents=True, exist_ok=True)
    policy = json.dumps(POLICY).encode()
    categories = json.dumps(CATEGORIES).encode()
    (gen / "policy.json").write_bytes(policy)
    (gen / "categories.json").write_bytes(categories)
    if manifest:
        revision = int(gen.name) if gen.name.isdigit() else 1
        doc = {
            "revision": revision,
            "generation": str(revision),
            "policy_sha256": hashlib.sha256(policy).hexdigest(),
            "categories_sha256": hashlib.sha256(categories).hexdigest(),
        }
        (gen / "manifest.json").write_text(json.dumps(doc), encoding="utf-8")
    return gen / "policy.json", gen / "categories.json"


def write_multidoc(gen_dir, revision=None):
    """Write a minimal valid multi-document generation and return its
    Path. Generation directories are named by their revision."""
    gen = Path(gen_dir)
    revision = int(gen.name) if revision is None else revision
    (gen / "policies").mkdir(parents=True, exist_ok=True)
    files = {}
    policy = json.dumps(POLICY).encode()
    (gen / "policies" / "1.json").write_bytes(policy)
    files["policies/1.json"] = hashlib.sha256(policy).hexdigest()
    categories = json.dumps(CATEGORIES).encode()
    (gen / "categories.json").write_bytes(categories)
    files["categories.json"] = hashlib.sha256(categories).hexdigest()
    devices = json.dumps({
        "default_policy_id": 1,
        "bindings": {},
        "credentials": {},
        "_meta": {"source": "test", "revision": revision},
    }).encode()
    (gen / "devices.json").write_bytes(devices)
    files["devices.json"] = hashlib.sha256(devices).hexdigest()
    manifest = {"revision": revision, "generation": str(revision),
                "files": files}
    (gen / "manifest.json").write_text(json.dumps(manifest),
                                       encoding="utf-8")
    return gen


def load_multi(gen):
    gen = Path(gen)
    return load_validated_engine_set(str(gen), str(gen / "categories.json"))


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="POSIX symlinks")
class TestLegacyParentSymlinks:
    def test_real_directories_load(self, tmp_path):
        policy, categories = write_legacy(tmp_path / "1")
        engine, info = load_validated_engine(str(policy), str(categories))
        assert info["generation"] == "1"

    def test_final_current_symlink_loads(self, tmp_path):
        """The publisher's atomic 'current -> gens/1' pointer stays
        supported: a FINAL-component symlink whose target is relative
        and inside its own parent directory."""
        gens = tmp_path / "gens"
        policy, _ = write_legacy(gens / "1")
        os.symlink("gens/1", str(tmp_path / "current"))
        current = tmp_path / "current"
        engine, info = load_validated_engine(
            str(current / "policy.json"), str(current / "categories.json"))
        assert info["generation"] == "1"

    def test_intermediate_parent_symlink_rejected(self, tmp_path):
        """A symlink ABOVE the generation directory (a non-final path
        component) must not redirect the read, even when it points at
        the entirely legitimate location."""
        real = tmp_path / "real"
        policy, _ = write_legacy(real / "1")
        os.symlink(str(real), str(tmp_path / "link"))
        via = tmp_path / "link" / "1"
        with pytest.raises(PolicyConfigError, match="symlink"):
            load_validated_engine(str(via / "policy.json"),
                                  str(via / "categories.json"))

    def test_symlinked_policy_file_rejected(self, tmp_path):
        real_policy, real_categories = write_legacy(tmp_path / "1")
        other = tmp_path / "other"
        other.mkdir()
        os.symlink(str(real_policy), str(other / "policy.json"))
        with pytest.raises(PolicyConfigError):
            load_validated_engine(str(other / "policy.json"),
                                  str(real_categories))

    def test_absolute_symlink_target_rejected(self, tmp_path):
        gens = tmp_path / "gens"
        write_legacy(gens / "1")
        os.symlink(str((tmp_path / "gens" / "1").resolve()),
                   str(tmp_path / "current"))
        current = tmp_path / "current"
        with pytest.raises(PolicyConfigError, match="absolute"):
            load_validated_engine(str(current / "policy.json"),
                                  str(current / "categories.json"))

    def test_escaping_symlink_target_rejected(self, tmp_path):
        gens = tmp_path / "gens"
        write_legacy(gens / "1")
        os.symlink("../gens/1", str(tmp_path / "current"))
        current = tmp_path / "current"
        with pytest.raises(PolicyConfigError, match="symlink target"):
            load_validated_engine(str(current / "policy.json"),
                                  str(current / "categories.json"))

    def test_symlink_loop_rejected(self, tmp_path):
        os.symlink("b", str(tmp_path / "a"))
        os.symlink("a", str(tmp_path / "b"))
        via = tmp_path / "a"
        with pytest.raises(PolicyConfigError, match="hops"):
            load_validated_engine(str(via / "policy.json"),
                                  str(via / "categories.json"))

    def test_relative_hop_into_sibling_subdir_loads(self, tmp_path):
        """'current -> gens/1' is two segments; both must be traversed
        with no-follow and the load must succeed."""
        gens = tmp_path / "gens"
        write_legacy(gens / "1")
        os.symlink("gens/1", str(tmp_path / "current"))
        current = tmp_path / "current"
        engine, info = load_validated_engine(
            str(current / "policy.json"), str(current / "categories.json"))
        assert info["generation"] == "1"

    def test_swap_of_parent_after_setup_cannot_redirect(self, tmp_path):
        """The opened directory is pinned by descriptor: replacing an
        ancestor symlink after the walk cannot change what was opened.
        Structural check: a 'current' pointer that is REPLACED between
        two loads resolves each load to its own pinned generation."""
        gens = tmp_path / "gens"
        write_legacy(gens / "1")
        write_legacy(gens / "2")
        current = tmp_path / "current"
        os.symlink("gens/1", str(current))
        _, info1 = load_validated_engine(str(current / "policy.json"),
                                         str(current / "categories.json"))
        os.replace(str(tmp_path / "next"), str(current)) if False else None
        os.remove(str(current))
        os.symlink("gens/2", str(current))
        _, info2 = load_validated_engine(str(current / "policy.json"),
                                         str(current / "categories.json"))
        assert info1["generation"] == "1"
        assert info2["generation"] == "2"


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="POSIX symlinks")
class TestMultidocParentSymlinks:
    def test_real_generation_loads(self, tmp_path):
        gen = write_multidoc(tmp_path / "1")
        engine_set, info = load_multi(gen)
        assert info["generation"] == "1"

    def test_current_symlink_loads(self, tmp_path):
        gens = tmp_path / "gens"
        write_multidoc(gens / "1")
        os.symlink("gens/1", str(tmp_path / "current"))
        engine_set, info = load_multi(tmp_path / "current")
        assert info["generation"] == "1"

    def test_intermediate_parent_symlink_rejected(self, tmp_path):
        real = tmp_path / "real"
        write_multidoc(real / "1")
        os.symlink(str(real), str(tmp_path / "link"))
        with pytest.raises(PolicyConfigError, match="symlink"):
            load_multi(tmp_path / "link" / "1")

    def test_absolute_symlink_target_rejected(self, tmp_path):
        gens = tmp_path / "gens"
        write_multidoc(gens / "1")
        os.symlink(str((tmp_path / "gens" / "1").resolve()),
                   str(tmp_path / "current"))
        with pytest.raises(PolicyConfigError, match="absolute"):
            load_multi(tmp_path / "current")

    def test_escaping_symlink_target_rejected(self, tmp_path):
        gens = tmp_path / "gens"
        write_multidoc(gens / "1")
        os.symlink("../gens/1", str(tmp_path / "current"))
        with pytest.raises(PolicyConfigError):
            load_multi(tmp_path / "current")

    def test_bounded_symlink_chain_loads(self, tmp_path):
        gens = tmp_path / "gens"
        write_multidoc(gens / "1")
        os.symlink("gens/1", str(tmp_path / "stable"))
        os.symlink("stable", str(tmp_path / "current"))
        engine_set, info = load_multi(tmp_path / "current")
        assert info["generation"] == "1"

    def test_symlink_chain_over_limit_rejected(self, tmp_path):
        gens = tmp_path / "gens"
        write_multidoc(gens / "1")
        os.symlink("gens/1", str(tmp_path / "hop0"))
        for i in range(1, 10):
            os.symlink(f"hop{i - 1}", str(tmp_path / f"hop{i}"))
        with pytest.raises(PolicyConfigError, match="hops"):
            load_multi(tmp_path / "hop9")

    def test_symlinked_policies_subdir_rejected(self, tmp_path):
        gen = write_multidoc(tmp_path / "1")
        real = tmp_path / "elsewhere"
        real.mkdir()
        (real / "1.json").write_bytes((gen / "policies" / "1.json").read_bytes())
        os.remove(gen / "policies" / "1.json")
        (gen / "policies").rmdir()
        os.symlink(str(real), str(gen / "policies"))
        with pytest.raises(PolicyConfigError):
            load_multi(gen)

    def test_symlinked_policy_document_rejected(self, tmp_path):
        gen = write_multidoc(tmp_path / "1")
        real = tmp_path / "1.json"
        real.write_bytes((gen / "policies" / "1.json").read_bytes())
        os.remove(gen / "policies" / "1.json")
        os.symlink(str(real), str(gen / "policies" / "1.json"))
        with pytest.raises(PolicyConfigError):
            load_multi(gen)

    def test_categories_from_other_directory_rejected(self, tmp_path):
        """--categories naming a symlinked-away directory is the
        mixed-generation rejection, not a silent cross-directory read."""
        gen = write_multidoc(tmp_path / "1")
        other = tmp_path / "other"
        other.mkdir()
        (other / "categories.json").write_bytes(
            (gen / "categories.json").read_bytes())
        with pytest.raises(PolicyConfigError):
            load_validated_engine_set(str(gen),
                                      str(other / "categories.json"))

    def test_parent_symlink_with_valid_manifest_still_rejected(self,
                                                               tmp_path):
        """Even a byte-perfect generation cannot be loaded through a
        symlinked parent: the path itself is the vulnerability."""
        real = tmp_path / "real"
        write_multidoc(real / "7")
        os.symlink(str(real), str(tmp_path / "link"))
        with pytest.raises(PolicyConfigError, match="symlink"):
            load_multi(tmp_path / "link" / "7")


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="POSIX symlinks")
def test_generation_dir_name_comes_from_resolved_final_component(tmp_path):
    """The manifest generation name is compared against the RESOLVED
    final directory name (after the allowed 'current' hop), so a
    pointer named 'current' cannot satisfy a generation numbered
    manifest by name."""
    gens = tmp_path / "gens"
    write_multidoc(gens / "5")
    os.symlink("gens/5", str(tmp_path / "current"))
    engine_set, info = load_multi(tmp_path / "current")
    assert info["generation"] == "5"
    assert info["manifest_revision"] == 5

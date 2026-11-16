"""Generation publisher adapted from the security-reviewed dashboard
publisher (Stage 11C, audited in Milestone 1 review).

Publishing discipline, unchanged from the reviewed source: validate
with the engine's own validators before writing; a generation directory
is written once and never overwritten; files are 0600 written via
temp + atomic rename inside a 0700 tree; the on-disk generation is
re-read and re-verified before the "current" symlink is switched by
atomic rename; a failed publish removes the partial generation and
leaves "current" untouched. Publishes serialize across threads and
processes with a lock file.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import threading
import time
from pathlib import Path

_ENGINE_SRC = os.path.join(os.path.dirname(__file__), "..", "..",
                           "filtering-engine", "src")
if os.path.abspath(_ENGINE_SRC) not in sys.path:
    sys.path.insert(0, os.path.abspath(_ENGINE_SRC))

import category_db  # noqa: E402
import policy_engine  # noqa: E402


class PublicationError(Exception):
    """A publication step failed; the previous generation is unchanged."""


def canonical_json(obj) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode("utf-8")


def validate_engine_documents(policy_obj, categories_obj) -> None:
    """Validate both documents with the filtering engine's own code."""
    if not isinstance(policy_obj, dict):
        raise policy_engine.PolicyConfigError("policy document must be an object")
    policy_engine.validate_policy(policy_obj)
    if not isinstance(categories_obj, dict) or not isinstance(
            categories_obj.get("domains"), dict):
        raise category_db.CategoryDBError(
            "categories document must be an object with a 'domains' object")
    category_db.CategoryDB(categories_obj["domains"],
                           meta=categories_obj.get("_meta", {}))


def _write_file_atomic(path: Path, content: bytes, token: str) -> None:
    """Write via unique temp file + atomic rename, mode 0600."""
    tmp = path.with_name(f"{path.name}.{token}.tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(str(tmp), 0o600)
        os.rename(str(tmp), str(path))
    except BaseException:
        try:
            os.unlink(str(tmp))
        except OSError:
            pass
        raise


class Publisher:
    """Publishes validated engine configuration generations under a root."""

    def __init__(self, root):
        self.root = Path(root)
        self.generations_dir = self.root / "generations"
        self.current_link = self.root / "current"
        self.lock_path = self.root / ".publish.lock"
        self._local_lock = threading.Lock()

    def ensure_root(self) -> None:
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.generations_dir.mkdir(mode=0o700, exist_ok=True)
        os.chmod(self.root, 0o700)
        os.chmod(self.generations_dir, 0o700)

    def locked(self):
        publisher = self

        class _Lock:
            def __enter__(self):
                publisher._local_lock.acquire()
                publisher.ensure_root()
                fd = os.open(str(publisher.lock_path),
                             os.O_CREAT | os.O_RDWR, 0o600)
                fcntl.flock(fd, fcntl.LOCK_EX)
                self._fd = fd
                return self

            def __exit__(self, *exc):
                try:
                    fcntl.flock(self._fd, fcntl.LOCK_UN)
                    os.close(self._fd)
                finally:
                    publisher._local_lock.release()
                return False

        return _Lock()

    def _remove_stale_temp_files(self, generation_dir: Path) -> None:
        for entry in generation_dir.iterdir():
            if entry.name.endswith(".tmp"):
                try:
                    entry.unlink()
                except OSError:
                    pass

    def publish(self, revision: int, policy_bytes: bytes,
                categories_bytes: bytes, metadata: dict) -> str:
        """Write, verify, and atomically activate one generation.

        The caller must hold locked(). Raises PublicationError (or the
        engine's validation errors) on failure; "current" is untouched.
        """
        self.ensure_root()
        token = f"{os.getpid()}.{threading.get_ident()}.{time.monotonic_ns()}"

        try:
            policy_obj = json.loads(policy_bytes.decode("utf-8"))
            categories_obj = json.loads(categories_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PublicationError(
                f"internal error: export produced invalid JSON: {exc}")
        try:
            validate_engine_documents(policy_obj, categories_obj)
        except (policy_engine.PolicyConfigError,
                category_db.CategoryDBError) as exc:
            raise PublicationError(
                f"exported configuration failed engine validation: {exc}")

        generation = str(revision)
        generation_dir = self.generations_dir / generation
        try:
            # A revision number is used once; an existing directory means
            # a serious bug or a replay - refuse, never overwrite.
            os.mkdir(str(generation_dir), 0o700)
            _write_file_atomic(generation_dir / "policy.json", policy_bytes, token)
            _write_file_atomic(generation_dir / "categories.json",
                               categories_bytes, token)
            manifest = dict(metadata)
            manifest.update({
                "revision": revision,
                "generation": generation,
                "policy_sha256": hashlib.sha256(policy_bytes).hexdigest(),
                "categories_sha256": hashlib.sha256(categories_bytes).hexdigest(),
                "files": ["policy.json", "categories.json"],
            })
            _write_file_atomic(generation_dir / "manifest.json",
                               canonical_json(manifest), token)
            self._remove_stale_temp_files(generation_dir)
            self.verify_generation(generation_dir)
            self._activate(generation, token)
            return generation
        except BaseException:
            try:
                shutil.rmtree(str(generation_dir))
            except OSError:
                pass
            raise

    def _activate(self, generation: str, token: str) -> None:
        """Atomically point "current" at the generation."""
        tmp_link = self.root / f".current.{token}.tmp"
        try:
            tmp_link.unlink()
        except FileNotFoundError:
            pass
        # Relative target so the tree can be moved or bind-mounted.
        os.symlink(f"generations/{generation}", str(tmp_link))
        os.rename(str(tmp_link), str(self.current_link))

    def _check_manifest(self, manifest, generation_dir: Path,
                        generation: str) -> None:
        if not isinstance(manifest, dict):
            raise PublicationError(f"{generation_dir}: manifest is not an object")
        if manifest.get("revision") != int(generation) or \
                manifest.get("generation") != generation:
            raise PublicationError(f"{generation_dir}: manifest identity mismatch")
        for name in ("policy", "categories"):
            digest = manifest.get(f"{name}_sha256")
            if not isinstance(digest, str) or len(digest) != 64:
                raise PublicationError(f"{generation_dir}: bad {name} hash")
            actual = hashlib.sha256(
                (generation_dir / f"{name}.json").read_bytes()).hexdigest()
            if digest != actual:
                raise PublicationError(
                    f"{generation_dir}: {name}.json hash mismatch")

    def verify_generation(self, generation_dir: Path) -> dict:
        """Re-read the on-disk generation and prove it against the manifest."""
        generation = generation_dir.name
        policy_bytes = (generation_dir / "policy.json").read_bytes()
        categories_bytes = (generation_dir / "categories.json").read_bytes()
        manifest_bytes = (generation_dir / "manifest.json").read_bytes()
        try:
            policy_obj = json.loads(policy_bytes.decode("utf-8"))
            categories_obj = json.loads(categories_bytes.decode("utf-8"))
            manifest = json.loads(manifest_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PublicationError(f"{generation_dir}: corrupt JSON: {exc}")
        self._check_manifest(manifest, generation_dir, generation)
        validate_engine_documents(policy_obj, categories_obj)
        for name in ("policy.json", "categories.json", "manifest.json"):
            mode = stat.S_IMODE(os.stat(str(generation_dir / name)).st_mode)
            if mode != 0o600:
                raise PublicationError(
                    f"{generation_dir}/{name}: mode {oct(mode)} != 0o600")
        return manifest

    def current(self) -> dict | None:
        """Manifest of the active generation, or None when unpublished."""
        if not self.current_link.is_symlink():
            return None
        generation_dir = (self.root / os.readlink(str(self.current_link))).resolve()
        if generation_dir.parent != self.generations_dir.resolve():
            raise PublicationError("current points outside generations/")
        return self.verify_generation(generation_dir)

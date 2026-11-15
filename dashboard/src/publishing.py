"""Generation-based publication of engine configuration (Stage 10).

The filtering engine reads two JSON documents: a policy file and a
category-database file. They must always come from the SAME published
configuration: a policy from one generation with categories from
another would silently mis-filter. This module makes mixed-generation
loads impossible by construction:

Layout under the publication root directory:

    <root>/
        generations/
            1/
                policy.json       (mode 0600)
                categories.json   (mode 0600)
                manifest.json     (mode 0600): revision, content hashes
            2/ ...
        current -> generations/2   (symlink; the ONLY mutable pointer)
        .publish.lock              (advisory lock serializing publishes)

Publication protocol (all on the same filesystem, POSIX semantics; the
deployment target is Linux under systemd, which guarantees them):

1. The complete generation is validated IN MEMORY with the filtering
   engine's own validators before anything is written.
2. A new generation directory generations/<revision> is created with
   mode 0700. It never exists before this publish (O_EXCL), so two
   publishes can never write the same generation.
3. policy.json and categories.json are each written to a uniquely named
   temporary file inside the generation directory and atomically
   renamed into place (0600). A crash can leave a stale temporary file,
   never a partially written final file.
4. manifest.json records the revision and the SHA-256 of both final
   files.
5. The files are RE-READ FROM DISK, re-validated with the engine's
   validators, and their hashes compared with the manifest. Only what
   is actually on disk and verified may become live.
6. The "current" symlink is switched atomically: a new temporary
   symlink is created and renamed over "current" (rename(2) is atomic
   on POSIX). A reader therefore sees either the complete old
   generation or the complete new generation - never a mixture, and
   never a generation that failed validation.

Any failure before step 6 leaves "current" pointing at the previous
generation, which remains complete and unchanged. The partial
generation directory is removed best-effort.

Concurrent publishers are serialized with an flock(2) advisory lock on
<root>/.publish.lock held for the whole operation.

The engine reads through <root>/current/policy.json and
<root>/current/categories.json. Its reload path re-verifies the
manifest hashes (see filtering-engine/src/dns_service.py), so a
corrupted generation is rejected even if it somehow became the current
one.

Permissions: the root and generation directories are 0700 and the
files 0600, matching the Stage 9B backup hardening. The dashboard and
the DNS service must run as the same user (the deployment units do).
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import threading
import time
from pathlib import Path

from engine_bridge import CategoryDB, CategoryDBError, PolicyConfigError, validate_policy


class PublicationError(Exception):
    """A publication step failed; the previous generation is unchanged."""


_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj) -> bytes:
    """Deterministic JSON encoding for exported configuration documents."""
    return (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode("utf-8")


def validate_engine_documents(policy_obj, categories_obj) -> None:
    """Validate both documents with the filtering engine's own code.

    Raises PolicyConfigError / CategoryDBError on the first problem. The
    dashboard never ships its own policy logic; this call is the same
    validation the engine itself performs at startup.
    """
    validate_policy(policy_obj)
    if not isinstance(categories_obj, dict) or not isinstance(categories_obj.get("domains"), dict):
        raise CategoryDBError("categories document must be an object with a 'domains' object")
    CategoryDB(categories_obj["domains"], meta=categories_obj.get("_meta", {}))


def _write_file_atomic(path: Path, content: bytes, token: str) -> None:
    """Write content to path via a unique temp file + atomic rename.

    The temp file lives in the same directory (same filesystem, so the
    rename is atomic) and carries a unique token so concurrent or
    retried writes never collide. The final file is 0600.
    """
    fd, tmp = tempfile.mkstemp(
        prefix=path.name + ".", suffix=f".{token}.tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
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
        # A process-local lock as well: flock serializes across
        # processes, this serializes threads inside this process.
        self._local_lock = threading.Lock()

    def ensure_root(self) -> None:
        """Create the root layout (0700) if missing; verify it otherwise."""
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.generations_dir.mkdir(mode=0o700, exist_ok=True)
        os.chmod(self.root, 0o700)
        os.chmod(self.generations_dir, 0o700)

    def locked(self):
        """Serialize publishes across threads and processes."""
        publisher = self

        class _Lock:
            def __enter__(self):
                publisher._local_lock.acquire()
                publisher.ensure_root()
                fd = os.open(str(publisher.lock_path), os.O_CREAT | os.O_RDWR, 0o600)
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

    def publish(self, revision: int, policy_bytes: bytes, categories_bytes: bytes,
                metadata: dict) -> str:
        """Write, verify, and atomically activate one generation.

        revision: the config_revisions row id; generation directories are
        named after it, which makes collisions between publishes
        impossible. metadata is recorded in manifest.json alongside the
        content hashes. Returns the generation name ("<revision>").

        The caller must hold locked(). Raises PublicationError (or the
        engine's validation errors) on failure; "current" is untouched.
        """
        self.ensure_root()
        token = f"{os.getpid()}.{threading.get_ident()}.{time.monotonic_ns()}"

        # Step 1: validate the in-memory documents with the engine's own
        # validators before writing anything.
        try:
            policy_obj = json.loads(policy_bytes.decode("utf-8"))
            categories_obj = json.loads(categories_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PublicationError(f"internal error: export produced invalid JSON: {exc}")
        try:
            validate_engine_documents(policy_obj, categories_obj)
        except (PolicyConfigError, CategoryDBError) as exc:
            raise PublicationError(f"exported configuration failed engine validation: {exc}")

        generation = str(revision)
        generation_dir = self.generations_dir / generation
        try:
            # Step 2: the generation directory must not exist yet; a
            # revision number is used once, so an existing directory
            # means a serious bug or a replay - refuse, never overwrite.
            os.mkdir(str(generation_dir), 0o700)

            # Step 3: write both documents atomically (0600).
            _write_file_atomic(generation_dir / "policy.json", policy_bytes, token)
            _write_file_atomic(generation_dir / "categories.json", categories_bytes, token)

            # Step 4: manifest with the hashes of what was written.
            manifest = dict(metadata)
            manifest.update({
                "revision": revision,
                "generation": generation,
                "policy_sha256": sha256_bytes(policy_bytes),
                "categories_sha256": sha256_bytes(categories_bytes),
                "files": ["policy.json", "categories.json"],
            })
            _write_file_atomic(
                generation_dir / "manifest.json",
                canonical_json(manifest), token)
            self._remove_stale_temp_files(generation_dir)

            # Step 5: prove the on-disk generation, not just the memory
            # copy: re-read, re-validate, and compare hashes.
            self.verify_generation(generation_dir)

            # Step 6: atomically switch the pointer.
            self._activate(generation, token)
            return generation
        except BaseException:
            # The failed generation never becomes current; remove the
            # partial directory best-effort so it cannot be mistaken for
            # a complete one.
            try:
                shutil.rmtree(str(generation_dir))
            except OSError:
                pass
            raise

    def _activate(self, generation: str, token: str) -> None:
        """Atomically point "current" at the generation (rename of a
        freshly created symlink)."""
        target = os.path.join("generations", generation)
        tmp = self.root / f".current.{token}.tmp"
        try:
            os.symlink(target, str(tmp))
            os.replace(str(tmp), str(self.current_link))
        except BaseException:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise

    def _check_manifest(self, manifest, generation_dir: Path,
                        policy_bytes: bytes, categories_bytes: bytes) -> None:
        """Fail-closed manifest validation, compatible with the
        engine's own rules in
        filtering-engine/src/dns_service.py:_validate_generation_manifest:
        a JSON object; both hashes present as 64-character lowercase
        SHA-256 hex; a non-negative-integer revision; a generation string
        equal to str(revision) and to the generation directory name;
        and both hashes matching the actual file bytes. Raises
        PublicationError on any defect."""
        if not isinstance(manifest, dict):
            raise PublicationError(
                f"generation {generation_dir.name}: manifest is not a JSON object")
        for key, data in (("policy_sha256", policy_bytes),
                          ("categories_sha256", categories_bytes)):
            value = manifest.get(key)
            if not isinstance(value, str) or not _SHA256_HEX.fullmatch(value):
                raise PublicationError(
                    f"generation {generation_dir.name}: manifest {key} is "
                    "missing or not a valid 64-character SHA-256 "
                    "hexadecimal value")
            if value != sha256_bytes(data):
                raise PublicationError(
                    f"generation {generation_dir.name}: "
                    f"{'policy.json' if key == 'policy_sha256' else 'categories.json'}"
                    " hash mismatch")
        revision = manifest.get("revision")
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
            raise PublicationError(
                f"generation {generation_dir.name}: manifest revision is "
                "missing or not a non-negative integer")
        generation = manifest.get("generation")
        if not isinstance(generation, str) or not generation:
            raise PublicationError(
                f"generation {generation_dir.name}: manifest generation is "
                "missing or not a non-empty string")
        if generation != str(revision):
            raise PublicationError(
                f"generation {generation_dir.name}: manifest generation "
                f"{generation!r} is inconsistent with revision {revision}")
        if generation != generation_dir.name:
            raise PublicationError(
                f"generation {generation_dir.name}: manifest generation "
                f"{generation!r} does not match its directory name")

    def verify_generation(self, generation_dir: Path) -> dict:
        """Re-read a generation from disk, validate it with the engine's
        own code, and verify the manifest strictly (structure, metadata
        consistency, and hashes). Returns the manifest.
        Raises PublicationError on any mismatch."""
        generation_dir = Path(generation_dir)
        manifest_path = generation_dir / "manifest.json"
        # Same rule as the engine (dns_service.load_validated_engine):
        # the manifest path itself must be a regular file. lstat, never
        # is_file: a symlink - even to a valid regular file - is
        # rejected, along with directories and every other non-regular
        # entry. A missing manifest in a generation directory the
        # publisher itself wrote is equally a failure.
        try:
            manifest_stat = os.lstat(manifest_path)
        except OSError as exc:
            raise PublicationError(
                f"generation {generation_dir.name}: manifest.json: {exc}")
        if not stat.S_ISREG(manifest_stat.st_mode):
            raise PublicationError(
                f"generation {generation_dir.name}: manifest.json is not "
                "a regular file (symlink, directory, or other "
                "non-regular entry)")
        try:
            policy_bytes = (generation_dir / "policy.json").read_bytes()
            categories_bytes = (generation_dir / "categories.json").read_bytes()
            manifest = json.loads(manifest_path.read_text("utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PublicationError(f"generation {generation_dir.name}: unreadable: {exc}")
        self._check_manifest(manifest, generation_dir, policy_bytes, categories_bytes)
        try:
            validate_engine_documents(
                json.loads(policy_bytes.decode("utf-8")),
                json.loads(categories_bytes.decode("utf-8")),
            )
        except (PolicyConfigError, CategoryDBError, UnicodeDecodeError,
                json.JSONDecodeError) as exc:
            raise PublicationError(
                f"generation {generation_dir.name}: failed engine validation: {exc}")
        return manifest

    def current(self) -> dict | None:
        """Describe the currently published generation, or None.

        The source of truth is the symlink on disk, not the database:
        this reports what a reader of <root>/current would actually get.
        """
        if not self.current_link.is_symlink():
            return None
        try:
            resolved = self.current_link.resolve(strict=True)
        except OSError:
            return {"broken": True, "target": os.readlink(str(self.current_link))}
        manifest = self.verify_generation(resolved)
        return {
            "generation": resolved.name,
            "path": str(resolved),
            "manifest": manifest,
        }

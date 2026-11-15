"""Fail-closed generation file I/O for the KosherGuard filtering engine.

One published configuration generation is a set of files that must always
be loaded TOGETHER: a policy from one generation with categories from
another would silently mis-filter. This module owns the low-level rules
for reading generation files safely, shared by the legacy single-policy
loader (dns_service.load_validated_engine) and the Stage 11C
multi-policy engine-set loader (engine_set.load_validated_engine_set):

- Every generation file is opened fail-closed: os.open with O_NOFOLLOW
  (the final path component cannot be a symlink of any kind), plus
  O_CLOEXEC and O_NONBLOCK where the platform offers them (so an
  unexpected FIFO cannot hang the open). os.fstat on the OPENED
  descriptor must show a regular file before any byte is read, and the
  bytes come from THAT descriptor only - there is no later path-based
  reopen, so replacing the pathname after the check cannot change which
  file is read (no time-of-check/time-of-use window).
- A manifest that exists but is unusable in any way (symlink, broken
  symlink, directory, FIFO, permission error, malformed JSON, missing
  or malformed fields, hash mismatch) rejects the whole generation. It
  is NEVER silently ignored in favor of unverified loading.
- On a platform without O_NOFOLLOW there is no safe way to distinguish
  "genuinely absent" from "replaced between check and read", so the
  optional-manifest helper fails closed UNCONDITIONALLY.

The Stage 10 two-file manifest format (policy_sha256 /
categories_sha256) and the Stage 11C multi-file manifest format
(files: {relative path: sha256}) are both validated here. See
docs/reviews/STAGE_11_TECHNICAL_PLAN.md section 7.1 and
filtering-engine/README.md for the formats.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path

from policy_engine import PolicyConfigError


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


def _safe_open_manifest(manifest_path):
    """Open a generation manifest fail-closed and return its descriptor.

    Returns None only when the path is genuinely absent (the legacy
    pre-publication layout). Raises PolicyConfigError for every
    present-but-unusable entry: any symlink or broken symlink (ELOOP),
    directory, FIFO, socket, device, permission error, or an
    uninspectable descriptor. os.path.lexists() is never consulted: its
    answer could change before the caller continues.
    """
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise PolicyConfigError(
            f"generation manifest {manifest_path}: this platform lacks "
            "O_NOFOLLOW, so no manifest path can be opened safely; "
            "refusing to load (legacy no-manifest loading is "
            "unavailable on this platform)")
    flags = os.O_RDONLY | nofollow
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)  # a FIFO cannot hang the open
    try:
        fd = os.open(manifest_path, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise PolicyConfigError(
            f"generation manifest {manifest_path}: cannot open safely "
            f"({exc}); refusing to load")
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise PolicyConfigError(
                f"generation manifest {manifest_path} exists but is not "
                "a regular file (directory, FIFO, socket, device, or "
                "other non-regular entry); refusing to load")
    except BaseException:
        os.close(fd)
        raise
    return fd


def safe_open_generation_file(path, description):
    """Open a REQUIRED generation file fail-closed; return its descriptor.

    Identical protections to _safe_open_manifest (O_NOFOLLOW, regular-file
    fstat on the opened descriptor, descriptor-only reads), but the file
    is required: an absent path raises instead of returning None, and a
    platform without O_NOFOLLOW always fails closed.
    """
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise PolicyConfigError(
            f"{description} {path}: this platform lacks O_NOFOLLOW, so no "
            "generation file can be opened safely; refusing to load")
    flags = os.O_RDONLY | nofollow
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise PolicyConfigError(
            f"{description} {path}: cannot open safely ({exc}); "
            "refusing to load")
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise PolicyConfigError(
                f"{description} {path} exists but is not a regular file "
                "(directory, FIFO, socket, device, or other non-regular "
                "entry); refusing to load")
    except BaseException:
        os.close(fd)
        raise
    return fd


def read_fd_bytes(fd, description) -> bytes:
    """Read all bytes from an already-verified descriptor, closing it on
    every path. The descriptor pins the opened file, which is what removes
    the time-of-check/time-of-use window between verifying the entry type
    and reading its bytes."""
    try:
        fh = os.fdopen(fd, "rb")
    except OSError as exc:
        os.close(fd)
        raise PolicyConfigError(f"{description}: cannot read: {exc}")
    try:
        with fh:
            return fh.read()
    except OSError as exc:
        raise PolicyConfigError(f"{description}: cannot read: {exc}")


def _read_manifest_fd(fd, manifest_path):
    """Read and parse the manifest from the already-verified
    descriptor; close the descriptor on every path."""
    data = read_fd_bytes(fd, f"generation manifest {manifest_path}")
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PolicyConfigError(
            f"unreadable generation manifest {manifest_path}: {exc}")


def load_json_strict(data: bytes, description: str):
    """Parse a JSON document, rejecting ANY duplicate object key.

    A hand-edited or corrupted document must not smuggle two values for
    one field past the loader: JSON's usual last-key-wins behavior would
    silently discard one of them (for example one of two identical
    binding keys, or two entries for one policy file in a manifest).
    Raises PolicyConfigError naming the duplicate key or the parse
    error.
    """
    def no_duplicates(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise PolicyConfigError(
                    f"{description}: duplicate key {key!r}; refusing to load")
            obj[key] = value
        return obj

    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PolicyConfigError(f"{description}: invalid JSON: {exc}")


def _validate_generation_manifest(manifest, policy_path, categories_path,
                                  policy_sha256, categories_sha256):
    """Fail-closed validation of a legacy Stage 10 generation manifest.

    When a manifest.json exists it MUST be complete, well-formed, and
    internally consistent with the generation being loaded; anything
    less is a corrupted or tampered publication and is rejected rather
    than silently falling back to unverified file loading. Required:
    a JSON object; both content hashes present and each a 64-character
    lowercase SHA-256 hexadecimal string; a non-negative-integer revision;
    a non-empty generation string equal to str(revision) AND to the
    resolved generation directory name; and both hashes matching the
    actual file bytes exactly. Raises PolicyConfigError on any defect.
    """
    manifest_path = Path(policy_path).parent / "manifest.json"
    if not isinstance(manifest, dict):
        raise PolicyConfigError(
            f"generation manifest {manifest_path} is not a JSON object; "
            "refusing to load")
    for key, path in (("policy_sha256", policy_path),
                      ("categories_sha256", categories_path)):
        value = manifest.get(key)
        if not isinstance(value, str) or not _SHA256_HEX.fullmatch(value):
            raise PolicyConfigError(
                f"generation manifest {manifest_path}: {key} is missing or "
                "not a valid 64-character SHA-256 hexadecimal value; "
                "refusing to load")
    revision = manifest.get("revision")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        raise PolicyConfigError(
            f"generation manifest {manifest_path}: revision is missing or "
            "not a non-negative integer; refusing to load")
    generation = manifest.get("generation")
    if not isinstance(generation, str) or not generation:
        raise PolicyConfigError(
            f"generation manifest {manifest_path}: generation is missing or "
            "not a non-empty string; refusing to load")
    if generation != str(revision):
        raise PolicyConfigError(
            f"generation manifest {manifest_path}: generation {generation!r} "
            f"is inconsistent with revision {revision}; refusing to load")
    directory = os.path.basename(os.path.dirname(os.path.realpath(policy_path)))
    if generation != directory:
        raise PolicyConfigError(
            f"generation manifest {manifest_path}: generation {generation!r} "
            f"does not match its directory {directory!r} (mixed-generation "
            "or relocated file set); refusing to load")
    if manifest["policy_sha256"] != policy_sha256:
        raise PolicyConfigError(
            f"{policy_path} does not match its generation manifest "
            "(corrupted or mixed-generation file); refusing to load")
    if manifest["categories_sha256"] != categories_sha256:
        raise PolicyConfigError(
            f"{categories_path} does not match its generation manifest "
            "(corrupted or mixed-generation file); refusing to load")


# A manifest file key is a relative POSIX path naming a file INSIDE the
# generation directory: no absolute paths, no backslashes, no empty,
# "." or ".." segments, and only a conservative character set, so a
# manifest can never point the loader outside its generation (path
# traversal) or at surprising filesystem entries.
_SAFE_PATH_SEGMENT = re.compile(r"[A-Za-z0-9._-]+")

MULTIDOC_MANIFEST_KEYS = {"revision", "generation", "files", "_meta"}


def validate_manifest_path_key(key, description: str) -> None:
    """Reject an unsafe or malformed manifest file key."""
    where = f"{description}: files entry {key!r}"
    if not isinstance(key, str) or not key:
        raise PolicyConfigError(
            f"{description}: files entry keys must be non-empty relative "
            f"path strings, got {key!r}")
    if key.startswith("/") or "\\" in key or "\x00" in key:
        raise PolicyConfigError(
            f"{where}: absolute paths and backslashes are not allowed")
    segments = key.split("/")
    for segment in segments:
        if segment in ("", ".", "..") or not _SAFE_PATH_SEGMENT.fullmatch(segment):
            raise PolicyConfigError(
                f"{where}: unsafe path segment {segment!r} (empty, '.', "
                "'..', or characters outside [A-Za-z0-9._-] are not allowed)")


def validate_multidoc_manifest(manifest, generation_dir_name: str,
                               manifest_path: str) -> dict:
    """Structural validation of a Stage 11C multi-document manifest.

    Required keys: revision (non-negative integer, not a boolean),
    generation (non-empty string equal to str(revision) AND to the
    resolved generation directory name), files (a non-empty object
    mapping safe relative paths to 64-character lowercase SHA-256
    hexadecimal strings). Optional: _meta (an object). Any other key is
    rejected: the format is strict so a typo or a smuggled entry fails
    loudly. Duplicate keys anywhere in the document were already
    rejected at parse time (load_json_strict).

    Returns the validated {relative path: sha256} map. Which files the
    map must CONTAIN (the required set, and that every hash matches the
    real bytes) is verified by the caller, which knows the generation's
    semantics; this function owns structure and safety only.
    """
    if not isinstance(manifest, dict):
        raise PolicyConfigError(
            f"generation manifest {manifest_path} is not a JSON object; "
            "refusing to load")
    unknown = set(manifest) - MULTIDOC_MANIFEST_KEYS
    if unknown:
        raise PolicyConfigError(
            f"generation manifest {manifest_path}: unknown keys "
            f"{sorted(unknown)} (valid keys: {sorted(MULTIDOC_MANIFEST_KEYS)}); "
            "refusing to load")
    revision = manifest.get("revision")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        raise PolicyConfigError(
            f"generation manifest {manifest_path}: revision is missing or "
            "not a non-negative integer; refusing to load")
    generation = manifest.get("generation")
    if not isinstance(generation, str) or not generation:
        raise PolicyConfigError(
            f"generation manifest {manifest_path}: generation is missing or "
            "not a non-empty string; refusing to load")
    if generation != str(revision):
        raise PolicyConfigError(
            f"generation manifest {manifest_path}: generation {generation!r} "
            f"is inconsistent with revision {revision}; refusing to load")
    if generation != generation_dir_name:
        raise PolicyConfigError(
            f"generation manifest {manifest_path}: generation {generation!r} "
            f"does not match its directory {generation_dir_name!r} "
            "(mixed-generation or relocated file set); refusing to load")
    meta = manifest.get("_meta")
    if meta is not None and not isinstance(meta, dict):
        raise PolicyConfigError(
            f"generation manifest {manifest_path}: _meta must be an object; "
            "refusing to load")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise PolicyConfigError(
            f"generation manifest {manifest_path}: files is missing, not an "
            "object, or empty; refusing to load")
    validated = {}
    for key, value in files.items():
        validate_manifest_path_key(key, f"generation manifest {manifest_path}")
        if not isinstance(value, str) or not _SHA256_HEX.fullmatch(value):
            raise PolicyConfigError(
                f"generation manifest {manifest_path}: files entry {key!r} is "
                "not a valid 64-character SHA-256 hexadecimal value; "
                "refusing to load")
        validated[key] = value
    return validated

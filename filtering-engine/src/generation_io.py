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

import errno
import hashlib
import json
import os
import re
import stat
from pathlib import Path

from policy_engine import PolicyConfigError


class GenerationFileNotFound(PolicyConfigError):
    """A generation file is genuinely absent (ENOENT during a safe open).

    Distinct from every other PolicyConfigError so the optional legacy
    manifest helper can tell "not there" (load unverified, the legacy
    pre-publication layout) from "there but unusable" (fail closed).
    """


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
                                  policy_sha256, categories_sha256,
                                  resolved_dir_name=None):
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
    directory = (resolved_dir_name if resolved_dir_name is not None
                 else os.path.basename(os.path.dirname(
                     os.path.realpath(policy_path))))
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


# -- no-follow directory-descriptor traversal ------------------------------
#
# The safe opens above protect the FINAL component of a generation file
# path. They cannot protect its PARENTS: if any directory component
# between the filesystem root and the generation directory is a symlink,
# the path silently resolves somewhere else and the "verified" bytes can
# come from outside the intended generation directory entirely. The
# functions below close that hole by walking the path one component at a
# time with os.open(..., O_DIRECTORY | O_NOFOLLOW, dir_fd=<parent>), so:
#
# - a symlink in ANY parent component is never followed (ELOOP fails
#   closed), whether it was planted before or swapped in during the load;
# - the returned descriptor pins the exact directory that was verified,
#   so renaming or replacing any ancestor afterwards cannot change which
#   directory generation files are read from (no TOCTOU window);
# - the one deliberate exception is the publisher's atomic
#   "current -> <generation>" pattern: the FINAL directory component may
#   be a symlink whose target is a relative path staying inside the
#   symlink's own parent directory (no absolute target, no "..", no
#   backslash, segments limited to [A-Za-z0-9._-]). At most
#   _MAX_SYMLINK_HOPS such hops are followed, so symlink chains and
#   loops fail closed instead of spinning.
#
# Consequence for deployments: every directory ABOVE the generation (the
# generations root and its ancestors) must be a real directory. That
# matches the deployment layout in deploy/; a deployment that needs a
# relocated root must bind-mount or move the directory, not symlink it.

_MAX_SYMLINK_HOPS = 8


def _nofollow_supported(description):
    if getattr(os, "O_NOFOLLOW", None) is None:
        raise PolicyConfigError(
            f"{description}: this platform lacks O_NOFOLLOW, so no "
            "directory can be traversed safely; refusing to load")


def _dir_open_flags(nofollow=True):
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    if nofollow:
        flags |= os.O_NOFOLLOW
    return flags


def _validate_symlink_target(target, description):
    """Validate the target of a followable FINAL-component symlink.

    Returns the target's path segments. The target must stay inside the
    symlink's own parent directory: relative, no empty/"."//".."
    segments after normalization, no backslash or NUL, and every
    segment within the conservative manifest character set.
    """
    if not isinstance(target, str) or not target:
        raise PolicyConfigError(
            f"{description}: unreadable or empty symlink target; "
            "refusing to load")
    if target.startswith("/"):
        raise PolicyConfigError(
            f"{description}: symlink target {target!r} is absolute; a "
            "generation symlink may only point inside its own parent "
            "directory; refusing to load")
    if "\\" in target or "\x00" in target:
        raise PolicyConfigError(
            f"{description}: symlink target {target!r} contains a "
            "backslash or NUL; refusing to load")
    segments = [s for s in target.split("/") if s not in ("", ".")]
    if not segments:
        raise PolicyConfigError(
            f"{description}: symlink target {target!r} names no "
            "directory; refusing to load")
    for segment in segments:
        if segment == ".." or not _SAFE_PATH_SEGMENT.fullmatch(segment):
            raise PolicyConfigError(
                f"{description}: symlink target segment {segment!r} is "
                "unsafe ('..' or characters outside [A-Za-z0-9._-]); a "
                "generation symlink may only point inside its own "
                "parent directory; refusing to load")
    return segments


def _open_dir_chain_nofollow(path, description):
    """Open the directory `path` through a per-component no-follow walk.

    Returns (dir_fd, final_dir_name): a descriptor pinning the verified
    directory, and the resolved name of its final component (after any
    allowed final-symlink hops), which callers compare against a
    manifest's declared generation name.

    Raises PolicyConfigError (fail closed) when any parent component is
    a symlink, a component cannot be opened, the final component is a
    symlink with an unsafe/absolute/escaping target or a hop loop, the
    path is not a directory, or the platform lacks O_NOFOLLOW.
    """
    _nofollow_supported(description)
    absolute = os.path.abspath(str(path))
    queue = [c for c in absolute.split(os.sep) if c not in ("", ".")]
    fd = os.open(os.sep, _dir_open_flags(nofollow=False))
    hops = 0
    index = 0
    try:
        while index < len(queue):
            component = queue[index]
            is_final = index == len(queue) - 1
            try:
                new_fd = os.open(component, _dir_open_flags(), dir_fd=fd)
            except OSError as exc:
                # Linux reports a symlink opened with O_DIRECTORY|
                # O_NOFOLLOW as ENOTDIR, and with O_NOFOLLOW alone as
                # ELOOP; identify symlinks reliably with a no-follow
                # stat instead of trusting one errno.
                try:
                    st = os.stat(component, dir_fd=fd,
                                 follow_symlinks=False)
                    is_symlink = stat.S_ISLNK(st.st_mode)
                except OSError:
                    is_symlink = exc.errno == errno.ELOOP
                if is_symlink and is_final:
                    if hops >= _MAX_SYMLINK_HOPS:
                        raise PolicyConfigError(
                            f"{description} {path}: more than "
                            f"{_MAX_SYMLINK_HOPS} symlink hops at the "
                            "final component (symlink chain or loop); "
                            "refusing to load")
                    try:
                        target = os.readlink(component, dir_fd=fd)
                    except OSError as read_exc:
                        raise PolicyConfigError(
                            f"{description} {path}: cannot inspect "
                            f"symlink {component!r} ({read_exc}); "
                            "refusing to load")
                    segments = _validate_symlink_target(
                        target, f"{description} {path}")
                    queue[index:index + 1] = segments
                    hops += 1
                    continue
                if is_symlink:
                    raise PolicyConfigError(
                        f"{description} {path}: parent directory "
                        f"component {component!r} is a symlink; "
                        "parent-directory symlinks are never followed "
                        "because they could redirect generation reads "
                        "outside the intended directory; refusing to "
                        "load")
                if exc.errno in (errno.ENOTDIR, errno.ELOOP):
                    raise PolicyConfigError(
                        f"{description} {path}: component {component!r} "
                        "is not a directory; refusing to load")
                raise PolicyConfigError(
                    f"{description} {path}: cannot traverse component "
                    f"{component!r} safely ({exc}); refusing to load")
            os.close(fd)
            fd = new_fd
            index += 1
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            raise PolicyConfigError(
                f"{description} {path}: not a directory; refusing to "
                "load")
    except BaseException:
        os.close(fd)
        raise
    return fd, (queue[-1] if queue else os.sep)


def open_generation_dir_nofollow(path, description="generation directory"):
    """Open a generation DIRECTORY through the no-follow chain.

    Returns (dir_fd, dir_name). All generation files must then be read
    relative to dir_fd via safe_open_under / read_under, never through
    a path string again.
    """
    return _open_dir_chain_nofollow(path, description)


def open_parent_dir_nofollow(file_path, description="generation file"):
    """Open the PARENT directory of a generation file through the
    no-follow chain; returns (dir_fd, dir_name, file_name).

    The file name itself is not opened or followed here; callers open
    it relative to dir_fd with safe_open_file_under, so a symlinked
    file is still rejected at open time with O_NOFOLLOW.
    """
    absolute = os.path.abspath(str(file_path))
    parent = os.path.dirname(absolute) or os.sep
    fd, name = _open_dir_chain_nofollow(parent, description)
    return fd, name, os.path.basename(absolute)


def _check_single_name(name, description):
    if (not name) or name in (".", "..") or "/" in name or "\\" in name \
            or "\x00" in name:
        raise PolicyConfigError(
            f"{description}: unsafe file name {name!r}; refusing to "
            "load")


def _open_under_segments(dir_fd, segments, description):
    """Open segments[-1] as a regular file under dir_fd, traversing any
    leading segments as no-follow directories. Returns the pinned file
    descriptor. Never consumes dir_fd."""
    _nofollow_supported(description)
    current = os.dup(dir_fd)
    try:
        for segment in segments[:-1]:
            try:
                next_fd = os.open(segment, _dir_open_flags(),
                                  dir_fd=current)
            except OSError as exc:
                try:
                    st = os.stat(segment, dir_fd=current,
                                 follow_symlinks=False)
                    is_symlink = stat.S_ISLNK(st.st_mode)
                except OSError:
                    is_symlink = exc.errno == errno.ELOOP
                if is_symlink:
                    raise PolicyConfigError(
                        f"{description}: directory {segment!r} inside "
                        "the generation is a symlink; refusing to load")
                if exc.errno == errno.ENOENT:
                    raise GenerationFileNotFound(
                        f"{description}: cannot open safely ({exc}); "
                        "refusing to load")
                raise PolicyConfigError(
                    f"{description}: cannot traverse directory "
                    f"{segment!r} safely ({exc}); refusing to load")
            os.close(current)
            current = next_fd
        flags = (os.O_RDONLY | os.O_NOFOLLOW
                 | getattr(os, "O_CLOEXEC", 0)
                 | getattr(os, "O_NONBLOCK", 0))
        try:
            file_fd = os.open(segments[-1], flags, dir_fd=current)
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                raise GenerationFileNotFound(
                    f"{description}: cannot open safely ({exc}); "
                    "refusing to load")
            raise PolicyConfigError(
                f"{description}: cannot open safely ({exc}); refusing "
                "to load")
        try:
            if not stat.S_ISREG(os.fstat(file_fd).st_mode):
                raise PolicyConfigError(
                    f"{description} exists but is not a regular file "
                    "(directory, FIFO, socket, device, or other "
                    "non-regular entry); refusing to load")
        except BaseException:
            os.close(file_fd)
            raise
        return file_fd
    finally:
        os.close(current)


def safe_open_under(dir_fd, rel_path, description):
    """Open a manifest-safe RELATIVE path under a verified directory fd.

    rel_path must pass the same rules as a manifest files key (no
    absolute paths, '..', backslashes, or unsafe characters), so it can
    never escape the pinned directory even by naming.
    """
    validate_manifest_path_key(rel_path, description)
    return _open_under_segments(dir_fd, rel_path.split("/"), description)


def safe_open_file_under(dir_fd, name, description):
    """Open one file NAME (no directory separators) under a verified
    directory fd with O_NOFOLLOW and a regular-file fstat check."""
    _check_single_name(name, description)
    return _open_under_segments(dir_fd, [name], description)


def read_under(dir_fd, rel_path, description):
    """safe_open_under + read_fd_bytes in one call."""
    return read_fd_bytes(safe_open_under(dir_fd, rel_path, description),
                         description)


def read_file_under(dir_fd, name, description):
    """safe_open_file_under + read_fd_bytes in one call."""
    return read_fd_bytes(safe_open_file_under(dir_fd, name, description),
                         description)


def open_optional_manifest_under(dir_fd, description):
    """Open manifest.json under a verified directory fd.

    Returns the pinned descriptor, or None when the manifest is
    genuinely absent (the legacy pre-publication layout). Any
    present-but-unusable entry (symlink, directory, FIFO, permission
    error) fails closed with PolicyConfigError.
    """
    try:
        return safe_open_file_under(dir_fd, "manifest.json", description)
    except GenerationFileNotFound:
        return None


def stat_entry_under(dir_fd, name):
    """os.lstat-equivalent for one entry under a verified directory fd.

    Returns the stat result WITHOUT following a symlinked entry, so a
    caller can distinguish a real subdirectory from a planted symlink
    before deciding to descend."""
    return os.stat(name, dir_fd=dir_fd, follow_symlinks=False)

"""File and directory hashing using SHA-256.

This module provides bounded, safe hashing of files and directory trees
for forensic comparison. Files are read in 64 KB chunks — never loaded
into memory in full. Symlink escapes and file-size limits are enforced.

This module depends only on config.py. It does not import any other
wp_forensics submodule, ensuring no circular imports.
"""

import hashlib
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from wp_forensics.config import ScanConfig

CHUNK_SIZE = 64 * 1024  # 64 KB


@dataclass
class DirectoryHashes:
    """Result of hashing all regular files in a directory tree.

    ``hashes`` maps POSIX-style relative paths to SHA-256 hex digests.
    ``errors`` lists non-fatal problems (oversized files, unreadable
    files, unsafe symlinks). ``limitations`` lists scan-limit events
    that may have truncated the walk.
    ``skipped`` contains paths that were seen during traversal but not hashed
    (due to symlinks, size limits, or read errors).
    """

    hashes: dict[str, str]
    file_count: int
    total_size_bytes: int
    errors: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    skipped: set[str] = field(default_factory=set)


def is_symlink_safe(path: Path, root: Path) -> bool:
    """Check if *path* is a symlink whose target stays within *root*.

    Returns ``True`` for non-symlink paths and for symlinks that resolve
    inside *root*. Returns ``False`` for symlinks that escape *root*.

    Broken symlinks are evaluated by their resolved target path: if the
    resolved target is within *root*, the link is considered safe even
    if the target does not exist.
    """
    if not path.is_symlink():
        return True
    try:
        resolved_path = path.resolve()
        resolved_root = root.resolve()
        resolved_path.relative_to(resolved_root)
        return True
    except (ValueError, OSError, RuntimeError):
        return False


def hash_file(
    file_path: Path | str,
    max_size_bytes: int | None = None,
) -> tuple[str | None, str | None]:
    """Compute the SHA-256 hash of a single file.

    Reads the file in bounded 64 KB chunks. If *max_size_bytes* is set
    and the file exceeds it (either by stat size or bytes read), the
    hash is not computed and an error message is returned.

    Returns ``(hash_hex, error)``. On success, ``error`` is ``None``.
    On failure, ``hash_hex`` is ``None`` and ``error`` describes the
    problem.
    """
    path = Path(file_path)

    try:
        stat_info = path.stat()
    except OSError as e:
        return None, f"Could not stat file {path}: {e}"

    file_size = stat_info.st_size

    if max_size_bytes is not None and file_size > max_size_bytes:
        return None, (
            f"File exceeds max size ({file_size} > {max_size_bytes}): {path}"
        )

    try:
        h = hashlib.sha256()
        bytes_read = 0
        with open(path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                bytes_read += len(chunk)
                if max_size_bytes is not None and bytes_read > max_size_bytes:
                    return None, (
                        f"File exceeded max size during read: {path}"
         )
                h.update(chunk)
        return h.hexdigest(), None
    except PermissionError:
        return None, f"Permission denied reading file: {path}"
    except IsADirectoryError:
        return None, f"Path is a directory, not a file: {path}"
    except OSError as e:
        return None, f"OS error reading file {path}: {e}"


def hash_directory(
    root: Path | str,
    config: ScanConfig,
) -> DirectoryHashes:
    """Hash all regular files in *root* recursively.

    Walks *root* using ``os.walk``, computing SHA-256 for each file.
    Respects config limits:

    - ``max_file_size_bytes`` — files exceeding this are skipped.
    - ``max_total_size_bytes`` — walk stops when cumulative size exceeds limit.
    - ``max_file_count`` — walk stops when file count exceeds limit.
    - ``scan_timeout_seconds`` — walk stops when elapsed time exceeds limit.
    - ``follow_symlinks`` — when False (default), symlinks are skipped.
      When True, symlinks are followed only if ``is_symlink_safe`` passes.

    Non-symlink paths and symlinks that resolve within *root* are hashed.
    Relative paths use POSIX separators (``/``) for cross-platform consistency.

    Returns a :class:`DirectoryHashes` with hashes, counts, errors, and
    limitations.
    """
    print(f'hash_directory called with root={root}, config={config}', flush=True)
    root_path = Path(root)

    if not root_path.exists():
        print(f'Root does not exist: {root_path}', flush=True)
        return DirectoryHashes(
            hashes={},
            file_count=0,
            total_size_bytes=0,
            errors=[f"Root directory does not exist: {root_path}"],
        )

    if not root_path.is_dir():
        print(f'Not a directory: {root_path}', flush=True)
        return DirectoryHashes(
            hashes={},
            file_count=0,
            total_size_bytes=0,
            errors=[f"Root path is not a directory: {root_path}"],
        )

    print(f'After checks, root_resolved will be: {root_path.resolve()}', flush=True)
    root_resolved = root_path.resolve()
    print(f'About to enter the walk loop', flush=True)
    print(f'About to walk root_resolved={root_resolved}, type={type(root_resolved)}, follow_symlinks={config.follow_symlinks}', flush=True)

    hashes: dict[str, str] = {}
    errors: list[str] = []
    limitations: list[str] = []
    skipped: set[str] = set()
    file_count = 0
    total_size = 0
    start_time = time.monotonic()

    def _check_timeout() -> bool:
        # print(f'_check_timeout called: {time.monotonic() - start_time} > {config.scan_timeout_seconds}?', flush=True)
        if time.monotonic() - start_time > config.scan_timeout_seconds:
            limitations.append(
                f"Scan timeout ({config.scan_timeout_seconds}s) reached"
            )
            return False
        return True

    print(f'About to enter the walk loop')
    print(f'About to start walk loop with root_resolved={root_resolved}', flush=True)
    for dirpath, dirnames, filenames in os.walk(
            str(root_resolved), followlinks=config.follow_symlinks
    ):
        print(f'Walking directory: {dirpath}, filenames: {filenames}', flush=True)
        if not _check_timeout():
            break

        if config.follow_symlinks:
            safe_dirs: list[str] = []
            for d in dirnames:
                dir_path = Path(dirpath) / d
                if dir_path.is_symlink() and not is_symlink_safe(dir_path, root_resolved):
                    rel = _safe_relative(dir_path, root_resolved)
                    errors.append(f"Skipped unsafe symlink directory: {rel}")
                else:
                    safe_dirs.append(d)
            dirnames[:] = safe_dirs
        else:
            dirnames[:] = [
                d
                for d in dirnames
                if not os.path.islink(os.path.join(dirpath, d))
            ]
        print(f'About to process filenames: {filenames}', flush=True)
        for filename in sorted(filenames):
            if not _check_timeout():
                break

            if file_count >= config.max_file_count:
                limitations.append(
                    f"File count limit ({config.max_file_count}) reached"
                )
                break

            file_path = Path(dirpath) / filename

            if file_path.is_symlink():
                if not config.follow_symlinks:
                    rel = _safe_relative(file_path, root_resolved)
                    skipped.add(rel)
                    continue
                if not is_symlink_safe(file_path, root_resolved):
                    rel = _safe_relative(file_path, root_resolved)
                    errors.append(f"Skipped unsafe symlink: {rel}")
                    skipped.add(rel)
                    continue

            try:
                file_stat = file_path.stat()
                file_size = file_stat.st_size
            except OSError as e:
                rel = _safe_relative(file_path, root_resolved)
                errors.append(f"Could not stat file {rel}: {e}")
                skipped.add(rel)
                continue

            rel = _safe_relative(file_path, root_resolved)

            if file_size > config.max_file_size_bytes:
                errors.append(
                    f"Skipped oversized file ({file_size} > "
                    f"{config.max_file_size_bytes}): {rel}"
                )
                skipped.add(rel)
                continue

            if total_size + file_size > config.max_total_size_bytes:
                limitations.append(
                    f"Total size limit ({config.max_total_size_bytes} bytes) reached"
                )
                break

            file_hash, error = hash_file(file_path, config.max_file_size_bytes)
            if file_hash is not None:
                hashes[rel] = file_hash
                file_count += 1
                total_size += file_size
            else:
                errors.append(f"Could not hash {rel}: {error}")
                skipped.add(rel)

    print(f'Returning result: hashes={len(hashes)} items, file_count={file_count}', flush=True)
    result = DirectoryHashes(
        hashes=hashes,
        file_count=file_count,
        total_size_bytes=total_size,
        errors=errors,
        limitations=limitations,
        skipped=skipped,
    )
    return result


def _safe_relative(path: Path, root: Path) -> str:
    """Return a POSIX-style relative path, or the absolute path on error."""
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)

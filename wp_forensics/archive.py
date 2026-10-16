"""Safe ZIP archive inspection and bounded extraction for WordPress forensics.

This module provides ZIP handling without executing or interpreting
archived content. All operations are bounded by ScanConfig limits.

Security guarantees:
- Path traversal prevented via normalization and `..` detection
- Symlinks detected via Unix file mode bits (S_IFLNK) and skipped
- Decompression bombs prevented via per-entry, total, and ratio limits
- Actual bytes read enforced during extraction (not just ZIP metadata)
- Corrupt/encrypted/unsupported entries handled gracefully
- No network requests, no modification of source archives
- Destination directory must not be a symlink or resolve outside intended path
- No overwrites by default (opt-in only)
- Duplicate paths detected and rejected
- CRC and data integrity verified during extraction

Known limitations:
- Not race-free: TOCTOU window between inspection and extraction exists
- Windows symlink detection requires admin privileges
- Concurrent filesystem changes not protected against
"""

import os
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from wp_forensics.config import ScanConfig


class BadCRCError(zipfile.BadZipFile):
    """Exception raised when CRC verification fails."""
    pass


__all__ = [
    "ZipEntry",
    "ArchiveInspectionResult",
    "inspect_zip",
    "safe_extract_zip",
]


@dataclass
class ZipEntry:
    """Represents a single entry in a ZIP archive.

    Attributes:
        name: Archive entry name as stored in ZIP (untrusted).
        file_size: Declared uncompressed size in bytes.
        compressed_size: Declared compressed size in bytes.
        is_symlink: True if entry is a Unix symlink (mode S_IFLNK).
        is_traversal_risk: True if normalized path would escape destination.
        error: Non-fatal error message (corrupt, encrypted, unsupported, etc.).
        normalized_name: Name after path normalization (if safe).
        is_safe_to_extract: True if entry passes all safety checks.
        is_duplicate: True if entry has a duplicate raw or normalized name.
    """

    name: str
    file_size: int
    compressed_size: int
    is_symlink: bool
    is_traversal_risk: bool
    error: str | None = None
    normalized_name: str | None = None
    is_safe_to_extract: bool = False
    is_duplicate: bool = False


@dataclass
class ArchiveInspectionResult:
    """Result of inspecting a ZIP archive without extraction."""

    archive_path: str
    entries: list[ZipEntry]
    total_entries: int
    total_uncompressed_bytes: int
    total_compressed_bytes: int
    errors: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    is_safe_to_extract: bool = False


def inspect_zip(
    zip_path: Path | str,
    config: ScanConfig | None = None,
) -> ArchiveInspectionResult:
    """Inspect a ZIP archive for safety without extracting entries.

    Reads the ZIP central directory and validates each entry against
    configured limits. No entry data is decompressed or written to disk.

    Args:
        zip_path: Path to the ZIP file.
        config: ScanConfig with limits. Defaults to ScanConfig().

    Returns:
        ArchiveInspectionResult with entry details and safety assessment.
    """
    if config is None:
        config = ScanConfig()

    zip_path = Path(zip_path)
    start_time = time.monotonic()

    result = ArchiveInspectionResult(
        archive_path=str(zip_path),
        entries=[],
        total_entries=0,
        total_uncompressed_bytes=0,
        total_compressed_bytes=0,
    )

    if not zip_path.exists():
        result.errors.append("Archive does not exist")
        return result

    if not zip_path.is_file():
        result.errors.append("Archive path is not a file")
        return result

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            # First pass: process all entries without limit checks
            infolist = zf.infolist()
            raw_entries: list[ZipEntry] = []
            normalized_to_indices: dict[str, list[int]] = {}
            raw_to_indices: dict[str, list[int]] = {}

            for idx, info in enumerate(infolist):
                if not _check_timeout(start_time, config.scan_timeout_seconds):
                    result.limitations.append("Inspection timeout reached")
                    break

                if idx >= config.zip_max_entries:
                    result.errors.append(
                        f"Entry count exceeds limit ({config.zip_max_entries})"
                    )
                    break

                entry = _process_zip_info(info, config)
                raw_entries.append(entry)

                # Track resolved names for duplicate detection (resolves .. to catch traversal duplicates)
                resolved = _resolve_path(info.filename)
                normalized_to_indices.setdefault(resolved, []).append(idx)
                raw_to_indices.setdefault(info.filename, []).append(idx)

            # Second pass: identify duplicates and apply limit checks
            total_uncompressed = 0
            total_compressed = 0
            entries_processed = 0

            for idx, entry in enumerate(raw_entries):
                if not _check_timeout(start_time, config.scan_timeout_seconds):
                    result.limitations.append("Inspection timeout reached")
                    break

                # Check for duplicates
                is_duplicate = False
                resolved = _resolve_path(entry.name)
                if len(normalized_to_indices.get(resolved, [])) > 1:
                    is_duplicate = True
                if len(raw_to_indices.get(entry.name, [])) > 1:
                    is_duplicate = True

                if is_duplicate:
                    entry.is_duplicate = True
                    entry.is_safe_to_extract = False
                    if entry.error is None:
                        entry.error = "Duplicate entry name (raw or normalized)"

                result.entries.append(entry)
                entries_processed += 1

                if entry.error is None and not entry.is_duplicate:
                    # Check limits before adding
                    if total_uncompressed + entry.file_size > config.zip_max_uncompressed_bytes:
                        result.errors.append(
                            f"Total uncompressed size exceeds limit "
                            f"({config.zip_max_uncompressed_bytes} bytes)"
                        )
                        break

                    if total_compressed + entry.compressed_size > config.zip_max_compressed_bytes:
                        result.errors.append(
                            f"Total compressed size exceeds limit "
                            f"({config.zip_max_compressed_bytes} bytes)"
                        )
                        break

                    total_uncompressed += entry.file_size
                    total_compressed += entry.compressed_size

                    if entry.compressed_size > 0:
                        ratio = entry.file_size / entry.compressed_size
                        if ratio > config.zip_max_ratio:
                            result.errors.append(
                                f"Compression ratio {ratio:.1f}:1 exceeds limit "
                                f"({config.zip_max_ratio}:1) for entry {entry.name}"
                            )
                            break

            result.total_entries = entries_processed
            result.total_uncompressed_bytes = total_uncompressed
            result.total_compressed_bytes = total_compressed

            # Determine overall safety
            result.is_safe_to_extract = (
                len(result.errors) == 0
                and all(e.is_safe_to_extract for e in result.entries)
            )

    except zipfile.BadZipFile:
        result.errors.append("Bad ZIP file (corrupt or not a ZIP)")
    except Exception as e:
        result.errors.append(f"Unexpected error during inspection: {e}")

    return result


def safe_extract_zip(
    zip_path: Path | str,
    dest_dir: Path | str,
    config: ScanConfig | None = None,
    overwrite: bool = False,
) -> list[str]:
    """Safely extract a ZIP archive with all security checks.

    Validates each entry before and during extraction. Enforces actual
    bytes-read limits during decompression. Only extracts entries that
    pass all safety checks.

    Args:
        zip_path: Path to the ZIP file.
        dest_dir: Destination directory (created if needed).
        config: ScanConfig with limits. Defaults to ScanConfig().
        overwrite: If True, allow overwriting existing files. Default False.

    Returns:
        List of successfully extracted relative paths (POSIX style).

    Raises:
        ValueError: If archive fails inspection, dest_dir is unsafe,
                    duplicate paths found, or extraction conflicts.
    """
    if config is None:
        config = ScanConfig()

    zip_path = Path(zip_path)
    dest_dir = Path(dest_dir)

    # Check destination safety before any resolution
    _validate_destination(dest_dir)

    dest_dir_resolved = dest_dir.resolve()

    # Inspect first
    inspection = inspect_zip(zip_path, config)

    # If inspection found fundamental errors (corrupt archive, etc.), raise
    if inspection.errors and not inspection.entries:
        error_msgs = "; ".join(inspection.errors)
        raise ValueError(f"Archive unsafe for extraction: {error_msgs}")

    # Check for duplicate normalized paths among all entries with normalized names
    entries_with_names = [e for e in inspection.entries if e.normalized_name]
    normalized_names: dict[str, list[ZipEntry]] = {}
    for entry in entries_with_names:
        normalized_names.setdefault(entry.normalized_name, []).append(entry)

    for name, entries in normalized_names.items():
        if len(entries) > 1:
            raw_names = [e.name for e in entries]
            raise ValueError(
                f"Duplicate normalized path '{name}' from entries: {raw_names}. "
                f"Duplicate entries cannot be extracted."
            )

    # All duplicate entries (raw or normalized) are ALWAYS skipped.
    # The overwrite flag only controls overwriting existing destination files.
    safe_entries = [e for e in inspection.entries if e.is_safe_to_extract]

    if not safe_entries:
        # No safe entries - extraction succeeds with empty result
        return []

    # Check if dest_dir exists and is a file (not a directory)
    if dest_dir_resolved.exists() and not dest_dir_resolved.is_dir():
        raise ValueError(f"Destination exists and is not a directory: {dest_dir_resolved}")

    dest_dir_resolved.mkdir(parents=True, exist_ok=True)

    # Pre-check for overwrite conflicts
    if not overwrite:
        for entry in safe_entries:
            target_path = (dest_dir_resolved / entry.normalized_name)
            if target_path.exists():
                raise ValueError(
                    f"Destination file already exists: {target_path}. "
                    f"Use overwrite=True to allow overwriting."
                )

    extracted: list[str] = []
    start_time = time.monotonic()
    total_bytes_read = 0

    # Re-validate archive hasn't changed by checking entry count and sizes
    _revalidate_archive(zip_path, inspection, config)

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for entry in safe_entries:
                if not _check_timeout(start_time, config.scan_timeout_seconds):
                    raise TimeoutError("Extraction timeout reached")

                if entry.error is not None:
                    # Allow duplicate errors when overwrite=True
                    if not (overwrite and entry.is_duplicate and "duplicate" in (entry.error or "").lower()):
                        continue  # Skip entries with errors

                # Resolve target path
                target_path = (dest_dir_resolved / entry.normalized_name).resolve()

                # Final containment check
                try:
                    target_path.relative_to(dest_dir_resolved)
                except ValueError:
                    raise ValueError(
                        f"Path escape detected during extraction: {entry.name}"
                    )

                # Ensure parent directory exists
                target_path.parent.mkdir(parents=True, exist_ok=True)

                # Extract with bounded reading and CRC verification
                try:
                    with zf.open(entry.name, "r") as src:
                        with open(target_path, "wb") as dst:
                            bytes_read = _copy_with_limit(
                                src, dst, entry.file_size, config.max_file_size_bytes
                            )
                    total_bytes_read += bytes_read

                    if total_bytes_read > config.zip_max_uncompressed_bytes:
                        # Clean up partially written file
                        target_path.unlink(missing_ok=True)
                        raise ValueError("Total extracted bytes exceed limit")

                    # Verify CRC if available
                    info = zf.getinfo(entry.name)
                    if info.CRC is not None:
                        _verify_crc(target_path, info.CRC)

                except zipfile.BadZipFile:
                    target_path.unlink(missing_ok=True)
                    raise
                except BadCRCError as e:
                    target_path.unlink(missing_ok=True)
                    raise ValueError(f"CRC mismatch for entry: {entry.name}: {e}")
                except Exception as e:
                    target_path.unlink(missing_ok=True)
                    raise ValueError(f"Failed to extract {entry.name}: {e}")

                extracted.append(entry.normalized_name)

    except zipfile.BadZipFile:
        raise ValueError("Bad ZIP file during extraction")
    except TimeoutError:
        raise
    except Exception as e:
        raise ValueError(f"Extraction failed: {e}")

    return extracted


def _process_zip_info(
    info: zipfile.ZipInfo,
    config: ScanConfig,
) -> ZipEntry:
    """Process a ZipInfo object into a ZipEntry with safety analysis."""
    # Check for NUL bytes in name (potential truncation attack)
    if "\x00" in info.filename:
        return ZipEntry(
            name=info.filename,
            file_size=info.file_size,
            compressed_size=info.compress_size,
            is_symlink=False,
            is_traversal_risk=True,
            error="NUL byte in entry name",
        )

    # Check for symlink (Unix external attributes)
    is_symlink = _is_symlink(info)

    # Normalize path for traversal check
    normalized = _normalize_entry_name(info.filename)

    # Check traversal risk on both original and normalized paths
    is_traversal = _is_traversal_risk(info.filename, normalized)

    # Check for absolute paths BEFORE normalization
    is_absolute = info.filename.startswith("/") or info.filename.startswith("\\")
    if len(info.filename) >= 2 and info.filename[1] == ":":
        # Windows drive letter (e.g., "C:...")
        is_absolute = True

    # Per-entry size limit check
    error = None
    is_safe = True
    if info.file_size > 1024 * 1024 * 1024:  # 1GB hard cap
        error = "Entry uncompressed size exceeds 1 GB hard limit"
        is_safe = False
    elif info.file_size > config.max_file_size_bytes:
        error = f"Entry size {info.file_size} exceeds limit {config.max_file_size_bytes} bytes"
        is_safe = False

    # Determine if safe to extract
    if is_safe:
        is_safe = (
            not is_symlink
            and not is_traversal
            and not is_absolute
            and info.file_size >= 0
            and info.compress_size >= 0
        )

    # Check for encryption
    if info.flag_bits & 0x1:
        error = "Entry is encrypted"
        is_safe = False

    # Check for unsupported compression
    if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        error = f"Unsupported compression method: {info.compress_type}"
        is_safe = False

    return ZipEntry(
        name=info.filename,
        file_size=info.file_size,
        compressed_size=info.compress_size,
        is_symlink=is_symlink,
        is_traversal_risk=is_traversal,
        error=error,
        normalized_name=normalized if is_safe else None,
        is_safe_to_extract=is_safe,
        is_duplicate=False,  # Will be set during second pass in inspect_zip
    )


def _normalize_entry_name(name: str) -> str:
    """Normalize a ZIP entry name for safe filesystem use.

    - Replaces backslashes with forward slashes
    - Removes leading slash/drive letter
    - Removes leading ./ and ./
    - Collapses /./ and duplicate slashes
    - Does NOT resolve '..' (that's checked separately)
    """
    # Replace backslashes
    name = name.replace("\\", "/")

    # Strip leading slashes
    name = name.lstrip("/")

    # Strip Windows drive letter (e.g., "C:...")
    if len(name) >= 2 and name[1] == ":":
        name = name[2:].lstrip("/")

    # Collapse /./ and duplicate slashes
    while "//" in name:
        name = name.replace("//", "/")
    while "/./" in name:
        name = name.replace("/./", "/")
    # Strip leading ./
    while name.startswith("./"):
        name = name[2:]

    return name


def _is_traversal_risk(original_name: str, normalized_name: str) -> bool:
    """Check if an entry name would escape the destination directory.

    Checks for absolute paths in original name and explicit `..` in normalized name.
    Does not use filesystem resolution to avoid platform-specific false positives.
    """
    if not normalized_name:
        return True

    # Check for absolute paths in original name
    if original_name.startswith("/") or original_name.startswith("\\"):
        return True
    if len(original_name) >= 2 and original_name[1] == ":":
        return True
    # UNC paths (\\server\share)
    if original_name.startswith("\\\\"):
        return True

    # Check for path traversal sequences in normalized path
    parts = normalized_name.split("/")
    for part in parts:
        if part == "..":
            return True
        if part == ".":
            continue

    return False


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    """Check if a ZIP entry is a Unix symlink via external attributes."""
    # Unix file type is stored in upper 16 bits of external_attr
    # S_IFLNK = 0o120000 = 0xA000
    if info.external_attr & 0xFFFF0000:
        file_type = (info.external_attr >> 16) & 0xFFFF
        return file_type == 0xA000  # S_IFLNK
    return False


def _resolve_path(name: str) -> str:
    """Resolve a ZIP entry name for duplicate detection.

    Like _normalize_entry_name but also resolves '..' components.
    This is used for duplicate detection only, not for traversal checking.
    """
    name = _normalize_entry_name(name)
    # Resolve .. components
    parts = []
    for part in name.split("/"):
        if part == "..":
            if parts:
                parts.pop()
        elif part and part != ".":
            parts.append(part)
    return "/".join(parts)
    """Return True if within timeout, False if exceeded."""
    return (time.monotonic() - start_time) <= timeout_seconds


def _validate_destination(dest_dir: Path) -> None:
    """Validate destination directory is safe for extraction.

    Checks:
    - Destination path is not a symlink
    - Destination parent directory components are not symlinks
    - Destination resolves to a path we can write to
    """
    # Check if any component of the path is a symlink
    # We check from root down to the destination
    path = dest_dir
    parts = []

    while path != path.parent:
        parts.append(path)
        path = path.parent
    parts.append(path)  # Add root
    parts.reverse()

    # Check each component
    current = Path(parts[0])
    for part in parts[1:]:
        current = current / part.name
        if current.is_symlink():
            raise ValueError(
                f"Destination path contains symlink component: {current}. "
                f"Refusing to extract through symlink."
            )

    # Check the destination itself if it exists
    if dest_dir.exists() and dest_dir.is_symlink():
        raise ValueError(
            f"Destination is a symlink: {dest_dir}. Refusing to extract through symlink."
        )


def _check_timeout(start_time: float, timeout_seconds: int) -> bool:
    """Return True if within timeout, False if exceeded."""
    return (time.monotonic() - start_time) <= timeout_seconds


def _revalidate_archive(
    zip_path: Path,
    inspection: ArchiveInspectionResult,
    config: ScanConfig,
) -> None:
    """Re-validate archive hasn't changed since inspection.

    This is a best-effort check to reduce TOCTOU risk. It verifies
    the archive still has the same entry count and sizes as inspected.

    Note: This does not eliminate TOCTOU races; it only reduces the window.
    """
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            current_entries = list(zf.infolist())

            if len(current_entries) != inspection.total_entries:
                raise ValueError(
                    f"Archive entry count changed during inspection: "
                    f"expected {inspection.total_entries}, got {len(current_entries)}"
                )

            # Verify each entry still matches
            for i, info in enumerate(current_entries):
                if i >= len(inspection.entries):
                    break
                expected = inspection.entries[i]
                if info.file_size != expected.file_size:
                    raise ValueError(
                        f"Archive entry {i} size changed: "
                        f"expected {expected.file_size}, got {info.file_size}"
                    )
                if info.compress_size != expected.compressed_size:
                    raise ValueError(
                        f"Archive entry {i} compressed size changed: "
                        f"expected {expected.compressed_size}, got {info.compress_size}"
                    )

    except zipfile.BadZipFile:
        raise ValueError("Archive became corrupt between inspection and extraction")


def _verify_crc(file_path: Path, expected_crc: int) -> None:
    """Verify file CRC matches expected value."""
    import zlib

    crc = 0
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(64 * 1024), b""):
            crc = zlib.crc32(chunk, crc)

    # CRC32 is unsigned 32-bit
    crc &= 0xFFFFFFFF
    if crc != expected_crc:
        raise BadCRCError(f"CRC mismatch: expected {expected_crc:#x}, got {crc:#x}")


def _copy_with_limit(
    src: Iterator[bytes] | zipfile.ZipExtFile,
    dst,
    expected_size: int,
    max_bytes: int,
) -> int:
    """Copy from source to destination with byte limit enforcement.

    Reads in chunks and stops if actual bytes read exceed max_bytes
    or declared expected_size.
    """
    chunk_size = 64 * 1024
    total_read = 0
    limit = min(expected_size, max_bytes) if expected_size > 0 else max_bytes

    while True:
        chunk = src.read(chunk_size)
        if not chunk:
            break
        total_read += len(chunk)
        if total_read > limit:
            raise ValueError(f"Entry exceeds size limit during extraction ({total_read} > {limit})")
        dst.write(chunk)

    return total_read
"""Directory snapshot comparison for forensic analysis.

This module compares two directory snapshots by their relative paths and
SHA-256 hashes. Files are classified as added, removed, modified, or unchanged
only when there is definitive evidence. Unreadable files and scan-limit
failures are tracked in limitations to indicate uncertainty.
"""

import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from wp_forensics.config import ScanConfig
from wp_forensics.hashing import hash_directory
from wp_forensics.models import (
    ComparisonEntry,
    ComparisonResult,
    COMPARISON_ADDED,
    COMPARISON_REMOVED,
    COMPARISON_MODIFIED,
    COMPARISON_UNCHANGED,
)

__all__ = [
    "SnapshotHashes",
    "compare_snapshots",
]


@dataclass
class SnapshotHashes:
    """Hashes and metadata for a single snapshot directory.

    Attributes:
        root: Absolute path to the snapshot root.
        hashes: Maps POSIX-style relative paths to SHA-256 hex digests.
        skipped: Paths seen during traversal but not hashed (due to symlinks,
            size limits, or read errors).
        file_count: Number of successfully hashed files.
        total_size_bytes: Total size of successfully hashed files.
        errors: Non-fatal errors from hashing.
        limitations: Scan-limit events (timeout, file count, size limits).
    """

    root: str
    hashes: dict[str, str]
    skipped: set[str]
    file_count: int
    total_size_bytes: int
    errors: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


def _build_snapshot(
    root: Path,
    config: ScanConfig,
) -> SnapshotHashes:
    """Build a snapshot of a directory using existing hash_directory.

    Args:
        root: Directory to snapshot.
        config: ScanConfig with limits.

    Returns:
        SnapshotHashes with hashes, skipped paths, and metadata.
    """
    result = hash_directory(root, config)

    return SnapshotHashes(
        root=str(root),
        hashes=result.hashes,
        skipped=result.skipped,
        file_count=result.file_count,
        total_size_bytes=result.total_size_bytes,
        errors=result.errors,
        limitations=result.limitations,
    )


def compare_snapshots(
    source: Path | str,
    dest: Path | str,
    config: ScanConfig | None = None,
) -> ComparisonResult:
    """Compare two directory snapshots by their SHA-256 hashes.

    Both directories are hashed independently with the given config.
    Files are classified as added, removed, modified, or unchanged.
    Unreadable files and scan-limit failures are tracked in limitations.

    Args:
        source: First directory (source/old).
        dest: Second directory (destination/new).
        config: ScanConfig with limits. Defaults to ScanConfig().

    Returns:
        ComparisonResult with entries, counts, and limitations.

    Raises:
        ValueError: If either path is not a directory.
    """
    if config is None:
        config = ScanConfig()

    source_path = Path(source)
    dest_path = Path(dest)

    if not source_path.exists() or not source_path.is_dir():
        raise ValueError(f"Source is not a directory: {source_path}")
    if not dest_path.exists() or not dest_path.is_dir():
        raise ValueError(f"Destination is not a directory: {dest_path}")

    start_time = time.monotonic()
    scan_timestamp = datetime.now(timezone.utc).isoformat()

    # Build snapshots independently
    source_snap = _build_snapshot(source_path, config)
    dest_snap = _build_snapshot(dest_path, config)

    # Compute comparison
    source_hashes = source_snap.hashes
    dest_hashes = dest_snap.hashes
    source_skipped = source_snap.skipped
    dest_skipped = dest_snap.skipped

    # All known paths (hashes + skipped)
    all_paths = sorted(
        set(source_hashes.keys())
        | set(dest_hashes.keys())
        | set(source_skipped)
        | set(dest_skipped)
    )

    entries: list[ComparisonEntry] = []
    added_count = 0
    removed_count = 0
    modified_count = 0
    unchanged_count = 0
    uncertain_paths: list[str] = []

    for path in all_paths:
        src_hash = source_hashes.get(path)
        dst_hash = dest_hashes.get(path)
        in_source_skipped = path in source_skipped
        in_dest_skipped = path in dest_skipped

        if src_hash is not None and dst_hash is not None:
            # Both hashed - compare hashes
            if src_hash != dst_hash:
                status = COMPARISON_MODIFIED
                modified_count += 1
            else:
                status = COMPARISON_UNCHANGED
                unchanged_count += 1
            entries.append(ComparisonEntry(
                path=path,
                source_hash=src_hash,
                dest_hash=dst_hash,
                status=status,
            ))
        elif src_hash is not None and dst_hash is None:
            # In source hashes, not in dest hashes
            if in_dest_skipped:
                # Dest couldn't hash it - uncertain
                uncertain_paths.append(path)
            elif dest_snap.limitations:
                # Dest scan had limitations - file might have been missed
                uncertain_paths.append(path)
            else:
                # Confirmed removal
                status = COMPARISON_REMOVED
                removed_count += 1
                entries.append(ComparisonEntry(
                    path=path,
                    source_hash=src_hash,
                    dest_hash=None,
                    status=status,
                ))
        elif src_hash is None and dst_hash is not None:
            # In dest hashes, not in source hashes
            if in_source_skipped:
                # Source couldn't hash it - uncertain
                uncertain_paths.append(path)
            elif source_snap.limitations:
                # Source scan had limitations - file might have been missed
                uncertain_paths.append(path)
            else:
                # Confirmed addition
                status = COMPARISON_ADDED
                added_count += 1
                entries.append(ComparisonEntry(
                    path=path,
                    source_hash=None,
                    dest_hash=dst_hash,
                    status=status,
                ))
        else:
            # Neither hashed - in skipped sets
            uncertain_paths.append(path)

    # Aggregate limitations
    all_limitations: list[str] = []
    all_limitations.extend(source_snap.limitations)
    all_limitations.extend(dest_snap.limitations)

    for path in uncertain_paths:
        all_limitations.append(
            f"Uncertain comparison for '{path}': file was skipped or "
            f"unreadable in one or both snapshots"
        )

    if source_snap.limitations or dest_snap.limitations or uncertain_paths:
        all_limitations.append(
            "Comparison may be incomplete due to scan limits or unreadable files"
        )

    return ComparisonResult(
        source_root=str(source_path),
        dest_root=str(dest_path),
        entries=entries,
        added_count=added_count,
        removed_count=removed_count,
        modified_count=modified_count,
        unchanged_count=unchanged_count,
        limitations=all_limitations,
    )
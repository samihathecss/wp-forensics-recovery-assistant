"""Tests for wp_forensics.compare module.

Covers: snapshot comparison, file classification (added/removed/modified/unchanged),
deterministic ordering, handling of unreadable/skipped files, scan limits,
symlink handling, and edge cases.
"""

import hashlib
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from wp_forensics.compare import SnapshotHashes, compare_snapshots
from wp_forensics.config import ScanConfig
from wp_forensics.models import (
    COMPARISON_ADDED,
    COMPARISON_REMOVED,
    COMPARISON_MODIFIED,
    COMPARISON_UNCHANGED,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_file(directory: Path, name: str, content: bytes) -> Path:
    """Create a file in directory with given content and return its path."""
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def _make_symlink(directory: Path, name: str, target: Path) -> Path:
    """Create a symlink in directory pointing to target and return its path."""
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.symlink_to(target)
    except (OSError, NotImplementedError):
        # Skip symlink creation if not supported (e.g., Windows without permissions)
        pass
    return path


def _can_use_symlinks() -> bool:
    """Return True if os.symlink actually works in this environment.
    
    On Windows, os.symlink exists but may fail with WinError 1314
    if the process lacks the SeCreateSymbolicLinkPrivilege.
    """
    if not hasattr(os, "symlink"):
        return False
    import tempfile

    try:
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            target = tdp / "target"
            target.touch()
            link = tdp / "link"
            link.symlink_to(target)
            link.unlink()
        return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# SnapshotHashes Tests
# ---------------------------------------------------------------------------

class TestSnapshotHashes:
    """Tests for the SnapshotHashes dataclass."""

    def test_creation_with_all_fields(self):
        sh = SnapshotHashes(
            root="/test/source",
            hashes={"a.txt": "abc123"},
            skipped={"b.txt"},
            file_count=1,
            total_size_bytes=10,
            errors=["some error"],
            limitations=["some limitation"],
        )
        assert sh.root == "/test/source"
        assert sh.hashes == {"a.txt": "abc123"}
        assert sh.skipped == {"b.txt"}
        assert sh.file_count == 1
        assert sh.total_size_bytes == 10
        assert sh.errors == ["some error"]
        assert sh.limitations == ["some limitation"]

    def test_defaults(self):
        sh = SnapshotHashes(
            root="/tmp",
            hashes={},
            skipped=set(),
            file_count=0,
            total_size_bytes=0,
        )
        assert sh.errors == []
        assert sh.limitations == []


# ---------------------------------------------------------------------------
# Basic Classification Tests
# ---------------------------------------------------------------------------

class TestBasicClassification:
    """Tests for added/removed/modified/unchanged classification."""

    def test_identical_snapshots(self, tmp_path: Path, default_config: ScanConfig):
        """Two identical snapshots should result in all files being unchanged."""
        source = tmp_path / "source"
        dest = tmp_path / "dest"
        source.mkdir()
        dest.mkdir()

        # Create identical files in both
        _make_file(source, "file1.txt", b"hello world")
        _make_file(source, "file2.txt", b"foo bar")
        _make_file(dest, "file1.txt", b"hello world")
        _make_file(dest, "file2.txt", b"foo bar")

        result = compare_snapshots(source, dest, default_config)

        assert result.added_count == 0
        assert result.removed_count == 0
        assert result.modified_count == 0
        assert result.unchanged_count == 2
        assert len(result.entries) == 2
        assert len(result.limitations) == 0

        # Check specific entries
        entry_map = {e.path: e for e in result.entries}
        assert entry_map["file1.txt"].status == COMPARISON_UNCHANGED
        assert entry_map["file2.txt"].status == COMPARISON_UNCHANGED

    def test_added_file(self, tmp_path: Path, default_config: ScanConfig):
        """File only in destination should be classified as added."""
        source = tmp_path / "source"
        dest = tmp_path / "dest"
        source.mkdir()
        dest.mkdir()

        _make_file(dest, "added.txt", b"new content")

        result = compare_snapshots(source, dest, default_config)

        assert result.added_count == 1
        assert result.removed_count == 0
        assert result.modified_count == 0
        assert result.unchanged_count == 0
        assert len(result.entries) == 1
        assert result.entries[0].path == "added.txt"
        assert result.entries[0].status == COMPARISON_ADDED
        assert result.entries[0].source_hash is None
        assert result.entries[0].dest_hash is not None

    def test_removed_file(self, tmp_path: Path, default_config: ScanConfig):
        """File only in source should be classified as removed."""
        source = tmp_path / "source"
        dest = tmp_path / "dest"
        source.mkdir()
        dest.mkdir()

        _make_file(source, "removed.txt", b"old content")

        result = compare_snapshots(source, dest, default_config)

        assert result.added_count == 0
        assert result.removed_count == 1
        assert result.modified_count == 0
        assert result.unchanged_count == 0
        assert len(result.entries) == 1
        assert result.entries[0].path == "removed.txt"
        assert result.entries[0].status == COMPARISON_REMOVED
        assert result.entries[0].source_hash is not None
        assert result.entries[0].dest_hash is None

    def test_modified_file(self, tmp_path: Path, default_config: ScanConfig):
        """File in both with different content should be modified."""
        source = tmp_path / "source"
        dest = tmp_path / "dest"
        source.mkdir()
        dest.mkdir()

        _make_file(source, "modified.txt", b"original content")
        _make_file(dest, "modified.txt", b"modified content")

        result = compare_snapshots(source, dest, default_config)

        assert result.added_count == 0
        assert result.removed_count == 0
        assert result.modified_count == 1
        assert result.unchanged_count == 0
        assert len(result.entries) == 1
        assert result.entries[0].path == "modified.txt"
        assert result.entries[0].status == COMPARISON_MODIFIED
        assert result.entries[0].source_hash is not None
        assert result.entries[0].dest_hash is not None
        assert result.entries[0].source_hash != result.entries[0].dest_hash

    def test_mixed_changes(self, tmp_path: Path, default_config: ScanConfig):
        """Snapshot with all types of changes."""
        source = tmp_path / "source"
        dest = tmp_path / "dest"
        source.mkdir()
        dest.mkdir()

        # Added file (in dest only)
        _make_file(dest, "added.txt", b"new")

        # Removed file (in source only)
        _make_file(source, "removed.txt", b"old")

        # Modified file (in both, different content)
        _make_file(source, "modified.txt", b"original")
        _make_file(dest, "modified.txt", b"changed")

        # Unchanged file (in both, same content)
        content = b"same"
        _make_file(source, "unchanged.txt", content)
        _make_file(dest, "unchanged.txt", content)

        result = compare_snapshots(source, dest, default_config)

        assert result.added_count == 1
        assert result.removed_count == 1
        assert result.modified_count == 1
        assert result.unchanged_count == 1
        assert len(result.entries) == 4

        # Check specific entries
        entry_map = {e.path: e for e in result.entries}
        assert entry_map["added.txt"].status == COMPARISON_ADDED
        assert entry_map["removed.txt"].status == COMPARISON_REMOVED
        assert entry_map["modified.txt"].status == COMPARISON_MODIFIED
        assert entry_map["unchanged.txt"].status == COMPARISON_UNCHANGED

    def test_empty_directories(self, tmp_path: Path, default_config: ScanConfig):
        """Two empty directories should have no entries and zero counts."""
        source = tmp_path / "source"
        dest = tmp_path / "dest"
        source.mkdir()
        dest.mkdir()

        result = compare_snapshots(source, dest, default_config)

        assert result.added_count == 0
        assert result.removed_count == 0
        assert result.modified_count == 0
        assert result.unchanged_count == 0
        assert result.entries == []
        assert result.limitations == []

    def test_deterministic_ordering(self, tmp_path: Path, default_config: ScanConfig):
        """Entries should be sorted by path for deterministic output."""
        source = tmp_path / "source"
        dest = tmp_path / "dest"
        source.mkdir()
        dest.mkdir()

        # Create files in non-sorted order
        _make_file(source, "z.txt", b"z")
        _make_file(source, "a.txt", b"a")
        _make_file(source, "m.txt", b"m")
        
        _make_file(dest, "z.txt", b"z")
        _make_file(dest, "a.txt", b"a modified")  # modified
        _make_file(dest, "m.txt", b"m")

        result = compare_snapshots(source, dest, default_config)

        paths = [e.path for e in result.entries]
        assert paths == sorted(paths)  # Should be ['a.txt', 'm.txt', 'z.txt']
        assert result.entries[0].path == "a.txt"
        assert result.entries[1].path == "m.txt"
        assert result.entries[2].path == "z.txt"

        # Check classifications
        assert result.entries[0].status == COMPARISON_MODIFIED  # a.txt
        assert result.entries[1].status == COMPARISON_UNCHANGED  # m.txt
        assert result.entries[2].status == COMPARISON_UNCHANGED  # z.txt

    def test_nested_relative_paths(self, tmp_path: Path, default_config: ScanConfig):
        """Files in nested directories should use POSIX-style relative paths."""
        source = tmp_path / "source"
        dest = tmp_path / "dest"
        source.mkdir()
        dest.mkdir()

        # Create nested files
        nested_dir = source / "sub" / "dir"
        nested_dir.mkdir(parents=True)
        _make_file(nested_dir, "nested.txt", b"nested content")
        
        nested_dir_dest = dest / "sub" / "dir"
        nested_dir_dest.mkdir(parents=True)
        _make_file(nested_dir_dest, "nested.txt", b"nested content")

        result = compare_snapshots(source, dest, default_config)

        assert len(result.entries) == 1
        assert result.entries[0].path == "sub/dir/nested.txt"
        assert result.entries[0].status == COMPARISON_UNCHANGED
        assert result.unchanged_count == 1


# ---------------------------------------------------------------------------
# Unreadable/Skipped File Tests
# ---------------------------------------------------------------------------

class TestUnreadableFiles:
    """Tests for handling of unreadable and skipped files."""

    def test_unreadable_file_not_classified_as_removed(self, tmp_path: Path):
        """File unreadable in source but absent in dest should NOT be removed."""
        source = tmp_path / "source"
        dest = tmp_path / "dest"
        source.mkdir()
        dest.mkdir()

        # Create a file in source that we'll make unreadable
        _make_file(source, "unreadable.txt", b"secret data")
        # Don't create the file in dest at all

        # Make the file unreadable by mocking open to raise PermissionError
        def mock_open_raise_permission(*args, **kwargs):
            # Check if we're trying to open the specific file
            if len(args) > 0 and "unreadable.txt" in str(args[0]):
                raise PermissionError("Cannot read file")
            # Otherwise, open normally
            return open(*args, **kwargs)

        with patch("builtins.open", side_effect=mock_open_raise_permission):
            result = compare_snapshots(source, dest, ScanConfig())

        # Should NOT be classified as removed
        removed_entries = [e for e in result.entries if e.status == COMPARISON_REMOVED]
        removed_paths = [e.path for e in removed_entries]
        assert "unreadable.txt" not in removed_paths
        
        # Should be in limitations as uncertain
        assert any("unreadable.txt" in lim and "Uncertain comparison" in lim 
                  for lim in result.limitations)
        
        # Should have incomplete comparison limitation
        assert any("incomplete" in lim.lower() for lim in result.limitations)

    def test_unreadable_file_not_classified_as_added(self, tmp_path: Path):
        """File unreadable in dest but absent in source should NOT be added."""
        source = tmp_path / "source"
        dest = tmp_path / "dest"
        source.mkdir()
        dest.mkdir()

        # Don't create the file in source
        # Create a file in dest that we'll make unreadable
        _make_file(dest, "unreadable.txt", b"secret data")

        # Make the file unreadable by mocking open to raise PermissionError
        def mock_open_raise_permission(*args, **kwargs):
            if len(args) > 0 and "unreadable.txt" in str(args[0]):
                raise PermissionError("Cannot read file")
            return open(*args, **kwargs)

        with patch("builtins.open", side_effect=mock_open_raise_permission):
            result = compare_snapshots(source, dest, ScanConfig())

        # Should NOT be classified as added
        added_entries = [e for e in result.entries if e.status == COMPARISON_ADDED]
        added_paths = [e.path for e in added_entries]
        assert "unreadable.txt" not in added_paths
        
        # Should be in limitations as uncertain
        assert any("unreadable.txt" in lim and "Uncertain comparison" in lim 
                  for lim in result.limitations)

    def test_file_skipped_due_to_size_not_classified_as_removed(self, tmp_path: Path):
        """Oversized file in source but absent in dest should NOT be removed."""
        source = tmp_path / "source"
        dest = tmp_path / "dest"
        source.mkdir()
        dest.mkdir()

        # Create an oversized file in source
        large_content = b"x" * 2000  # 2000 bytes
        _make_file(source, "large.txt", large_content)
        # Don't create it in dest

        # Use small size limit to make it get skipped
        config = ScanConfig(
            max_file_size_bytes=1000,  # 1000 byte limit
            max_total_size_bytes=10_000,
            max_file_count=100,
        )

        result = compare_snapshots(source, dest, config)

        # Should NOT be classified as removed
        removed_entries = [e for e in result.entries if e.status == COMPARISON_REMOVED]
        removed_paths = [e.path for e in removed_entries]
        assert "large.txt" not in removed_paths
        
        # Should be in limitations as uncertain
        assert any("large.txt" in lim and "Uncertain comparison" in lim 
                  for lim in result.limitations)

    def test_file_hashed_in_source_skipped_in_dest_not_removed(self, tmp_path: Path):
        """File hashed in source but skipped in dest should NOT be classified as removed."""
        source = tmp_path / "source"
        dest = tmp_path / "dest"
        source.mkdir()
        dest.mkdir()

        # Create a normal file in source
        _make_file(source, "file.txt", b"content")
        # Create an oversized version in dest (will be skipped)
        _make_file(dest, "file.txt", b"x" * 2000)

        config = ScanConfig(
            max_file_size_bytes=1000,  # Will cause dest file to be skipped
            max_total_size_bytes=10_000,
            max_file_count=100,
        )

        result = compare_snapshots(source, dest, config)

        # Should NOT be classified as removed (because dest couldn't hash it)
        removed_entries = [e for e in result.entries if e.status == COMPARISON_REMOVED]
        removed_paths = [e.path for e in removed_entries]
        assert "file.txt" not in removed_paths
        
        # Should be in limitations as uncertain
        assert any("file.txt" in lim and "Uncertain comparison" in lim 
                  for lim in result.limitations)

    def test_file_hashed_in_dest_skipped_in_source_not_added(self, tmp_path: Path):
        """File skipped in source but hashed in dest should NOT be classified as added."""
        source = tmp_path / "source"
        dest = tmp_path / "dest"
        source.mkdir()
        dest.mkdir()

        # Create an oversized version in source (will be skipped)
        _make_file(source, "file.txt", b"x" * 2000)
        # Create a normal file in dest
        _make_file(dest, "file.txt", b"content")

        config = ScanConfig(
            max_file_size_bytes=1000,  # Will cause source file to be skipped
            max_total_size_bytes=10_000,
            max_file_count=100,
        )

        result = compare_snapshots(source, dest, config)

        # Should NOT be classified as added (because source couldn't hash it)
        added_entries = [e for e in result.entries if e.status == COMPARISON_ADDED]
        added_paths = [e.path for e in added_entries]
        assert "file.txt" not in added_paths
        
        # Should be in limitations as uncertain
        assert any("file.txt" in lim and "Uncertain comparison" in lim 
                  for lim in result.limitations)


# ---------------------------------------------------------------------------
# Scan Limits Tests
# ---------------------------------------------------------------------------

class TestScanLimits:
    """Tests for how scan limits affect comparison."""

    def test_file_count_limit_affects_comparison(self, tmp_path: Path):
        """When file count limit is triggered, comparison should be incomplete."""
        source = tmp_path / "source"
        dest = tmp_path / "dest"
        source.mkdir()
        dest.mkdir()

        # Create more files than the limit
        for i in range(10):
            _make_file(source, f"file{i}.txt", b"content")
            _make_file(dest, f"file{i}.txt", b"content")

        # Set very low file count limit
        config = ScanConfig(
            max_file_count=3,
            max_file_size_bytes=1024*1024,
            max_total_size_bytes=100*1024*1024,
        )

        result = compare_snapshots(source, dest, config)

        # Should have limitations due to file count limit
        assert len(result.limitations) > 0
        assert any("file count" in lim.lower() for lim in result.limitations)
        assert any("incomplete" in lim.lower() for lim in result.limitations)
        
        # Should have processed only up to the limit
        # Note: we can't easily check exactly which files were processed,
        # but we know the comparison was incomplete

    def test_total_size_limit_affects_comparison(self, tmp_path: Path):
        """When total size limit is triggered, comparison should be incomplete."""
        source = tmp_path / "source"
        dest = tmp_path / "dest"
        source.mkdir()
        dest.mkdir()

        # Create files that will exceed total size limit when combined
        for i in range(10):
            content = b"x" * 2000  # 2KB each
            _make_file(source, f"file{i}.txt", content)
            _make_file(dest, f"file{i}.txt", content)

        # Set very low total size limit (less than what we need for all files)
        config = ScanConfig(
            max_file_size_bytes=10000,
            max_total_size_bytes=10000,  # Only 10KB total - enough for ~5 files
            max_file_count=100,
        )

        result = compare_snapshots(source, dest, config)

        # Should have limitations due to total size limit
        assert len(result.limitations) > 0
        assert any("total size" in lim.lower() for lim in result.limitations)
        assert any("incomplete" in lim.lower() for lim in result.limitations)

    def test_timeout_limit_affects_comparison(self, tmp_path: Path):
        """When timeout is triggered, comparison should be incomplete."""
        source = tmp_path / "source"
        dest = tmp_path / "dest"
        source.mkdir()
        dest.mkdir()

        # Create many files to potentially trigger timeout
        # Increase count to ensure timeout triggers on slower systems
        for i in range(10000):
            _make_file(source, f"file{i}.txt", b"content")
            _make_file(dest, f"file{i}.txt", b"content")

        # Set very short timeout
        config = ScanConfig(
            max_file_size_bytes=1024*1024,
            max_total_size_bytes=100*1024*1024,
            max_file_count=10000,
            scan_timeout_seconds=1,  # 1 second timeout
        )

        result = compare_snapshots(source, dest, config)

        # Should have limitations due to timeout OR file count (whichever hits first)
        # At least one limitation should be present
        assert len(result.limitations) > 0, f"No limitations found: {result.limitations}"
        has_timeout_limitation = any("timeout" in lim.lower() for lim in result.limitations)
        has_file_count_limitation = any("file count" in lim.lower() for lim in result.limitations)
        has_incomplete_limitation = any("incomplete" in lim.lower() for lim in result.limitations)
        assert has_timeout_limitation or has_file_count_limitation, f"No timeout or file count limitation found: {result.limitations}"
        assert has_incomplete_limitation, f"No incomplete limitation found: {result.limitations}"


# ---------------------------------------------------------------------------
# Symlink Tests
# ---------------------------------------------------------------------------

class TestSymlinks:
    """Tests for symlink handling."""

    @pytest.mark.skipif(not _can_use_symlinks(), reason="symlinks not supported")
    def test_symlink_not_followed_by_default(self, tmp_path: Path):
        """Symlinks should not be followed when follow_symlinks=False (default)."""
        source = tmp_path / "source"
        dest = tmp_path / "dest"
        source.mkdir()
        dest.mkdir()

        # Create target file outside the source directory
        target_outside = tmp_path / "outside.txt"
        target_outside.write_bytes(b"outside content")
        
        # Create symlink in source pointing to outside target
        _make_symlink(source, "symlink.txt", target_outside)
        # Don't create anything in dest for this path

        # Use default config (follow_symlinks=False)
        result = compare_snapshots(source, dest, ScanConfig())

        # The symlink should be seen but not hashed (skipped)
        # Since it's not in dest at all, it should be uncertain, not removed
        assert "symlink.txt" not in [e.path for e in result.entries 
                                   if e.status == COMPARISON_REMOVED]
        
        # Should be in limitations as uncertain
        assert any("symlink.txt" in lim and "Uncertain comparison" in lim 
                  for lim in result.limitations)

    @pytest.mark.skipif(not _can_use_symlinks(), reason="symlinks not supported")
    def test_symlink_not_followed_in_both_directories(self, tmp_path: Path):
        """Symlink present in both source and dest should be uncertain."""
        source = tmp_path / "source"
        dest = tmp_path / "dest"
        source.mkdir()
        dest.mkdir()

        # Create target outside both directories
        target_outside = tmp_path / "outside.txt"
        target_outside.write_bytes(b"outside content")
        
        # Create identical symlinks in both source and dest
        _make_symlink(source, "symlink.txt", target_outside)
        _make_symlink(dest, "symlink.txt", target_outside)

        # Use default config (follow_symlinks=False)
        result = compare_snapshots(source, dest, ScanConfig())

        # Symlink should be seen in both but not hashed in either
        # Should be uncertain, not unchanged
        entry_map = {e.path: e for e in result.entries}
        assert "symlink.txt" not in entry_map  # Should not appear in entries at all
        
        # Should be in limitations as uncertain
        assert any("symlink.txt" in lim and "Uncertain comparison" in lim 
                  for lim in result.limitations)


# ---------------------------------------------------------------------------
# Error Handling Tests
# ---------------------------------------------------------------------------

class TestErrorHandling:
    """Tests for error handling and edge cases."""

    def test_nonexistent_source_directory(self, tmp_path: Path, default_config: ScanConfig):
        """Should raise ValueError for nonexistent source directory."""
        dest = tmp_path / "dest"
        dest.mkdir()

        with pytest.raises(ValueError, match="Source is not a directory"):
            compare_snapshots(tmp_path / "nonexistent", dest, default_config)

    def test_nonexistent_destination_directory(self, tmp_path: Path, default_config: ScanConfig):
        """Should raise ValueError for nonexistent destination directory."""
        source = tmp_path / "source"
        source.mkdir()

        with pytest.raises(ValueError, match="Destination is not a directory"):
            compare_snapshots(source, tmp_path / "nonexistent", default_config)

    def test_source_is_file_not_directory(self, tmp_path: Path, default_config: ScanConfig):
        """Should raise ValueError when source is a file."""
        source = tmp_path / "file.txt"
        source.write_bytes(b"hello")
        dest = tmp_path / "dest"
        dest.mkdir()

        with pytest.raises(ValueError, match="Source is not a directory"):
            compare_snapshots(source, dest, default_config)

    def test_destination_is_file_not_directory(self, tmp_path: Path, default_config: ScanConfig):
        """Should raise ValueError when destination is a file."""
        source = tmp_path / "source"
        source.mkdir()
        dest = tmp_path / "file.txt"
        dest.write_bytes(b"hello")

        with pytest.raises(ValueError, match="Destination is not a directory"):
            compare_snapshots(source, dest, default_config)

    def test_files_changed_during_scanning(self, tmp_path: Path):
        """Files that change during scanning should be handled gracefully."""
        source = tmp_path / "source"
        dest = tmp_path / "dest"
        source.mkdir()
        dest.mkdir()

        # Create initial files
        _make_file(source, "file.txt", b"initial")
        _make_file(dest, "file.txt", b"initial")

        # Track how many times our mock is called for each file path
        call_counts = {}
        original_hashes = {}

        def mock_hash_file_changing(file_path, max_size_bytes=None):
            path_str = file_path.name
            call_counts[path_str] = call_counts.get(path_str, 0) + 1
            print(f"MOCK CALLED: {file_path.name}, call count: {call_counts[path_str]}", flush=True)
             
            # On first call for each file, return a fixed original hash
            if call_counts[path_str] == 1:
                original_hash = ("original_hash", None)
                original_hashes[path_str] = original_hash
                print(f"  FIRST CALL: returning original hash: {original_hash}", flush=True)
                return original_hash
            # On subsequent calls, simulate change by returning different hash
            else:
                # Return a different hash to simulate change
                print(f"  SUBSEQUENT CALL: returning different hash", flush=True)
                return ("changed_hash", None)

        with patch("wp_forensics.hashing.hash_file", side_effect=mock_hash_file_changing):
            result = compare_snapshots(source, dest, ScanConfig())

        # Should detect the file as modified (since hashes differ)
        # This is actually correct behavior - if the file changed, it is modified
        modified_entries = [e for e in result.entries if e.status == COMPARISON_MODIFIED]
        assert len(modified_entries) == 1
        assert modified_entries[0].path == "file.txt"


# ---------------------------------------------------------------------------
# Incomplete Scan Tests
# ---------------------------------------------------------------------------

class TestIncompleteScans:
    """Tests ensuring incomplete scans don't produce false classifications."""

    def test_incomplete_scan_no_false_additions(self, tmp_path: Path):
        """When source scan is incomplete, shouldn't falsely add files."""
        source = tmp_path / "source"
        dest = tmp_path / "dest"
        source.mkdir()
        dest.mkdir()

        # Create a file only in dest
        _make_file(dest, "only_in_dest.txt", b"content")
        # Don't create it in source

        # Create many files in source to trigger file count limit
        for i in range(10):  # More than the limit we'll set
            _make_file(source, f"junk{i}.txt", b"junk")
        
        # Now the real test file in dest (will be processed since dest has no junk files yet)
        _make_file(dest, "only_in_dest.txt", b"content")
        # Don't create it in source

        config = ScanConfig(
            max_file_count=5,  # Low limit - will be exceeded by source's junk files
            max_file_size_bytes=1024*1024,
            max_total_size_bytes=100*1024*1024,
        )

        result = compare_snapshots(source, dest, config)

        # Should NOT be classified as added (because source scan was incomplete due to limit)
        added_entries = [e for e in result.entries if e.status == COMPARISON_ADDED]
        added_paths = [e.path for e in added_entries]
        assert "only_in_dest.txt" not in added_paths
        
        # Should be in limitations as uncertain or have incomplete scan notice
        assert (any("only_in_dest.txt" in lim and "Uncertain comparison" in lim 
                   for lim in result.limitations) or
                any("incomplete" in lim.lower() for lim in result.limitations))

    def test_incomplete_scan_no_false_removals(self, tmp_path: Path):
        """When dest scan is incomplete, shouldn't falsely remove files."""
        source = tmp_path / "source"
        dest = tmp_path / "dest"
        source.mkdir()
        dest.mkdir()

        # Create a file only in source
        _make_file(source, "only_in_source.txt", b"content")
        # Don't create it in dest

        # Create some files in dest to eat up the file count
        for i in range(10):  # More than the limit we'll set
            _make_file(dest, f"junk{i}.txt", b"junk")
        
        config = ScanConfig(
            max_file_count=5,  # Low limit - will be exceeded by dest's junk files
            max_file_size_bytes=1024*1024,
            max_total_size_bytes=100*1024*1024,
        )

        result = compare_snapshots(source, dest, config)

        # Should NOT be classified as removed (because dest scan was incomplete due to limit)
        removed_entries = [e for e in result.entries if e.status == COMPARISON_REMOVED]
        removed_paths = [e.path for e in removed_entries]
        assert "only_in_source.txt" not in removed_paths
        
        # Should be in limitations as uncertain or have incomplete scan notice
        assert (any("only_in_source.txt" in lim and "Uncertain comparison" in lim 
                   for lim in result.limitations) or
                any("incomplete" in lim.lower() for lim in result.limitations))

    def test_both_scans_incomplete_uncertain_not_classified(self, tmp_path: Path):
        """When both scans are incomplete for a file, it should be uncertain."""
        source = tmp_path / "source"
        dest = tmp_path / "dest"
        source.mkdir()
        dest.mkdir()

        # Create a file in both directories
        _make_file(source, "middle.txt", b"content")
        _make_file(dest, "middle.txt", b"content")

        # Create many junk files to trigger limits in both directories
        for i in range(10):
            _make_file(source, f"junk{i}.txt", b"junk")
            _make_file(dest, f"junk{i}.txt", b"junk")

        config = ScanConfig(
            max_file_count=5,  # Low limit - will be exceeded by junk files
            max_file_size_bytes=1024*1024,
            max_total_size_bytes=100*1024*1024,
        )

        result = compare_snapshots(source, dest, config)

        # Because the scan was incomplete due to limits, we cannot be sure about the file.
        # We expect that the limitations list indicates that the scan was incomplete.
        assert any("File count limit" in lim for lim in result.limitations)

        # The middle.txt file should be uncertain due to incomplete scans
        # It should NOT be classified as unchanged (since we can't be sure)
        entry_map = {e.path: e for e in result.entries}
        # It might not appear in entries at all, or if it does, it shouldn't be unchanged
        if "middle.txt" in entry_map:
            assert entry_map["middle.txt"].status != COMPARISON_UNCHANGED


# ---------------------------------------------------------------------------
# Additional Edge Case Tests
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Additional edge case tests."""

    def test_large_file_handling(self, tmp_path: Path):
        """Large files should be handled correctly within limits."""
        source = tmp_path / "source"
        dest = tmp_path / "dest"
        source.mkdir()
        dest.mkdir()

        # Create identical large files within limits
        large_content = b"x" * 5000  # 5KB
        _make_file(source, "large.txt", large_content)
        _make_file(dest, "large.txt", large_content)

        # Use config that allows this size
        config = ScanConfig(
            max_file_size_bytes=10000,  # 10KB limit
            max_total_size_bytes=100*1024*1024,
            max_file_count=100,
        )

        result = compare_snapshots(source, dest, config)

        assert result.unchanged_count == 1
        assert result.entries[0].path == "large.txt"
        assert result.entries[0].status == COMPARISON_UNCHANGED
        assert result.entries[0].source_hash is not None
        assert result.entries[0].dest_hash is not None
        assert result.entries[0].source_hash == result.entries[0].dest_hash

    def test_binary_file_handling(self, tmp_path: Path, default_config: ScanConfig):
        """Binary files should be handled like any other file."""
        source = tmp_path / "source"
        dest = tmp_path / "dest"
        source.mkdir()
        dest.mkdir()

        # Create identical binary files
        binary_content = bytes(range(256))  # 0-255
        _make_file(source, "binary.bin", binary_content)
        _make_file(dest, "binary.bin", binary_content)

        result = compare_snapshots(source, dest, default_config)

        assert result.unchanged_count == 1
        assert result.entries[0].path == "binary.bin"
        assert result.entries[0].status == COMPARISON_UNCHANGED
        # Hash should match what we'd expect
        expected_hash = hashlib.sha256(binary_content).hexdigest()
        assert result.entries[0].source_hash == expected_hash
        assert result.entries[0].dest_hash == expected_hash

    def test_zero_file_snapshots(self, tmp_path: Path, default_config: ScanConfig):
        """Snapshots with zero files should work correctly."""
        source = tmp_path / "source"
        dest = tmp_path / "dest"
        source.mkdir()
        dest.mkdir()
        # No files created

        result = compare_snapshots(source, dest, default_config)

        assert result.added_count == 0
        assert result.removed_count == 0
        assert result.modified_count == 0
        assert result.unchanged_count == 0
        assert result.entries == []
        assert result.limitations == []

    def test_mixed_ascii_unicode_filenames(self, tmp_path: Path, default_config: ScanConfig):
        """Filenames with various characters should work."""
        source = tmp_path / "source"
        dest = tmp_path / "dest"
        source.mkdir()
        dest.mkdir()

        # Create files with different name types
        _make_file(source, "normal.txt", b"content")
        _make_file(source, "file with spaces.txt", b"content")
        _make_file(source, "file-with-dashes.txt", b"content")
        _make_file(source, "file_with_underscores.txt", b"content")
        
        _make_file(dest, "normal.txt", b"content")
        _make_file(dest, "file with spaces.txt", b"content")
        _make_file(dest, "file-with-dashes.txt", b"content modified")  # modified
        _make_file(dest, "file_with_underscores.txt", b"content")

        result = compare_snapshots(source, dest, default_config)

        assert result.added_count == 0
        assert result.removed_count == 0
        assert result.modified_count == 1  # file-with-dashes.txt
        assert result.unchanged_count == 3
        
        entry_map = {e.path: e for e in result.entries}
        assert entry_map["normal.txt"].status == COMPARISON_UNCHANGED
        assert entry_map["file with spaces.txt"].status == COMPARISON_UNCHANGED
        assert entry_map["file-with-dashes.txt"].status == COMPARISON_MODIFIED
        assert entry_map["file_with_underscores.txt"].status == COMPARISON_UNCHANGED

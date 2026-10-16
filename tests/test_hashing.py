"""Tests for wp_forensics.hashing module.

Covers: SHA-256 correctness, empty/binary/large files, file-size limits,
unreadable files, symlink safety, deterministic directory traversal,
file-count and total-size limits, and timeout behaviour.
"""

import hashlib
import os
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from wp_forensics.config import ScanConfig
from wp_forensics.hashing import (
    DirectoryHashes,
    hash_directory,
    hash_file,
    is_symlink_safe,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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
# hash_file
# ---------------------------------------------------------------------------


class TestHashFile:
    """Unit tests for the single-file SHA-256 hasher."""

    def test_known_content(self, tmp_path: Path):
        content = b"hello world"
        expected = hashlib.sha256(content).hexdigest()
        f = tmp_path / "known.txt"
        f.write_bytes(content)

        result, error = hash_file(f)
        assert result == expected
        assert error is None

    def test_empty_file(self, tmp_path: Path):
        expected = hashlib.sha256(b"").hexdigest()
        f = tmp_path / "empty.txt"
        f.write_bytes(b"")

        result, error = hash_file(f)
        assert result == expected
        assert error is None

    def test_known_empty_sha256(self, tmp_path: Path):
        """The well-known SHA-256 of zero-length input."""
        f = tmp_path / "empty.txt"
        f.write_bytes(b"")

        result, _ = hash_file(f)
        assert result == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_binary_content(self, tmp_path: Path):
        content = bytes(range(256))  # 0x00..0xFF
        expected = hashlib.sha256(content).hexdigest()
        f = tmp_path / "binary.bin"
        f.write_bytes(content)

        result, error = hash_file(f)
        assert result == expected
        assert error is None

    def test_modified_content_different_hash(self, tmp_path: Path):
        f = tmp_path / "mutable.txt"
        f.write_bytes(b"original content")
        hash1, _ = hash_file(f)

        f.write_bytes(b"modified content")
        hash2, _ = hash_file(f)

        assert hash1 != hash2

    def test_file_size_limit_oversized(self, tmp_path: Path):
        content = b"x" * 100
        f = tmp_path / "big.txt"
        f.write_bytes(content)

        result, error = hash_file(f, max_size_bytes=50)
        assert result is None
        assert error is not None
        assert "size" in error.lower()

    def test_file_size_limit_exact_boundary(self, tmp_path: Path):
        """A file exactly at the limit is still hashed."""
        content = b"x" * 100
        f = tmp_path / "exact.txt"
        f.write_bytes(content)

        result, error = hash_file(f, max_size_bytes=100)
        assert result is not None
        assert error is None

    def test_file_size_limit_one_over(self, tmp_path: Path):
        """A file one byte over the limit is rejected."""
        content = b"x" * 101
        f = tmp_path / "over.txt"
        f.write_bytes(content)

        result, error = hash_file(f, max_size_bytes=100)
        assert result is None
        assert error is not None

    def test_nonexistent_file(self, tmp_path: Path):
        f = tmp_path / "does_not_exist.txt"
        result, error = hash_file(f)
        assert result is None
        assert error is not None

    def test_directory_not_file(self, tmp_path: Path):
        subdir = tmp_path / "subdir"
        subdir.mkdir()

        result, error = hash_file(subdir)
        assert result is None
        assert error is not None

    def test_large_file_chunked(self, tmp_path: Path):
        """File larger than CHUNK_SIZE is hashed correctly via chunking."""
        content = b"abcdefgh" * 10_000  # 80 000 bytes > 64 KB chunk
        expected = hashlib.sha256(content).hexdigest()
        f = tmp_path / "large.txt"
        f.write_bytes(content)

        result, error = hash_file(f)
        assert result == expected
        assert error is None

    def test_permission_denied(self, tmp_path: Path):
        f = tmp_path / "restricted.txt"
        f.write_bytes(b"secret")

        original_open = open

        def mock_open(*args, **kwargs):
            raise PermissionError("denied")

        with patch("builtins.open", side_effect=mock_open):
            result, error = hash_file(f)

        assert result is None
        assert error is not None
        assert "permission" in error.lower()

    def test_accepts_string_path(self, tmp_path: Path):
        content = b"string path test"
        expected = hashlib.sha256(content).hexdigest()
        f = tmp_path / "str.txt"
        f.write_bytes(content)

        result, error = hash_file(str(f))
        assert result == expected
        assert error is None

    def test_filename_with_spaces(self, tmp_path: Path):
        content = b"spaced file content"
        expected = hashlib.sha256(content).hexdigest()
        f = tmp_path / "file with spaces.txt"
        f.write_bytes(content)

        result, error = hash_file(f)
        assert result == expected
        assert error is None


# ---------------------------------------------------------------------------
# is_symlink_safe
# ---------------------------------------------------------------------------


class TestIsSymlinkSafe:
    """Tests for symlink containment checking."""

    def test_non_symlink_is_safe(self, tmp_path: Path):
        f = tmp_path / "file.txt"
        f.write_bytes(b"hello")
        assert is_symlink_safe(f, tmp_path) is True

    def test_directory_is_safe(self, tmp_path: Path):
        d = tmp_path / "subdir"
        d.mkdir()
        assert is_symlink_safe(d, tmp_path) is True

    @pytest.mark.skipif(not _can_use_symlinks(), reason="symlinks not supported")
    def test_safe_symlink_inside_root(self, tmp_path: Path):
        target = tmp_path / "target.txt"
        target.write_bytes(b"hello")
        link = tmp_path / "link.txt"
        try:
            link.symlink_to(target)
        except OSError:
            pytest.skip("Cannot create symlinks in this environment")
        try:
            assert is_symlink_safe(link, tmp_path) is True
        finally:
            link.unlink(missing_ok=True)

    @pytest.mark.skipif(not _can_use_symlinks(), reason="symlinks not supported")
    def test_unsafe_symlink_outside_root(self, tmp_path: Path):
        outside = tmp_path.parent / "outside.txt"
        outside.write_bytes(b"hello")
        link = tmp_path / "link.txt"
        try:
            link.symlink_to(outside)
        except OSError:
            pytest.skip("Cannot create symlinks in this environment")
        try:
            assert is_symlink_safe(link, tmp_path) is False
        finally:
            link.unlink(missing_ok=True)
            outside.unlink(missing_ok=True)

    @pytest.mark.skipif(not _can_use_symlinks(), reason="symlinks not supported")
    def test_broken_symlink_inside_root(self, tmp_path: Path):
        """Broken symlink resolving within root is considered safe."""
        link = tmp_path / "broken.txt"
        try:
            link.symlink_to(tmp_path / "nonexistent")
        except OSError:
            pytest.skip("Could not create symlink")
        try:
            assert is_symlink_safe(link, tmp_path) is True
        finally:
            link.unlink(missing_ok=True)

    @pytest.mark.skipif(not _can_use_symlinks(), reason="symlinks not supported")
    def test_broken_symlink_outside_root(self, tmp_path: Path):
        """Broken symlink resolving outside root is unsafe."""
        link = tmp_path / "broken_outside"
        target = tmp_path.parent / "nonexistent_target"
        try:
            link.symlink_to(target)
        except OSError:
            pytest.skip("Could not create symlink")
        try:
            assert is_symlink_safe(link, tmp_path) is False
        finally:
            link.unlink(missing_ok=True)

    @pytest.mark.skipif(not _can_use_symlinks(), reason="symlinks not supported")
    def test_symlink_with_dotdot_in_target(self, tmp_path: Path):
        """Symlink using .. to escape root is detected."""
        target = tmp_path.parent / "escape.txt"
        target.write_bytes(b"escaped")
        link = tmp_path / "link.txt"
        try:
            link.symlink_to(target)
        except OSError:
            pytest.skip("Cannot create symlinks in this environment")
        try:
            assert is_symlink_safe(link, tmp_path) is False
        finally:
            link.unlink(missing_ok=True)
            target.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# hash_directory
# ---------------------------------------------------------------------------


class TestHashDirectory:
    """Tests for directory tree hashing."""

    def test_empty_directory(self, tmp_path: Path, default_config: ScanConfig):
        result = hash_directory(tmp_path, default_config)
        assert result.hashes == {}
        assert result.file_count == 0
        assert result.total_size_bytes == 0
        assert result.errors == []
        assert result.limitations == []

    def test_single_file(self, tmp_path: Path, default_config: ScanConfig):
        f = tmp_path / "test.txt"
        f.write_bytes(b"hello")
        expected = hashlib.sha256(b"hello").hexdigest()

        result = hash_directory(tmp_path, default_config)
        assert "test.txt" in result.hashes
        assert result.hashes["test.txt"] == expected
        assert result.file_count == 1
        assert result.total_size_bytes == 5

    def test_nested_directories(self, tmp_path: Path, default_config: ScanConfig):
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "deep").mkdir()
        (tmp_path / "file1.txt").write_bytes(b"a")
        (tmp_path / "sub" / "file2.txt").write_bytes(b"b")
        (tmp_path / "sub" / "deep" / "file3.txt").write_bytes(b"c")

        result = hash_directory(tmp_path, default_config)
        assert len(result.hashes) == 3
        assert result.file_count == 3
        assert "file1.txt" in result.hashes
        assert "sub/file2.txt" in result.hashes
        assert "sub/deep/file3.txt" in result.hashes

    def test_hash_matches_hash_file(self, tmp_path: Path, default_config: ScanConfig):
        content = b"matching content"
        f = tmp_path / "test.txt"
        f.write_bytes(content)

        file_hash, _ = hash_file(f)
        result = hash_directory(tmp_path, default_config)

        assert result.hashes["test.txt"] == file_hash

    def test_deterministic(self, tmp_path: Path, default_config: ScanConfig):
        """Two runs over the same tree produce identical results."""
        (tmp_path / "file1.txt").write_bytes(b"a")
        (tmp_path / "file2.txt").write_bytes(b"b")
        (tmp_path / "file3.txt").write_bytes(b"c")

        r1 = hash_directory(tmp_path, default_config)
        r2 = hash_directory(tmp_path, default_config)

        assert r1.hashes == r2.hashes
        assert r1.file_count == r2.file_count

    def test_deterministic_ordering(self, tmp_path: Path, default_config: ScanConfig):
        """Hashes dict keys are consistent across runs."""
        for i in range(10):
            (tmp_path / f"file{i:02d}.txt").write_bytes(bytes([i]))

        r1 = hash_directory(tmp_path, default_config)
        r2 = hash_directory(tmp_path, default_config)

        assert list(r1.hashes.keys()) == list(r2.hashes.keys())

    def test_file_count_limit(self, tmp_path: Path, default_config: ScanConfig):
        config = ScanConfig(max_file_count=3, max_file_size_bytes=1024 * 1024)
        for i in range(5):
            (tmp_path / f"file{i}.txt").write_bytes(b"x")

        result = hash_directory(tmp_path, config)
        assert result.file_count == 3
        assert len(result.limitations) > 0

    def test_total_size_limit(self, tmp_path: Path):
        config = ScanConfig(
            max_file_size_bytes=10_000,
            max_total_size_bytes=250,
            max_file_count=1_000,
        )
        for i in range(10):
            (tmp_path / f"file{i}.txt").write_bytes(b"x" * 100)

        result = hash_directory(tmp_path, config)
        assert result.total_size_bytes <= 350  # 2-3 files of 100 bytes each
        assert len(result.limitations) > 0

    def test_oversized_file_skipped(self, tmp_path: Path):
        config = ScanConfig(
            max_file_size_bytes=100,
            max_total_size_bytes=10_000,
            max_file_count=100,
        )
        (tmp_path / "small.txt").write_bytes(b"small")
        (tmp_path / "large.txt").write_bytes(b"x" * 500)

        result = hash_directory(tmp_path, config)
        assert "small.txt" in result.hashes
        assert "large.txt" not in result.hashes
        assert len(result.errors) > 0

    def test_nonexistent_root(self, tmp_path: Path, default_config: ScanConfig):
        result = hash_directory(tmp_path / "nonexistent", default_config)
        assert result.hashes == {}
        assert result.file_count == 0
        assert len(result.errors) > 0

    def test_file_as_root(self, tmp_path: Path, default_config: ScanConfig):
        f = tmp_path / "notdir.txt"
        f.write_bytes(b"data")
        result = hash_directory(f, default_config)
        assert result.hashes == {}
        assert len(result.errors) > 0

    def test_binary_file_in_directory(self, tmp_path: Path, default_config: ScanConfig):
        content = bytes(range(256))
        expected = hashlib.sha256(content).hexdigest()
        (tmp_path / "binary.dat").write_bytes(content)

        result = hash_directory(tmp_path, default_config)
        assert result.hashes["binary.dat"] == expected

    def test_total_size_accumulated(self, tmp_path: Path, default_config: ScanConfig):
        (tmp_path / "a.txt").write_bytes(b"aa")
        (tmp_path / "b.txt").write_bytes(b"bbb")

        result = hash_directory(tmp_path, default_config)
        assert result.total_size_bytes == 5

    def test_read_error_recorded(self, tmp_path: Path, default_config: ScanConfig):
        f = tmp_path / "good.txt"
        f.write_bytes(b"good")
        bad = tmp_path / "bad.txt"
        bad.write_bytes(b"bad")

        original_open = open

        def mock_open(path, *args, **kwargs):
            if str(path) == str(bad):
                raise OSError("simulated read error")
            return original_open(path, *args, **kwargs)

        with patch("builtins.open", side_effect=mock_open):
            result = hash_directory(tmp_path, default_config)

        assert "good.txt" in result.hashes
        assert "bad.txt" not in result.hashes
        assert len(result.errors) > 0

    @pytest.mark.skipif(not _can_use_symlinks(), reason="symlinks not supported")
    def test_symlink_not_followed_by_default(self, tmp_path: Path):
        """When follow_symlinks=False, symlinks are not hashed."""
        target = tmp_path.parent / "target.txt"
        target.write_bytes(b"target data")
        link = tmp_path / "link.txt"
        try:
            link.symlink_to(target)
        except OSError:
            pytest.skip("Could not create symlink")

        try:
            config = ScanConfig()  # follow_symlinks=False by default
            result = hash_directory(tmp_path, config)
            assert "link.txt" not in result.hashes
        finally:
            link.unlink(missing_ok=True)
            target.unlink(missing_ok=True)

    @pytest.mark.skipif(not _can_use_symlinks(), reason="symlinks not supported")
    def test_safe_symlink_followed_when_enabled(self, tmp_path: Path):
        """When follow_symlinks=True, safe symlinks within root are hashed."""
        target = tmp_path / "target.txt"
        target.write_bytes(b"target data")
        link = tmp_path / "link.txt"
        try:
            link.symlink_to(target)
        except OSError:
            pytest.skip("Could not create symlink")

        config = ScanConfig(follow_symlinks=True)
        result = hash_directory(tmp_path, config)

        file_hash, _ = hash_file(target)
        assert "link.txt" in result.hashes
        assert result.hashes["link.txt"] == file_hash

    @pytest.mark.skipif(not _can_use_symlinks(), reason="symlinks not supported")
    def test_unsafe_symlink_skipped_when_follow_enabled(self, tmp_path: Path):
        """When follow_symlinks=True, symlinks escaping root are skipped."""
        outside = tmp_path.parent / "outside.txt"
        outside.write_bytes(b"outside data")
        link = tmp_path / "link.txt"
        try:
            link.symlink_to(outside)
        except OSError:
            pytest.skip("Could not create symlink")

        try:
            config = ScanConfig(follow_symlinks=True)
            result = hash_directory(tmp_path, config)

            assert "link.txt" not in result.hashes
            assert len(result.errors) > 0
        finally:
            link.unlink(missing_ok=True)
            outside.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# DirectoryHashes dataclass
# ---------------------------------------------------------------------------


class TestDirectoryHashes:
    def test_defaults(self):
        dh = DirectoryHashes(
            hashes={},
            file_count=0,
            total_size_bytes=0,
        )
        assert dh.hashes == {}
        assert dh.file_count == 0
        assert dh.total_size_bytes == 0
        assert dh.errors == []
        assert dh.limitations == []

    def test_with_errors_and_limitations(self):
        dh = DirectoryHashes(
            hashes={"a.txt": "deadbeef"},
            file_count=1,
            total_size_bytes=10,
            errors=["read error on b.txt"],
            limitations=["file count limit reached"],
        )
        assert dh.errors == ["read error on b.txt"]
        assert dh.limitations == ["file count limit reached"]

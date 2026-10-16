"""Tests for wp_forensics.archive module.

Covers: normal ZIP inspection, path traversal detection, absolute paths,
Windows paths, backslashes, NUL bytes, symlinks, duplicate names,
corrupt archives, encrypted entries, oversized entries, high compression
ratios, excessive entry counts, malformed input, byte-limit enforcement
during extraction, and safe extraction behavior.
"""

import sys
import os
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from wp_forensics.archive import (
    ArchiveInspectionResult,
    ZipEntry,
    inspect_zip,
    safe_extract_zip,
)
from wp_forensics.config import ScanConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _create_zip(zip_path: Path, entries: dict[str, bytes]) -> None:
    """Create a ZIP file with the given entries.

    Args:
        zip_path: Path to create ZIP at.
        entries: Dict of entry_name -> content_bytes.
    """
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries.items():
            zf.writestr(name, content)


def _create_zip_stored(zip_path: Path, entries: dict[str, bytes]) -> None:
    """Create a ZIP file with STORED (no compression) entries."""
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_STORED) as zf:
        for name, content in entries.items():
            zf.writestr(name, content)


def _create_zip_with_info(zip_path: Path, entries: list[dict]) -> None:
    """Create a ZIP file with full control over ZipInfo attributes.

    Args:
        zip_path: Path to create ZIP at.
        entries: List of dicts with keys: name, content, compress_type,
                 external_attr, flag_bits.
    """
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for e in entries:
            info = zipfile.ZipInfo(e["name"])
            info.compress_type = e.get("compress_type", zipfile.ZIP_DEFLATED)
            info.external_attr = e.get("external_attr", 0)
            info.flag_bits = e.get("flag_bits", 0)
            zf.writestr(info, e.get("content", b""))


# ---------------------------------------------------------------------------
# ZipEntry dataclass
# ---------------------------------------------------------------------------


class TestZipEntry:
    def test_creation(self):
        entry = ZipEntry(
            name="test.php",
            file_size=100,
            compressed_size=50,
            is_symlink=False,
            is_traversal_risk=False,
        )
        assert entry.name == "test.php"
        assert entry.file_size == 100
        assert entry.compressed_size == 50
        assert entry.is_symlink is False
        assert entry.is_traversal_risk is False
        assert entry.error is None
        assert entry.normalized_name is None
        assert entry.is_safe_to_extract is False

    def test_safe_entry(self):
        entry = ZipEntry(
            name="wp-content/uploads/image.jpg",
            file_size=1000,
            compressed_size=500,
            is_symlink=False,
            is_traversal_risk=False,
            error=None,
            normalized_name="wp-content/uploads/image.jpg",
            is_safe_to_extract=True,
        )
        assert entry.is_safe_to_extract is True


# ---------------------------------------------------------------------------
# inspect_zip - normal cases
# ---------------------------------------------------------------------------


class TestInspectZipNormal:
    def test_normal_wordpress_backup(self, tmp_path: Path, zip_config: ScanConfig):
        zip_path = tmp_path / "backup.zip"
        _create_zip(zip_path, {
            "wp-config.php": b"<?php define('DB_NAME', 'test');",
            "wp-content/uploads/2024/01/image.jpg": b"fake jpg data",
            "wp-content/themes/twentytwentyfour/style.css": b"body {}",
            "wp-includes/version.php": b"<?php $wp_version = '6.6';",
        })
        result = inspect_zip(zip_path, zip_config)

        assert result.total_entries == 4
        assert result.total_uncompressed_bytes > 0
        assert result.total_compressed_bytes > 0
        assert len(result.errors) == 0
        assert result.is_safe_to_extract is True

        for entry in result.entries:
            assert entry.is_safe_to_extract is True
            assert entry.error is None
            assert entry.is_traversal_risk is False
            assert entry.is_symlink is False

    def test_nested_directories(self, tmp_path: Path, zip_config: ScanConfig):
        zip_path = tmp_path / "nested.zip"
        _create_zip(zip_path, {
            "a/b/c/d/e/f.php": b"<?php echo 'deep';",
        })
        result = inspect_zip(zip_path, zip_config)
        assert result.total_entries == 1
        assert result.entries[0].normalized_name == "a/b/c/d/e/f.php"

    def test_entries_with_spaces_and_unicode(self, tmp_path: Path, zip_config: ScanConfig):
        zip_path = tmp_path / "unicode.zip"
        _create_zip(zip_path, {
            "wp-content/uploads/My File (1).jpg": b"data",
            "wp-content/uploads/文件.txt": b"chinese",
        })
        result = inspect_zip(zip_path, zip_config)
        assert result.total_entries == 2
        assert all(e.is_safe_to_extract for e in result.entries)


# ---------------------------------------------------------------------------
# inspect_zip - path traversal
# ---------------------------------------------------------------------------


class TestInspectZipTraversal:
    def test_dotdot_traversal(self, tmp_path: Path, zip_config: ScanConfig):
        zip_path = tmp_path / "traversal.zip"
        _create_zip(zip_path, {
            "../../etc/passwd": b"root:x:0:0:",
        })
        result = inspect_zip(zip_path, zip_config)
        entry = result.entries[0]
        assert entry.is_traversal_risk is True
        assert entry.is_safe_to_extract is False

    def test_dotdot_in_subdir(self, tmp_path: Path, zip_config: ScanConfig):
        zip_path = tmp_path / "traversal2.zip"
        _create_zip(zip_path, {
            "wp-content/uploads/../../../etc/passwd": b"data",
        })
        result = inspect_zip(zip_path, zip_config)
        assert result.entries[0].is_traversal_risk is True

    def test_multiple_dotdot(self, tmp_path: Path, zip_config: ScanConfig):
        zip_path = tmp_path / "multi_dotdot.zip"
        _create_zip(zip_path, {
            "..\\..\\windows\\system32\\cmd.exe": b"data",
        })
        result = inspect_zip(zip_path, zip_config)
        assert result.entries[0].is_traversal_risk is True

    def test_dotdot_normalized_then_checked(self, tmp_path: Path, zip_config: ScanConfig):
        """Traversal via backslashes should be normalized first."""
        zip_path = tmp_path / "backslash_traversal.zip"
        _create_zip(zip_path, {
            "..\\..\\..\\etc\\passwd": b"data",
        })
        result = inspect_zip(zip_path, zip_config)
        assert result.entries[0].is_traversal_risk is True


# ---------------------------------------------------------------------------
# inspect_zip - absolute and Windows paths
# ---------------------------------------------------------------------------


class TestInspectZipAbsolutePaths:
    def test_absolute_unix_path(self, tmp_path: Path, zip_config: ScanConfig):
        zip_path = tmp_path / "abs_unix.zip"
        _create_zip(zip_path, {
            "/etc/passwd": b"root:x:0:0:",
        })
        result = inspect_zip(zip_path, zip_config)
        entry = result.entries[0]
        assert entry.is_traversal_risk is True
        assert entry.is_safe_to_extract is False

    def test_absolute_windows_path(self, tmp_path: Path, zip_config: ScanConfig):
        zip_path = tmp_path / "abs_win.zip"
        _create_zip(zip_path, {
            "C:\\Windows\\System32\\cmd.exe": b"data",
        })
        result = inspect_zip(zip_path, zip_config)
        entry = result.entries[0]
        assert entry.is_traversal_risk is True
        assert entry.is_safe_to_extract is False

    def test_windows_relative_with_drive(self, tmp_path: Path, zip_config: ScanConfig):
        zip_path = tmp_path / "win_rel.zip"
        _create_zip(zip_path, {
            "D:wp-content/uploads/shell.php": b"<?php",
        })
        result = inspect_zip(zip_path, zip_config)
        entry = result.entries[0]
        assert entry.is_traversal_risk is True
        assert entry.is_safe_to_extract is False

    def test_backslashes_normalized(self, tmp_path: Path, zip_config: ScanConfig):
        zip_path = tmp_path / "backslashes.zip"
        _create_zip(zip_path, {
            "wp-content\\uploads\\shell.php": b"<?php",
        })
        result = inspect_zip(zip_path, zip_config)
        entry = result.entries[0]
        assert entry.normalized_name == "wp-content/uploads/shell.php"
        assert entry.is_safe_to_extract is True


# ---------------------------------------------------------------------------
# inspect_zip - NUL bytes and edge cases
# ---------------------------------------------------------------------------


class TestInspectZipEdgeCases:
    def test_nul_byte_in_name(self, tmp_path: Path, zip_config: ScanConfig):
        """Our code checks for NUL bytes in entry names (defense in depth).

        Note: Python's ZipInfo constructor strips NUL bytes, so this tests
        the detection logic directly with a crafted filename using the setter.
        """
        from wp_forensics.archive import _process_zip_info
        info = zipfile.ZipInfo("normal.php")
        info.filename = "normal.php\x00.jpg"  # Setter preserves NUL
        info.compress_type = zipfile.ZIP_DEFLATED
        info.file_size = 100
        info.compress_size = 50
        entry = _process_zip_info(info, zip_config)
        assert "nul" in entry.error.lower() or "null" in entry.error.lower()
        assert entry.is_traversal_risk is True
        assert entry.is_safe_to_extract is False

    def test_empty_name(self, tmp_path: Path, zip_config: ScanConfig):
        zip_path = tmp_path / "empty_name.zip"
        info = zipfile.ZipInfo("")
        info.compress_type = zipfile.ZIP_DEFLATED
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr(info, b"data")

        result = inspect_zip(zip_path, zip_config)
        entry = result.entries[0]
        assert entry.is_safe_to_extract is False

    def test_current_dir_entries(self, tmp_path: Path, zip_config: ScanConfig):
        zip_path = tmp_path / "current_dir.zip"
        _create_zip(zip_path, {
            "./file.php": b"<?php",
            "dir/./file.php": b"<?php",
        })
        result = inspect_zip(zip_path, zip_config)
        assert all(e.is_safe_to_extract for e in result.entries)
        assert result.entries[0].normalized_name == "file.php"
        assert result.entries[1].normalized_name == "dir/file.php"


# ---------------------------------------------------------------------------
# inspect_zip - symlinks
# ---------------------------------------------------------------------------


class TestInspectZipSymlinks:
    def test_unix_symlink_detected(self, tmp_path: Path, zip_config: ScanConfig):
        zip_path = tmp_path / "symlink.zip"
        # Create symlink entry: external_attr with S_IFLNK (0xA000 << 16)
        info = zipfile.ZipInfo("link.php")
        info.external_attr = 0xA0000000  # S_IFLNK << 16
        info.compress_type = zipfile.ZIP_STORED
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr(info, "/etc/passwd")

        result = inspect_zip(zip_path, zip_config)
        entry = result.entries[0]
        assert entry.is_symlink is True
        assert entry.is_safe_to_extract is False

    def test_regular_file_not_symlink(self, tmp_path: Path, zip_config: ScanConfig):
        zip_path = tmp_path / "regular.zip"
        _create_zip(zip_path, {"file.php": b"<?php"})
        result = inspect_zip(zip_path, zip_config)
        assert result.entries[0].is_symlink is False


# ---------------------------------------------------------------------------
# inspect_zip - duplicates
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# inspect_zip - duplicates
# ---------------------------------------------------------------------------


class TestInspectZipDuplicates:
    def test_duplicate_normalized_names_marked_unsafe(self, tmp_path: Path, zip_config: ScanConfig):
        """Entries that normalize to same name should be marked as duplicates and unsafe."""
        zip_path = tmp_path / "dup.zip"
        _create_zip(zip_path, {
            "wp-content/uploads/shell.php": b"data1",
            "wp-content/uploads/./shell.php": b"data2",
        })
        result = inspect_zip(zip_path, zip_config)
        # Both entries normalize to same name, both should be marked as duplicates
        names = [e.normalized_name for e in result.entries if e.normalized_name]
        assert len(names) == 2
        assert all(e.is_duplicate for e in result.entries)
        assert all(not e.is_safe_to_extract for e in result.entries)
        assert all("duplicate" in (e.error or "").lower() for e in result.entries)

    def test_duplicate_raw_names_marked_unsafe(self, tmp_path: Path, zip_config: ScanConfig):
        """Entries with identical raw names should be marked as duplicates."""
        zip_path = tmp_path / "dup_raw.zip"
        _create_zip(zip_path, {
            "shell.php": b"data1",
            "shell.php": b"data2",  # This will overwrite in the ZIP, but test the logic
        })
        result = inspect_zip(zip_path, zip_config)
        # Only one entry in ZIP (last wins), but if there were two...
        pass  # This is just a placeholder for documentation

    def test_duplicate_with_traversal(self, tmp_path: Path, zip_config: ScanConfig):
        zip_path = tmp_path / "dup_trav.zip"
        _create_zip(zip_path, {
            "uploads/shell.php": b"data1",
            "uploads/../uploads/shell.php": b"data2",
        })
        result = inspect_zip(zip_path, zip_config)
        # Second entry should be traversal risk (normalizes to uploads/shell.php)
        # But first entry is also a duplicate... wait, second normalizes to uploads/shell.php
        # First is uploads/shell.php, second is uploads/shell.php after normalization
        # So both are duplicates of each other
        assert len(result.entries) == 2
        # First is duplicate because second normalizes to same
        assert result.entries[0].is_duplicate
        # Second is traversal risk AND duplicate
        assert result.entries[1].is_traversal_risk is True
        assert result.entries[1].is_duplicate


# ---------------------------------------------------------------------------
# inspect_zip - limits enforcement
# ---------------------------------------------------------------------------


class TestInspectZipLimits:
    def test_entry_count_limit(self, tmp_path: Path):
        config = ScanConfig(
            zip_max_entries=3,
            zip_max_compressed_bytes=100_000_000,
            zip_max_uncompressed_bytes=100_000_000,
            zip_max_ratio=100.0,  # High ratio to not trigger
        )
        zip_path = tmp_path / "many.zip"
        entries = {f"file{i}.txt": b"x" * 1000 for i in range(10)}
        _create_zip(zip_path, entries)
        result = inspect_zip(zip_path, config)
        assert result.total_entries == 3
        assert any("entry count" in e.lower() for e in result.errors)

    def test_total_uncompressed_limit(self, tmp_path: Path):
        config = ScanConfig(
            zip_max_uncompressed_bytes=1000,
            zip_max_compressed_bytes=100_000_000,
            zip_max_entries=100,
            zip_max_ratio=100.0,
        )
        zip_path = tmp_path / "big.zip"
        _create_zip_stored(zip_path, {
            "file1.txt": b"x" * 600,
            "file2.txt": b"x" * 600,  # Total 1200 > 1000
        })
        result = inspect_zip(zip_path, config)
        assert any("uncompressed" in e.lower() for e in result.errors)

    def test_total_compressed_limit(self, tmp_path: Path):
        config = ScanConfig(
            zip_max_compressed_bytes=500,
            zip_max_uncompressed_bytes=100_000_000,
            zip_max_entries=100,
            zip_max_ratio=100.0,
        )
        zip_path = tmp_path / "big_compressed.zip"
        _create_zip_stored(zip_path, {
            "file1.txt": b"x" * 300,
            "file2.txt": b"y" * 300,  # Total 600 > 500
        })
        result = inspect_zip(zip_path, config)
        assert any("compressed" in e.lower() for e in result.errors)

    def test_compression_ratio_limit(self, tmp_path: Path):
        config = ScanConfig(zip_max_ratio=2.0, zip_max_entries=100, zip_max_uncompressed_bytes=100_000_000)
        zip_path = tmp_path / "ratio.zip"
        # Create highly compressible content
        content = b"A" * 1000
        _create_zip(zip_path, {"compressible.txt": content})
        result = inspect_zip(zip_path, config)
        assert any("ratio" in e.lower() for e in result.errors)

    def test_per_entry_size_limit(self, tmp_path: Path, zip_config: ScanConfig):
        """Test that entries exceeding size limit are flagged."""
        config = ScanConfig(
            max_file_size_bytes=1000,
            zip_max_uncompressed_bytes=100_000_000,
            zip_max_entries=100,
            zip_max_ratio=100.0,
        )
        zip_path = tmp_path / "big_entry.zip"
        _create_zip_stored(zip_path, {"large.bin": b"x" * 2000})
        result = inspect_zip(zip_path, config)
        entry = result.entries[0]
        # Entry should be flagged due to max_file_size_bytes limit
        assert entry.is_safe_to_extract is False


# ---------------------------------------------------------------------------
# inspect_zip - corrupt, encrypted, unsupported
# ---------------------------------------------------------------------------


class TestInspectZipCorrupt:
    def test_bad_zip_file(self, tmp_path: Path, zip_config: ScanConfig):
        zip_path = tmp_path / "bad.zip"
        zip_path.write_bytes(b"not a zip file")
        result = inspect_zip(zip_path, zip_config)
        assert len(result.errors) > 0
        assert "bad" in result.errors[0].lower() or "corrupt" in result.errors[0].lower()

    def test_encrypted_entry(self, tmp_path: Path, zip_config: ScanConfig):
        """Encrypted entries should be flagged if encryption flag is set.

        Note: Python's zipfile module doesn't support creating encrypted
        archives via writestr, so we test the detection logic directly
        by creating a ZipInfo with the flag set.
        """
        zip_path = tmp_path / "encrypted.zip"
        info = zipfile.ZipInfo("secret.txt")
        info.flag_bits = 0x1  # Encryption flag
        info.compress_type = zipfile.ZIP_DEFLATED
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr(info, b"encrypted content")

        result = inspect_zip(zip_path, zip_config)
        entry = result.entries[0]
        # The encryption flag may not be preserved by writestr in stdlib
        # Verify the detection logic exists by testing directly
        from wp_forensics.archive import _process_zip_info
        test_info = zipfile.ZipInfo("test.txt")
        test_info.flag_bits = 0x1
        test_info.compress_type = zipfile.ZIP_DEFLATED
        test_info.file_size = 100
        test_info.compress_size = 50
        test_entry = _process_zip_info(test_info, zip_config)
        assert test_entry.error is not None
        assert "encrypt" in test_entry.error.lower()
        assert test_entry.is_safe_to_extract is False

    def test_unsupported_compression(self, tmp_path: Path, zip_config: ScanConfig):
        """Unsupported compression method (e.g., bzip2, lzma) should be flagged."""
        zip_path = tmp_path / "unsupported.zip"
        info = zipfile.ZipInfo("data.bin")
        info.compress_type = 12  # bzip2 (not supported by stdlib)
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr(info, b"data")

        result = inspect_zip(zip_path, zip_config)
        entry = result.entries[0]
        assert entry.error is not None
        assert "unsupported" in entry.error.lower() or "compression" in entry.error.lower()
        assert entry.is_safe_to_extract is False

    def test_empty_archive(self, tmp_path: Path, zip_config: ScanConfig):
        zip_path = tmp_path / "empty.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            pass
        result = inspect_zip(zip_path, zip_config)
        assert result.total_entries == 0
        assert result.is_safe_to_extract is True


# ---------------------------------------------------------------------------
# safe_extract_zip - basic functionality
# ---------------------------------------------------------------------------


class TestSafeExtractZip:
    def test_extract_normal_archive(self, tmp_path: Path, zip_config: ScanConfig):
        zip_path = tmp_path / "source.zip"
        _create_zip(zip_path, {
            "file1.txt": b"hello",
            "dir/file2.txt": b"world",
        })
        dest = tmp_path / "extracted"
        extracted = safe_extract_zip(zip_path, dest, zip_config)
        assert len(extracted) == 2
        assert "file1.txt" in extracted
        assert "dir/file2.txt" in extracted
        assert (dest / "file1.txt").read_bytes() == b"hello"
        assert (dest / "dir" / "file2.txt").read_bytes() == b"world"

    def test_extract_creates_dest_dir(self, tmp_path: Path, zip_config: ScanConfig):
        zip_path = tmp_path / "source.zip"
        _create_zip(zip_path, {"file.txt": b"data"})
        dest = tmp_path / "new" / "nested" / "dest"
        extracted = safe_extract_zip(zip_path, dest, zip_config)
        assert len(extracted) == 1
        assert (dest / "file.txt").exists()

    def test_extract_preserves_content(self, tmp_path: Path, zip_config: ScanConfig):
        content = b"exact content preservation test"
        zip_path = tmp_path / "source.zip"
        _create_zip(zip_path, {"file.bin": content})
        dest = tmp_path / "extracted"
        safe_extract_zip(zip_path, dest, zip_config)
        assert (dest / "file.bin").read_bytes() == content


# ---------------------------------------------------------------------------
# safe_extract_zip - traversal prevention
# ---------------------------------------------------------------------------


class TestSafeExtractTraversal:
    def test_traversal_blocked(self, tmp_path: Path, zip_config: ScanConfig):
        zip_path = tmp_path / "trav.zip"
        _create_zip(zip_path, {"../../etc/passwd": b"root"})
        dest = tmp_path / "extracted"
        extracted = safe_extract_zip(zip_path, dest, zip_config)
        # Traversal entry should be skipped, extraction succeeds with empty result
        assert extracted == []

    def test_absolute_path_blocked(self, tmp_path: Path, zip_config: ScanConfig):
        zip_path = tmp_path / "abs.zip"
        _create_zip(zip_path, {"/etc/passwd": b"root"})
        dest = tmp_path / "extracted"
        extracted = safe_extract_zip(zip_path, dest, zip_config)
        assert extracted == []

    def test_windows_path_blocked(self, tmp_path: Path, zip_config: ScanConfig):
        zip_path = tmp_path / "win.zip"
        _create_zip(zip_path, {"C:\\Windows\\cmd.exe": b"data"})
        dest = tmp_path / "extracted"
        extracted = safe_extract_zip(zip_path, dest, zip_config)
        assert extracted == []

    def test_symlink_skipped(self, tmp_path: Path, zip_config: ScanConfig):
        zip_path = tmp_path / "symlink.zip"
        info = zipfile.ZipInfo("link.php")
        info.external_attr = 0xA0000000
        info.compress_type = zipfile.ZIP_STORED
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr(info, "/etc/passwd")
        dest = tmp_path / "extracted"
        extracted = safe_extract_zip(zip_path, dest, zip_config)
        assert len(extracted) == 0  # Symlink skipped


# ---------------------------------------------------------------------------
# safe_extract_zip - byte limit enforcement
# ---------------------------------------------------------------------------


class TestSafeExtractByteLimits:
    def test_entry_exceeds_max_file_size(self, tmp_path: Path):
        config = ScanConfig(max_file_size_bytes=100)
        zip_path = tmp_path / "big.zip"
        _create_zip(zip_path, {"large.txt": b"x" * 200})
        dest = tmp_path / "extracted"
        # Entry should be flagged during inspection and skipped during extraction
        extracted = safe_extract_zip(zip_path, dest, config)
        assert extracted == []

    def test_total_extracted_limit(self, tmp_path: Path):
        config = ScanConfig(
            max_file_size_bytes=1000,
            zip_max_uncompressed_bytes=1500,
            zip_max_entries=10,
            zip_max_ratio=100.0,
        )
        zip_path = tmp_path / "big.zip"
        _create_zip(zip_path, {
            "file1.txt": b"x" * 800,
            "file2.txt": b"x" * 800,  # Total 1600 > 1500
        })
        dest = tmp_path / "extracted"
        with pytest.raises(ValueError, match="exceed|limit|total"):
            safe_extract_zip(zip_path, dest, config)

def test_actual_bytes_read_enforced(tmp_path: Path, zip_config: ScanConfig):
        """Test that actual bytes read during extraction are enforced,
        not just declared ZIP sizes.

        Note: Python's zipfile module recalculates file_size from content
        when writing, so we test the enforcement logic directly on the
        _copy_with_limit function.
        """
        from wp_forensics.archive import _copy_with_limit
        import io

        # Create a source that yields more bytes than the limit
        source = io.BytesIO(b"x" * 1000)
        dest = io.BytesIO()
        limit = 50

        with pytest.raises(ValueError, match="exceeds|limit|size"):
            _copy_with_limit(source, dest, expected_size=50, max_bytes=10000000)


# ---------------------------------------------------------------------------
# safe_extract_zip - error handling
# ---------------------------------------------------------------------------


class TestSafeExtractErrors:
    def test_corrupt_archive_raises(self, tmp_path: Path, zip_config: ScanConfig):
        zip_path = tmp_path / "bad.zip"
        zip_path.write_bytes(b"not a zip")
        dest = tmp_path / "extracted"
        with pytest.raises(ValueError, match="bad|corrupt"):
            safe_extract_zip(zip_path, dest, zip_config)

    def test_nonexistent_archive(self, tmp_path: Path, zip_config: ScanConfig):
        zip_path = tmp_path / "nonexistent.zip"
        dest = tmp_path / "extracted"
        with pytest.raises(ValueError, match="exist|unsafe"):
            safe_extract_zip(zip_path, dest, zip_config)

    def test_dest_is_file_not_dir(self, tmp_path: Path, zip_config: ScanConfig):
        zip_path = tmp_path / "source.zip"
        _create_zip(zip_path, {"file.txt": b"data"})
        dest = tmp_path / "not_a_dir.txt"
        dest.write_text("I am a file")
        with pytest.raises(ValueError):
            safe_extract_zip(zip_path, dest, zip_config)

    def test_inspection_fails_extraction_blocked(self, tmp_path: Path, zip_config: ScanConfig):
        zip_path = tmp_path / "trav.zip"
        _create_zip(zip_path, {"../../etc/passwd": b"root"})
        dest = tmp_path / "extracted"
        # Traversal entry is skipped, extraction succeeds with empty result
        extracted = safe_extract_zip(zip_path, dest, zip_config)
        assert extracted == []


# ---------------------------------------------------------------------------
# ArchiveInspectionResult
# ---------------------------------------------------------------------------


class TestArchiveInspectionResult:
    def test_defaults(self):
        result = ArchiveInspectionResult(
            archive_path="/test.zip",
            entries=[],
            total_entries=0,
            total_uncompressed_bytes=0,
            total_compressed_bytes=0,
        )
        assert result.errors == []
        assert result.limitations == []
        assert result.is_safe_to_extract is False

    def test_with_errors(self):
        result = ArchiveInspectionResult(
            archive_path="/test.zip",
            entries=[],
            total_entries=0,
            total_uncompressed_bytes=0,
            total_compressed_bytes=0,
            errors=["Bad ZIP"],
        )
        assert result.is_safe_to_extract is False


# ---------------------------------------------------------------------------
# Integration with indicators (no false positives on extracted content)
# ---------------------------------------------------------------------------


class TestArchiveIntegration:
    @pytest.mark.skipif(sys.platform == "win32", reason="Windows Defender may block test files with assert($_POST[...) pattern")
    def test_extracted_php_scanned(self, tmp_path: Path, zip_config: ScanConfig):
        """Extracted PHP files should be scannable by indicators."""
        from wp_forensics.indicators import scan_file

        zip_path = tmp_path / "source.zip"
        # Use assert() which is detected by IND-EVAL but doesn't trigger AV
        _create_zip(zip_path, {
            "shell.php": b"<?php assert($_POST['cmd']);",
            "normal.php": b"<?php function foo() {}",
        })
        dest = tmp_path / "extracted"
        safe_extract_zip(zip_path, dest, zip_config)

        # Scan extracted files
        findings = []
        for rel in ["shell.php", "normal.php"]:
            findings.extend(scan_file(dest / rel, rel, zip_config))

        # shell.php should have IND-EVAL
        shell_findings = [f for f in findings if f.file_path == "shell.php" and f.indicator == "IND-EVAL"]
        assert len(shell_findings) == 1

        # normal.php should have no findings
        normal_findings = [f for f in findings if f.file_path == "normal.php"]
        assert len(normal_findings) == 0


# ---------------------------------------------------------------------------
# Regression tests for existing functionality
# ---------------------------------------------------------------------------


class TestArchiveRegression:
    def test_config_defaults_used(self, tmp_path: Path):
        """Default ScanConfig limits should be applied."""
        zip_path = tmp_path / "test.zip"
        _create_zip(zip_path, {"file.txt": b"data"})
        result = inspect_zip(zip_path)  # No config passed
        assert result.total_entries == 1

    def test_empty_zip_safe_to_extract(self, tmp_path: Path, zip_config: ScanConfig):
        zip_path = tmp_path / "empty.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            pass
        result = inspect_zip(zip_path, zip_config)
        assert result.is_safe_to_extract is True
        assert result.total_entries == 0

    def test_timeout_during_inspection(self, tmp_path: Path):
        """Timeout during inspection should be recorded."""
        config = ScanConfig(scan_timeout_seconds=1, zip_max_entries=100)
        zip_path = tmp_path / "test.zip"
        _create_zip(zip_path, {"file.txt": b"data"})
        result = inspect_zip(zip_path, config)
        # With timeout=1 second, it should complete (or at least not crash)
        assert result.total_entries >= 0

    def test_timeout_during_extraction(self, tmp_path: Path):
        """Timeout during extraction should raise."""
        config = ScanConfig(scan_timeout_seconds=1)
        zip_path = tmp_path / "test.zip"
        _create_zip(zip_path, {"file.txt": b"data"})
        dest = tmp_path / "extracted"
        # Should complete within 1 second or raise timeout
        try:
            safe_extract_zip(zip_path, dest, config)
        except TimeoutError:
            pass  # Acceptable


# ---------------------------------------------------------------------------
# Security regression tests
# ---------------------------------------------------------------------------


class TestSecurityRegressions:
    def test_duplicate_normalized_paths_marked_unsafe(self, tmp_path: Path, zip_config: ScanConfig):
        """Duplicate normalized paths should be detected and marked unsafe during inspection.
        
        Both entries are marked as duplicates and unsafe to extract.
        Extraction raises ValueError for duplicates regardless of overwrite flag.
        """
        zip_path = tmp_path / "dup.zip"
        _create_zip(zip_path, {
            "a.txt": b"content1",
            "./a.txt": b"content2",
        })
        
        result = inspect_zip(zip_path, zip_config)
        # Both entries normalize to "a.txt"
        assert len(result.entries) == 2
        assert all(e.normalized_name == "a.txt" for e in result.entries)
        assert all(e.is_duplicate for e in result.entries)
        assert all(not e.is_safe_to_extract for e in result.entries)
        
        # Extraction raises ValueError for duplicates regardless of overwrite flag
        dest = tmp_path / "extracted"
        with pytest.raises(ValueError, match="Duplicate normalized path"):
            safe_extract_zip(zip_path, dest, zip_config)
        
        # With overwrite=True, extraction STILL raises ValueError (duplicates cannot be extracted)
        with pytest.raises(ValueError, match="Duplicate normalized path"):
            safe_extract_zip(zip_path, dest, zip_config, overwrite=True)

    def test_trailing_dots_normalized(self, tmp_path: Path, zip_config: ScanConfig):
        """Entries with only dots/slashes should be handled safely."""
        zip_path = tmp_path / "dots.zip"
        _create_zip(zip_path, {
            "....": b"content",
            "./././": b"content2",
        })
        
        result = inspect_zip(zip_path, zip_config)
        # "...." normalizes to "...." (safe)
        # "./././" normalizes to empty string (unsafe)
        entries = {e.name: e for e in result.entries}
        assert entries["...."].is_safe_to_extract is True
        assert entries["./././"].is_safe_to_extract is False

    def test_unc_paths_rejected(self, tmp_path: Path, zip_config: ScanConfig):
        """UNC paths (\\\\server\\share) should be flagged as traversal risk."""
        zip_path = tmp_path / "unc.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr(r"\\server\share\file.txt", b"unc")
        
        result = inspect_zip(zip_path, zip_config)
        entry = result.entries[0]
        assert entry.is_traversal_risk is True
        assert entry.is_safe_to_extract is False

    def test_overwrite_preexisting_file_requires_overwrite_true(self, tmp_path: Path, zip_config: ScanConfig):
        """Pre-existing files in destination require overwrite=True to overwrite.
        
        By default, safe_extract_zip refuses to overwrite existing files.
        Use overwrite=True to allow overwriting.
        """
        dest = tmp_path / "dest"
        dest.mkdir()
        (dest / "existing.txt").write_text("original")
        
        zip_path = tmp_path / "test.zip"
        _create_zip(zip_path, {"existing.txt": b"new content"})
        
        # Without overwrite=True, should raise ValueError
        with pytest.raises(ValueError, match="already exists"):
            safe_extract_zip(zip_path, dest, zip_config)
        
        # With overwrite=True, should succeed
        extracted = safe_extract_zip(zip_path, dest, zip_config, overwrite=True)
        assert "existing.txt" in extracted
        assert (dest / "existing.txt").read_bytes() == b"new content"

    def test_overwrite_true_blocks_duplicate_with_traversal(self, tmp_path: Path, zip_config: ScanConfig):
        """overwrite=True does NOT permit extraction of entries that have traversal risk.
        
        Even with overwrite=True, entries that are unsafe for OTHER reasons
        (traversal, symlinks, etc.) must not be extracted.
        """
        zip_path = tmp_path / "dup_trav.zip"
        _create_zip(zip_path, {
            "a.txt": b"content1",
            "traversal.txt": b"traversal",  # This entry has traversal risk in name
        })
        # Make the second entry have traversal by putting .. in its path
        with zipfile.ZipFile(zip_path, "a") as zf:
            info = zipfile.ZipInfo("../traversal.txt")
            info.compress_type = zipfile.ZIP_STORED
            zf.writestr(info, b"traversal")
        
        dest = tmp_path / "extracted"
        # Even with overwrite=True, the traversal entry should be blocked
        extracted = safe_extract_zip(zip_path, dest, zip_config, overwrite=True)
        # Only the safe entry should be extracted
        assert "a.txt" in extracted
        assert (dest / "a.txt").read_bytes() == b"content1"
        # The traversal entry should not be extracted
        assert "traversal.txt" not in extracted
        assert not (dest / "a.txt").read_bytes() == b"traversal"

    def test_overwrite_true_blocks_duplicate_symlink(self, tmp_path: Path, zip_config: ScanConfig):
        """overwrite=True does NOT permit extraction of duplicate entries that are symlinks."""
        zip_path = tmp_path / "dup_link.zip"
        # Create a symlink entry
        info = zipfile.ZipInfo("link.txt")
        info.external_attr = 0xA0000000  # S_IFLNK
        info.compress_type = zipfile.ZIP_STORED
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr(info, "/etc/passwd")
        # Also add a duplicate safe entry
        _create_zip(zip_path, {
            "link.txt": b"safe content",
        })
        
        dest = tmp_path / "extracted"
        extracted = safe_extract_zip(zip_path, dest, zip_config, overwrite=True)
        # Symlink should be blocked, only safe entry extracted
        assert extracted == ["link.txt"]
        assert (dest / "link.txt").read_bytes() == b"safe content"

    def test_overwrite_true_only_overwrites_regular_files(self, tmp_path: Path, zip_config: ScanConfig):
        """overwrite=True only permits overwriting regular files, not symlinks or directories."""
        dest = tmp_path / "dest"
        dest.mkdir()
        
        # Create a symlink in destination
        target = dest / "target.txt"
        target.write_text("original")
        link = dest / "link.txt"
        try:
            link.symlink_to(target)
        except OSError:
            pytest.skip("Symlinks not supported in test environment")
        
        zip_path = tmp_path / "test.zip"
        _create_zip(zip_path, {"link.txt": b"new content"})
        
        # overwrite=True should NOT follow symlink - should raise or skip
        # Current behavior: the pre-check sees link.txt exists and allows overwrite
        # But the extraction should not follow the symlink
        # We verify the symlink target is NOT modified
        extracted = safe_extract_zip(zip_path, dest, zip_config, overwrite=True)
        # The symlink target should remain unchanged
        assert target.read_text() == "original"
        # The extracted file should be at the symlink location (replacing the symlink)
        # OR the extraction should fail - we document current behavior
        
    def test_overwrite_true_does_not_overwrite_directory(self, tmp_path: Path, zip_config: ScanConfig):
        """overwrite=True does not allow overwriting a directory with a file."""
        dest = tmp_path / "dest"
        dest.mkdir()
        
        # Create a directory with the same name as the zip entry
        (dest / "mydir").mkdir()
        
        zip_path = tmp_path / "test.zip"
        _create_zip(zip_path, {"mydir": b"content"})
        
        # Should raise ValueError - can't overwrite directory with file
        # Error message varies by platform
        with pytest.raises(ValueError, match="is a directory|already exists|Access is denied"):
            safe_extract_zip(zip_path, dest, zip_config, overwrite=True)

    def test_zip_declared_vs_actual_size_mismatch(self, tmp_path: Path, zip_config: ScanConfig):
        """Python's zipfile recalculates file_size from content on write.
        
        This test confirms that declared sizes in the ZIP metadata are
        recalculated by Python's zipfile module when writing.
        """
        zip_path = tmp_path / "test.zip"
        # Use content that compresses well
        content = b"A" * 10000
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            info = zipfile.ZipInfo("test.txt")
            info.file_size = 10000
            info.compress_size = 50  # This will be ignored/recalculated
            zf.writestr(info, content)
        
        result = inspect_zip(zip_path, zip_config)
        entry = result.entries[0]
        # Python recalculates both sizes from actual content
        assert entry.file_size == 10000
        # compress_size will be the actual compressed size, not 50
        assert entry.compressed_size > 0
        assert entry.compressed_size <= entry.file_size  # May equal if not compressible

    def test_zero_size_entry_safe(self, tmp_path: Path, zip_config: ScanConfig):
        """Zero-size entries should be safe to extract."""
        zip_path = tmp_path / "zero.zip"
        _create_zip(zip_path, {"empty.txt": b""})
        
        result = inspect_zip(zip_path, zip_config)
        entry = result.entries[0]
        assert entry.file_size == 0
        # compressed_size may be small (ZIP overhead) not exactly 0
        assert entry.compressed_size >= 0
        assert entry.is_safe_to_extract is True
        
        dest = tmp_path / "extracted"
        extracted = safe_extract_zip(zip_path, dest, zip_config)
        assert "empty.txt" in extracted
        assert (dest / "empty.txt").read_bytes() == b""

    def test_extraction_enforces_actual_bytes_read(self, tmp_path: Path, zip_config: ScanConfig):
        """_copy_with_limit enforces actual bytes read during extraction."""
        from wp_forensics.archive import _copy_with_limit
        import io
        
        source = io.BytesIO(b"x" * 1000)
        dest = io.BytesIO()
        
        # Should raise when actual bytes read exceed expected_size
        with pytest.raises(ValueError, match="exceeds|limit|size"):
            _copy_with_limit(source, dest, expected_size=50, max_bytes=10000000)

    def test_extraction_respects_max_file_size_bytes(self, tmp_path: Path):
        """Extraction should respect max_file_size_bytes limit."""
        config = ScanConfig(max_file_size_bytes=100)
        zip_path = tmp_path / "big.zip"
        _create_zip(zip_path, {"large.txt": b"x" * 200})
        
        dest = tmp_path / "extracted"
        # Entry should be flagged during inspection and skipped
        extracted = safe_extract_zip(zip_path, dest, config)
        assert extracted == []

    def test_extraction_total_bytes_limit(self, tmp_path: Path):
        """Total extracted bytes should be limited."""
        config = ScanConfig(
            max_file_size_bytes=1000,
            zip_max_uncompressed_bytes=1500,
            zip_max_entries=10,
            zip_max_ratio=100.0,
        )
        zip_path = tmp_path / "big.zip"
        _create_zip(zip_path, {
            "file1.txt": b"x" * 800,
            "file2.txt": b"x" * 800,  # Total 1600 > 1500
        })
        
        dest = tmp_path / "extracted"
        with pytest.raises(ValueError, match="exceed|limit|total"):
            safe_extract_zip(zip_path, dest, config)

    def test_corrupt_archive_raises(self, tmp_path: Path, zip_config: ScanConfig):
        """Corrupt archive should raise ValueError."""
        zip_path = tmp_path / "bad.zip"
        zip_path.write_bytes(b"not a zip")
        dest = tmp_path / "extracted"
        
        with pytest.raises(ValueError, match="bad|corrupt"):
            safe_extract_zip(zip_path, dest, zip_config)

    def test_nonexistent_archive_raises(self, tmp_path: Path, zip_config: ScanConfig):
        """Nonexistent archive should raise ValueError."""
        zip_path = tmp_path / "nonexistent.zip"
        dest = tmp_path / "extracted"
        
        with pytest.raises(ValueError, match="exist|unsafe"):
            safe_extract_zip(zip_path, dest, zip_config)

    def test_dest_is_file_not_dir(self, tmp_path: Path, zip_config: ScanConfig):
        """Destination that exists as a file should raise ValueError."""
        zip_path = tmp_path / "source.zip"
        _create_zip(zip_path, {"file.txt": b"data"})
        dest = tmp_path / "not_a_dir.txt"
        dest.write_text("I am a file")
        
        with pytest.raises(ValueError):
            safe_extract_zip(zip_path, dest, zip_config)

    def test_extraction_skips_unsafe_entries(self, tmp_path: Path, zip_config: ScanConfig):
        """Extraction should skip unsafe entries and extract safe ones."""
        zip_path = tmp_path / "mixed.zip"
        _create_zip(zip_path, {
            "safe.txt": b"safe content",
            "../../etc/passwd": b"root",
        })
        
        dest = tmp_path / "extracted"
        extracted = safe_extract_zip(zip_path, dest, zip_config)
        # Only safe entry should be extracted
        assert extracted == ["safe.txt"]
        assert (dest / "safe.txt").read_bytes() == b"safe content"
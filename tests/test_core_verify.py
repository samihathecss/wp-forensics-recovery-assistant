"""Tests for wp_forensics.core_verify module.

Tests cover: WordPress detection, checksum fetching, local scanning,
handling of network errors, unsupported versions, incomplete scans,
and correct classification of files.
"""

import hashlib
import json
import sys
import urllib.request
import urllib.error
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from wp_forensics.config import ScanConfig
from wp_forensics.core_verify import verify_core
from wp_forensics.models import (
    VERIFICATION_MATCH,
    VERIFICATION_MISMATCH,
    VERIFICATION_MISSING,
    VERIFICATION_UNCHECKED,
    VERIF_RESULT_VERIFIED,
    VERIF_RESULT_MISMATCHES,
    VERIF_RESULT_MISSING,
    VERIF_RESULT_INCOMPLETE,
    VERIF_RESULT_NETWORK_ERROR,
    VERIF_RESULT_NOT_DETECTED,
)


# ---------------------------------------------------------------------------
# Helper to create a file with given content
# ---------------------------------------------------------------------------


def _make_file(directory: Path, name: str, content: bytes) -> Path:
    """Create a file with the given content in the directory."""
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestVerifyCore:
    def test_not_wordpress(self, tmp_path: Path):
        """Non-WordPress directory should return NOT_DETECTED."""
        (tmp_path / "index.html").write_text("<h1>hello</h1>")
        result = verify_core(tmp_path)
        assert result.status == VERIF_RESULT_NOT_DETECTED
        assert result.version is None
        assert result.locale is None
        assert result.verified_matches == 0
        assert result.mismatches == 0
        assert result.missing == 0
        assert result.unchecked == 0
        assert len(result.files) == 0
        assert "No WordPress" in result.error

    def test_wordpress_but_no_version_php(self, tmp_path: Path):
        """WordPress markers but no version.php -> NOT_DETECTED."""
        (tmp_path / "wp-includes").mkdir()
        (tmp_path / "wp-config.php").write_text("<?php")
        result = verify_core(tmp_path)
        assert result.status == VERIF_RESULT_NOT_DETECTED
        assert result.version is None
        assert result.locale is None
        assert "version.php" in result.error.lower()

    def test_version_not_detected(self, tmp_path: Path):
        """WordPress but version.php has no  -> NOT_DETECTED."""
        (tmp_path / "wp-includes").mkdir()
        version_file = tmp_path / "wp-includes" / "version.php"
        version_file.write_text("<?php\n = 'en_US';\n")
        result = verify_core(tmp_path)
        assert result.status == VERIF_RESULT_NOT_DETECTED
        assert result.version is None
        assert result.locale is None
        # The error should come from version detection
        assert result.error is not None
        assert len(result.error) > 0
        # Optionally, we can check for the specific error
        # assert " literal assignment not found in version.php" in result.error

    def test_network_error_http(self, tmp_path: Path, monkeypatch):
        """Simulate HTTP error when fetching checksums."""
        # Setup a minimal WordPress site
        (tmp_path / "wp-includes").mkdir()
        version_file = tmp_path / "wp-includes" / "version.php"
        version_file.write_text("<?php\n$wp_version = '6.6';\n$wp_locale = 'en_US';\n")
        (tmp_path / "wp-config.php").write_text("<?php")

        # Mock urlopen to raise an HTTPError
        def mock_urlopen(*args, **kwargs):
            raise urllib.error.HTTPError(
                url="http://example.com",
                code=404,
                msg="Not Found",
                hdrs={},
                fp=None,
            )

        monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

        result = verify_core(tmp_path)
        assert result.status == VERIF_RESULT_NETWORK_ERROR
        assert result.version == "6.6"
        assert result.locale == "en_US"
        assert result.verified_matches == 0
        assert result.mismatches == 0
        assert result.missing == 0
        assert result.unchecked == 0
        assert len(result.files) == 0
        assert "HTTP error" in result.error

    def test_network_error_url(self, tmp_path: Path, monkeypatch):
        """Simulate URL error (e.g., timeout) when fetching checksums."""
        (tmp_path / "wp-includes").mkdir()
        version_file = tmp_path / "wp-includes" / "version.php"
        version_file.write_text("<?php\n$wp_version = '6.6';\n$wp_locale = 'en_US';\n")
        (tmp_path / "wp-config.php").write_text("<?php")

        def mock_urlopen(*args, **kwargs):
            raise urllib.error.URLError("timeout")

        monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

        result = verify_core(tmp_path)
        assert result.status == VERIF_RESULT_NETWORK_ERROR
        assert result.version == "6.6"
        assert result.locale == "en_US"
        assert "URL error" in result.error

    def test_network_error_invalid_json(self, tmp_path: Path, monkeypatch):
        """Simulate invalid JSON response."""
        (tmp_path / "wp-includes").mkdir()
        version_file = tmp_path / "wp-includes" / "version.php"
        version_file.write_text("<?php\n$wp_version = '6.6';\n$wp_locale = 'en_US';\n")
        (tmp_path / "wp-config.php").write_text("<?php")

        def mock_urlopen(*args, **kwargs):
            resp = MagicMock()
            resp.__enter__ = MagicMock(return_value=resp)
            resp.__exit__ = MagicMock(return_value=None)
            resp.read.side_effect = [b"not json", b""]
            resp.length = 100
            return resp

        monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

        result = verify_core(tmp_path)
        assert result.status == VERIF_RESULT_NETWORK_ERROR
        assert result.version == "6.6"
        assert result.locale == "en_US"
        assert "Invalid JSON response" in result.error

    def test_network_error_malformed_response(self, tmp_path: Path, monkeypatch):
        """Simulate response missing 'checksums' key."""
        (tmp_path / "wp-includes").mkdir()
        version_file = tmp_path / "wp-includes" / "version.php"
        version_file.write_text("<?php\n$wp_version = '6.6';\n$wp_locale = 'en_US';\n")
        (tmp_path / "wp-config.php").write_text("<?php")

        def mock_urlopen(*args, **kwargs):
            resp = MagicMock()
            resp.__enter__ = MagicMock(return_value=resp)
            resp.__exit__ = MagicMock(return_value=None)
            resp.read.side_effect = [b'{"algorithm": "sha256"}', b""]
            resp.length = 100
            return resp

        monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

        result = verify_core(tmp_path)
        assert result.status == VERIF_RESULT_NETWORK_ERROR
        assert result.version == "6.6"
        assert result.locale == "en_US"
        assert "Missing 'checksums' in response" in result.error

    def test_happy_path_all_match(self, tmp_path: Path, monkeypatch):
        """All files match -> VERIFIED."""
        (tmp_path / "wp-includes").mkdir()
        version_file = tmp_path / "wp-includes" / "version.php"
        version_file.write_text("<?php\n$wp_version = '6.6';\n$wp_locale = 'en_US';\n")
        (tmp_path / "wp-config.php").write_text("<?php")

        # Create a few files
        _make_file(tmp_path, "wp-config.php", b"<?php\n")
        _make_file(tmp_path, "index.php", b"<?php\n")
        _make_file(tmp_path / "wp-includes", "version.php", b"<?php\n$wp_version = '6.6';\n$wp_locale = 'en_US';\n")

        # Mock the checksums API to return hashes matching our files
        def mock_urlopen(*args, **kwargs):
            # Compute hashes of the files we created
            base = tmp_path
            file_hashes = {}
            for rel_path in ["wp-config.php", "index.php", "wp-includes/version.php"]:
                file_path = base / rel_path
                if file_path.exists():
                    file_hashes[rel_path] = hashlib.sha256(file_path.read_bytes()).hexdigest()
                else:
                    # If the file doesn't exist, we still need to provide a hash? We'll skip.
                    pass
            resp = MagicMock()
            resp.__enter__ = MagicMock(return_value=resp)
            resp.__exit__ = MagicMock(return_value=None)
            data = json.dumps(
                {
                    "algorithm": "sha256",
                    "checksums": file_hashes,
                }
            ).encode("utf-8")
            resp.read.side_effect = [data, b""]
            resp.length = len(data)
            return resp

        monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

        result = verify_core(tmp_path)
        assert result.status == VERIF_RESULT_VERIFIED
        assert result.version == "6.6"
        assert result.locale == "en_US"
        assert result.verified_matches == 3
        assert result.mismatches == 0
        assert result.missing == 0
        assert result.unchecked == 0
        assert len(result.files) == 3
        assert result.error is None
        # Check that each file has status MATCH
        for fv in result.files:
            assert fv.status == VERIFICATION_MATCH
            assert fv.expected_hash == fv.actual_hash

    def test_mismatch(self, tmp_path: Path, monkeypatch):
        """One file mismatches -> MISMATCHES."""
        (tmp_path / "wp-includes").mkdir()
        version_file = tmp_path / "wp-includes" / "version.php"
        version_file.write_text("<?php\n$wp_version = '6.6';\n$wp_locale = 'en_US';\n")
        (tmp_path / "wp-config.php").write_text("<?php")

        # Create a file with known content
        file_content = b"hello"
        _make_file(tmp_path, "wp-config.php", file_content)
        expected_hash = hashlib.sha256(file_content).hexdigest()

        # Mock the checksums API to return a different hash for wp-config.php
        def mock_urlopen(*args, **kwargs):
            # We'll return a hash that is off by one bit
            wrong_hash = hashlib.sha256(b"hellp").hexdigest()
            resp = MagicMock()
            resp.__enter__ = MagicMock(return_value=resp)
            resp.__exit__ = MagicMock(return_value=None)
            data = json.dumps(
                {
                    "algorithm": "sha256",
                    "checksums": {
                        "wp-config.php": wrong_hash,
                    },
                }
            ).encode("utf-8")
            resp.read.side_effect = [data, b""]
            resp.length = len(data)
            return resp

        monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

        result = verify_core(tmp_path)
        assert result.status == VERIF_RESULT_MISMATCHES
        assert result.version == "6.6"
        assert result.locale == "en_US"
        assert result.verified_matches == 0
        assert result.mismatches == 1
        assert result.missing == 0
        assert result.unchecked == 0
        assert len(result.files) == 1
        assert result.error is None
        fv = result.files[0]
        assert fv.path == "wp-config.php"
        assert fv.expected_hash == hashlib.sha256(b"hellp").hexdigest()
        assert fv.actual_hash == expected_hash
        assert fv.status == VERIFICATION_MISMATCH

    def test_missing_file(self, tmp_path: Path, monkeypatch):
        """File listed in checksums but missing locally -> MISSING."""
        (tmp_path / "wp-includes").mkdir()
        version_file = tmp_path / "wp-includes" / "version.php"
        version_file.write_text("<?php\n$wp_version = '6.6';\n$wp_locale = 'en_US';\n")
        (tmp_path / "wp-config.php").write_text("<?php")

        # Mock the checksums API to expect a file that we won't create
        def mock_urlopen(*args, **kwargs):
            resp = MagicMock()
            resp.__enter__ = MagicMock(return_value=resp)
            resp.__exit__ = MagicMock(return_value=None)
            data = json.dumps(
                {
                    "algorithm": "sha256",
                    "checksums": {
                        "missing.txt": hashlib.sha256(b"some content").hexdigest(),
                    },
                }
            ).encode("utf-8")
            resp.read.side_effect = [data, b""]
            resp.length = len(data)
            return resp

        monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

        result = verify_core(tmp_path)
        assert result.status == VERIF_RESULT_MISSING
        assert result.version == "6.6"
        assert result.locale == "en_US"
        assert result.verified_matches == 0
        assert result.mismatches == 0
        assert result.missing == 1
        assert result.unchecked == 0
        assert len(result.files) == 1
        assert result.error is None
        fv = result.files[0]
        assert fv.path == "missing.txt"
        assert fv.expected_hash is not None
        assert fv.actual_hash is None
        assert fv.status == VERIFICATION_MISSING

    def _can_create_symlink(self):
        """Check if we can create a symlink (requires privileges on Windows)."""
        if sys.platform.startswith('win'):
            # On Windows, creating symlinks requires elevated privileges or developer mode.
            # We'll try to create a temporary symlink and see if it works.
            try:
                with tempfile.TemporaryDirectory() as td:
                    link_path = Path(td) / "link.txt"
                    target = Path(td) / "target.txt"
                    target.write_text("test")
                    link_path.symlink_to(target)
                    return True
            except (OSError, NotImplementedError):
                return False
        else:
            # On Unix-like systems, we assume we can create symlinks.
            return True

    @pytest.mark.skipif(
        not _can_create_symlink(None),
        reason="Symlink creation not supported (requires privileges on Windows)",
    )
    def test_unchecked_due_to_symlink(self, tmp_path: Path, monkeypatch):
        """Symlink file (with follow_symlinks=False) -> UNCHECKED."""
        (tmp_path / "wp-includes").mkdir()
        version_file = tmp_path / "wp-includes" / "version.php"
        version_file.write_text("<?php\n$wp_version = '6.6';\n$wp_locale = 'en_US';\n")
        (tmp_path / "wp-config.php").write_text("<?php")

        # Create a symlink to a file outside the root (unsafe symlink)
        link_path = tmp_path / "link.txt"
        target = tmp_path.parent / "outside.txt"
        target.write_text("outside")
        link_path.symlink_to(target)

        # Mock the checksums API to expect the symlink file
        def mock_urlopen(*args, **kwargs):
            resp = MagicMock()
            resp.__enter__ = MagicMock(return_value=resp)
            resp.__exit__ = MagicMock(return_value=None)
            data = json.dumps(
                {
                    "algorithm": "sha256",
                    "checksums": {
                        "link.txt": hashlib.sha256(b"outside").hexdigest(),
                    },
                }
            ).encode("utf-8")
            resp.read.side_effect = [data, b""]
            resp.length = len(data)
            return resp

        monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

        result = verify_core(tmp_path)
        # Since follow_symlinks=False by default, the symlink should be skipped
        assert result.status == VERIF_RESULT_INCOMPLETE  # because we have an unchecked file
        assert result.version == "6.6"
        assert result.locale == "en_US"
        assert result.verified_matches == 0
        assert result.mismatches == 0
        assert result.missing == 0
        assert result.unchecked == 1
        assert len(result.files) == 1
        assert result.error is None
        fv = result.files[0]
        assert fv.path == "link.txt"
        assert fv.expected_hash is not None
        assert fv.actual_hash is None
        assert fv.status == VERIFICATION_UNCHECKED

    def test_unchecked_due_to_file_count_limit(self, tmp_path: Path, monkeypatch):
        """More files than max_file_count -> some files unchecked -> INCOMPLETE."""
        (tmp_path / "wp-includes").mkdir()
        version_file = tmp_path / "wp-includes" / "version.php"
        version_file.write_text("<?php\n$wp_version = '6.6';\n$wp_locale = 'en_US';\n")
        (tmp_path / "wp-config.php").write_text("<?php")

        # Create more files than the default max_file_count (50_000) is too many for a test.
        # We'll set a low limit in the config.
        config = ScanConfig(max_file_count=5)

        # Create 6 files
        for i in range(6):
            _make_file(tmp_path, f"file{i}.txt", b"content")

        # Mock the checksums API to expect all 6 files
        def mock_urlopen(*args, **kwargs):
            checksums = {}
            for i in range(6):
                checksums[f"file{i}.txt"] = hashlib.sha256(b"content").hexdigest()
            resp = MagicMock()
            resp.__enter__ = MagicMock(return_value=resp)
            resp.__exit__ = MagicMock(return_value=None)
            data = json.dumps(
                {
                    "algorithm": "sha256",
                    "checksums": checksums,
                }
            ).encode("utf-8")
            resp.read.side_effect = [data, b""]
            resp.length = len(data)
            return resp

        monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

        result = verify_core(tmp_path, config=config)
        # We expect that only 5 files were hashed (due to limit) and 1 unchecked
        # So status should be INCOMPLETE (since unchecked > 0 and no mismatches/missing)
        assert result.status == VERIF_RESULT_INCOMPLETE
        assert result.version == "6.6"
        assert result.locale == "en_US"
        assert result.verified_matches == 5
        assert result.mismatches == 0
        assert result.missing == 0
        assert result.unchecked == 1
        assert len(result.files) == 6
        # Check that exactly one file is unchecked and the rest are matches
        match_count = sum(1 for fv in result.files if fv.status == VERIFICATION_MATCH)
        unchecked_count = sum(1 for fv in result.files if fv.status == VERIFICATION_UNCHECKED)
        assert match_count == 5
        assert unchecked_count == 1
        assert result.error is not None
        assert "File count limit" in result.error

    def test_unchecked_due_to_total_size_limit(self, tmp_path: Path, monkeypatch):
        """Total size exceeds limit -> some files unchecked -> INCOMPLETE."""
        (tmp_path / "wp-includes").mkdir()
        version_file = tmp_path / "wp-includes" / "version.php"
        version_file.write_text("<?php\n$wp_version = '6.6';\n$wp_locale = 'en_US';\n")
        (tmp_path / "wp-config.php").write_text("<?php")

        # Set a low total size limit
        config = ScanConfig(max_total_size_bytes=100)  # 100 bytes

        # Create two files that together exceed the limit
        _make_file(tmp_path, "file1.txt", b"x" * 60)  # 60 bytes
        _make_file(tmp_path, "file2.txt", b"y" * 60)  # 60 bytes, total 120 > 100

        # Mock the checksums API to expect both files
        def mock_urlopen(*args, **kwargs):
            checksums = {
                "file1.txt": hashlib.sha256(b"x" * 60).hexdigest(),
                "file2.txt": hashlib.sha256(b"y" * 60).hexdigest(),
            }
            resp = MagicMock()
            resp.__enter__ = MagicMock(return_value=resp)
            resp.__exit__ = MagicMock(return_value=None)
            data = json.dumps(
                {
                    "algorithm": "sha256",
                    "checksums": checksums,
                }
            ).encode("utf-8")
            resp.read.side_effect = [data, b""]
            resp.length = len(data)
            return resp

        monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

        result = verify_core(tmp_path, config=config)
        # We expect that the first file was hashed (60 bytes) and then the second file
        # would cause the total size to exceed the limit, so it should be skipped (or we stop before hashing it?).
        # The hash_directory function stops when adding the file would exceed the limit.
        # So we expect one file hashed and one unchecked (or maybe the second file is not even visited?).
        # Actually, the function checks before adding: if total_size + file_size > limit, then break.
        # So when we are about to process the second file, we see that 60 + 60 > 100, so we break and do not process the second file at all.
        # Therefore, the second file is not in hashes and not in skipped (because we never visited it).
        # So we expect one match and one unchecked (due to not being visited).
        assert result.status == VERIF_RESULT_INCOMPLETE
        assert result.version == "6.6"
        assert result.locale == "en_US"
        assert result.verified_matches == 1
        assert result.mismatches == 0
        assert result.missing == 0
        assert result.unchecked == 1
        assert len(result.files) == 2
        match_count = sum(1 for fv in result.files if fv.status == VERIFICATION_MATCH)
        unchecked_count = sum(1 for fv in result.files if fv.status == VERIFICATION_UNCHECKED)
        assert match_count == 1
        assert unchecked_count == 1
        assert result.error is not None
        assert "Total size limit" in result.error

    def test_unchecked_due_to_timeout(self, tmp_path: Path, monkeypatch):
        """Timeout during scan -> some files unchecked -> INCOMPLETE."""
        (tmp_path / "wp-includes").mkdir()
        version_file = tmp_path / "wp-includes" / "version.php"
        version_file.write_text("<?php\n$wp_version = '6.6';\n$wp_locale = 'en_US';\n")
        (tmp_path / "wp-config.php").write_text("<?php")

        # Create many files to cause a timeout if we set a very short timeout
        config = ScanConfig(scan_timeout_seconds=1)  # 1 second timeout

        # Create 100 small files
        for i in range(1000):
            _make_file(tmp_path, f"file{i}.txt", b"x")

        # Mock the checksums API to expect all files
        def mock_urlopen(*args, **kwargs):
            checksums = {}
            for i in range(100):
                checksums[f"file{i}.txt"] = hashlib.sha256(b"x").hexdigest()
            resp = MagicMock()
            resp.__enter__ = MagicMock(return_value=resp)
            resp.__exit__ = MagicMock(return_value=None)
            data = json.dumps(
                {
                    "algorithm": "sha256",
                    "checksums": checksums,
                }
            ).encode("utf-8")
            resp.read.side_effect = [data, b""]
            resp.length = len(data)
            return resp

        monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

        result = verify_core(tmp_path, config=config)
        # We expect that the scan timed out before hashing all files, so we have some matches and some unchecked
        assert result.status == VERIF_RESULT_INCOMPLETE
        assert result.version == "6.6"
        assert result.locale == "en_US"
        assert result.verified_matches > 0
        assert result.mismatches == 0
        assert result.missing == 0
        assert result.unchecked > 0
        assert len(result.files) == 100
        # Check that we have at least one match and at least one unchecked
        match_count = sum(1 for fv in result.files if fv.status == VERIFICATION_MATCH)
        unchecked_count = sum(1 for fv in result.files if fv.status == VERIFICATION_UNCHECKED)
        assert match_count > 0
        assert unchecked_count > 0
        assert result.error is not None
        assert "Scan timeout" in result.error

    def test_symlink_safe_followed_when_enabled(self, tmp_path: Path, monkeypatch):
        """When follow_symlinks=True, safe symlinks are followed and hashed."""
        # Skip if we cannot create symlinks
        if not self._can_create_symlink():
            pytest.skip("Symlink creation not supported (requires privileges on Windows)")

        (tmp_path / "wp-includes").mkdir()
        version_file = tmp_path / "wp-includes" / "version.php"
        version_file.write_text("<?php\n$wp_version = '6.6';\n$wp_locale = 'en_US';\n")
        (tmp_path / "wp-config.php").write_text("<?php")

        # Create a symlink to a file inside the root (safe symlink)
        link_path = tmp_path / "link.txt"
        target = tmp_path / "real.txt"
        _make_file(tmp_path, "real.txt", b"real content")
        link_path.symlink_to(target)

        # Set follow_symlinks=True
        config = ScanConfig(follow_symlinks=True)

        # Mock the checksums API to expect the symlink file (which should point to real.txt)
        def mock_urlopen(*args, **kwargs):
            expected_hash = hashlib.sha256(b"real content").hexdigest()
            resp = MagicMock()
            resp.__enter__ = MagicMock(return_value=resp)
            resp.__exit__ = MagicMock(return_value=None)
            data = json.dumps(
                {
                    "algorithm": "sha256",
                    "checksums": {
                        "link.txt": expected_hash,
                    },
                }
            ).encode("utf-8")
            resp.read.side_effect = [data, b""]
            resp.length = len(data)

        monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

        result = verify_core(tmp_path, config=config)
        assert result.status == VERIF_RESULT_VERIFIED
        assert result.version == "6.6"
        assert result.locale == "en_US"
        assert result.verified_matches == 1
        assert result.mismatches == 0
        assert result.missing == 0
        assert result.unchecked == 0
        assert len(result.files) == 1
        fv = result.files[0]
        assert fv.path == "link.txt"
        assert fv.expected_hash == fv.actual_hash
        assert fv.status == VERIFICATION_MATCH

    @pytest.mark.skipif(
        not _can_create_symlink(None),
        reason="Symlink creation not supported (requires privileges on Windows)",
    )
    def test_symlink_unsafe_not_followed_even_if_enabled(self, tmp_path: Path, monkeypatch):
        """Unsafe symlink (points outside root) is not followed even if follow_symlinks=True."""
        # Skip if we cannot create symlinks
        if not self._can_create_symlink():
            pytest.skip("Symlink creation not supported (requires privileges on Windows)")

        (tmp_path / "wp-includes").mkdir()
        version_file = tmp_path / "wp-includes" / "version.php"
        version_file.write_text("<?php\n$wp_version = '6.6';\n$wp_locale = 'en_US';\n")
        (tmp_path / "wp-config.php").write_text("<?php")

        # Create a symlink to a file outside the root
        link_path = tmp_path / "link.txt"
        target = tmp_path.parent / "outside.txt"
        _make_file(target, "outside.txt", b"outside content")
        link_path.symlink_to(target)

        # Set follow_symlinks=True
        config = ScanConfig(follow_symlinks=True)

        # Mock the checksums API to expect the symlink file (which points to outside)
        def mock_urlopen(*args, **kwargs):
            expected_hash = hashlib.sha256(b"outside content").hexdigest()
            resp = MagicMock()
            resp.__enter__ = MagicMock(return_value=resp)
            resp.__exit__ = MagicMock(return_value=None)
            data = json.dumps(
                {
                    "algorithm": "sha256",
                    "checksums": {
                        "link.txt": expected_hash,
                    },
                }
            ).encode("utf-8")
            resp.read.side_effect = [data, b""]
            resp.length = len(data)
            return resp

        monkeypatch.setattr(urllib.request, "urlopen", mock_urlopen)

        result = verify_core(tmp_path, config=config)
        # The symlink is unsafe, so it should be skipped (not followed) regardless of follow_symlinks setting
        assert result.status == VERIF_RESULT_INCOMPLETE
        assert result.version == "6.6"
        assert result.locale == "en_US"
        assert result.verified_matches == 0
        assert result.mismatches == 0
        assert result.missing == 0
        assert result.unchecked == 1
        assert len(result.files) == 1
        fv = result.files[0]
        assert fv.path == "link.txt"
        assert fv.expected_hash is not None
        assert fv.actual_hash is None
        assert fv.status == VERIFICATION_UNCHECKED






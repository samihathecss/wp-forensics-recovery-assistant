"""Tests for ScanConfig."""

import pytest

from wp_forensics.config import ScanConfig


class TestScanConfigDefaults:
    """Default configuration values match the specification."""

    def test_max_file_size_bytes_default(self):
        assert ScanConfig().max_file_size_bytes == 5 * 1024 * 1024

    def test_max_total_size_bytes_default(self):
        assert ScanConfig().max_total_size_bytes == 500 * 1024 * 1024

    def test_max_file_count_default(self):
        assert ScanConfig().max_file_count == 50_000

    def test_scan_timeout_seconds_default(self):
        assert ScanConfig().scan_timeout_seconds == 300

    def test_follow_symlinks_default(self):
        assert ScanConfig().follow_symlinks is False

    def test_zip_max_entries_default(self):
        assert ScanConfig().zip_max_entries == 10_000

    def test_zip_max_compressed_bytes_default(self):
        assert ScanConfig().zip_max_compressed_bytes == 500 * 1024 * 1024

    def test_zip_max_uncompressed_bytes_default(self):
        assert ScanConfig().zip_max_uncompressed_bytes == 1024 * 1024 * 1024

    def test_zip_max_ratio_default(self):
        assert ScanConfig().zip_max_ratio == 10.0

    def test_request_timeout_seconds_default(self):
        assert ScanConfig().request_timeout_seconds == 15


class TestScanConfigCustom:
    """Custom values are accepted and retrievable."""

    def test_custom_values_accepted(self):
        config = ScanConfig(
            max_file_size_bytes=1024,
            max_total_size_bytes=2048,
            max_file_count=10,
            scan_timeout_seconds=30,
            follow_symlinks=True,
            zip_max_entries=50,
            zip_max_compressed_bytes=1024,
            zip_max_uncompressed_bytes=2048,
            zip_max_ratio=5.0,
            request_timeout_seconds=10,
        )
        assert config.max_file_size_bytes == 1024
        assert config.max_total_size_bytes == 2048
        assert config.max_file_count == 10
        assert config.follow_symlinks is True
        assert config.zip_max_entries == 50
        assert config.zip_max_ratio == 5.0

    def test_to_dict_returns_all_fields(self):
        config = ScanConfig(max_file_size_bytes=100)
        d = config.to_dict()
        assert isinstance(d, dict)
        assert d["max_file_size_bytes"] == 100
        assert d["max_total_size_bytes"] == 500 * 1024 * 1024
        assert d["follow_symlinks"] is False
        assert d["zip_max_ratio"] == 10.0

    def test_partial_override_keeps_defaults(self):
        config = ScanConfig(max_file_count=5)
        assert config.max_file_count == 5
        assert config.max_file_size_bytes == 5 * 1024 * 1024
        assert config.follow_symlinks is False


class TestScanConfigValidation:
    """Invalid values raise ValueError."""

    def test_max_file_size_zero_raises(self):
        with pytest.raises(ValueError, match="max_file_size_bytes"):
            ScanConfig(max_file_size_bytes=0)

    def test_max_file_size_negative_raises(self):
        with pytest.raises(ValueError, match="max_file_size_bytes"):
            ScanConfig(max_file_size_bytes=-1)

    def test_max_file_size_non_integer_raises(self):
        with pytest.raises(ValueError, match="max_file_size_bytes"):
            ScanConfig(max_file_size_bytes="5MB")

    def test_max_file_size_bool_rejected(self):
        with pytest.raises(ValueError, match="max_file_size_bytes"):
            ScanConfig(max_file_size_bytes=True)

    def test_max_total_size_zero_raises(self):
        with pytest.raises(ValueError, match="max_total_size_bytes"):
            ScanConfig(max_total_size_bytes=0)

    def test_max_file_count_negative_raises(self):
        with pytest.raises(ValueError, match="max_file_count"):
            ScanConfig(max_file_count=-1)

    def test_zip_max_entries_zero_raises(self):
        with pytest.raises(ValueError, match="zip_max_entries"):
            ScanConfig(zip_max_entries=0)

    def test_zip_max_ratio_zero_raises(self):
        with pytest.raises(ValueError, match="zip_max_ratio"):
            ScanConfig(zip_max_ratio=0.0)

    def test_zip_max_ratio_negative_raises(self):
        with pytest.raises(ValueError, match="zip_max_ratio"):
            ScanConfig(zip_max_ratio=-1.0)

    def test_scan_timeout_zero_raises(self):
        with pytest.raises(ValueError, match="scan_timeout_seconds"):
            ScanConfig(scan_timeout_seconds=0)

    def test_request_timeout_zero_raises(self):
        with pytest.raises(ValueError, match="request_timeout_seconds"):
            ScanConfig(request_timeout_seconds=0)

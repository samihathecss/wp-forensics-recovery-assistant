"""Shared pytest fixtures for WP Forensics & Recovery Assistant tests."""

import pytest

from wp_forensics.config import ScanConfig


@pytest.fixture
def default_config():
    """Return a default ScanConfig."""
    return ScanConfig()


@pytest.fixture
def small_config():
    """Return a ScanConfig with small limits for fast tests."""
    return ScanConfig(
        max_file_size_bytes=1024,
        max_total_size_bytes=10_240,
        max_file_count=100,
        scan_timeout_seconds=5,
        zip_max_entries=50,
        zip_max_compressed_bytes=10_240,
        zip_max_uncompressed_bytes=102_400,
        zip_max_ratio=5.0,
        request_timeout_seconds=5,
    )


@pytest.fixture
def zip_config():
    """Return a ScanConfig with generous ZIP limits for archive tests."""
    return ScanConfig(
        max_file_size_bytes=10_000_000,
        max_total_size_bytes=100_000_000,
        max_file_count=1000,
        scan_timeout_seconds=30,
        zip_max_entries=1000,
        zip_max_compressed_bytes=50_000_000,
        zip_max_uncompressed_bytes=100_000_000,
        zip_max_ratio=100.0,
        request_timeout_seconds=5,
    )

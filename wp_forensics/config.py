"""Scan configuration with conservative safety limits.

ScanConfig is a leaf module with no dependencies on other wp_forensics
modules, so it can be imported anywhere without circular imports.
"""

from dataclasses import asdict, dataclass


@dataclass
class ScanConfig:
    """Configuration for scanning and verification operations.

    All limits are conservative defaults suitable for investigating
    WordPress backups. Override as needed, but always enforce upper bounds.
    """

    max_file_size_bytes: int = 5 * 1024 * 1024
    max_total_size_bytes: int = 500 * 1024 * 1024
    max_file_count: int = 50_000
    scan_timeout_seconds: int = 300
    follow_symlinks: bool = False
    zip_max_entries: int = 10_000
    zip_max_compressed_bytes: int = 500 * 1024 * 1024
    zip_max_uncompressed_bytes: int = 1024 * 1024 * 1024
    zip_max_ratio: float = 10.0
    request_timeout_seconds: int = 15

    def __post_init__(self) -> None:
        int_limits = {
            "max_file_size_bytes": self.max_file_size_bytes,
            "max_total_size_bytes": self.max_total_size_bytes,
            "max_file_count": self.max_file_count,
            "scan_timeout_seconds": self.scan_timeout_seconds,
            "zip_max_entries": self.zip_max_entries,
            "zip_max_compressed_bytes": self.zip_max_compressed_bytes,
            "zip_max_uncompressed_bytes": self.zip_max_uncompressed_bytes,
            "request_timeout_seconds": self.request_timeout_seconds,
        }
        for name, value in int_limits.items():
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be a positive integer, got {value!r}")

        if not isinstance(self.zip_max_ratio, (int, float)) or self.zip_max_ratio <= 0:
            raise ValueError(f"zip_max_ratio must be positive, got {self.zip_max_ratio!r}")

    def to_dict(self) -> dict:
        return asdict(self)

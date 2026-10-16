# wp_forensics/__init__.py

"""WP Forensics & Recovery Assistant - scanning engine.

The scanning engine is independent of Streamlit. All modules can be
imported and tested without the UI.
"""

from wp_forensics.config import ScanConfig

from wp_forensics.models import (
    Finding,
    ScanResult,
    ComparisonEntry,
    ComparisonResult,
    FileVerification,
    VerificationResult,
)

from wp_forensics.version import VersionDetection
from wp_forensics.core_verify import verify_core
from wp_forensics.indicators import IndicatorRule

from wp_forensics.archive import (
    ZipEntry,
    ArchiveInspectionResult,
    inspect_zip,
    safe_extract_zip,
)

from wp_forensics.report import generate_html_report, generate_json_report

__all__ = [
    "ScanConfig",
    "Finding",
    "ScanResult",
    "ComparisonEntry",
    "ComparisonResult",
    "FileVerification",
    "VerificationResult",
    "VersionDetection",
    "IndicatorRule",
    "ZipEntry",
    "ArchiveInspectionResult",
    "inspect_zip",
    "safe_extract_zip",
    "verify_core",
    "generate_html_report",
    "generate_json_report",
]

__version__ = "0.1.0"

"""Core data models for scan results, findings, and verification.

All models use dataclasses for clarity and type safety. Enum-like
constants are used for severity, confidence, and status fields to
prevent invalid values.

This module depends only on config.py (for the ScanConfig type used
in ScanResult). No circular imports.
"""

from dataclasses import dataclass, field

from wp_forensics.config import ScanConfig

# ---------------------------------------------------------------------------
# Severity levels
# ---------------------------------------------------------------------------

SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"
SEVERITY_CRITICAL = "critical"
VALID_SEVERITIES = frozenset(
    {SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL}
)

# ---------------------------------------------------------------------------
# Confidence levels
# ---------------------------------------------------------------------------

CONFIDENCE_LOW = "low"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_HIGH = "high"
VALID_CONFIDENCES = frozenset(
    {CONFIDENCE_LOW, CONFIDENCE_MEDIUM, CONFIDENCE_HIGH}
)

# ---------------------------------------------------------------------------
# Finding status — distinguishes indicators from confirmed malicious behavior
# ---------------------------------------------------------------------------

STATUS_SUSPICIOUS = "suspicious"
STATUS_POTENTIAL_MALWARE = "potential_malware"
VALID_FINDING_STATUSES = frozenset(
    {STATUS_SUSPICIOUS, STATUS_POTENTIAL_MALWARE}
)

# ---------------------------------------------------------------------------
# Comparison entry status
# ---------------------------------------------------------------------------

COMPARISON_ADDED = "added"
COMPARISON_REMOVED = "removed"
COMPARISON_MODIFIED = "modified"
COMPARISON_UNCHANGED = "unchanged"
VALID_COMPARISON_STATUSES = frozenset(
    {
        COMPARISON_ADDED,
        COMPARISON_REMOVED,
        COMPARISON_MODIFIED,
        COMPARISON_UNCHANGED,
    }
)

# ---------------------------------------------------------------------------
# Per-file verification status
# ---------------------------------------------------------------------------

VERIFICATION_MATCH = "match"
VERIFICATION_MISMATCH = "mismatch"
VERIFICATION_MISSING = "missing"
VERIFICATION_UNCHECKED = "unchecked"
VALID_VERIFICATION_FILE_STATUSES = frozenset(
    {
        VERIFICATION_MATCH,
        VERIFICATION_MISMATCH,
        VERIFICATION_MISSING,
        VERIFICATION_UNCHECKED,
    }
)

# ---------------------------------------------------------------------------
# Overall verification result status
# ---------------------------------------------------------------------------

VERIF_RESULT_VERIFIED = "verified"
VERIF_RESULT_MISMATCHES = "mismatches_found"
VERIF_RESULT_MISSING = "missing_files"
VERIF_RESULT_NETWORK_ERROR = "network_error"
VERIF_RESULT_UNSUPPORTED = "unsupported_version"
VERIF_RESULT_NOT_DETECTED = "version_not_detected"
VERIF_RESULT_INCOMPLETE = "incomplete"
VALID_VERIFICATION_RESULT_STATUSES = frozenset(
    {
        VERIF_RESULT_VERIFIED,
        VERIF_RESULT_MISMATCHES,
        VERIF_RESULT_MISSING,
        VERIF_RESULT_NETWORK_ERROR,
        VERIF_RESULT_UNSUPPORTED,
        VERIF_RESULT_NOT_DETECTED,
        VERIF_RESULT_INCOMPLETE,
    }
)


@dataclass
class Finding:
    """A single suspicious indicator found during scanning.

    ``status`` distinguishes indicators from confirmed malicious behavior.
    Never use ``"confirmed_malware"`` without strong corroborating evidence.
    """

    file_path: str
    indicator: str
    severity: str
    confidence: str
    category: str
    explanation: str
    evidence: str
    line_number: int | None = None
    file_sha256: str | None = None
    status: str = STATUS_SUSPICIOUS

    def __post_init__(self) -> None:
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(
                f"severity must be one of {VALID_SEVERITIES}, got {self.severity!r}"
            )
        if self.confidence not in VALID_CONFIDENCES:
            raise ValueError(
                f"confidence must be one of {VALID_CONFIDENCES}, got {self.confidence!r}"
            )
        if self.status not in VALID_FINDING_STATUSES:
            raise ValueError(
                f"status must be one of {VALID_FINDING_STATUSES}, got {self.status!r}"
            )


@dataclass
class ScanResult:
    """Aggregate result of scanning a directory tree."""

    scan_time: str
    scan_root: str
    findings: list[Finding]
    file_count: int
    scanned_size_bytes: int
    config_used: ScanConfig
    errors: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


@dataclass
class ComparisonEntry:
    """A single file entry in a comparison result."""

    path: str
    source_hash: str | None
    dest_hash: str | None
    status: str

    def __post_init__(self) -> None:
        if self.status not in VALID_COMPARISON_STATUSES:
            raise ValueError(
                f"status must be one of {VALID_COMPARISON_STATUSES}, got {self.status!r}"
            )


@dataclass
class ComparisonResult:
    """Result of comparing two directory snapshots."""

    source_root: str
    dest_root: str
    entries: list[ComparisonEntry]
    added_count: int
    removed_count: int
    modified_count: int
    unchanged_count: int
    limitations: list[str] = field(default_factory=list)


@dataclass
class FileVerification:
    """Verification of a single core file against WordPress.org checksums."""

    path: str
    expected_hash: str | None
    actual_hash: str | None
    status: str

    def __post_init__(self) -> None:
        if self.status not in VALID_VERIFICATION_FILE_STATUSES:
            raise ValueError(
                f"status must be one of {VALID_VERIFICATION_FILE_STATUSES}, "
                f"got {self.status!r}"
            )


@dataclass
class VerificationResult:
    """Result of WordPress core file integrity verification."""

    version: str | None
    locale: str | None
    status: str
    verified_matches: int
    mismatches: int
    missing: int
    unchecked: int
    files: list[FileVerification] = field(default_factory=list)
    error: str | None = None

    def __post_init__(self) -> None:
        if self.status not in VALID_VERIFICATION_RESULT_STATUSES:
            raise ValueError(
                f"status must be one of {VALID_VERIFICATION_RESULT_STATUSES}, "
                f"got {self.status!r}"
            )



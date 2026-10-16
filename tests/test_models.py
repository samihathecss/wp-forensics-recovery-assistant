"""Tests for data models (Finding, ScanResult, ComparisonResult, etc.)."""

import pytest

from wp_forensics.config import ScanConfig
from wp_forensics.models import (
    COMPARISON_ADDED,
    COMPARISON_MODIFIED,
    COMPARISON_REMOVED,
    COMPARISON_UNCHANGED,
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    FileVerification,
    Finding,
    ComparisonEntry,
    ComparisonResult,
    ScanResult,
    STATUS_POTENTIAL_MALWARE,
    STATUS_SUSPICIOUS,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    VERIF_RESULT_MISSING,
    VERIF_RESULT_MISMATCHES,
    VERIF_RESULT_NETWORK_ERROR,
    VERIF_RESULT_NOT_DETECTED,
    VERIF_RESULT_UNSUPPORTED,
    VERIF_RESULT_VERIFIED,
    VERIFICATION_MATCH,
    VERIFICATION_MISMATCH,
    VERIFICATION_MISSING,
    VERIFICATION_UNCHECKED,
    VerificationResult,
)


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


class TestFinding:
    def test_required_fields(self):
        f = Finding(
            file_path="wp-content/uploads/evil.php",
            indicator="php_in_uploads",
            severity=SEVERITY_HIGH,
            confidence=CONFIDENCE_HIGH,
            category="unexpected_file",
            explanation="PHP file found in uploads directory",
            evidence="<?php eval($_GET['c']); ?>",
        )
        assert f.file_path == "wp-content/uploads/evil.php"
        assert f.indicator == "php_in_uploads"
        assert f.severity == SEVERITY_HIGH
        assert f.confidence == CONFIDENCE_HIGH
        assert f.category == "unexpected_file"
        assert f.explanation == "PHP file found in uploads directory"
        assert f.evidence == "<?php eval($_GET['c']); ?>"

    def test_optional_defaults(self):
        f = Finding(
            file_path="t.php",
            indicator="t",
            severity=SEVERITY_LOW,
            confidence=CONFIDENCE_LOW,
            category="t",
            explanation="t",
            evidence="t",
        )
        assert f.line_number is None
        assert f.file_sha256 is None
        assert f.status == STATUS_SUSPICIOUS

    def test_custom_status(self):
        f = Finding(
            file_path="t.php",
            indicator="t",
            severity=SEVERITY_HIGH,
            confidence=CONFIDENCE_HIGH,
            category="t",
            explanation="t",
            evidence="t",
            status=STATUS_POTENTIAL_MALWARE,
        )
        assert f.status == STATUS_POTENTIAL_MALWARE

    def test_invalid_severity_raises(self):
        with pytest.raises(ValueError, match="severity"):
            Finding(
                file_path="t.php",
                indicator="t",
                severity="extreme",
                confidence=CONFIDENCE_LOW,
                category="t",
                explanation="t",
                evidence="t",
            )

    def test_invalid_confidence_raises(self):
        with pytest.raises(ValueError, match="confidence"):
            Finding(
                file_path="t.php",
                indicator="t",
                severity=SEVERITY_LOW,
                confidence="maybe",
                category="t",
                explanation="t",
                evidence="t",
            )

    def test_invalid_status_raises(self):
        with pytest.raises(ValueError, match="status"):
            Finding(
                file_path="t.php",
                indicator="t",
                severity=SEVERITY_LOW,
                confidence=CONFIDENCE_LOW,
                category="t",
                explanation="t",
                evidence="t",
                status="confirmed_malware",
            )

    def test_all_valid_severities(self):
        for sev in (SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL):
            f = Finding(
                file_path="t.php",
                indicator="t",
                severity=sev,
                confidence=CONFIDENCE_LOW,
                category="t",
                explanation="t",
                evidence="t",
            )
            assert f.severity == sev

    def test_all_valid_confidences(self):
        for conf in (CONFIDENCE_LOW, CONFIDENCE_MEDIUM, CONFIDENCE_HIGH):
            f = Finding(
                file_path="t.php",
                indicator="t",
                severity=SEVERITY_LOW,
                confidence=conf,
                category="t",
                explanation="t",
                evidence="t",
            )
            assert f.confidence == conf

    def test_line_number_and_hash_optional(self):
        f = Finding(
            file_path="t.php",
            indicator="eval",
            severity=SEVERITY_HIGH,
            confidence=CONFIDENCE_HIGH,
            category="risky_function",
            explanation="eval found",
            evidence="eval(",
            line_number=42,
            file_sha256="abc123",
        )
        assert f.line_number == 42
        assert f.file_sha256 == "abc123"


# ---------------------------------------------------------------------------
# ScanResult
# ---------------------------------------------------------------------------


class TestScanResult:
    def test_required_fields(self):
        config = ScanConfig()
        result = ScanResult(
            scan_time="2026-10-14T08:00:00Z",
            scan_root="/tmp/site",
            findings=[],
            file_count=100,
            scanned_size_bytes=50000,
            config_used=config,
        )
        assert result.scan_time == "2026-10-14T08:00:00Z"
        assert result.scan_root == "/tmp/site"
        assert result.findings == []
        assert result.file_count == 100
        assert result.scanned_size_bytes == 50000
        assert result.config_used is config

    def test_optional_defaults(self):
        result = ScanResult(
            scan_time="2026-10-14T08:00:00Z",
            scan_root="/tmp/site",
            findings=[],
            file_count=0,
            scanned_size_bytes=0,
            config_used=ScanConfig(),
        )
        assert result.errors == []
        assert result.limitations == []

    def test_with_findings_errors_limitations(self):
        finding = Finding(
            file_path="t.php",
            indicator="t",
            severity=SEVERITY_HIGH,
            confidence=CONFIDENCE_HIGH,
            category="t",
            explanation="t",
            evidence="t",
        )
        result = ScanResult(
            scan_time="2026-10-14T08:00:00Z",
            scan_root="/tmp/site",
            findings=[finding],
            file_count=1,
            scanned_size_bytes=100,
            config_used=ScanConfig(),
            errors=["Could not read file: permission denied"],
            limitations=["File count limit may have truncated scan"],
        )
        assert len(result.findings) == 1
        assert len(result.errors) == 1
        assert len(result.limitations) == 1


# ---------------------------------------------------------------------------
# ComparisonEntry
# ---------------------------------------------------------------------------


class TestComparisonEntry:
    def test_modified_entry(self):
        e = ComparisonEntry(
            path="wp-config.php",
            source_hash="abc123",
            dest_hash="def456",
            status=COMPARISON_MODIFIED,
        )
        assert e.path == "wp-config.php"
        assert e.status == COMPARISON_MODIFIED

    def test_added_entry(self):
        e = ComparisonEntry(
            path="new.php",
            source_hash=None,
            dest_hash="def456",
            status=COMPARISON_ADDED,
        )
        assert e.source_hash is None
        assert e.dest_hash == "def456"

    def test_removed_entry(self):
        e = ComparisonEntry(
            path="old.php",
            source_hash="abc123",
            dest_hash=None,
            status=COMPARISON_REMOVED,
        )
        assert e.source_hash == "abc123"
        assert e.dest_hash is None

    def test_unchanged_entry(self):
        e = ComparisonEntry(
            path="same.php",
            source_hash="abc123",
            dest_hash="abc123",
            status=COMPARISON_UNCHANGED,
        )
        assert e.source_hash == e.dest_hash

    def test_invalid_status_raises(self):
        with pytest.raises(ValueError, match="status"):
            ComparisonEntry(path="t", source_hash="a", dest_hash="b", status="unknown")

    def test_all_valid_statuses(self):
        for s in (
            COMPARISON_ADDED,
            COMPARISON_REMOVED,
            COMPARISON_MODIFIED,
            COMPARISON_UNCHANGED,
        ):
            e = ComparisonEntry(path="t", source_hash="a", dest_hash="b", status=s)
            assert e.status == s


# ---------------------------------------------------------------------------
# ComparisonResult
# ---------------------------------------------------------------------------


class TestComparisonResult:
    def test_required_fields(self):
        r = ComparisonResult(
            source_root="/src",
            dest_root="/dst",
            entries=[],
            added_count=0,
            removed_count=0,
            modified_count=0,
            unchanged_count=0,
        )
        assert r.source_root == "/src"
        assert r.dest_root == "/dst"
        assert r.entries == []
        assert r.limitations == []
        assert r.added_count == 0
        assert r.removed_count == 0
        assert r.modified_count == 0
        assert r.unchanged_count == 0

    def test_with_entries_and_limitations(self):
        entries = [
            ComparisonEntry(path="a.php", source_hash="1", dest_hash="2", status=COMPARISON_MODIFIED),
            ComparisonEntry(path="b.php", source_hash=None, dest_hash="3", status=COMPARISON_ADDED),
        ]
        r = ComparisonResult(
            source_root="/src",
            dest_root="/dst",
            entries=entries,
            added_count=1,
            removed_count=0,
            modified_count=1,
            unchanged_count=0,
            limitations=["Could not read 2 files"],
        )
        assert len(r.entries) == 2
        assert r.added_count == 1
        assert r.modified_count == 1
        assert len(r.limitations) == 1


# ---------------------------------------------------------------------------
# FileVerification
# ---------------------------------------------------------------------------


class TestFileVerification:
    def test_match_status(self):
        fv = FileVerification(
            path="wp-admin/index.php",
            expected_hash="abc123",
            actual_hash="abc123",
            status=VERIFICATION_MATCH,
        )
        assert fv.status == VERIFICATION_MATCH

    def test_mismatch_status(self):
        fv = FileVerification(
            path="wp-admin/index.php",
            expected_hash="abc123",
            actual_hash="def456",
            status=VERIFICATION_MISMATCH,
        )
        assert fv.expected_hash != fv.actual_hash

    def test_missing_status(self):
        fv = FileVerification(
            path="wp-admin/missing.php",
            expected_hash="abc123",
            actual_hash=None,
            status=VERIFICATION_MISSING,
        )
        assert fv.actual_hash is None

    def test_unchecked_status(self):
        fv = FileVerification(
            path="wp-admin/custom.php",
            expected_hash=None,
            actual_hash="abc123",
            status=VERIFICATION_UNCHECKED,
        )
        assert fv.expected_hash is None

    def test_invalid_status_raises(self):
        with pytest.raises(ValueError, match="status"):
            FileVerification(path="t", expected_hash="a", actual_hash="b", status="unknown")

    def test_all_valid_statuses(self):
        for s in (
            VERIFICATION_MATCH,
            VERIFICATION_MISMATCH,
            VERIFICATION_MISSING,
            VERIFICATION_UNCHECKED,
        ):
            fv = FileVerification(path="t", expected_hash="a", actual_hash="b", status=s)
            assert fv.status == s


# ---------------------------------------------------------------------------
# VerificationResult
# ---------------------------------------------------------------------------


class TestVerificationResult:
    def test_verified_status(self):
        r = VerificationResult(
            version="6.6",
            locale="en_US",
            status=VERIF_RESULT_VERIFIED,
            verified_matches=200,
            mismatches=0,
            missing=0,
            unchecked=5,
        )
        assert r.version == "6.6"
        assert r.status == VERIF_RESULT_VERIFIED
        assert r.verified_matches == 200

    def test_network_error_status(self):
        r = VerificationResult(
            version=None,
            locale=None,
            status=VERIF_RESULT_NETWORK_ERROR,
            verified_matches=0,
            mismatches=0,
            missing=0,
            unchecked=0,
            error="Connection timed out",
        )
        assert r.error == "Connection timed out"
        assert r.status == VERIF_RESULT_NETWORK_ERROR

    def test_mismatches_status(self):
        r = VerificationResult(
            version="6.6",
            locale="en_US",
            status=VERIF_RESULT_MISMATCHES,
            verified_matches=198,
            mismatches=2,
            missing=0,
            unchecked=5,
        )
        assert r.mismatches == 2
        assert r.verified_matches == 198

    def test_missing_status(self):
        r = VerificationResult(
            version="6.6",
            locale="en_US",
            status=VERIF_RESULT_MISSING,
            verified_matches=200,
            mismatches=0,
            missing=3,
            unchecked=0,
        )
        assert r.missing == 3

    def test_unsupported_version_status(self):
        r = VerificationResult(
            version="99.0",
            locale="en_US",
            status=VERIF_RESULT_UNSUPPORTED,
            verified_matches=0,
            mismatches=0,
            missing=0,
            unchecked=0,
            error="Version 99.0 not found in WordPress.org API",
        )
        assert r.error is not None

    def test_version_not_detected_status(self):
        r = VerificationResult(
            version=None,
            locale=None,
            status=VERIF_RESULT_NOT_DETECTED,
            verified_matches=0,
            mismatches=0,
            missing=0,
            unchecked=0,
            error="Could not detect WordPress version",
        )
        assert r.version is None

    def test_invalid_status_raises(self):
        with pytest.raises(ValueError, match="status"):
            VerificationResult(
                version="6.6",
                locale="en_US",
                status="unknown",
                verified_matches=0,
                mismatches=0,
                missing=0,
                unchecked=0,
            )

    def test_all_valid_statuses(self):
        for s in (
            VERIF_RESULT_VERIFIED,
            VERIF_RESULT_MISMATCHES,
            VERIF_RESULT_MISSING,
            VERIF_RESULT_NETWORK_ERROR,
            VERIF_RESULT_UNSUPPORTED,
            VERIF_RESULT_NOT_DETECTED,
        ):
            r = VerificationResult(
                version="6.6" if s != VERIF_RESULT_NOT_DETECTED else None,
                locale="en_US",
                status=s,
                verified_matches=0,
                mismatches=0,
                missing=0,
                unchecked=0,
            )
            assert r.status == s

    def test_default_files_and_error(self):
        r = VerificationResult(
            version="6.6",
            locale="en_US",
            status=VERIF_RESULT_VERIFIED,
            verified_matches=0,
            mismatches=0,
            missing=0,
            unchecked=0,
        )
        assert r.files == []
        assert r.error is None

    def test_with_files(self):
        files = [
            FileVerification(path="wp-admin/index.php", expected_hash="a", actual_hash="a", status=VERIFICATION_MATCH),
            FileVerification(path="wp-admin/edit.php", expected_hash="b", actual_hash="c", status=VERIFICATION_MISMATCH),
        ]
        r = VerificationResult(
            version="6.6",
            locale="en_US",
            status=VERIF_RESULT_MISMATCHES,
            verified_matches=1,
            mismatches=1,
            missing=0,
            unchecked=0,
            files=files,
        )
        assert len(r.files) == 2

"""Tests for wp_forensics.report module.

Tests cover: JSON and HTML report generation for scan results,
comparison results, and verification results.
"""
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from wp_forensics.config import ScanConfig
from wp_forensics.models import (
    ComparisonEntry,
    ComparisonResult,
    Finding,
    ScanResult,
    VerificationResult,
    FileVerification,
    VERIFICATION_MATCH,
    VERIFICATION_MISMATCH,
    VERIFICATION_MISSING,
    VERIFICATION_UNCHECKED,
    VERIF_RESULT_VERIFIED,
    VERIF_RESULT_MISMATCHES,
    VERIF_RESULT_MISSING,
    VERIF_RESULT_INCOMPLETE,
)
from wp_forensics.report import generate_html_report, generate_json_report

# Test helper functions
def _make_sample_finding() -> Finding:
    """Create a sample finding for testing."""
    return Finding(
        file_path="wp-content/plugins/test.php",
        indicator="eval(base64_decode($_GET['test']));",
        severity="high",
        confidence="high",
        category="web_shell",
        explanation="Potential web shell found via base64 encoded eval.",
        evidence="eval(base64_decode($_GET['test']));",
        line_number=42,
        file_sha256="a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
        status="suspicious",
    )


def _make_sample_scan_result() -> ScanResult:
    """Create a sample scan result for testing."""
    return ScanResult(
        scan_time="2026-10-14T10:30:00Z",
        scan_root="/tmp/test_wordpress",
        findings=[_make_sample_finding()],
        file_count=150,
        scanned_size_bytes=1024000,
        config_used=ScanConfig(),
        errors=["Failed to read .htaccess file"],
        limitations=["Symlink scanning disabled"],
    )


def _make_sample_comparison_result() -> ComparisonResult:
    """Create a sample comparison result for testing."""
    return ComparisonResult(
        source_root="/tmp/wordpress_clean",
        dest_root="/tmp/wordpress_suspect",
        entries=[
            ComparisonEntry(
                path="wp-config.php",
                source_hash="a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
                dest_hash="a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
                status="unchanged",
            ),
            ComparisonEntry(
                path="index.php",
                source_hash="a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
                dest_hash="b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef12345678",
                status="modified",
            ),
            ComparisonEntry(
                path="wp-content/plugins/new-plugin.php",
                source_hash=None,
                dest_hash="c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456789d",
                status="added",
            ),
            ComparisonEntry(
                path="wp-content/plugins/old-plugin.php",
                source_hash="d4e5f6789012345678901234567890abcdef1234567890abcdef123456789e",
                dest_hash=None,
                status="removed",
            ),
        ],
        added_count=1,
        removed_count=1,
        modified_count=1,
        unchanged_count=1,
        limitations=["File count limit prevented scanning all files"],
    )


def _make_sample_verification_result() -> VerificationResult:
    """Create a sample verification result for testing."""
    return VerificationResult(
        version="6.5.2",
        locale="en_US",
        status="verified",
        verified_matches=5,
        mismatches=0,
        missing=0,
        unchecked=0,
        files=[
            FileVerification(
                path="wp-config.php",
                expected_hash="a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
                actual_hash="a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
                status="match",
            ),
            FileVerification(
                path="index.php",
                expected_hash="b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef12345678",
                actual_hash="b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef12345678",
                status="match",
            ),
        ],
        error=None,
    )


# Test JSON report generation
class TestJSONReportGeneration:
    def test_scan_result_json(self):
        """Test JSON report generation for ScanResult."""
        result = _make_sample_scan_result()
        json_report = generate_json_report(result)

        # Verify it's valid JSON
        parsed = json.loads(json_report)

        # Check key fields
        assert parsed["scan_root"] == "/tmp/test_wordpress"
        assert parsed["file_count"] == 150
        assert parsed["scanned_size_bytes"] == 1024000
        assert len(parsed["findings"]) == 1
        assert parsed["findings"][0]["file_path"] == "wp-content/plugins/test.php"
        assert parsed["errors"] == ["Failed to read .htaccess file"]
        assert parsed["limitations"] == ["Symlink scanning disabled"]

        # Verify deterministic ordering (keys should be sorted)
        keys = list(parsed.keys())
        assert keys == sorted(keys)

        # Check nested objects also have sorted keys
        finding_keys = list(parsed["findings"][0].keys())
        assert finding_keys == sorted(finding_keys)

    def test_comparison_result_json(self):
        """Test JSON report generation for ComparisonResult."""
        result = _make_sample_comparison_result()
        json_report = generate_json_report(result)

        # Verify it's valid JSON
        parsed = json.loads(json_report)

        # Check key fields
        assert parsed["source_root"] == "/tmp/wordpress_clean"
        assert parsed["dest_root"] == "/tmp/wordpress_suspect"
        assert parsed["added_count"] == 1
        assert parsed["removed_count"] == 1
        assert parsed["modified_count"] == 1
        assert parsed["unchanged_count"] == 1
        assert len(parsed["entries"]) == 4
        assert parsed["limitations"] == ["File count limit prevented scanning all files"]

        # Verify deterministic ordering
        keys = list(parsed.keys())
        assert keys == sorted(keys)

    def test_verification_result_json(self):
        """Test JSON report generation for VerificationResult."""
        result = _make_sample_verification_result()
        json_report = generate_json_report(result)

        # Verify it's valid JSON
        parsed = json.loads(json_report)

        # Check key fields
        assert parsed["version"] == "6.5.2"
        assert parsed["locale"] == "en_US"
        assert parsed["status"] == "verified"
        assert parsed["verified_matches"] == 5
        assert parsed["mismatches"] == 0
        assert parsed["missing"] == 0
        assert parsed["unchecked"] == 0
        assert len(parsed["files"]) == 2
        assert parsed["error"] is None

        # Verify deterministic ordering
        keys = list(parsed.keys())
        assert keys == sorted(keys)

    def test_invalid_result_type(self):
        """Test that invalid result types raise TypeError."""
        with pytest.raises(TypeError, match="Unsupported result type"):
            generate_json_report("invalid_result")


# Test HTML report generation
class TestHTMLReportGeneration:
    def test_scan_result_html(self):
        """Test HTML report generation for ScanResult."""
        result = _make_sample_scan_result()
        html_report = generate_html_report(result)

        # Check that it contains expected elements
        assert "<!DOCTYPE html>" in html_report
        assert "<title>WP Forensics Scan Report</title>" in html_report
        assert "/tmp/test_wordpress" in html_report
        assert "150" in html_report  # file count
        assert "1,024,000" in html_report  # formatted file size
        assert "wp-content/plugins/test.php" in html_report
        assert "eval(base64_decode" in html_report  # evidence
        assert "Failed to read .htaccess file" in html_report  # error
        assert "Symlink scanning disabled" in html_report  # limitation

        # Check that untrusted content is escaped
        assert "&lt;" in html_report or "&#60;" in html_report  # < should be escaped
        assert "&gt;" in html_report or "&#62;" in html_report  # > should be escaped
        assert "&amp;" in html_report or "&#38;" in html_report  # & should be escaped
        assert "&quot;" in html_report or "&#34;" in html_report  # " should be escaped
        assert "&#x27;" in html_report  # ' should be escaped

    def test_comparison_result_html(self):
        """Test HTML report generation for ComparisonResult."""
        result = _make_sample_comparison_result()
        html_report = generate_html_report(result)

        # Check that it contains expected elements
        assert "<!DOCTYPE html>" in html_report
        assert "<title>WP Forensics Comparison Report</title>" in html_report
        assert "/tmp/wordpress_clean" in html_report
        assert "/tmp/wordpress_suspect" in html_report
        assert "1" in html_report  # added count
        assert "1" in html_report  # removed count
        assert "1" in html_report  # modified count
        assert "1" in html_report  # unchanged count
        assert "wp-config.php" in html_report
        assert "index.php" in html_report
        assert "wp-content/plugins/new-plugin.php" in html_report
        assert "wp-content/plugins/old-plugin.php" in html_report
        assert "File count limit prevented scanning all files" in html_report  # limitation

        # Check that untrusted content is escaped
        assert "&lt;" in html_report or "&#60;" in html_report
        assert "&gt;" in html_report or "&#62;" in html_report
        assert "&amp;" in html_report or "&#38;" in html_report
        assert "&quot;" in html_report or "&#34;" in html_report
        assert "&#x27;" in html_report

    def test_verification_result_html(self):
        """Test HTML report generation for VerificationResult."""
        result = _make_sample_verification_result()
        html_report = generate_html_report(result)

        # Check that it contains expected elements
        assert "<!DOCTYPE html>" in html_report
        assert "<title>WP Forensics Verification Report</title>" in html_report
        assert "6.5.2" in html_report  # version
        assert "en_US" in html_report  # locale
        assert "Verified" in html_report  # status
        assert "5" in html_report  # verified matches
        assert "wp-config.php" in html_report
        assert "index.php" in html_report

        # Check that untrusted content is escaped
        assert "&lt;" in html_report or "&#60;" in html_report
        assert "&gt;" in html_report or "&#62;" in html_report
        assert "&amp;" in html_report or "&#38;" in html_report
        assert "&quot;" in html_report or "&#34;" in html_report
        assert "&#x27;" in html_report

    def test_verification_result_html_with_error(self):
        """Test HTML report generation for VerificationResult with error."""
        result = _make_sample_verification_result()
        result.error = "Network timeout"
        html_report = generate_html_report(result)

        assert "Network timeout" in html_report
        assert "error-box" in html_report  # CSS class for error display

    def test_invalid_result_type_html(self):
        """Test that invalid result types raise TypeError for HTML reports."""
        with pytest.raises(TypeError, match="Unsupported result type"):
            generate_html_report("invalid_result")


# Test edge cases and special characters
class TestEdgeCases:
    def test_html_report_with_special_characters(self):
        """Test that HTML report properly escapes special characters."""
        # Create a finding with special characters that need escaping
        finding = Finding(
            file_path='<script>alert("xss")</script>.php',
            indicator='alert("xss");',
            severity="high",
            confidence="high",
            category="xss",
            explanation='<script>alert("xss")</script>',
            evidence='<img src=x onerror=alert("xss")>',
            line_number=999,
            file_sha256="a" * 64,
            status="suspicious",
        )

        result = ScanResult(
            scan_time="2026-10-14T10:30:00Z",
            scan_root="/tmp/test",
            findings=[finding],
            file_count=1,
            scanned_size_bytes=1024,
            config_used=ScanConfig(),
            errors=[],
            limitations=[],
        )

        html_report = generate_html_report(result)

        # Verify that HTML special characters are escaped
        assert "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;.php" in html_report
        assert "&lt;img src=x onerror=alert(&quot;xss&quot;)&gt;" in html_report
        assert "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;" in html_report

        # Verify that the HTML is still valid
        assert "<!DOCTYPE html>" in html_report
        assert "</html>" in html_report

    def test_json_report_deterministic_ordering(self):
        """Test that JSON report generation produces deterministic output."""
        result1 = _make_sample_scan_result()
        result2 = _make_sample_scan_result()

        # Generate JSON reports multiple times
        json1 = generate_json_report(result1)
        json2 = generate_json_report(result2)

        # They should be identical
        assert json1 == json2

        # Parse and check that keys are sorted
        parsed1 = json.loads(json1)
        parsed2 = json.loads(json2)

        assert list(parsed1.keys()) == sorted(parsed1.keys())
        assert list(parsed2.keys()) == sorted(parsed2.keys())

    def test_empty_results(self):
        """Test report generation with empty/minimal results."""
        # Empty scan result
        empty_scan = ScanResult(
            scan_time="2026-10-14T10:30:00Z",
            scan_root="/tmp/empty",
            findings=[],
            file_count=0,
            scanned_size_bytes=0,
            config_used=ScanConfig(),
            errors=[],
            limitations=[],
        )

        json_report = generate_json_report(empty_scan)
        parsed = json.loads(json_report)
        assert parsed["file_count"] == 0
        assert parsed["findings"] == []
        assert parsed["errors"] == []
        assert parsed["limitations"] == []

        html_report = generate_html_report(empty_scan)
        assert "No findings detected." in html_report

        # Empty comparison result
        empty_comparison = ComparisonResult(
            source_root="/tmp/empty1",
            dest_root="/tmp/empty2",
            entries=[],
            added_count=0,
            removed_count=0,
            modified_count=0,
            unchanged_count=0,
            limitations=[],
        )

        json_report = generate_json_report(empty_comparison)
        parsed = json.loads(json_report)
        assert parsed["added_count"] == 0
        assert parsed["removed_count"] == 0
        assert parsed["modified_count"] == 0
        assert parsed["unchanged_count"] == 0
        assert parsed["entries"] == []
        assert parsed["limitations"] == []

        html_report = generate_html_report(empty_comparison)
        assert "No files compared." in html_report

        # Empty verification result
        empty_verification = VerificationResult(
            version=None,
            locale=None,
            status="version_not_detected",
            verified_matches=0,
            mismatches=0,
            missing=0,
            unchecked=0,
            files=[],
            error="No WordPress installation markers found",
        )

        json_report = generate_json_report(empty_verification)
        parsed = json.loads(json_report)
        assert parsed["version"] is None
        assert parsed["locale"] is None
        assert parsed["status"] == "version_not_detected"
        assert parsed["error"] == "No WordPress installation markers found"

        html_report = generate_html_report(empty_verification)
        assert "<not detected>" in html_report
        assert "Version Not Detected" in html_report
        assert "No WordPress installation markers found" in html_report

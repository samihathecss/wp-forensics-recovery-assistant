# wp_forensics/report.py
# JSON and HTML report generation for WP Forensics & Recovery Assistant

"""JSON and HTML report generation for WP Forensics & Recovery Assistant.

This module provides report generation for scan findings, comparison results,
and core-verification results. Reports include relevant paths, hashes, severity,
status, timestamps, counts, limitations, and errors.

All untrusted content is properly escaped in HTML output to prevent XSS.
JSON output is serialized deterministically for consistent results.
"""

from __future__ import annotations

import html
import json
from datetime import datetime
from typing import Any

from wp_forensics.models import (
    ComparisonResult,
    Finding,
    ScanResult,
    VerificationResult,
)

# Constants for comparison status (imported from models but re-exported for convenience)
COMPARISON_ADDED = "added"
COMPARISON_REMOVED = "removed"
COMPARISON_MODIFIED = "modified"
COMPARISON_UNCHANGED = "unchanged"

# Constants for verification status (imported from models but re-exported for convenience)
VERIF_RESULT_VERIFIED = "verified"
VERIF_RESULT_MISMATCHES = "mismatches_found"
VERIF_RESULT_MISSING = "missing_files"
VERIF_RESULT_NETWORK_ERROR = "network_error"
VERIF_RESULT_UNSUPPORTED = "unsupported_version"
VERIF_RESULT_NOT_DETECTED = "version_not_detected"
VERIF_RESULT_INCOMPLETE = "incomplete"

VERIFICATION_MATCH = "match"
VERIFICATION_MISMATCH = "mismatch"
VERIFICATION_MISSING = "missing"
VERIFICATION_UNCHECKED = "unchecked"


def _format_timestamp(timestamp_str: str) -> str:
    """Format a timestamp string for display, returning original if parsing fails."""
    try:
        dt = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except ValueError:
        return timestamp_str


def _make_serializable(obj: Any) -> Any:
    """Convert an object to a JSON-serializable form with deterministic ordering.

    Handles dataclasses, lists, dicts, and primitive types.
    """
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    elif isinstance(obj, dict):
        return {k: _make_serializable(v) for k, v in sorted(obj.items())}
    elif isinstance(obj, (list, tuple)):
        return [_make_serializable(item) for item in obj]
    elif hasattr(obj, "__dataclass_fields__"):
        result = {}
        for field in sorted(obj.__dataclass_fields__.keys()):
            value = getattr(obj, field)
            result[field] = _make_serializable(value)
        return result
    else:
        return str(obj)


def generate_json_report(result: Any) -> str:
    """Generate a JSON report from a scan, comparison, or verification result.

    Args:
        result: A ScanResult, ComparisonResult, or VerificationResult object

    Returns:
        JSON string with deterministic ordering and proper serialization

    Raises:
        TypeError: If result is not a supported type
    """
    if not isinstance(result, (ScanResult, ComparisonResult, VerificationResult)):
        raise TypeError(
            f"Unsupported result type: {type(result)}. "
            f"Expected ScanResult, ComparisonResult, or VerificationResult."
        )

    serializable = _make_serializable(result)
    return json.dumps(serializable, indent=2, sort_keys=True)


def _escape_html_content(content: str) -> str:
    """Escape HTML content to prevent XSS while preserving readability."""
    if not isinstance(content, str):
        content = str(content)
    return html.escape(content, quote=True)


def generate_html_report(result: Any) -> str:
    """Generate an HTML report from a scan, comparison, or verification result.

    Args:
        result: A ScanResult, ComparisonResult, or VerificationResult object

    Returns:
        HTML string with all untrusted content properly escaped

    Raises:
        TypeError: If result is not a supported type
    """
    if not isinstance(result, (ScanResult, ComparisonResult, VerificationResult)):
        raise TypeError(
            f"Unsupported result type: {type(result)}. "
            f"Expected ScanResult, ComparisonResult, or VerificationResult."
        )

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    if isinstance(result, ScanResult):
        return _generate_scan_result_html(result, timestamp)
    elif isinstance(result, ComparisonResult):
        return _generate_comparison_result_html(result, timestamp)
    elif isinstance(result, VerificationResult):
        return _generate_verification_result_html(result, timestamp)
    else:
        raise TypeError(f"Unsupported result type: {type(result)}")


def _generate_scan_result_html(result: ScanResult, timestamp: str) -> str:
    """Generate HTML report for a ScanResult."""
    escaped_root = _escape_html_content(result.scan_root)
    escaped_time = _escape_html_content(_format_timestamp(result.scan_time))
    escaped_report_time = _escape_html_content(timestamp)

    html_parts = [
        "<!DOCTYPE html>",
        "<html>",
        "<head>",
        "  <meta charset='utf-8'>",
        "  <title>WP Forensics Scan Report</title>",
        "  <style>",
        "    body { font-family: Arial, sans-serif; margin: 20px; }",
        "    h1, h2, h3 { color: #2c3e50; }",
        "    .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }",
        "    .finding { margin: 10px 0; padding: 10px; background-color: #f8f9fa; border-left: 4px solid; }",
        "    .severity-low { border-left-color: #28a745; }",
        "    .severity-medium { border-left-color: #ffc107; }",
        "    .severity-high { border-left-color: #fd7e14; }",
        "    .severity-critical { border-left-color: #dc3545; }",
        "    .stats { display: flex; gap: 20px; margin: 15px 0; }",
        "    .stat { text-align: center; }",
        "    .stat-value { font-size: 24px; font-weight: bold; color: #2c3e50; }",
        "    .stat-label { font-size: 14px; color: #6c757d; }",
        "    table { width: 100%; border-collapse: collapse; margin: 10px 0; }",
        "    th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }",
        "    th { background-color: #f8f9fa; }",
        "    tr:hover { background-color: #f1f1f1; }",
        "    .limitations, .errors { background-color: #fff3cd; border: 1px solid #ffeaa7; }",
        "    .limitations h3, .errors h3 { color: #856404; margin-top: 0; }",
        "  </style>",
        "</head>",
        "<body>",
        "  <h1>WP Forensics Scan Report</h1>",
        f"  <p><strong>Generated:</strong> {escaped_report_time}</p>",
        "",
        "  <div class='section'>",
        "    <h2>Scan Information</h2>",
        f"    <p><strong>Scan Root:</strong> {escaped_root}</p>",
        f"    <p><strong>Scan Time:</strong> {escaped_time}</p>",
        "  </div>",
        "",
        "  <div class='section'>",
        "    <h2>Statistics</h2>",
        "    <div class='stats'>",
        "      <div class='stat'>",
        f"        <div class='stat-value'>{result.file_count}</div>",
        "        <div class='stat-label'>Total Files</div>",
        "      </div>",
        "      <div class='stat'>",
        f"        <div class='stat-value'>{result.scanned_size_bytes:,}</div>",
        "        <div class='stat-label'>Scanned Size (bytes)</div>",
        "      </div>",
        "      <div class='stat'>",
        f"        <div class='stat-value'>{len(result.findings)}</div>",
        "        <div class='stat-label'>Findings</div>",
        "      </div>",
        "    </div>",
        "  </div>",
        "",
        "  <div class='section'>",
        f"    <h2>Findings ({len(result.findings)})</h2>",
    ]

    if result.findings:
        html_parts.append("    <table>")
        html_parts.append("      <thead>")
        html_parts.append("        <tr>")
        html_parts.append("          <th>File</th>")
        html_parts.append("          <th>Indicator</th>")
        html_parts.append("          <th>Severity</th>")
        html_parts.append("          <th>Confidence</th>")
        html_parts.append("          <th>Category</th>")
        html_parts.append("          <th>Status</th>")
        html_parts.append("          <th>Line</th>")
        html_parts.append("          <th>Evidence</th>")
        html_parts.append("        </tr>")
        html_parts.append("      </thead>")
        html_parts.append("      <tbody>")

        for finding in result.findings:
            escaped_file_path = _escape_html_content(finding.file_path)
            escaped_indicator = _escape_html_content(finding.indicator)
            escaped_severity = _escape_html_content(finding.severity)
            escaped_confidence = _escape_html_content(finding.confidence)
            escaped_category = _escape_html_content(finding.category)
            escaped_status = _escape_html_content(finding.status)
            escaped_line = _escape_html_content(
                str(finding.line_number) if finding.line_number is not None else ""
            )
            escaped_evidence = _escape_html_content(finding.evidence)
            escaped_explanation = _escape_html_content(finding.explanation)

            html_parts.append(f"      <tr class='finding severity-{finding.severity}'>")
            html_parts.append(f"        <td>{escaped_file_path}</td>")
            html_parts.append(f"        <td>{escaped_indicator}</td>")
            html_parts.append(f"        <td>{escaped_severity}</td>")
            html_parts.append(f"        <td>{escaped_confidence}</td>")
            html_parts.append(f"        <td>{escaped_category}</td>")
            html_parts.append(f"        <td>{escaped_status}</td>")
            html_parts.append(f"        <td>{escaped_line}</td>")
            html_parts.append(f"        <td>{escaped_evidence}</td>")
            html_parts.append("      </tr>")
            html_parts.append("      <tr>")
            html_parts.append("        <td colspan='8' style='padding: 10px; background-color: #f1f1f1; font-style: italic;'>")
            html_parts.append(f"          Explanation: {escaped_explanation}")
            html_parts.append("        </td>")
            html_parts.append("      </tr>")

        html_parts.append("      </tbody>")
        html_parts.append("    </table>")
    else:
        html_parts.append("    <p>No findings detected.</p>")

    html_parts.append("  </div>")

    if result.limitations:
        html_parts.extend([
            "  <div class='section limitations'>",
            "    <h2>Limitations</h2>",
            "    <ul>",
        ])
        for limitation in result.limitations:
            escaped_limitation = _escape_html_content(limitation)
            html_parts.append(f"      <li>{escaped_limitation}</li>")
        html_parts.extend([
            "    </ul>",
            "  </div>",
        ])

    if result.errors:
        html_parts.extend([
            "  <div class='section errors'>",
            "    <h2>Errors</h2>",
            "    <ul>",
        ])
        for error in result.errors:
            escaped_error = _escape_html_content(error)
            html_parts.append(f"      <li>{escaped_error}</li>")
        html_parts.extend([
            "    </ul>",
            "  </div>",
        ])

    html_parts.extend([
        "  <div class='section'>",
        "    <p><small>All untrusted content is HTML-escaped for safety: &lt; &gt; &amp; &quot; &#x27;.</small></p>",
        "  </div>",

        "</body>",
        "</html>",
    ])

    return "\n".join(html_parts)


def _generate_comparison_result_html(result: ComparisonResult, timestamp: str) -> str:
    """Generate HTML report for a ComparisonResult."""
    escaped_source = _escape_html_content(result.source_root)
    escaped_dest = _escape_html_content(result.dest_root)
    escaped_report_time = _escape_html_content(timestamp)

    html_parts = [
        "<!DOCTYPE html>",
        "<html>",
        "<head>",
        "  <meta charset='utf-8'>",
        "  <title>WP Forensics Comparison Report</title>",
        "  <style>",
        "    body { font-family: Arial, sans-serif; margin: 20px; }",
        "    h1, h2, h3 { color: #2c3e50; }",
        "    .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }",
        "    .stats { display: flex; gap: 20px; margin: 15px 0; }",
        "    .stat { text-align: center; }",
        "    .stat-value { font-size: 24px; font-weight: bold; color: #2c3e50; }",
        "    .stat-label { font-size: 14px; color: #6c757d; }",
        "    table { width: 100%; border-collapse: collapse; margin: 10px 0; }",
        "    th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }",
        "    th { background-color: #f8f9fa; }",
        "    tr:hover { background-color: #f1f1f1; }",
        "    .added { background-color: #d4edda; }",
        "    .removed { background-color: #f8d7da; }",
        "    .modified { background-color: #fff3cd; }",
        "    .unchanged { background-color: #e2e3e5; }",
        "    .limitations { background-color: #fff3cd; border: 1px solid #ffeaa7; }",
        "    .limitations h3 { color: #856404; margin-top: 0; }",
        "  </style>",
        "</head>",
        "<body>",
        "  <h1>WP Forensics Comparison Report</h1>",
        f"  <p><strong>Generated:</strong> {escaped_report_time}</p>",
        "",
        "  <div class='section'>",
        "    <h2>Comparison Information</h2>",
        f"    <p><strong>Source Root:</strong> {escaped_source}</p>",
        f"    <p><strong>Destination Root:</strong> {escaped_dest}</p>",
        "  </div>",
        "",
        "  <div class='section'>",
        "    <h2>Statistics</h2>",
        "    <div class='stats'>",
        "      <div class='stat'>",
        f"        <div class='stat-value'>{result.added_count}</div>",
        "        <div class='stat-label'>Added Files</div>",
        "      </div>",
        "      <div class='stat'>",
        f"        <div class='stat-value'>{result.removed_count}</div>",
        "        <div class='stat-label'>Removed Files</div>",
        "      </div>",
        "      <div class='stat'>",
        f"        <div class='stat-value'>{result.modified_count}</div>",
        "        <div class='stat-label'>Modified Files</div>",
        "      </div>",
        "      <div class='stat'>",
        f"        <div class='stat-value'>{result.unchanged_count}</div>",
        "        <div class='stat-label'>Unchanged Files</div>",
        "      </div>",
        "    </div>",
        "  </div>",
        "",
        "  <div class='section'>",
        f"    <h2>File Comparisons ({len(result.entries)})</h2>",
    ]

    if result.entries:
        html_parts.append("    <table>")
        html_parts.append("      <thead>")
        html_parts.append("        <tr>")
        html_parts.append("          <th>File Path</th>")
        html_parts.append("          <th>Source Hash</th>")
        html_parts.append("          <th>Dest Hash</th>")
        html_parts.append("          <th>Status</th>")
        html_parts.append("        </tr>")
        html_parts.append("      </thead>")
        html_parts.append("      <tbody>")

        for entry in result.entries:
            escaped_path = _escape_html_content(entry.path)
            escaped_source_hash = _escape_html_content(entry.source_hash or "<none>")
            escaped_dest_hash = _escape_html_content(entry.dest_hash or "<none>")
            escaped_status = _escape_html_content(entry.status)

            row_class = ""
            if entry.status == COMPARISON_ADDED:
                row_class = "added"
            elif entry.status == COMPARISON_REMOVED:
                row_class = "removed"
            elif entry.status == COMPARISON_MODIFIED:
                row_class = "modified"
            elif entry.status == COMPARISON_UNCHANGED:
                row_class = "unchanged"

            html_parts.append(f"      <tr class='{row_class}'>")
            html_parts.append(f"        <td>{escaped_path}</td>")
            html_parts.append(f"        <td>{escaped_source_hash}</td>")
            html_parts.append(f"        <td>{escaped_dest_hash}</td>")
            html_parts.append(f"        <td>{escaped_status}</td>")
            html_parts.append("      </tr>")

        html_parts.append("      </tbody>")
        html_parts.append("    </table>")
    else:
        html_parts.append("    <p>No files compared.</p>")

    html_parts.append("  </div>")

    if result.limitations:
        html_parts.extend([
            "  <div class='section limitations'>",
            "    <h2>Limitations</h2>",
            "    <ul>",
        ])
        for limitation in result.limitations:
            escaped_limitation = _escape_html_content(limitation)
            html_parts.append(f"      <li>{escaped_limitation}</li>")
        html_parts.extend([
            "    </ul>",
            "  </div>",
        ])

    html_parts.extend([
        "  <div class='section'>",
        "    <p><small>All untrusted content is HTML-escaped for safety: &lt; &gt; &amp; &quot; &#x27;.</small></p>",
        "  </div>",

        "</body>",
        "</html>",
    ])

    return "\n".join(html_parts)


def _generate_verification_result_html(result: VerificationResult, timestamp: str) -> str:
    escaped_version = _escape_html_content(result.version) if result.version else "<not detected>"
    escaped_locale = _escape_html_content(result.locale) if result.locale else "<not detected>"
    escaped_report_time = _escape_html_content(timestamp)

    status_info = {
        VERIF_RESULT_VERIFIED: ("Verified", "#28a745"),
        VERIF_RESULT_MISMATCHES: ("Mismatches Found", "#dc3545"),
        VERIF_RESULT_MISSING: ("Missing Files", "#fd7e14"),
        VERIF_RESULT_NETWORK_ERROR: ("Network Error", "#6c757d"),
        VERIF_RESULT_UNSUPPORTED: ("Unsupported Version", "#6f42c1"),
        VERIF_RESULT_NOT_DETECTED: ("Version Not Detected", "#6c757d"),
        VERIF_RESULT_INCOMPLETE: ("Incomplete Scan", "#ffc107"),
    }

    status_text, status_color = status_info.get(
        result.status,
        (result.status, "#6c757d")
    )

    html_parts = [
        "<!DOCTYPE html>",
        "<html>",
        "<head>",
        "  <meta charset='utf-8'>",
        "  <title>WP Forensics Verification Report</title>",
        "  <style>",
        "    body { font-family: Arial, sans-serif; margin: 20px; }",
        "    h1, h2, h3 { color: #2c3e50; }",
        "    .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }",
        "    .status-badge {",
        "      display: inline-block;",
        "      padding: 5px 15px;",
        "      font-weight: bold;",
        "      color: white;",
        f"      background-color: {status_color};",
        "      border-radius: 3px;",
        "      font-size: 18px;",
        "    }",
        "    .stats { display: flex; gap: 20px; margin: 15px 0; }",
        "    .stat { text-align: center; }",
        "    .stat-value { font-size: 24px; font-weight: bold; color: #2c3e50; }",
        "    .stat-label { font-size: 14px; color: #6c757d; }",
        "    table { width: 100%; border-collapse: collapse; margin: 10px 0; }",
        "    th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }",
        "    th { background-color: #f8f9fa; }",
        "    tr:hover { background-color: #f1f1f1; }",
        "    .match { background-color: #d4edda; }",
        "    .mismatch { background-color: #f8d7da; }",
        "    .missing { background-color: #fff3cd; }",
        "    .unchecked { background-color: #e2e3e5; }",
        "    .error-box {",
        "      background-color: #f8d7da;",
        "      border: 1px solid #f5c6cb;",
        "      color: #721c24;",
        "      padding: 10px;",
        "      border-radius: 4px;",
        "      margin: 10px 0;",
        "    }",
        "  </style>",
        "</head>",
        "<body>",
        "  <h1>WP Forensics Verification Report</h1>",
        f"  <p><strong>Generated:</strong> {escaped_report_time}</p>",
        "",
        "  <div class='section'>",
        "    <h2>Verification Information</h2>",
        f"    <p><strong>WordPress Version:</strong> {escaped_version}</p>",
        f"    <p><strong>Locale:</strong> {escaped_locale}</p>",
        "    <p><strong>Overall Status:</strong></p>",
        f"    <p class='status-badge'>{status_text}</p>",
        "  </div>",
        "",
        "  <div class='section'>",
        "    <h2>Statistics</h2>",
        "    <div class='stats'>",
        "      <div class='stat'>",
        f"        <div class='stat-value'>{result.verified_matches}</div>",
        "        <div class='stat-label'>Verified Matches</div>",
        "      </div>",
        "      <div class='stat'>",
        f"        <div class='stat-value'>{result.mismatches}</div>",
        "        <div class='stat-label'>Mismatches</div>",
        "      </div>",
        "      <div class='stat'>",
        f"        <div class='stat-value'>{result.missing}</div>",
        "        <div class='stat-label'>Missing Files</div>",
        "      </div>",
        "      <div class='stat'>",
        f"        <div class='stat-value'>{result.unchecked}</div>",
        "        <div class='stat-label'>Unchecked Files</div>",
        "      </div>",
        "    </div>",
        "  </div>",
        "",
        "  <div class='section'>",
        f"    <h2>File Verification Details ({len(result.files)})</h2>",
    ]

    if result.files:
        html_parts.append("    <table>")
        html_parts.append("      <thead>")
        html_parts.append("        <tr>")
        html_parts.append("          <th>File Path</th>")
        html_parts.append("          <th>Expected Hash</th>")
        html_parts.append("          <th>Actual Hash</th>")
        html_parts.append("          <th>Status</th>")
        html_parts.append("        </tr>")
        html_parts.append("      </thead>")
        html_parts.append("      <tbody>")

        for file_ver in result.files:
            escaped_path = _escape_html_content(file_ver.path)
            escaped_expected = _escape_html_content(file_ver.expected_hash or "<none>")
            escaped_actual = _escape_html_content(file_ver.actual_hash or "<none>")
            escaped_status = _escape_html_content(file_ver.status)

            row_class = ""
            if file_ver.status == VERIFICATION_MATCH:
                row_class = "match"
            elif file_ver.status == VERIFICATION_MISMATCH:
                row_class = "mismatch"
            elif file_ver.status == VERIFICATION_MISSING:
                row_class = "missing"
            elif file_ver.status == VERIFICATION_UNCHECKED:
                row_class = "unchecked"

            html_parts.append(f"      <tr class='{row_class}'>")
            html_parts.append(f"        <td>{escaped_path}</td>")
            html_parts.append(f"        <td>{escaped_expected}</td>")
            html_parts.append(f"        <td>{escaped_actual}</td>")
            html_parts.append(f"        <td>{escaped_status}</td>")
            html_parts.append("      </tr>")

        html_parts.append("      </tbody>")
        html_parts.append("    </table>")
    else:
        html_parts.append("    <p>No files verified.</p>")

    html_parts.append("  </div>")

    if result.error:
        escaped_error = _escape_html_content(result.error)
        html_parts.extend([
            "  <div class='section'>",
            "    <div class='error-box'>",
            f"      <strong>Error:</strong> {escaped_error}",
            "    </div>",
            "  </div>",
        ])

    html_parts.extend([
        "  <div class='section'>",
        "    <p><small>All untrusted content is HTML-escaped for safety: &lt; &gt; &amp; &quot; &#x27;.</small></p>",
        "  </div>",

        "</body>",
        "</html>",
    ])

    return "\n".join(html_parts)

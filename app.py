"""WP Forensics & Recovery Assistant — Streamlit UI.

Local web interface for all features: scan, compare, verify core, and ZIP
inspection. Reports are generated as JSON/HTML and offered via download.
"""

from __future__ import annotations

import html
import io
import json
from pathlib import Path
from typing import Any

import streamlit as st

from wp_forensics.archive import ArchiveInspectionResult, inspect_zip
from wp_forensics.compare import compare_snapshots
from wp_forensics.config import ScanConfig
from wp_forensics.core_verify import verify_core
from wp_forensics.indicators import scan_directory
from wp_forensics.models import (
    ComparisonResult,
    Finding,
    ScanResult,
    VerificationResult,
)
from wp_forensics.report import generate_html_report, generate_json_report

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="WP Forensics & Recovery Assistant",
    page_icon="🔍",
    layout="wide",
)

st.title("🔍 WP Forensics & Recovery Assistant")
st.caption("Investigate WordPress backups for security issues — local, read-only scanning.")

# ---------------------------------------------------------------------------
# Sidebar: mode selector + configuration
# ---------------------------------------------------------------------------

st.sidebar.header("Configuration")

mode = st.sidebar.selectbox(
    "Mode",
    options=["Scan", "Compare", "Verify Core", "Inspect ZIP"],
    index=0,
)

st.sidebar.subheader("Scan Limits")
max_file_size_mb = st.sidebar.number_input(
    "Max file size (MB)", min_value=1, max_value=100, value=5, step=1,
)
max_files = st.sidebar.number_input(
    "Max files", min_value=1, max_value=100000, value=50000, step=1000,
)
max_total_size_mb = st.sidebar.number_input(
    "Max total size (MB)", min_value=1, max_value=10000, value=500, step=100,
)

config = ScanConfig(
    max_file_size_bytes=max_file_size_mb * 1024 * 1024,
    max_file_count=int(max_files),
    max_total_size_bytes=max_total_size_mb * 1024 * 1024,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_dataframe(result: Any) -> Any:
    """Convert a result object to a pandas DataFrame suitable for st.dataframe."""
    import pandas as pd

    if isinstance(result, ScanResult):
        rows = [
            {
                "File": f.file_path,
                "Indicator": f.indicator,
                "Severity": f.severity,
                "Confidence": f.confidence,
                "Category": f.category,
                "Status": f.status,
                "Line": f.line_number if f.line_number is not None else "",
                "Evidence": f.evidence,
                "Explanation": f.explanation,
                "SHA-256": f.file_sha256 or "",
            }
            for f in result.findings
        ]
        return pd.DataFrame(rows)

    if isinstance(result, ComparisonResult):
        rows = [
            {
                "Path": e.path,
                "Source Hash": e.source_hash or "",
                "Dest Hash": e.dest_hash or "",
                "Status": e.status,
            }
            for e in result.entries
        ]
        return pd.DataFrame(rows)

    if isinstance(result, VerificationResult):
        rows = [
            {
                "File": fv.path,
                "Expected Hash": fv.expected_hash or "",
                "Actual Hash": fv.actual_hash or "",
                "Status": fv.status,
            }
            for fv in result.files
        ]
        return pd.DataFrame(rows)

    return pd.DataFrame()


def _write_report_buttons(
    result: Any,
    base_name: str,
) -> None:
    """Render JSON/HTML download buttons for a result."""
    col1, col2 = st.columns(2)
    with col1:
        json_bytes = generate_json_report(result).encode("utf-8")
        st.download_button(
            label=f"📥 Download {base_name} (JSON)",
            data=json_bytes,
            file_name=f"{base_name}.json",
            mime="application/json",
        )
    with col2:
        html_bytes = generate_html_report(result).encode("utf-8")
        st.download_button(
            label=f"📥 Download {base_name} (HTML)",
            data=html_bytes,
            file_name=f"{base_name}.html",
            mime="text/html",
        )


def _render_scan_result(result: ScanResult) -> None:
    """Render a ScanResult in the UI."""
    st.subheader("Scan Results")
    c1, c2, c3 = st.columns(3)
    c1.metric("Files Scanned", result.file_count)
    c2.metric("Findings", len(result.findings))
    c3.metric("Scanned Size", f"{result.scanned_size_bytes:,} bytes")

    if result.errors:
        for err in result.errors:
            st.error(f"Error: {err}")
    if result.limitations:
        for lim in result.limitations:
            st.warning(f"Limitation: {lim}")

    # Severity filter
    severities = ["low", "medium", "high", "critical"]
    selected = st.segmented_control(
        "Filter by severity",
        options=severities,
        default=severities,
        label_visibility="collapsed",
    )
    if selected is None:
        selected = severities

    filtered = [
        f for f in result.findings if f.severity in selected
    ]

    if filtered:
        df = _to_dataframe(result)
        # Filter dataframe rows
        mask = df["Severity"].isin(selected)
        st.dataframe(df[mask], use_container_width=True, hide_index=True)
    else:
        st.info("No findings matching the selected severity filter.")

    _write_report_buttons(result, "scan_report")


def _render_comparison_result(result: ComparisonResult) -> None:
    """Render a ComparisonResult in the UI."""
    st.subheader("Comparison Results")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Added", result.added_count)
    c2.metric("Removed", result.removed_count)
    c3.metric("Modified", result.modified_count)
    c4.metric("Unchanged", result.unchanged_count)

    if result.limitations:
        for lim in result.limitations:
            st.warning(f"Limitation: {lim}")

    df = _to_dataframe(result)
    statuses = ["added", "removed", "modified", "unchanged"]
    selected_status = st.segmented_control(
        "Filter by status",
        options=statuses,
        default=statuses,
        label_visibility="collapsed",
    )
    if selected_status is None:
        selected_status = statuses

    mask = df["Status"].isin(selected_status)
    st.dataframe(df[mask], use_container_width=True, hide_index=True)

    _write_report_buttons(result, "comparison_report")


def _render_verification_result(result: VerificationResult) -> None:
    """Render a VerificationResult in the UI."""
    st.subheader("Verification Results")
    st.metric("Version", result.version or "Not detected")
    st.metric("Locale", result.locale or "Not detected")
    st.metric("Status", result.status)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Matches", result.verified_matches)
    c2.metric("Mismatches", result.mismatches)
    c3.metric("Missing", result.missing)
    c4.metric("Unchecked", result.unchecked)

    if result.error:
        st.error(f"Error: {result.error}")

    if result.files:
        df = _to_dataframe(result)
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No files verified.")

    _write_report_buttons(result, "verification_report")


# ---------------------------------------------------------------------------
# Main: mode-specific interface
# ---------------------------------------------------------------------------

if mode == "Scan":
    st.header("Scan Mode")
    directory = st.text_input("Directory to scan", placeholder="Enter path to WordPress site")

    if st.button("Run Scan", type="primary"):
        if not directory:
            st.error("Please enter a directory path.")
        else:
            root = Path(directory)
            if not root.exists():
                st.error(f"Directory does not exist: {root}")
            elif not root.is_dir():
                st.error(f"Not a directory: {root}")
            else:
                with st.status("Scanning directory...", expanded=True) as status:
                    try:
                        result = scan_directory(root, config)
                        status.update(label="Scan complete", state="complete")
                        _render_scan_result(result)
                        st.session_state["last_scan_result"] = result
                    except Exception as exc:
                        status.update(label="Scan failed", state="error")
                        st.error(f"Scan failed: {exc}")

elif mode == "Compare":
    st.header("Compare Mode")
    col1, col2 = st.columns(2)
    with col1:
        source = st.text_input("Source directory", placeholder="Enter source path")
    with col2:
        destination = st.text_input("Destination directory", placeholder="Enter destination path")

    if st.button("Run Compare", type="primary"):
        if not source or not destination:
            st.error("Please enter both directory paths.")
        else:
            src = Path(source)
            dst = Path(destination)
            if not src.exists():
                st.error(f"Source directory does not exist: {src}")
            elif not dst.exists():
                st.error(f"Destination directory does not exist: {dst}")
            else:
                with st.status("Comparing directories...", expanded=True) as status:
                    try:
                        result = compare_snapshots(src, dst, config)
                        status.update(label="Comparison complete", state="complete")
                        _render_comparison_result(result)
                        st.session_state["last_compare_result"] = result
                    except Exception as exc:
                        status.update(label="Comparison failed", state="error")
                        st.error(f"Comparison failed: {exc}")

elif mode == "Verify Core":
    st.header("Verify Core Mode")
    directory = st.text_input("WordPress directory", placeholder="Enter path to WordPress site")

    if st.button("Run Verification", type="primary"):
        if not directory:
            st.error("Please enter a directory path.")
        else:
            root = Path(directory)
            if not root.exists():
                st.error(f"Directory does not exist: {root}")
            elif not root.is_dir():
                st.error(f"Not a directory: {root}")
            else:
                with st.status("Verifying WordPress core...", expanded=True) as status:
                    try:
                        result = verify_core(root, config)
                        status.update(label="Verification complete", state="complete")
                        _render_verification_result(result)
                        st.session_state["last_verify_result"] = result
                    except Exception as exc:
                        status.update(label="Verification failed", state="error")
                        st.error(f"Verification failed: {exc}")

elif mode == "Inspect ZIP":
    st.header("Inspect ZIP Mode")
    uploaded = st.file_uploader("Upload ZIP archive", type=["zip"])

    if uploaded is not None:
        if st.button("Run Inspection", type="primary"):
            with st.status("Inspecting ZIP archive...", expanded=True) as status:
                try:
                    # Save uploaded file to a temp location
                    import tempfile

                    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                        tmp.write(uploaded.read())
                        tmp_path = Path(tmp.name)

                    result = inspect_zip(tmp_path, config)
                    tmp_path.unlink(missing_ok=True)

                    status.update(label="Inspection complete", state="complete")

                    st.subheader("ZIP Inspection Results")
                    c1, c2 = st.columns(2)
                    c1.metric("Total Entries", result.total_entries)
                    c2.metric("Safe to Extract", "Yes" if result.is_safe_to_extract else "No")
                    st.metric("Total Uncompressed", f"{result.total_uncompressed_bytes:,} bytes")
                    st.metric("Total Compressed", f"{result.total_compressed_bytes:,} bytes")

                    if result.errors:
                        for err in result.errors:
                            st.error(f"Error: {err}")
                    if result.limitations:
                        for lim in result.limitations:
                            st.warning(f"Limitation: {lim}")

                    if result.entries:
                        import pandas as pd

                        rows = [
                            {
                                "Name": e.name,
                                "Size": e.file_size,
                                "Symlink": "Yes" if e.is_symlink else "No",
                                "Traversal Risk": "Yes" if e.is_traversal_risk else "No",
                                "Safe": "Yes" if e.is_safe_to_extract else "No",
                                "Error": e.error or "",
                            }
                            for e in result.entries
                        ]
                        df = pd.DataFrame(rows)
                        st.dataframe(df, use_container_width=True, hide_index=True)

                    _write_report_buttons(result, "zip_inspection")
                except Exception as exc:
                    status.update(label="Inspection failed", state="error")
                    st.error(f"Inspection failed: {exc}")

st.divider()
st.caption(
    "WP Forensics & Recovery Assistant — read-only forensic scanning. "
    "No original files are modified, deleted, or quarantined."
)

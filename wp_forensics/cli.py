"""Command-line interface for WP Forensics & Recovery Assistant.

Provides subcommands for scanning directories, comparing snapshots,
and inspecting ZIP archives. All reports are written to a separate
output directory.

Usage:
    python -m wp_forensics.cli scan <dir> [-o PATH] [--verify-core]
    python -m wp_forensics.cli compare <src> <dst> [-o PATH]
    python -m wp_forensics.cli inspect-zip <zip> [-o PATH]
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from html import escape as html_escape
from pathlib import Path
from typing import Any

from wp_forensics.archive import ArchiveInspectionResult, ZipEntry, inspect_zip
from wp_forensics.compare import compare_snapshots
from wp_forensics.config import ScanConfig
from wp_forensics.core_verify import verify_core
from wp_forensics.indicators import scan_directory
from wp_forensics.models import (
    ComparisonResult,
    ScanResult,
    VerificationResult,
)
from wp_forensics.report import generate_html_report, generate_json_report


def _build_config(args: argparse.Namespace) -> ScanConfig:
    """Create a ScanConfig from CLI arguments, applying only provided overrides."""
    config = ScanConfig()
    if getattr(args, "max_file_size", None) is not None:
        config.max_file_size_bytes = args.max_file_size * 1024 * 1024
    if getattr(args, "max_files", None) is not None:
        config.max_file_count = args.max_files
    if getattr(args, "max_total_size", None) is not None:
        config.max_total_size_bytes = args.max_total_size * 1024 * 1024
    return config


def _write_reports(
    output_dir: Path,
    base_name: str,
    json_content: str,
    html_content: str,
) -> None:
    """Write JSON and HTML report files to the output directory."""
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / f"{base_name}.json").write_text(json_content, encoding="utf-8")
    (output_dir / f"{base_name}.html").write_text(html_content, encoding="utf-8")


def _print_summary(scan_result: ScanResult) -> None:
    """Print a summary of the scan results to stderr."""
    print(f"\nScan summary:", file=sys.stderr)
    print(f"  Files scanned: {scan_result.file_count}", file=sys.stderr)
    print(f"  Findings: {len(scan_result.findings)}", file=sys.stderr)
    if scan_result.errors:
        print(f"  Errors: {len(scan_result.errors)}", file=sys.stderr)
    if scan_result.limitations:
        print(f"  Limitations: {len(scan_result.limitations)}", file=sys.stderr)


def cmd_scan(args: argparse.Namespace) -> int:
    """Run the scan subcommand."""
    root = Path(args.directory)
    if not root.exists():
        print(f"Error: Directory does not exist: {root}", file=sys.stderr)
        return 1
    if not root.is_dir():
        print(f"Error: Not a directory: {root}", file=sys.stderr)
        return 1

    config = _build_config(args)
    result = scan_directory(root, config)

    if args.output:
        output_dir = Path(args.output)
        _write_reports(
            output_dir,
            "scan_report",
            generate_json_report(result),
            generate_html_report(result),
        )
        print(f"Reports written to: {output_dir}", file=sys.stderr)

        if args.verify_core:
            verification = verify_core(root, config)
            _write_reports(
                output_dir,
                "verification_report",
                generate_json_report(verification),
                generate_html_report(verification),
            )
            print(f"  Verification status: {verification.status}", file=sys.stderr)
    else:
        print(generate_json_report(result))

    _print_summary(result)
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    """Run the compare subcommand."""
    source = Path(args.source)
    dest = Path(args.destination)

    if not source.exists():
        print(f"Error: Source directory does not exist: {source}", file=sys.stderr)
        return 1
    if not dest.exists():
        print(f"Error: Destination directory does not exist: {dest}", file=sys.stderr)
        return 1

    config = _build_config(args)
    result = compare_snapshots(source, dest, config)

    if args.output:
        output_dir = Path(args.output)
        _write_reports(
            output_dir,
            "comparison_report",
            generate_json_report(result),
            generate_html_report(result),
        )
        print(f"Reports written to: {output_dir}", file=sys.stderr)
    else:
        print(generate_json_report(result))

    print(f"\nComparison summary:", file=sys.stderr)
    print(f"  Added: {result.added_count}", file=sys.stderr)
    print(f"  Removed: {result.removed_count}", file=sys.stderr)
    print(f"  Modified: {result.modified_count}", file=sys.stderr)
    print(f"  Unchanged: {result.unchanged_count}", file=sys.stderr)

    return 0


def cmd_inspect_zip(args: argparse.Namespace) -> int:
    """Run the inspect-zip subcommand."""
    zip_path = Path(args.zipfile)
    if not zip_path.exists():
        print(f"Error: ZIP file does not exist: {zip_path}", file=sys.stderr)
        return 1
    if not zip_path.is_file():
        print(f"Error: Not a file: {zip_path}", file=sys.stderr)
        return 1

    config = _build_config(args)
    result = inspect_zip(zip_path, config)

    json_content = _serialize_zip_result(result)
    html_content = _generate_zip_html(result)

    if args.output:
        output_dir = Path(args.output)
        _write_reports(
            output_dir,
            "zip_inspection",
            json_content,
            html_content,
        )
        print(f"Reports written to: {output_dir}", file=sys.stderr)
    else:
        print(json_content)

    print(f"\nZIP inspection summary:", file=sys.stderr)
    print(f"  Total entries: {result.total_entries}", file=sys.stderr)
    print(f"  Safe to extract: {result.is_safe_to_extract}", file=sys.stderr)
    if result.errors:
        print(f"  Errors: {len(result.errors)}", file=sys.stderr)

    return 0


def _serialize_zip_result(result: ArchiveInspectionResult) -> str:
    """Serialize an ArchiveInspectionResult to a JSON string."""
    data = {
        "archive_path": result.archive_path,
        "entries": [_zip_entry_to_dict(e) for e in result.entries],
        "errors": result.errors,
        "limitations": result.limitations,
        "is_safe_to_extract": result.is_safe_to_extract,
        "total_compressed_bytes": result.total_compressed_bytes,
        "total_entries": result.total_entries,
        "total_uncompressed_bytes": result.total_uncompressed_bytes,
    }
    return json.dumps(data, indent=2, sort_keys=True, default=str)


def _zip_entry_to_dict(entry: ZipEntry) -> dict[str, Any]:
    """Convert a ZipEntry to a dictionary for JSON serialization."""
    return {
        "compressed_size": entry.compressed_size,
        "error": entry.error,
        "file_size": entry.file_size,
        "is_duplicate": entry.is_duplicate,
        "is_safe_to_extract": entry.is_safe_to_extract,
        "is_symlink": entry.is_symlink,
        "is_traversal_risk": entry.is_traversal_risk,
        "name": entry.name,
        "normalized_name": entry.normalized_name,
    }


def _generate_zip_html(result: ArchiveInspectionResult) -> str:
    """Generate a simple HTML report for ZIP inspection results."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    def esc(value: Any) -> str:
        return html_escape(str(value), quote=True)

    parts: list[str] = [
        "<!DOCTYPE html>",
        "<html>",
        "<head>",
        "  <meta charset='utf-8'>",
        "  <title>WP Forensics ZIP Inspection Report</title>",
        "  <style>",
        "    body { font-family: Arial, sans-serif; margin: 20px; }",
        "    h1, h2 { color: #2c3e50; }",
        "    .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }",
        "    table { width: 100%; border-collapse: collapse; margin: 10px 0; }",
        "    th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }",
        "    th { background-color: #f8f9fa; }",
        "    tr:hover { background-color: #f1f1f1; }",
        "    .safe { background-color: #d4edda; }",
        "    .unsafe { background-color: #f8d7da; }",
        "  </style>",
        "</head>",
        "<body>",
        "  <h1>WP Forensics ZIP Inspection Report</h1>",
        f"  <p><strong>Generated:</strong> {esc(timestamp)}</p>",
        "  <div class='section'>",
        f"    <p><strong>Archive:</strong> {esc(result.archive_path)}</p>",
        f"    <p><strong>Total Entries:</strong> {result.total_entries}</p>",
        f"    <p><strong>Total Uncompressed:</strong> {result.total_uncompressed_bytes} bytes</p>",
        f"    <p><strong>Total Compressed:</strong> {result.total_compressed_bytes} bytes</p>",
        f"    <p><strong>Safe to Extract:</strong> {'Yes' if result.is_safe_to_extract else 'No'}</p>",
        "  </div>",
    ]

    if result.entries:
        parts.append("  <div class='section'>")
        parts.append("    <h2>Entries</h2>")
        parts.append("    <table>")
        parts.append("      <thead>")
        parts.append("        <tr>")
        parts.append("          <th>Name</th>")
        parts.append("          <th>Size</th>")
        parts.append("          <th>Symlink</th>")
        parts.append("          <th>Traversal</th>")
        parts.append("          <th>Safe</th>")
        parts.append("          <th>Error</th>")
        parts.append("        </tr>")
        parts.append("      </thead>")
        parts.append("      <tbody>")
        for entry in result.entries:
            row_class = "safe" if entry.is_safe_to_extract else "unsafe"
            parts.append(f"        <tr class='{row_class}'>")
            parts.append(f"          <td>{esc(entry.name)}</td>")
            parts.append(f"          <td>{entry.file_size}</td>")
            parts.append(f"          <td>{'Yes' if entry.is_symlink else 'No'}</td>")
            parts.append(f"          <td>{'Yes' if entry.is_traversal_risk else 'No'}</td>")
            parts.append(f"          <td>{'Yes' if entry.is_safe_to_extract else 'No'}</td>")
            parts.append(f"          <td>{esc(entry.error) if entry.error else ''}</td>")
            parts.append("        </tr>")
        parts.append("      </tbody>")
        parts.append("    </table>")
        parts.append("  </div>")

    if result.errors:
        parts.append("  <div class='section'>")
        parts.append("    <h2>Errors</h2>")
        parts.append("    <ul>")
        for err in result.errors:
            parts.append(f"      <li>{esc(err)}</li>")
        parts.append("    </ul>")
        parts.append("  </div>")

    if result.limitations:
        parts.append("  <div class='section'>")
        parts.append("    <h2>Limitations</h2>")
        parts.append("    <ul>")
        for lim in result.limitations:
            parts.append(f"      <li>{esc(lim)}</li>")
        parts.append("    </ul>")
        parts.append("  </div>")

    parts.extend([
        "  <div class='section'>",
        "    <p><small>All untrusted content is HTML-escaped: &lt; &gt; &amp; &quot; &#x27;.</small></p>",
        "  </div>",
        "</body>",
        "</html>",
    ])

    return "\n".join(parts)


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser for the WP Forensics CLI."""
    parser = argparse.ArgumentParser(
        prog="wp-forensics",
        description=(
            "WP Forensics & Recovery Assistant — investigate WordPress "
            "backups for security issues."
        ),
    )

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    # --- scan ---
    scan_parser = subparsers.add_parser(
        "scan", help="Scan a directory for suspicious files and indicators."
    )
    scan_parser.add_argument("directory", help="Directory to scan")
    scan_parser.add_argument(
        "-o", "--output", help="Output directory for reports"
    )
    scan_parser.add_argument(
        "--verify-core", action="store_true",
        help="Also verify core files against WordPress.org checksums",
    )
    scan_parser.add_argument(
        "--max-file-size", type=int, metavar="MB",
        help="Maximum per-file size to scan (default: 5 MB)",
    )
    scan_parser.add_argument(
        "--max-files", type=int, metavar="N",
        help="Maximum number of files to scan (default: 50 000)",
    )
    scan_parser.add_argument(
        "--max-total-size", type=int, metavar="MB",
        help="Maximum total size to scan (default: 500 MB)",
    )
    scan_parser.set_defaults(func=cmd_scan)

    # --- compare ---
    compare_parser = subparsers.add_parser(
        "compare", help="Compare two directory snapshots."
    )
    compare_parser.add_argument("source", help="Source directory")
    compare_parser.add_argument("destination", help="Destination directory")
    compare_parser.add_argument(
        "-o", "--output", help="Output directory for reports"
    )
    compare_parser.add_argument(
        "--max-file-size", type=int, metavar="MB",
        help="Maximum per-file size in MB",
    )
    compare_parser.add_argument(
        "--max-files", type=int, metavar="N",
        help="Maximum number of files",
    )
    compare_parser.set_defaults(func=cmd_compare)

    # --- inspect-zip ---
    zip_parser = subparsers.add_parser(
        "inspect-zip", help="Inspect a ZIP archive for security issues."
    )
    zip_parser.add_argument("zipfile", help="ZIP file to inspect")
    zip_parser.add_argument(
        "-o", "--output", help="Output directory for reports"
    )
    zip_parser.add_argument(
        "--max-file-size", type=int, metavar="MB",
        help="Maximum per-entry size in MB",
    )
    zip_parser.add_argument(
        "--max-files", type=int, metavar="N",
        help="Maximum number of ZIP entries",
    )
    zip_parser.set_defaults(func=cmd_inspect_zip)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for the WP Forensics CLI.

    Args:
        argv: Command-line arguments (excluding program name).
            If None, uses sys.argv[1:].

    Returns:
        Exit code: 0 on success, 1 on error.
    """
    parser = create_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

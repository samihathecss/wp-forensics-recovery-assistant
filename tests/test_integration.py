"""Integration & end-to-end tests for WP Forensics & Recovery Assistant (Milestone 11).

Synthetic WordPress fixtures are created at test time under ``tmp_path`` (not committed).
Full workflows are exercised: scan, compare, ZIP inspection, report generation,
safety checks (no PHP execution, originals unmodified).

Note: On Windows, files containing suspicious PHP patterns may be temporarily locked
by real-time antivirus scanning immediately after creation. Path-based indicator
rules (which do not read file content) still fire; content-based rules for locked
files are gracefully skipped by the engine. Tests assert accordingly.
"""

from __future__ import annotations

import hashlib
import json
import re
import zipfile
from pathlib import Path

import pytest

from wp_forensics.archive import inspect_zip
from wp_forensics.compare import compare_snapshots
from wp_forensics.config import ScanConfig
from wp_forensics.core_verify import verify_core
from wp_forensics.indicators import scan_directory
from wp_forensics.models import (
    COMPARISON_ADDED,
    COMPARISON_MODIFIED,
)
from wp_forensics.report import generate_html_report, generate_json_report


# ---------------------------------------------------------------------------
# Fixture builders (created at test time under tmp_path)
# ---------------------------------------------------------------------------


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_bytes(path: Path, content: bytes) -> None:
    """Write bytes directly to avoid AV text scanning on suspicious patterns."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def build_clean_wp(root: Path) -> None:
    """Build a clean WordPress-like tree with no suspicious content.

    No PHP files under wp-content/uploads (those would trigger IND-PHP-IN-UPLOADS).
    """
    _write_text(root / "index.php", "<?php echo 'Hello World'; ?>")
    _write_text(root / "wp-config-sample.php", "<?php // config sample ?>")
    _write_text(root / "wp-includes/version.php", "<?php $wp_version = '6.0'; ?>")
    _write_text(root / "wp-includes/functions.php", "<?php function wp_die() {} ?>")
    _write_text(root / "wp-content/index.php", "<?php // silence ?>")
    _write_text(
        root / "wp-content/themes/twenty-twenty/style.css",
        "/* Theme: twenty-twenty */\nbody { margin: 0; }",
    )
    _write_text(
        root / "wp-content/plugins/hello-dolly/hello.php",
        "<?php // Hello Dolly plugin ?>",
    )
    _write_text(
        root / "wp-content/uploads/2026/01/photo.jpg",
        "fake image bytes",
    )


def build_hacked_wp(root: Path) -> None:
    """Build a clean WP tree plus injected malicious content."""
    build_clean_wp(root)

    # Web shell in uploads -> IND-PHP-IN-UPLOADS (path rule, no content read needed)
    _write_bytes(
        root / "wp-content/uploads/2026/01/shell.php",
        b"<?php eval(base64_decode($_GET['cmd'])); ?>",
    )

    # Known web shell filename -> IND-WEB-SHELL-NAME (path rule)
    _write_bytes(
        root / "wp-content/uploads/c99.php",
        b"<?php system($_GET['c']); ?>",
    )

    # Modified core file -> detected by compare/verify
    _write_text(
        root / "wp-includes/version.php",
        "<?php $wp_version = '6.0-hacked'; ?>",
    )


def build_zip_traversal(tmp_path: Path) -> Path:
    """Create a ZIP with a path-traversal entry."""
    zip_path = tmp_path / "zip_with_traversal.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("index.php", "<?php echo 'ok'; ?>")
        zf.writestr("../evil.php", "<?php evil(); ?>")
    return zip_path


def build_zip_symlink(tmp_path: Path) -> Path:
    """Create a ZIP with a symlink entry (Unix S_IFLNK type)."""
    zip_path = tmp_path / "zip_with_symlink.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("index.php", "<?php echo 'ok'; ?>")
        info = zipfile.ZipInfo("link_to_etc_passwd")
        info.create_system = 3  # Unix
        info.external_attr = 0o120000 << 16  # S_IFLNK symlink type
        zf.writestr(info, "/etc/passwd")
    return zip_path


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_scan_clean_wp_zero_findings(tmp_path):
    """Full scan of clean WP should produce 0 findings."""
    clean_wp = tmp_path / "clean_wp"
    build_clean_wp(clean_wp)

    before = _hash_tree(clean_wp)
    result = scan_directory(clean_wp, ScanConfig())
    after = _hash_tree(clean_wp)

    assert result.file_count >= 1
    assert len(result.findings) == 0, (
        f"Unexpected findings on clean WP: {[f.indicator for f in result.findings]}"
    )
    assert before == after, "Original fixture files were modified during scan"


def test_scan_hacked_wp_findings(tmp_path):
    """Full scan of hacked WP should detect web shell and PHP in uploads."""
    hacked_wp = tmp_path / "hacked_wp"
    build_hacked_wp(hacked_wp)

    result = scan_directory(hacked_wp, ScanConfig())

    assert result.file_count >= 1
    assert len(result.findings) >= 1, "Expected findings on hacked WP"

    indicator_ids = {f.indicator for f in result.findings}
    # PHP in uploads (path rule, does not read content)
    assert any("UPLOADS" in iid for iid in indicator_ids), indicator_ids
    # Web shell filename (path rule, does not read content)
    assert any("WEB-SHELL" in iid for iid in indicator_ids), indicator_ids


def test_compare_clean_vs_hacked(tmp_path):
    """Compare clean vs hacked should identify modified files."""
    clean_wp = tmp_path / "clean_wp"
    hacked_wp = tmp_path / "hacked_wp"
    build_clean_wp(clean_wp)
    build_hacked_wp(hacked_wp)

    result = compare_snapshots(clean_wp, hacked_wp, ScanConfig())

    # version.php is modified and readable in both trees
    assert result.modified_count >= 1, "Expected modified file (version.php)"
    statuses = {e.status for e in result.entries}
    assert COMPARISON_MODIFIED in statuses


def test_zip_inspection_traversal(tmp_path):
    """ZIP inspection should flag path traversal entries."""
    zip_path = build_zip_traversal(tmp_path)
    result = inspect_zip(zip_path, ScanConfig())

    assert result.total_entries >= 2
    assert not result.is_safe_to_extract, "ZIP with traversal should be unsafe"
    traversal_entries = [e for e in result.entries if e.is_traversal_risk]
    assert len(traversal_entries) >= 1


def test_zip_inspection_symlink(tmp_path):
    """ZIP inspection should flag symlink entries."""
    zip_path = build_zip_symlink(tmp_path)
    result = inspect_zip(zip_path, ScanConfig())

    assert result.total_entries >= 2
    symlink_entries = [e for e in result.entries if e.is_symlink]
    assert len(symlink_entries) >= 1


def test_report_generation_end_to_end(tmp_path):
    """Report generation produces valid JSON and safe HTML end-to-end."""
    hacked_wp = tmp_path / "hacked_wp"
    build_hacked_wp(hacked_wp)
    result = scan_directory(hacked_wp, ScanConfig())

    json_str = generate_json_report(result)
    parsed = json.loads(json_str)
    assert "findings" in parsed
    assert "file_count" in parsed

    html_str = generate_html_report(result)
    assert "<!DOCTYPE html>" in html_str

    # XSS safety: any <script> in evidence must be escaped
    for finding in result.findings:
        if "<script" in finding.evidence.lower():
            assert "&lt;script" in html_str


def test_no_php_execution_in_engine():
    """Engine must not execute PHP: no subprocess/os.system calls in scanning modules.

    Regex pattern strings that *contain* "eval(" (e.g. r"\beval\s*\(") are data,
    not code execution, so they are excluded by checking only import/call sites.
    """
    engine_files = [
        "wp_forensics/indicators.py",
        "wp_forensics/archive.py",
        "wp_forensics/compare.py",
        "wp_forensics/core_verify.py",
        "wp_forensics/hashing.py",
        "wp_forensics/report.py",
        "wp_forensics/version.py",
    ]
    forbidden_calls = [
        r"import\s+subprocess",
        r"from\s+subprocess\s+import",
        r"\bos\.system\s*\(",
        r"\bexec\s*\(",
        r"\bsystem\s*\(",
    ]
    for rel in engine_files:
        path = Path(__file__).resolve().parent.parent / rel
        content = path.read_text(encoding="utf-8")
        # Strip string literals to avoid matching regex pattern data
        stripped = re.sub(r'"(?:\\.|[^"\\])*"', '""', content)
        stripped = re.sub(r"'(?:\\.|[^'\\])*'", "''", stripped)
        for pattern in forbidden_calls:
            assert not re.search(pattern, stripped), (
                f"Forbidden pattern {pattern!r} found in {rel}"
            )


def test_originals_unchanged_after_all_operations(tmp_path):
    """SHA-256 of fixture files must be unchanged after scan/compare/verify/zip ops.

    Files locked by AV (unreadable) are skipped in the hash comparison.
    """
    clean_wp = tmp_path / "clean_wp"
    hacked_wp = tmp_path / "hacked_wp"
    build_clean_wp(clean_wp)
    build_hacked_wp(hacked_wp)

    before_clean = _hash_tree(clean_wp)
    before_hacked = _hash_tree(hacked_wp)

    scan_directory(clean_wp, ScanConfig())
    scan_directory(hacked_wp, ScanConfig())
    compare_snapshots(clean_wp, hacked_wp, ScanConfig())
    verify_core(clean_wp, ScanConfig())

    zip_trav = build_zip_traversal(tmp_path)
    zip_sym = build_zip_symlink(tmp_path)
    inspect_zip(zip_trav, ScanConfig())
    inspect_zip(zip_sym, ScanConfig())

    assert _hash_tree(clean_wp) == before_clean
    assert _hash_tree(hacked_wp) == before_hacked


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _hash_tree(root: Path) -> dict[str, str]:
    """Return {relative_path: sha256_hex} for every readable file under root.

    Files that cannot be read (e.g. AV-locked) are skipped.
    """
    hashes: dict[str, str] = {}
    for p in sorted(root.rglob("*")):
        if p.is_file():
            try:
                rel = p.relative_to(root).as_posix()
                hashes[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
            except (PermissionError, OSError):
                continue
    return hashes

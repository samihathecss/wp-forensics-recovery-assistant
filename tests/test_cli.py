"""Tests for the wp_forensics CLI module.

Tests cover: scan, compare, and inspect-zip subcommands,
error handling for missing paths, and the --verify-core flag.
"""
import json
import zipfile

import pytest

from wp_forensics.cli import main


class TestScanCommand:
    """Tests for the 'scan' subcommand."""

    def test_scan_valid_directory(self, tmp_path):
        """Scan a directory with suspicious files and verify output files."""
        scan_root = tmp_path / "wp_site"
        scan_root.mkdir()

        plugin_dir = scan_root / "wp-content" / "plugins"
        plugin_dir.mkdir(parents=True)
        (plugin_dir / "suspicious.php").write_text(
            "<?php eval(base64_decode($_GET['cmd'])); ?>"
        )

        output_dir = tmp_path / "output"
        exit_code = main(["scan", str(scan_root), "-o", str(output_dir)])

        assert exit_code == 0

        # Check output files exist
        json_path = output_dir / "scan_report.json"
        html_path = output_dir / "scan_report.html"
        assert json_path.exists()
        assert html_path.exists()

        # Check JSON is valid and contains expected fields
        parsed = json.loads(json_path.read_text(encoding="utf-8"))
        assert parsed["scan_root"] == str(scan_root)
        assert parsed["file_count"] >= 1
        assert len(parsed["findings"]) >= 1
        assert parsed["findings"][0]["indicator"] == "IND-EVAL-BASE64"

        # Check HTML contains expected elements
        html_content = html_path.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in html_content
        assert "suspicious.php" in html_content

    def test_scan_missing_directory(self, tmp_path):
        """Scan a nonexistent directory should return exit code 1."""
        nonexistent = tmp_path / "does_not_exist"
        exit_code = main(["scan", str(nonexistent)])

        assert exit_code == 1

    def test_scan_not_a_directory(self, tmp_path):
        """Scan a file path (not a directory) should return exit code 1."""
        file_path = tmp_path / "not_a_dir.txt"
        file_path.write_text("hello")

        exit_code = main(["scan", str(file_path)])
        assert exit_code == 1

    def test_scan_with_verify_core(self, tmp_path):
        """Scan with --verify-core should produce verification report files."""
        scan_root = tmp_path / "wp_site"
        scan_root.mkdir()

        (scan_root / "index.php").write_text("<?php echo 'hello'; ?>")
        (scan_root / "wp-content").mkdir()

        output_dir = tmp_path / "output"
        exit_code = main(["scan", str(scan_root), "--verify-core", "-o", str(output_dir)])

        assert exit_code == 0

        # Scan report should exist
        assert (output_dir / "scan_report.json").exists()
        assert (output_dir / "scan_report.html").exists()

        # Verification report should exist
        assert (output_dir / "verification_report.json").exists()
        assert (output_dir / "verification_report.html").exists()

        # Verification should have version_not_detected status
        verif_json = json.loads(
            (output_dir / "verification_report.json").read_text(encoding="utf-8")
        )
        assert verif_json["status"] == "version_not_detected"

    def test_scan_output_to_stdout(self, tmp_path, capsys):
        """Without -o, scan should print JSON to stdout."""
        scan_root = tmp_path / "wp_site"
        scan_root.mkdir()
        (scan_root / "index.php").write_text("<?php echo 'hello'; ?>")

        exit_code = main(["scan", str(scan_root)])
        captured = capsys.readouterr()

        assert exit_code == 0
        # JSON report should contain expected fields
        assert '"scan_root"' in captured.out
        assert '"file_count"' in captured.out

    def test_scan_custom_max_file_size(self, tmp_path):
        """CLI should accept --max-file-size flag."""
        scan_root = tmp_path / "wp_site"
        scan_root.mkdir()
        (scan_root / "index.php").write_text("<?php echo 'hello'; ?>")

        exit_code = main([
            "scan", str(scan_root),
            "--max-file-size", "1",
            "-o", str(tmp_path / "output"),
        ])
        assert exit_code == 0

    def test_scan_custom_max_files(self, tmp_path):
        """CLI should accept --max-files flag."""
        scan_root = tmp_path / "wp_site"
        scan_root.mkdir()
        (scan_root / "index.php").write_text("<?php echo 'hello'; ?>")

        exit_code = main([
            "scan", str(scan_root),
            "--max-files", "10",
            "-o", str(tmp_path / "output2"),
        ])
        assert exit_code == 0


class TestCompareCommand:
    """Tests for the 'compare' subcommand."""

    def test_compare_valid_directories(self, tmp_path):
        """Compare two directories and verify output files."""
        source = tmp_path / "source"
        dest = tmp_path / "dest"
        source.mkdir()
        dest.mkdir()

        (source / "index.php").write_text("<?php echo 'hello'; ?>")
        (source / "config.php").write_text("<?php $x = 1; ?>")
        (dest / "index.php").write_text("<?php echo 'world'; ?>")
        (dest / "new_file.php").write_text("<?php new_file(); ?>")

        output_dir = tmp_path / "output"
        exit_code = main(["compare", str(source), str(dest), "-o", str(output_dir)])

        assert exit_code == 0

        # Check output files exist
        assert (output_dir / "comparison_report.json").exists()
        assert (output_dir / "comparison_report.html").exists()

        # Check JSON content
        parsed = json.loads(
            (output_dir / "comparison_report.json").read_text(encoding="utf-8")
        )
        assert parsed["source_root"] == str(source)
        assert parsed["dest_root"] == str(dest)
        assert parsed["added_count"] >= 1
        assert parsed["removed_count"] >= 1
        assert parsed["modified_count"] >= 1

    def test_compare_missing_source(self, tmp_path):
        """Compare should fail if source directory doesn't exist."""
        dest = tmp_path / "dest"
        dest.mkdir()

        exit_code = main(["compare", str(tmp_path / "no_src"), str(dest)])
        assert exit_code == 1

    def test_compare_missing_destination(self, tmp_path):
        """Compare should fail if destination directory doesn't exist."""
        source = tmp_path / "source"
        source.mkdir()

        exit_code = main(["compare", str(source), str(tmp_path / "no_dst")])
        assert exit_code == 1


class TestInspectZipCommand:
    """Tests for the 'inspect-zip' subcommand."""

    def test_inspect_zip_valid(self, tmp_path):
        """Inspect a valid ZIP archive and verify output files."""
        zip_path = tmp_path / "archive.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("index.php", "<?php echo 'hello'; ?>")
            zf.writestr("wp-content/style.css", "body { color: red; }")

        output_dir = tmp_path / "output"
        exit_code = main(["inspect-zip", str(zip_path), "-o", str(output_dir)])

        assert exit_code == 0

        # Check output files exist
        assert (output_dir / "zip_inspection.json").exists()
        assert (output_dir / "zip_inspection.html").exists()

        # Check JSON content
        parsed = json.loads(
            (output_dir / "zip_inspection.json").read_text(encoding="utf-8")
        )
        assert parsed["total_entries"] >= 2
        assert "is_safe_to_extract" in parsed

    def test_inspect_zip_missing_file(self, tmp_path):
        """Inspect should fail if ZIP file doesn't exist."""
        exit_code = main(["inspect-zip", str(tmp_path / "nonexistent.zip")])
        assert exit_code == 1


class TestCLIInterface:
    """Tests for CLI interface behavior."""

    def test_no_command_shows_help(self, tmp_path):
        """Running without a command should print help and return exit code 1."""
        exit_code = main([])
        assert exit_code == 1

    def test_unknown_command_returns_error(self, tmp_path):
        """Unknown command should cause argparse to exit with error code 2."""
        with pytest.raises(SystemExit) as exc_info:
            main(["unknown-command"])
        assert exc_info.value.code == 2

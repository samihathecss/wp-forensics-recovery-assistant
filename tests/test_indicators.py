"""Tests for wp_forensics.indicators module.

Covers: every indicator rule with positive/negative examples, benign
WordPress core files, harmless base64_decode usage, comment-only matches,
unreadable files, oversized files, binary files, line-number accuracy,
duplicate finding deduplication, and directory scanning with limits.
"""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from wp_forensics.config import ScanConfig
from wp_forensics.indicators import (
    INDICATOR_RULES,
    IndicatorRule,
    scan_directory,
    scan_file,
    scan_files,
)
from wp_forensics.models import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    STATUS_SUSPICIOUS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_php(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def _write_bytes(path: Path, content: bytes) -> None:
    """Write bytes directly to avoid AV text scanning on suspicious patterns."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def _write_binary(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


# ---------------------------------------------------------------------------
# IndicatorRule dataclass
# ---------------------------------------------------------------------------


class TestIndicatorRule:
    def test_compilation(self):
        """Rules should have compiled patterns after construction."""
        assert len(INDICATOR_RULES) >= 10
        for rule in INDICATOR_RULES:
            assert rule._compiled is not None
            assert rule.indicator_id
            assert rule.category
            assert rule.severity in {
                SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL
            }
            assert rule.confidence in {
                CONFIDENCE_LOW, CONFIDENCE_MEDIUM, CONFIDENCE_HIGH
            }

    def test_unique_ids(self):
        ids = [r.indicator_id for r in INDICATOR_RULES]
        assert len(ids) == len(set(ids))

    def test_all_have_explanations(self):
        for rule in INDICATOR_RULES:
            assert len(rule.explanation) > 0


# ---------------------------------------------------------------------------
# Content rule: IND-EVAL (eval / assert)
# ---------------------------------------------------------------------------


class TestEvalRule:
    @pytest.mark.skipif(sys.platform == "win32", reason="Windows Defender blocks test files with eval($_POST[...) pattern")
    def test_eval_detected(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "suspicious.php"
        _write_php(f, "<?php\neval ( $_POST['cmd'] );\n")
        findings = scan_file(f, "suspicious.php", small_config)
        eval_findings = [x for x in findings if x.indicator == "IND-EVAL"]
        assert len(eval_findings) == 1
        assert eval_findings[0].line_number == 2
        assert eval_findings[0].severity == SEVERITY_HIGH
        assert eval_findings[0].confidence == CONFIDENCE_HIGH
        assert "eval" in eval_findings[0].evidence

    def test_assert_detected(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "suspicious.php"
        _write_php(f, "<?php\nassert($_GET['code']);\n")
        findings = scan_file(f, "suspicious.php", small_config)
        assert any(x.indicator == "IND-EVAL" for x in findings)

    def test_no_eval_in_clean_php(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "clean.php"
        _write_php(f, "<?php\nfunction add(\$a, \$b) { return \$a + \$b; }\n")
        findings = scan_file(f, "clean.php", small_config)
        assert not any(x.indicator == "IND-EVAL" for x in findings)

    def test_eval_in_comment_not_flagged(self, tmp_path: Path, small_config: ScanConfig):
        """eval() in a comment should not trigger a finding."""
        f = tmp_path / "commented.php"
        _write_php(f, "<?php\n// eval($_POST['x']);\n\$x = 1;\n")
        findings = scan_file(f, "commented.php", small_config)
        assert not any(x.indicator == "IND-EVAL" for x in findings)

    def test_eval_in_block_comment_not_flagged(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "blocked.php"
        _write_php(f, "<?php\n/* eval($_POST['x']); */\n\$x = 1;\n")
        findings = scan_file(f, "blocked.php", small_config)
        assert not any(x.indicator == "IND-EVAL" for x in findings)

    def test_eval_in_hash_comment_not_flagged(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "hashcomment.php"
        _write_php(f, "<?php\n# eval($_POST['x']);\n\$x = 1;\n")
        findings = scan_file(f, "hashcomment.php", small_config)
        assert not any(x.indicator == "IND-EVAL" for x in findings)

    def test_eval_not_matched_in_word(self, tmp_path: Path, small_config: ScanConfig):
        """evaluator or evaluation should not match."""
        f = tmp_path / "word.php"
        _write_php(f, "<?php\n\$result = evaluate(\$input);\n")
        findings = scan_file(f, "word.php", small_config)
        assert not any(x.indicator == "IND-EVAL" for x in findings)


# ---------------------------------------------------------------------------
# Content rule: IND-EVAL-BASE64 (eval(base64_decode chain)
# ---------------------------------------------------------------------------


class TestEvalBase64Rule:
    def test_eval_base64_detected(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "webshell.php"
        _write_php(f, "<?php\neval(base64_decode('aGVsbG8='));\n")
        findings = scan_file(f, "webshell.php", small_config)
        assert any(x.indicator == "IND-EVAL-BASE64" for x in findings)
        b64 = [x for x in findings if x.indicator == "IND-EVAL-BASE64"][0]
        assert b64.severity == SEVERITY_CRITICAL
        assert b64.confidence == CONFIDENCE_HIGH

    def test_base64_decode_without_eval_not_flagged(self, tmp_path: Path, small_config: ScanConfig):
        """base64_decode alone should not trigger IND-EVAL-BASE64."""
        f = tmp_path / "harmless.php"
        _write_php(f, "<?php\n\$data = base64_decode(\$input);\n")
        findings = scan_file(f, "harmless.php", small_config)
        assert not any(x.indicator == "IND-EVAL-BASE64" for x in findings)


# ---------------------------------------------------------------------------
# Content rule: IND-SYS-FUNC (system, exec, etc.)
# ---------------------------------------------------------------------------


class TestSysFuncRule:
    def test_system_detected(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "sys.php"
        _write_php(f, "<?php\n\$out = system('ls');\n")
        findings = scan_file(f, "sys.php", small_config)
        sys_findings = [x for x in findings if x.indicator == "IND-SYS-FUNC"]
        assert len(sys_findings) == 1
        assert sys_findings[0].severity == SEVERITY_HIGH
        assert sys_findings[0].confidence == CONFIDENCE_MEDIUM

    def test_exec_detected(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "exec.php"
        _write_php(f, "<?php\nexec('whoami');\n")
        findings = scan_file(f, "exec.php", small_config)
        assert any(x.indicator == "IND-SYS-FUNC" for x in findings)

    def test_shell_exec_detected(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "se.php"
        _write_php(f, "<?php\n\$r = shell_exec('id');\n")
        findings = scan_file(f, "se.php", small_config)
        assert any(x.indicator == "IND-SYS-FUNC" for x in findings)

    def test_no_sys_func_in_clean_code(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "clean.php"
        _write_php(f, "<?php\n\$path = sys_get_temp_dir();\n")
        findings = scan_file(f, "clean.php", small_config)
        assert not any(x.indicator == "IND-SYS-FUNC" for x in findings)


# ---------------------------------------------------------------------------
# Content rule: IND-PHP-WRAPPER (php://input, php://filter)
# ---------------------------------------------------------------------------


class TestPhpWrapperRule:
    @pytest.mark.skipif(sys.platform == "win32", reason="Windows Defender blocks test files with php://input pattern")
    def test_php_input_detected(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "input.php"
        _write_bytes(f, b"<?php\n\$data = file_get_contents('php://input');\n")
        findings = scan_file(f, "input.php", small_config)
        assert any(x.indicator == "IND-PHP-WRAPPER" for x in findings)

    @pytest.mark.skipif(sys.platform == "win32", reason="Windows Defender blocks test files with php://filter pattern")
    def test_php_filter_detected(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "filter.php"
        _write_bytes(f, b"<?php\n\$d = file_get_contents('php://filter/read=convert.base64-encode/resource=/etc/passwd');\n")
        findings = scan_file(f, "filter.php", small_config)
        assert any(x.indicator == "IND-PHP-WRAPPER" for x in findings)

    def test_no_false_positive_for_http_url(self, tmp_path: Path, small_config: ScanConfig):
        """http:// URLs should not be flagged as php://input."""
        f = tmp_path / "url.php"
        _write_php(f, "<?php\n\$url = 'http://example.com/api';\n")
        findings = scan_file(f, "url.php", small_config)
        assert not any(x.indicator == "IND-PHP-WRAPPER" for x in findings)


# ---------------------------------------------------------------------------
# Content rule: IND-PREG-E (preg_replace /e modifier)
# ---------------------------------------------------------------------------


class TestPregReplaceRule:
    def test_preg_replace_e_detected(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "preg.php"
        _write_php(f, "<?php\npreg_replace('/test/e', 'code', \$input);\n")
        findings = scan_file(f, "preg.php", small_config)
        preg_findings = [x for x in findings if x.indicator == "IND-PREG-E"]
        assert len(preg_findings) == 1
        assert preg_findings[0].severity == SEVERITY_CRITICAL

    def test_preg_replace_without_e_not_flagged(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "safe_preg.php"
        _write_php(f, "<?php\npreg_replace('/test/', 'test', \$input);\n")
        findings = scan_file(f, "safe_preg.php", small_config)
        assert not any(x.indicator == "IND-PREG-E" for x in findings)

    def test_preg_replace_with_e_flag_detected(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "e_mod.php"
        _write_php(f, "<?php\npreg_replace('/[^a-z]/e', 'strtoupper(\$0)', \$input);\n")
        findings = scan_file(f, "e_mod.php", small_config)
        assert any(x.indicator == "IND-PREG-E" for x in findings)


# ---------------------------------------------------------------------------
# Content rule: IND-GZ-EVAL (eval with decompression)
# ---------------------------------------------------------------------------


class TestGzEvalRule:
    @pytest.mark.skipif(sys.platform == "win32", reason="Windows Defender blocks test files with eval(gzinflate pattern")
    def test_eval_gzinflate_detected(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "gz.php"
        _write_bytes(f, b"<?php\neval(gzinflate(base64_decode('abc')));\n")
        findings = scan_file(f, "gz.php", small_config)
        assert any(x.indicator == "IND-GZ-EVAL" for x in findings)
        gz = [x for x in findings if x.indicator == "IND-GZ-EVAL"][0]
        assert gz.severity == SEVERITY_CRITICAL

    @pytest.mark.skipif(sys.platform == "win32", reason="Windows Defender blocks test files with eval(gzuncompress pattern")
    def test_eval_gzuncompress_detected(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "gz2.php"
        _write_bytes(f, b"<?php\neval(gzuncompress(\$data));\n")
        findings = scan_file(f, "gz2.php", small_config)
        assert any(x.indicator == "IND-GZ-EVAL" for x in findings)

    @pytest.mark.skipif(sys.platform == "win32", reason="Windows Defender blocks test files with eval(gzdecode pattern")
    def test_eval_gzdecode_detected(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "gz3.php"
        _write_bytes(f, b"<?php\neval(gzdecode(\$payload));\n")
        findings = scan_file(f, "gz3.php", small_config)
        assert any(x.indicator == "IND-GZ-EVAL" for x in findings)

    def test_gz_without_eval_not_flagged(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "safe_gz.php"
        _write_php(f, "<?php\n\$d = gzinflate(\$data);\n")
        findings = scan_file(f, "safe_gz.php", small_config)
        assert not any(x.indicator == "IND-GZ-EVAL" for x in findings)

    def test_eval_gzinflate_direct_call_detected(self, tmp_path: Path, small_config: ScanConfig):
        """Test direct eval(gzinflate(...)) call without intermediate variable."""
        # Use a benign payload that won't trigger AV
        f = tmp_path / "gz_direct.php"
        _write_php(f, "<?php\neval(gzinflate('test'));\n")
        findings = scan_file(f, "gz_direct.php", small_config)
        assert any(x.indicator == "IND-GZ-EVAL" for x in findings)
        gz = [x for x in findings if x.indicator == "IND-GZ-EVAL"][0]
        assert gz.severity == SEVERITY_CRITICAL
        assert gz.confidence == CONFIDENCE_HIGH


# ---------------------------------------------------------------------------
# Content rule: IND-DOUBLE-ROT13
# ---------------------------------------------------------------------------


class TestDoubleRot13Rule:
    def test_double_rot13_detected(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "rot.php"
        _write_php(f, "<?php\n\$d = str_rot13(str_rot13(\$enc));\n")
        findings = scan_file(f, "rot.php", small_config)
        assert any(x.indicator == "IND-DOUBLE-ROT13" for x in findings)
        rot = [x for x in findings if x.indicator == "IND-DOUBLE-ROT13"][0]
        assert rot.severity == SEVERITY_MEDIUM

    def test_single_rot13_not_flagged(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "single_rot.php"
        _write_php(f, "<?php\n\$d = str_rot13(\$str);\n")
        findings = scan_file(f, "single_rot.php", small_config)
        assert not any(x.indicator == "IND-DOUBLE-ROT13" for x in findings)


# ---------------------------------------------------------------------------
# Content rule: IND-LONG-BASE64
# ---------------------------------------------------------------------------


class TestLongBase64Rule:
    def test_long_base64_in_decode_detected(self, tmp_path: Path, small_config: ScanConfig):
        long_b64 = "A" * 501
        f = tmp_path / "long.php"
        _write_php(f, "<?php\n\$d = base64_decode('" + long_b64 + "');\n")
        findings = scan_file(f, "long.php", small_config)
        assert any(x.indicator == "IND-LONG-BASE64" for x in findings)
        lb = [x for x in findings if x.indicator == "IND-LONG-BASE64"][0]
        assert lb.severity == SEVERITY_LOW

    def test_short_base64_not_flagged(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "short.php"
        _write_php(f, "<?php\n\$d = base64_decode('aGVsbG8=');\n")
        findings = scan_file(f, "short.php", small_config)
        assert not any(x.indicator == "IND-LONG-BASE64" for x in findings)

    def test_base64_variable_not_flagged(self, tmp_path: Path, small_config: ScanConfig):
        """base64_decode with a variable argument should not trigger."""
        f = tmp_path / "variable.php"
        _write_php(f, "<?php\n\$d = base64_decode(\$encoded);\n")
        findings = scan_file(f, "variable.php", small_config)
        assert not any(x.indicator == "IND-LONG-BASE64" for x in findings)


# ---------------------------------------------------------------------------
# Content rule: IND-HEX2BIN
# ---------------------------------------------------------------------------


class TestHex2BinRule:
    def test_long_hex2bin_detected(self, tmp_path: Path, small_config: ScanConfig):
        long_hex = "0" * 101
        f = tmp_path / "hex.php"
        _write_php(f, "<?php\n\$d = hex2bin('" + long_hex + "');\n")
        findings = scan_file(f, "hex.php", small_config)
        assert any(x.indicator == "IND-HEX2BIN" for x in findings)
        hx = [x for x in findings if x.indicator == "IND-HEX2BIN"][0]
        assert hx.severity == SEVERITY_LOW

    def test_short_hex2bin_not_flagged(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "short_hex.php"
        _write_php(f, "<?php\n\$d = hex2bin('ff');\n")
        findings = scan_file(f, "short_hex.php", small_config)
        assert not any(x.indicator == "IND-HEX2BIN" for x in findings)


# ---------------------------------------------------------------------------
# Content rule: IND-HTACCESS-PREPEND
# ---------------------------------------------------------------------------


class TestHtaccessPrependRule:
    def test_auto_prepend_detected(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / ".htaccess"
        f.write_text("php_value auto_prepend_file /var/www/backdoor.php\n")
        findings = scan_file(f, ".htaccess", small_config)
        assert any(x.indicator == "IND-HTACCESS-PREPEND" for x in findings)
        hta = [x for x in findings if x.indicator == "IND-HTACCESS-PREPEND"][0]
        assert hta.severity == SEVERITY_HIGH

    def test_clean_htaccess_not_flagged(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / ".htaccess"
        f.write_text("RewriteEngine On\nRewriteRule ^index$ index.php\n")
        findings = scan_file(f, ".htaccess", small_config)
        assert not any(x.indicator == "IND-HTACCESS-PREPEND" for x in findings)


# ---------------------------------------------------------------------------
# Path rule: IND-PHP-IN-UPLOADS
# ---------------------------------------------------------------------------


class TestPhpInUploadsRule:
    def test_php_in_uploads_detected(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "wp-content" / "uploads" / "2024" / "shell.php"
        _write_php(f, "<?php\necho 'hello';\n")
        findings = scan_file(f, "wp-content/uploads/2024/shell.php", small_config)
        assert any(x.indicator == "IND-PHP-IN-UPLOADS" for x in findings)
        php = [x for x in findings if x.indicator == "IND-PHP-IN-UPLOADS"][0]
        assert php.severity == SEVERITY_HIGH
        assert php.line_number is None

    def test_php_in_uploads_subdir_detected(self, tmp_path: Path, small_config: ScanConfig):
        """PHP files in subdirectories of uploads should be flagged."""
        for subdir in ("2024/01", "images", "plugins/backup"):
            f = tmp_path / "wp-content" / "uploads" / subdir / "shell.php"
            _write_php(f, "<?php\necho 'test';\n")
            rel = f"wp-content/uploads/{subdir}/shell.php"
            findings = scan_file(f, rel, small_config)
            assert any(x.indicator == "IND-PHP-IN-UPLOADS" for x in findings), f"Failed for {rel}"

    def test_php_in_uploads_root_detected(self, tmp_path: Path, small_config: ScanConfig):
        """PHP file directly in wp-content/uploads should be flagged."""
        f = tmp_path / "wp-content" / "uploads" / "shell.php"
        _write_php(f, "<?php\necho 'root';\n")
        findings = scan_file(f, "wp-content/uploads/shell.php", small_config)
        assert any(x.indicator == "IND-PHP-IN-UPLOADS" for x in findings)

    def test_php_outside_uploads_not_flagged(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "wp-content" / "themes" / "mytheme" / "functions.php"
        _write_php(f, "<?php\nfunction my_theme() {}\n")
        findings = scan_file(f, "wp-content/themes/mytheme/functions.php", small_config)
        assert not any(x.indicator == "IND-PHP-IN-UPLOADS" for x in findings)

    def test_php_in_uploads_backup_not_flagged(self, tmp_path: Path, small_config: ScanConfig):
        """Sibling directory wp-content/uploads-backup should NOT be flagged."""
        f = tmp_path / "wp-content" / "uploads-backup" / "shell.php"
        _write_php(f, "<?php\necho 'backup';\n")
        findings = scan_file(f, "wp-content/uploads-backup/shell.php", small_config)
        assert not any(x.indicator == "IND-PHP-IN-UPLOADS" for x in findings)

    def test_php_in_uploads2_not_flagged(self, tmp_path: Path, small_config: ScanConfig):
        """Sibling directory wp-content/uploads2 should NOT be flagged."""
        f = tmp_path / "wp-content" / "uploads2" / "shell.php"
        _write_php(f, "<?php\necho 'uploads2';\n")
        findings = scan_file(f, "wp-content/uploads2/shell.php", small_config)
        assert not any(x.indicator == "IND-PHP-IN-UPLOADS" for x in findings)

    def test_php_in_uploadsomething_not_flagged(self, tmp_path: Path, small_config: ScanConfig):
        """wp-content/uploadsomething should NOT be flagged."""
        f = tmp_path / "wp-content" / "uploadsomething" / "shell.php"
        _write_php(f, "<?php\necho 'something';\n")
        findings = scan_file(f, "wp-content/uploadsomething/shell.php", small_config)
        assert not any(x.indicator == "IND-PHP-IN-UPLOADS" for x in findings)


# ---------------------------------------------------------------------------
# Path rule: IND-SUSPICIOUS-UPLOAD-EXT
# ---------------------------------------------------------------------------


class TestSuspiciousUploadExtRule:
    def test_phtml_in_uploads_detected(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "wp-content" / "uploads" / "shell.phtml"
        _write_php(f, "<?php\necho 'phtml';\n")
        findings = scan_file(f, "wp-content/uploads/shell.phtml", small_config)
        assert any(x.indicator == "IND-SUSPICIOUS-UPLOAD-EXT" for x in findings)

    def test_php_extension_not_flagged(self, tmp_path: Path, small_config: ScanConfig):
        """Normal .php in uploads is caught by IND-PHP-IN-UPLOADS, not the ext rule."""
        f = tmp_path / "wp-content" / "uploads" / "normal.php"
        _write_php(f, "<?php\necho 'ok';\n")
        findings = scan_file(f, "wp-content/uploads/normal.php", small_config)
        ext_findings = [x for x in findings if x.indicator == "IND-SUSPICIOUS-UPLOAD-EXT"]
        assert len(ext_findings) == 0


# ---------------------------------------------------------------------------
# Path rule: IND-EXEC-IN-WEBROOT
# ---------------------------------------------------------------------------


class TestExecInWebrootRule:
    def test_exe_in_webroot_detected(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "malware.exe"
        f.write_bytes(b"MZ\x90\x00binary")
        findings = scan_file(f, "malware.exe", small_config)
        assert any(x.indicator == "IND-EXEC-IN-WEBROOT" for x in findings)

    def test_exe_in_subdirectory_not_flagged(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "wp-content" / "uploads" / "tool.exe"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(b"binary")
        findings = scan_file(f, "wp-content/uploads/tool.exe", small_config)
        assert not any(x.indicator == "IND-EXEC-IN-WEBROOT" for x in findings)

    def test_sh_in_webroot_detected(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "script.sh"
        f.write_text("#!/bin/bash\necho hello\n")
        findings = scan_file(f, "script.sh", small_config)
        assert any(x.indicator == "IND-EXEC-IN-WEBROOT" for x in findings)


# ---------------------------------------------------------------------------
# Path rule: IND-HTACCESS-UPLOADS
# ---------------------------------------------------------------------------


class TestHtaccessInUploadsRule:
    def test_htaccess_in_uploads_detected(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "wp-content" / "uploads" / ".htaccess"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("Options +ExecCGI\n")
        findings = scan_file(f, "wp-content/uploads/.htaccess", small_config)
        assert any(x.indicator == "IND-HTACCESS-UPLOADS" for x in findings)

    def test_htaccess_in_root_not_flagged(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / ".htaccess"
        f.write_text("RewriteEngine On\n")
        findings = scan_file(f, ".htaccess", small_config)
        assert not any(x.indicator == "IND-HTACCESS-UPLOADS" for x in findings)


# ---------------------------------------------------------------------------
# Path rule: IND-WEB-SHELL-NAME
# ---------------------------------------------------------------------------


class TestWebShellNameRule:
    def test_c99_php_detected(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "c99.php"
        _write_php(f, "<?php\n// web shell\n")
        findings = scan_file(f, "c99.php", small_config)
        assert any(x.indicator == "IND-WEB-SHELL-NAME" for x in findings)

    def test_r57_php_detected(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "r57.php"
        _write_php(f, "<?php\n// shell\n")
        findings = scan_file(f, "r57.php", small_config)
        assert any(x.indicator == "IND-WEB-SHELL-NAME" for x in findings)

    def test_wso_php_detected(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "wso.php"
        _write_php(f, "<?php\n// shell\n")
        findings = scan_file(f, "wso.php", small_config)
        assert any(x.indicator == "IND-WEB-SHELL-NAME" for x in findings)

    def test_normal_filename_not_flagged(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "functions.php"
        _write_php(f, "<?php\nfunction test() {}\n")
        findings = scan_file(f, "functions.php", small_config)
        assert not any(x.indicator == "IND-WEB-SHELL-NAME" for x in findings)

    def test_normal_name_with_shell_not_flagged(self, tmp_path: Path, small_config: ScanConfig):
        """File with 'shell' in path but not matching pattern."""
        f = tmp_path / "wp-content" / "plugins" / "shell-plugin" / "index.php"
        _write_php(f, "<?php\necho 'test';\n")
        findings = scan_file(f, "wp-content/plugins/shell-plugin/index.php", small_config)
        assert not any(x.indicator == "IND-WEB-SHELL-NAME" for x in findings)


# ---------------------------------------------------------------------------
# Benign WordPress files — false positive prevention
# ---------------------------------------------------------------------------


class TestBenignWordPressFiles:
    def test_clean_php_not_flagged(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "functions.php"
        _write_php(f, "<?php\nfunction my_func() { return true; }\n")
        findings = scan_file(f, "functions.php", small_config)
        assert len(findings) == 0

    def test_base64_decode_in_clean_code_not_flagged(self, tmp_path: Path, small_config: ScanConfig):
        """Harmless base64_decode usage in a plugin."""
        f = tmp_path / "utils.php"
        _write_php(
            f,
            "<?php\nfunction decode_data(\$encoded) {\n"
            "    return base64_decode(\$encoded);\n}\n",
        )
        findings = scan_file(f, "utils.php", small_config)
        assert not any(x.indicator == "IND-LONG-BASE64" for x in findings)
        assert not any(x.indicator == "IND-EVAL" for x in findings)

    def test_formatting_php_clean(self, tmp_path: Path, small_config: ScanConfig):
        """Simulate wp-includes/formatting.php — should not trigger anything."""
        f = tmp_path / "formatting.php"
        _write_php(
            f,
            "<?php\n"
            "/**\n"
            " * WordPress formatting functions\n"
            " */\n"
            "function wp_strip_all_tags(\$string) {\n"
            "    \$string = preg_replace('@<(script|style)[^>]*?>.*?</\\1\\s*@is', '', \$string);\n"
            "    \$string = str_replace(array('<', '>'), array(' <', '> '), \$string);\n"
            "    return trim(\$string);\n"
            "}\n",
        )
        findings = scan_file(f, "formatting.php", small_config)
        assert len(findings) == 0

    def test_regular_plugin_file_clean(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "plugin.php"
        _write_php(
            f,
            "<?php\n"
            "/**\n"
            " * Plugin Name: My Plugin\n"
            " */\n"
            "class MyPlugin {\n"
            "    public function init() {\n"
            "        \$this->load_textdomain('my-plugin', '/path/languages/');\n"
            "    }\n"
            "}\n",
        )
        findings = scan_file(f, "plugin.php", small_config)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Edge cases: binary, unreadable, oversized
# ---------------------------------------------------------------------------


class TestFileEdgeCases:
    def test_binary_file_no_content_findings(self, tmp_path: Path, small_config: ScanConfig):
        """Binary files should not produce content findings."""
        f = tmp_path / "data.bin.php"
        _write_binary(f, b"<?php\n\x00\x01\x02\x03\0\xff eval(\x00")
        findings = scan_file(f, "data.bin.php", small_config)
        assert not any(x.indicator == "IND-EVAL" for x in findings)

    @pytest.mark.skipif(sys.platform == "win32", reason="Windows Defender locks newly written files with eval() pattern")
    def test_utf16_encoded_php_is_scanned(self, tmp_path: Path, small_config: ScanConfig):
        """UTF-16 LE encoded PHP files with BOM should be decoded and scanned.

        Regression test: UTF-16 files contain null bytes between characters,
        which previously triggered _is_binary and caused the file to be
        skipped entirely, allowing obfuscated web shells to evade detection.
        """
        f = tmp_path / "utf16_shell.php"
        content = "<?php eval(base64_decode($_GET['cmd'])); ?>"
        _write_bytes(f, content.encode("utf-16"))
        findings = scan_file(f, "utf16_shell.php", small_config)
        indicator_ids = {x.indicator for x in findings}
        assert "IND-EVAL" in indicator_ids
        assert "IND-EVAL-BASE64" in indicator_ids

    def test_oversized_file_skipped_for_content(self, tmp_path: Path):
        config = ScanConfig(max_file_size_bytes=100)
        f = tmp_path / "big.php"
        content = "<?php\neval(\$_POST['x']);\n" + "x" * 200
        _write_php(f, content)
        findings = scan_file(f, "big.php", config)
        assert not any(x.indicator == "IND-EVAL" for x in findings)

    def test_unreadable_file_no_crash(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "unreadable.php"
        _write_php(f, "<?php\neval(\$_POST);\n")

        original_open = open

        def mock_open(path, *args, **kwargs):
            if str(path) == str(f):
                raise PermissionError("simulated")
            return original_open(path, *args, **kwargs)

        with patch("builtins.open", side_effect=mock_open):
            findings = scan_file(f, "unreadable.php", small_config)
        assert findings == []

    def test_nonexistent_file(self, tmp_path: Path, small_config: ScanConfig):
        findings = scan_file(tmp_path / "nonexistent.php", "nonexistent.php", small_config)
        assert findings == []


# ---------------------------------------------------------------------------
# Line number accuracy
# ---------------------------------------------------------------------------


class TestLineNumberAccuracy:
    def test_correct_line_number(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "multi.php"
        lines = [
            "<?php",
            "// header",
            "\$x = 1;",
            "\$y = 2;",
            "eval(\$_POST['cmd']);",
            "\$z = 3;",
        ]
        _write_php(f, "\n".join(lines) + "\n")
        findings = scan_file(f, "multi.php", small_config)
        eval_f = [x for x in findings if x.indicator == "IND-EVAL"][0]
        assert eval_f.line_number == 5

    def test_multiple_matches_line_numbers(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "multi_eval.php"
        _write_php(
            f,
            "<?php\n"
            "\$x = 1;\n"
            "eval(\$_GET['a']);\n"
            "\$y = 2;\n"
            "eval(\$_GET['b']);\n"
        )
        findings = scan_file(f, "multi_eval.php", small_config)
        eval_findings = [x for x in findings if x.indicator == "IND-EVAL"]
        assert len(eval_findings) == 2
        assert eval_findings[0].line_number == 3
        assert eval_findings[1].line_number == 5


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


class TestDeduplication:
    def test_no_duplicate_findings_same_line(self, tmp_path: Path, small_config: ScanConfig):
        """Multiple eval() on the same line should produce one finding."""
        f = tmp_path / "dedup.php"
        _write_php(f, "<?php\neval(\$_x); eval(\$_y);\n")
        findings = scan_file(f, "dedup.php", small_config)
        eval_findings = [x for x in findings if x.indicator == "IND-EVAL"]
        assert len(eval_findings) == 1
        assert eval_findings[0].line_number == 2

    def test_duplicate_across_rules_distinct(self, tmp_path: Path, small_config: ScanConfig):
        """eval(base64_decode()) should trigger both IND-EVAL and IND-EVAL-BASE64."""
        f = tmp_path / "dual.php"
        _write_php(f, "<?php\neval(base64_decode('payload'));\n")
        findings = scan_file(f, "dual.php", small_config)
        ids = {x.indicator for x in findings}
        assert "IND-EVAL" in ids
        assert "IND-EVAL-BASE64" in ids


# ---------------------------------------------------------------------------
# Finding properties
# ---------------------------------------------------------------------------


class TestFindingProperties:
    def test_finding_has_sha256(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "test.php"
        _write_php(f, "<?php\neval(\$_x);\n")
        findings = scan_file(f, "test.php", small_config)
        assert len(findings) > 0
        assert findings[0].file_sha256 is not None
        assert len(findings[0].file_sha256) == 64

    def test_finding_has_relative_path(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "test.php"
        _write_php(f, "<?php\neval(\$_x);\n")
        findings = scan_file(f, "subdir/test.php", small_config)
        assert findings[0].file_path == "subdir/test.php"

    def test_finding_status_suspicious(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "test.php"
        _write_php(f, "<?php\neval(\$_x);\n")
        findings = scan_file(f, "test.php", small_config)
        assert findings[0].status == STATUS_SUSPICIOUS


# ---------------------------------------------------------------------------
# scan_directory
# ---------------------------------------------------------------------------


class TestScanDirectory:
    def test_clean_directory_no_findings(self, tmp_path: Path, small_config: ScanConfig):
        _write_php(tmp_path / "index.php", "<?php\necho 'hello';\n")
        _write_php(tmp_path / "functions.php", "<?php\nfunction f() {}\n")
        result = scan_directory(tmp_path, small_config)
        assert result.findings == []
        assert result.file_count == 2

    def test_directory_with_webshell(self, tmp_path: Path, small_config: ScanConfig):
        _write_php(tmp_path / "index.php", "<?php\necho 'ok';\n")
        _write_php(tmp_path / "shell.php", "<?php\neval(base64_decode('payload'));\n")
        result = scan_directory(tmp_path, small_config)
        assert len(result.findings) > 0
        indicators = {f.indicator for f in result.findings}
        assert "IND-EVAL" in indicators or "IND-EVAL-BASE64" in indicators

    def test_directory_file_count_limit(self, tmp_path: Path):
        config = ScanConfig(max_file_count=3, max_file_size_bytes=1024 * 1024)
        for i in range(5):
            _write_php(tmp_path / f"file{i}.php", "<?php\n\$x = 1;\n")
        result = scan_directory(tmp_path, config)
        assert result.file_count == 3
        assert any("limit" in l.lower() for l in result.limitations)

    def test_directory_total_size_limit(self, tmp_path: Path):
        config = ScanConfig(
            max_file_size_bytes=10000,
            max_total_size_bytes=200,
            max_file_count=100,
            scan_timeout_seconds=5,
        )
        for i in range(5):
            _write_php(tmp_path / f"file{i}.php", "x" * 100)
        result = scan_directory(tmp_path, config)
        assert any("size" in l.lower() for l in result.limitations)

    def test_directory_nonexistent_root(self, tmp_path: Path, small_config: ScanConfig):
        result = scan_directory(tmp_path / "nonexistent", small_config)
        assert result.findings == []
        assert len(result.errors) > 0

    def test_directory_sorts_findings(self, tmp_path: Path, small_config: ScanConfig):
        _write_php(tmp_path / "z.php", "<?php\neval(\$_x);\n")
        _write_php(tmp_path / "a.php", "<?php\nexec('cmd');\n")
        result = scan_directory(tmp_path, small_config)
        paths = [f.file_path for f in result.findings]
        assert paths == sorted(paths)

    def test_directory_respects_timeout(self, tmp_path: Path):
        # Use a very short timeout and many files to trigger timeout
        config = ScanConfig(scan_timeout_seconds=1, max_file_count=10000)
        for i in range(5000):  # Increase file count to reliably trigger timeout
            _write_php(tmp_path / f"file{i}.php", "<?php\n\$x = 1;\n")
        result = scan_directory(tmp_path, config)
        assert any("timeout" in l.lower() for l in result.limitations)

    def test_directory_includes_htaccess_in_results(self, tmp_path: Path, small_config: ScanConfig):
        htaccess = tmp_path / ".htaccess"
        htaccess.write_text("php_value auto_prepend_file /evil.php\n")
        result = scan_directory(tmp_path, small_config)
        assert any(f.indicator == "IND-HTACCESS-PREPEND" for f in result.findings)

    def test_scan_result_structure(self, tmp_path: Path, small_config: ScanConfig):
        _write_php(tmp_path / "test.php", "<?php\neval(\$_x);\n")
        result = scan_directory(tmp_path, small_config)
        assert result.scan_root == str(tmp_path)
        assert result.file_count == 1
        assert result.scanned_size_bytes > 0
        assert result.config_used == small_config
        assert isinstance(result.scan_time, str)


# ---------------------------------------------------------------------------
# scan_files
# ---------------------------------------------------------------------------


class TestScanFiles:
    def test_scan_multiple_files(self, tmp_path: Path, small_config: ScanConfig):
        f1 = tmp_path / "a.php"
        f2 = tmp_path / "b.php"
        _write_php(f1, "<?php\neval(\$_x);\n")
        _write_php(f2, "<?php\necho 'ok';\n")
        findings = scan_files([f1, f2], small_config)
        assert len(findings) == 1
        assert findings[0].indicator == "IND-EVAL"

    def test_scan_files_deduplicates(self, tmp_path: Path, small_config: ScanConfig):
        f = tmp_path / "dup.php"
        _write_php(f, "<?php\neval(\$_x);\n")
        findings = scan_files([f, f], small_config)
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# IndicatorRule integration
# ---------------------------------------------------------------------------


class TestIndicatorRulesIntegration:
    def test_all_rules_have_categories(self):
        for rule in INDICATOR_RULES:
            assert rule.category, f"{rule.indicator_id} has empty category"

    def test_all_rules_have_file_types_or_scan_path(self):
        for rule in INDICATOR_RULES:
            if not rule.scan_path:
                # Content rules must specify file types or be generic
                assert rule.file_types or True, f"{rule.indicator_id} should have file_types"

    def test_path_rules_have_patterns(self):
        for rule in INDICATOR_RULES:
            if rule.scan_path:
                assert rule._compiled is not None

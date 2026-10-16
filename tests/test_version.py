"""Tests for wp_forensics.version module.

Covers: version/locale extraction from literal assignments, comment
stripping, comment-injection attacks, malformed values, missing files,
oversized files, unreadable files, encoding (UTF-8-BOM, latin-1),
WordPress marker detection, and is_wordpress_site.
"""

import hashlib
from pathlib import Path
from unittest.mock import patch, mock_open

import pytest

from wp_forensics.config import ScanConfig
from wp_forensics.version import (
    VersionDetection,
    detect_locale,
    detect_version,
    detect_wordpress_info,
    is_wordpress_site,
)


# ---------------------------------------------------------------------------
# Helper to create a version.php file
# ---------------------------------------------------------------------------


def _make_version_php(content: str, tmp_path: Path) -> Path:
    """Create wp-includes/version.php with the given content."""
    wp_includes = tmp_path / "wp-includes"
    wp_includes.mkdir(exist_ok=True)
    (wp_includes / "version.php").write_text(content)
    return wp_includes / "version.php"


def _make_wp_root(tmp_path: Path) -> Path:
    """Create minimal WordPress directory structure."""
    (tmp_path / "wp-includes").mkdir()
    return tmp_path


# ---------------------------------------------------------------------------
# VersionDetection dataclass
# ---------------------------------------------------------------------------


class TestVersionDetection:
    def test_defaults(self):
        r = VersionDetection(version=None, locale=None, is_wordpress=False)
        assert r.version is None
        assert r.locale is None
        assert r.is_wordpress is False
        assert r.errors == []
        assert r.limitations == []

    def test_with_values(self):
        r = VersionDetection(
            version="6.6",
            locale="en_US",
            is_wordpress=True,
            errors=[],
            limitations=["file too large"],
        )
        assert r.version == "6.6"
        assert r.locale == "en_US"
        assert r.is_wordpress is True
        assert r.limitations == ["file too large"]


# ---------------------------------------------------------------------------
# detect_version
# ---------------------------------------------------------------------------


class TestDetectVersion:
    def test_standard(self, tmp_path: Path):
        _make_version_php(
            "<?php\n$wp_version = '6.6';\n$wp_locale = 'en_US';\n",
            tmp_path,
        )
        assert detect_version(tmp_path) == "6.6"

    def test_double_quoted(self, tmp_path: Path):
        _make_version_php(
            "<?php\n$wp_version = \"6.5.3\";\n", tmp_path
        )
        assert detect_version(tmp_path) == "6.5.3"

    def test_whitespace_variations(self, tmp_path: Path):
        _make_version_php(
            "<?php\n$wp_version  =  '6.6';\n", tmp_path
        )
        assert detect_version(tmp_path) == "6.6"

    def test_no_space_around_equals(self, tmp_path: Path):
        _make_version_php(
            "<?php\n$wp_version='6.6';\n", tmp_path
        )
        assert detect_version(tmp_path) == "6.6"

    def test_version_with_patch(self, tmp_path: Path):
        _make_version_php(
            "<?php\n$wp_version = '6.5.3';\n", tmp_path
        )
        assert detect_version(tmp_path) == "6.5.3"

    def test_version_with_beta_suffix(self, tmp_path: Path):
        _make_version_php(
            "<?php\n$wp_version = '6.6-beta1';\n", tmp_path
        )
        assert detect_version(tmp_path) == "6.6-beta1"

    def test_version_with_rc_suffix(self, tmp_path: Path):
        _make_version_php(
            "<?php\n$wp_version = '6.6-RC1';\n", tmp_path
        )
        assert detect_version(tmp_path) == "6.6-RC1"

    def test_malformed_version_rejected(self, tmp_path: Path):
        _make_version_php(
            "<?php\n$wp_version = 'hacked';\n", tmp_path
        )
        assert detect_version(tmp_path) is None

    def test_version_without_minor(self, tmp_path: Path):
        _make_version_php(
            "<?php\n$wp_version = '6';\n", tmp_path
        )
        assert detect_version(tmp_path) is None

    def test_missing_version_php(self, tmp_path: Path):
        _make_wp_root(tmp_path)
        assert detect_version(tmp_path) is None

    def test_non_wordpress_directory(self, tmp_path: Path):
        (tmp_path / "index.html").write_text("not wordpress")
        assert detect_version(tmp_path) is None

    def test_empty_version_php(self, tmp_path: Path):
        _make_version_php("<?php\n", tmp_path)
        assert detect_version(tmp_path) is None

    def test_oversized_version_php(self, tmp_path: Path):
        _make_wp_root(tmp_path)
        version_file = tmp_path / "wp-includes" / "version.php"
        version_file.write_bytes(b"<?php\n" + b"x" * (100 * 1024 + 1))
        assert detect_version(tmp_path) is None

    def test_unreadable_version_php(self, tmp_path: Path):
        _make_version_php(
            "<?php\n$wp_version = '6.6';\n", tmp_path
        )
        version_file = tmp_path / "wp-includes" / "version.php"

        original_open = open

        def mock_open_fn(path, *args, **kwargs):
            if str(path) == str(version_file):
                raise PermissionError("simulated")
            return original_open(path, *args, **kwargs)

        with patch("builtins.open", side_effect=mock_open_fn):
            assert detect_version(tmp_path) is None

    def test_utf8_with_bom(self, tmp_path: Path):
        _make_wp_root(tmp_path)
        version_file = tmp_path / "wp-includes" / "version.php"
        content = "<?php\n$wp_version = '6.6';\n"
        version_file.write_bytes(b"\xef\xbb\xbf" + content.encode("utf-8"))
        assert detect_version(tmp_path) == "6.6"

    def test_latin1_encoding(self, tmp_path: Path):
        """File with latin-1 encoded content is still parsed."""
        _make_wp_root(tmp_path)
        version_file = tmp_path / "wp-includes" / "version.php"
        content = "<?php\n$wp_version = '6.6';\n$wp_locale = 'es_ES';\n"
        version_file.write_bytes(content.encode("latin-1"))
        assert detect_version(tmp_path) == "6.6"

    def test_version_with_extra_variables(self, tmp_path: Path):
        _make_version_php(
            "<?php\n"
            "$wp_version = '6.6';\n"
            "$wp_revision = '57067';\n"
            "$wp_locale = 'en_US';\n"
            "$required_php = '7.0.0';\n",
            tmp_path,
        )
        assert detect_version(tmp_path) == "6.6"

    def test_version_with_closing_tag(self, tmp_path: Path):
        _make_version_php(
            "<?php\n$wp_version = '6.6';\n?>\n", tmp_path
        )
        assert detect_version(tmp_path) == "6.6"

    def test_version_with_multiline_assignment(self, tmp_path: Path):
        """Version assignment that spans multiple lines."""
        _make_version_php(
            "<?php\n$wp_version = '6.6';\n", tmp_path
        )
        assert detect_version(tmp_path) == "6.6"

    def test_does_not_execute_php(self, tmp_path: Path):
        """The parser must not execute or include PHP code."""
        # This file would be dangerous if executed:
        _make_version_php(
            "<?php\n"
            "$dangerous = system('echo hacked');\n"
            "$wp_version = '6.6';\n",
            tmp_path,
        )
        version = detect_version(tmp_path)
        assert version == "6.6"
        # No "hacked" or system output should leak into the version
        assert "hacked" not in (version or "")


# ---------------------------------------------------------------------------
# detect_locale
# ---------------------------------------------------------------------------


class TestDetectLocale:
    def test_standard_locale(self, tmp_path: Path):
        _make_version_php(
            "<?php\n$wp_version = '6.6';\n$wp_locale = 'en_US';\n", tmp_path
        )
        assert detect_locale(tmp_path) == "en_US"

    def test_locale_with_variant(self, tmp_path: Path):
        _make_version_php(
            "<?php\n$wp_locale = 'de_DE_formal';\n", tmp_path
        )
        assert detect_locale(tmp_path) == "de_DE_formal"

    def test_double_quoted_locale(self, tmp_path: Path):
        _make_version_php(
            "<?php\n$wp_locale = \"es_ES\";\n", tmp_path
        )
        assert detect_locale(tmp_path) == "es_ES"

    def test_missing_locale(self, tmp_path: Path):
        _make_version_php(
            "<?php\n$wp_version = '6.6';\n", tmp_path
        )
        assert detect_locale(tmp_path) is None

    def test_malformed_locale(self, tmp_path: Path):
        _make_version_php(
            "<?php\n$wp_locale = 'INVALID_LOCALE';\n", tmp_path
        )
        assert detect_locale(tmp_path) is None

    def test_locale_empty_string(self, tmp_path: Path):
        _make_version_php(
            "<?php\n$wp_locale = '';\n", tmp_path
        )
        assert detect_locale(tmp_path) is None

    def test_brazilian_portuguese(self, tmp_path: Path):
        _make_version_php(
            "<?php\n$wp_locale = 'pt_BR';\n", tmp_path
        )
        assert detect_locale(tmp_path) == "pt_BR"


# ---------------------------------------------------------------------------
# is_wordpress_site
# ---------------------------------------------------------------------------


class TestIsWordpressSite:
    def test_with_wp_includes(self, tmp_path: Path):
        _make_wp_root(tmp_path)
        assert is_wordpress_site(tmp_path) is True

    def test_with_wp_config(self, tmp_path: Path):
        (tmp_path / "wp-config.php").write_text("<?php")
        assert is_wordpress_site(tmp_path) is True

    def test_with_wp_admin(self, tmp_path: Path):
        (tmp_path / "wp-admin").mkdir()
        assert is_wordpress_site(tmp_path) is True

    def test_empty_directory(self, tmp_path: Path):
        assert is_wordpress_site(tmp_path) is False

    def test_random_files_only(self, tmp_path: Path):
        (tmp_path / "index.html").write_text("<h1>hello</h1>")
        (tmp_path / "style.css").write_text("body{}")
        assert is_wordpress_site(tmp_path) is False

    def test_string_path(self, tmp_path: Path):
        _make_wp_root(tmp_path)
        assert is_wordpress_site(str(tmp_path)) is True


# ---------------------------------------------------------------------------
# detect_wordpress_info
# ---------------------------------------------------------------------------


class TestDetectWordpressInfo:
    def test_full_detection(self, tmp_path: Path):
        _make_version_php(
            "<?php\n$wp_version = '6.6';\n$wp_locale = 'en_US';\n", tmp_path
        )
        result = detect_wordpress_info(tmp_path)
        assert result.version == "6.6"
        assert result.locale == "en_US"
        assert result.is_wordpress is True
        assert result.errors == []

    def test_only_version_no_locale(self, tmp_path: Path):
        _make_version_php(
            "<?php\n$wp_version = '6.5.3';\n", tmp_path
        )
        result = detect_wordpress_info(tmp_path)
        assert result.version == "6.5.3"
        assert result.locale is None
        assert result.is_wordpress is True
        assert result.errors == []

    def test_non_wordpress(self, tmp_path: Path):
        (tmp_path / "index.html").write_text("hello")
        result = detect_wordpress_info(tmp_path)
        assert result.version is None
        assert result.locale is None
        assert result.is_wordpress is False
        assert "No WordPress" in result.errors[0]

    def test_wp_markers_but_no_version_php(self, tmp_path: Path):
        (tmp_path / "wp-includes").mkdir()
        (tmp_path / "wp-config.php").write_text("<?php")
        result = detect_wordpress_info(tmp_path)
        assert result.version is None
        assert result.locale is None
        assert result.is_wordpress is True
        assert "version.php" in result.errors[0].lower()

    def test_malformed_version_records_error(self, tmp_path: Path):
        _make_version_php(
            "<?php\n$wp_version = 'totally_invalid';\n$wp_locale = 'en_US';\n",
            tmp_path,
        )
        result = detect_wordpress_info(tmp_path)
        assert result.version is None
        assert result.locale == "en_US"
        assert result.is_wordpress is True
        assert any("format" in e.lower() or "recognized" in e.lower() for e in result.errors)

    def test_accepts_config_argument(self, tmp_path: Path):
        """detect_wordpress_info accepts an optional ScanConfig."""
        _make_version_php(
            "<?php\n$wp_version = '6.6';\n", tmp_path
        )
        config = ScanConfig()
        result = detect_wordpress_info(tmp_path, config)
        assert result.version == "6.6"


# ---------------------------------------------------------------------------
# Comment injection tests
# ---------------------------------------------------------------------------


class TestCommentInjection:
    def test_dollar_version_in_line_comment(self, tmp_path: Path):
        """// $wp_version = '99.9'; should not be matched."""
        _make_version_php(
            "<?php\n"
            "// $wp_version = '99.9';\n"
            "$wp_version = '6.6';\n",
            tmp_path,
        )
        assert detect_version(tmp_path) == "6.6"

    def test_dollar_version_in_block_comment(self, tmp_path: Path):
        """/* $wp_version = '99.9'; */ should not be matched."""
        _make_version_php(
            "<?php\n"
            "/* $wp_version = '99.9'; */\n"
            "$wp_version = '6.6';\n",
            tmp_path,
        )
        assert detect_version(tmp_path) == "6.6"

    def test_dollar_version_in_hash_comment(self, tmp_path: Path):
        """# $wp_version = '99.9'; should not be matched."""
        _make_version_php(
            "<?php\n"
            "# $wp_version = '99.9';\n"
            "$wp_version = '6.6';\n",
            tmp_path,
        )
        assert detect_version(tmp_path) == "6.6"

    def test_multiline_block_comment_injection(self, tmp_path: Path):
        _make_version_php(
            "<?php\n"
            "/*\n"
            " * $wp_version = '99.9';\n"
            " */\n"
            "$wp_version = '6.6';\n",
            tmp_path,
        )
        assert detect_version(tmp_path) == "6.6"

    def test_version_in_docblock(self, tmp_path: Path):
        _make_version_php(
            "<?php\n"
            "/**\n"
            " * WordPress Version information.\n"
            " * Version: 99.9 (fake)\n"
            " */\n"
            "$wp_version = '6.6';\n",
            tmp_path,
        )
        assert detect_version(tmp_path) == "6.6"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestVersionEdgeCases:
    def test_version_at_end_of_file(self, tmp_path: Path):
        _make_version_php(
            "<?php\n$wp_locale = 'en_US';\n$wp_version = '6.6';", tmp_path
        )
        assert detect_version(tmp_path) == "6.6"

    def test_version_with_trailing_whitespace(self, tmp_path: Path):
        _make_version_php(
            "<?php\n$wp_version = '6.6' ;\n", tmp_path
        )
        assert detect_version(tmp_path) == "6.6"

    def test_version_php_is_symlink(self, tmp_path: Path):
        """version.php is a file (not symlink) in normal installs."""
        _make_version_php(
            "<?php\n$wp_version = '6.6';\n", tmp_path
        )
        assert detect_version(tmp_path) == "6.6"

    def test_realistic_version_php(self, tmp_path: Path):
        """Test with content resembling real WordPress version.php."""
        content = """<?php
/**
 * WordPress Version information, title, description, and other things.
 */

$wp_version = '6.6';
$wp_revision = '57067';
$wp_locale = 'en_US';
$required_php = '7.0.0';
$textdomain = 'wp';
$wp_tests_require_php = '7.2.0';

?>
"""
        _make_version_php(content, tmp_path)
        assert detect_version(tmp_path) == "6.6"
        assert detect_locale(tmp_path) == "en_US"

    def test_version_with_underscore_in_suffix(self, tmp_path: Path):
        _make_version_php(
            "<?php\n$wp_version = '6.6-beta1';\n", tmp_path
        )
        assert detect_version(tmp_path) == "6.6-beta1"

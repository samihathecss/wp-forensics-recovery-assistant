"""WordPress version detection by parsing wp-includes/version.php as text.

This module never executes PHP. It reads version.php as plain text and
extracts $wp_version and $wp_locale using regex on literal assignments.
PHP comments are stripped before matching to prevent misleading assignments
inside comments from being treated as real version values.

Detected version information is not proof of authenticity — only core
checksum verification (Milestone 7) can confirm file integrity.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path

from wp_forensics.config import ScanConfig

_MAX_VERSION_FILE_BYTES = 100 * 1024

_VERSION_PATTERN = re.compile(r'''\$wp_version\s*=\s*['"]([^'"]+)['"]''')
_LOCALE_PATTERN = re.compile(r'''\$wp_locale\s*=\s*['"]([^'"]+)['"]''')

_VERSION_FORMAT = re.compile(r"^\d+\.\d+(\.\d+)?(-[a-zA-Z0-9]+)?$")
_LOCALE_FORMAT = re.compile(r"^[a-z]{2,3}_[A-Z]{2,3}(_[a-z]+)?$")

_PHP_COMMENT_BLOCK = re.compile(r"/\*.*?\*/", re.DOTALL)
_PHP_COMMENT_LINE = re.compile(r"//[^\n]*")
_PHP_COMMENT_HASH = re.compile(r"#[^\n]*")


@dataclass
class VersionDetection:
    """Result of WordPress version and locale detection.

    Attributes:
        version: Detected version string (e.g., "6.6") or None.
        locale: Detected locale string (e.g., "en_US") or None.
        is_wordpress: True if WordPress installation markers were found.
        errors: Detection errors or issues (not fatal — version may still
            be detected from partial data).
        limitations: Constraints applied during detection (e.g., file
            too large to read).
    """

    version: str | None
    locale: str | None
    is_wordpress: bool
    errors: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


def detect_version(root: Path | str) -> str | None:
    """Detect the WordPress version from the installation at *root*.

    Reads wp-includes/version.php as text (never executes it).
    Returns the version string (e.g., "6.6") if detected and valid,
    or None if not found, malformed, or unreadable.
    """
    return detect_wordpress_info(root).version


def detect_locale(root: Path | str) -> str | None:
    """Detect the WordPress locale from the installation at *root*.

    Returns the locale string (e.g., "en_US") if detected,
    or None if not found or unreadable.
    """
    return detect_wordpress_info(root).locale


def is_wordpress_site(root: Path | str) -> bool:
    """Quick check: does *root* contain WordPress installation markers?

    Checks for wp-includes/ directory, wp-config.php, or wp-admin/ directory.
    Does not read any file contents.
    """
    root_path = Path(root)
    return (
        (root_path / "wp-includes").is_dir()
        or (root_path / "wp-config.php").is_file()
        or (root_path / "wp-admin").is_dir()
    )


def detect_wordpress_info(
    root: Path | str,
    config: ScanConfig | None = None,
) -> VersionDetection:
    """Detect WordPress version and locale from *root*.

    Reads wp-includes/version.php as plain text, strips PHP comments,
    and extracts $wp_version and $wp_locale from literal assignments.

    Returns a :class:`VersionDetection` with detected values and any
    errors encountered. Detection errors do not raise exceptions —
    callers should check the ``errors`` list for details.
    """
    root_path = Path(root)

    result = VersionDetection(
        version=None,
        locale=None,
        is_wordpress=False,
    )

    has_wp_includes = (root_path / "wp-includes").is_dir()
    has_wp_config = (root_path / "wp-config.php").is_file()
    has_wp_admin = (root_path / "wp-admin").is_dir()

    result.is_wordpress = has_wp_includes or has_wp_config or has_wp_admin

    if not result.is_wordpress:
        result.errors.append("No WordPress installation markers found")
        return result

    version_file = root_path / "wp-includes" / "version.php"

    if not version_file.is_file():
        result.errors.append("wp-includes/version.php not found")
        return result

    text, read_error = _read_limited(version_file)
    if read_error is not None:
        result.errors.append(read_error)
        return result

    if text is None:
        result.errors.append("Failed to read wp-includes/version.php")
        return result

    text = _strip_php_comments(text)

    version_match = _VERSION_PATTERN.search(text)
    if version_match:
        raw_version = version_match.group(1).strip()
        if _VERSION_FORMAT.match(raw_version):
            result.version = raw_version
        else:
            result.errors.append(
                f"Version format not recognized: {raw_version}"
            )
    else:
        result.errors.append(
            "$wp_version literal assignment not found in version.php"
        )

    locale_match = _LOCALE_PATTERN.search(text)
    if locale_match:
        raw_locale = locale_match.group(1).strip()
        if _LOCALE_FORMAT.match(raw_locale):
            result.locale = raw_locale
        else:
            result.errors.append(
                f"Locale format not recognized: {raw_locale}"
            )

    return result


def _read_limited(
    path: Path,
    max_bytes: int = _MAX_VERSION_FILE_BYTES,
) -> tuple[str | None, str | None]:
    """Read a file as text with a byte-size limit.

    Returns (text, error). On success, error is None.
    Reads at most *max_bytes* to prevent unbounded file reads.
    Tries UTF-8 (stripping BOM), falls back to latin-1.
    Does not expose file contents in error messages.
    """
    try:
        file_size = path.stat().st_size
    except OSError:
        return None, "Could not stat version.php"

    if file_size > max_bytes:
        return None, "version.php exceeds maximum size"

    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes + 1)
    except PermissionError:
        return None, "Permission denied reading version.php"
    except IsADirectoryError:
        return None, "version.php path is a directory"
    except OSError:
        return None, "Could not read version.php"

    if len(data) > max_bytes:
        return None, "version.php exceeds maximum size"

    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = data.decode("latin-1")

    return text, None


def _strip_php_comments(text: str) -> str:
    """Remove PHP-style comments from text.

    Handles /* */ block comments (including multi-line), // line comments,
    and # line comments. This is a best-effort text filter — it does not
    fully parse PHP. String literals containing comment markers are not
    perfectly preserved, but WordPress version.php does not contain
    such patterns.
    """
    text = _PHP_COMMENT_BLOCK.sub("", text)
    text = _PHP_COMMENT_LINE.sub("", text)
    text = _PHP_COMMENT_HASH.sub("", text)
    return text

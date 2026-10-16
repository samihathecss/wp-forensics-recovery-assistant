"""Suspicious indicators engine for WordPress forensic scanning.

This module provides a data-driven, rule-based scanner that detects
suspicious patterns in files without executing, importing, evaluating,
or interpreting PHP code. All rules are regex-based and operate on
plain text content or file paths.

Findings from this module are indicators only — they require further
investigation to confirm malicious intent. The default Finding status is
STATUS_SUSPICIOUS; this module never marks files as confirmed malware.

Known limitation: PHP comment stripping is text-based (regex), not a
full PHP parser. Comment markers inside string literals (e.g., ``//``
in a URL string) may cause adjacent content to be ignored. This does
not produce false positives but may cause rare false negatives.
"""

import os
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from wp_forensics.config import ScanConfig
from wp_forensics.hashing import hash_file, is_symlink_safe
from wp_forensics.models import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    Finding,
    ScanResult,
    STATUS_SUSPICIOUS,
)

__all__ = [
    "IndicatorRule",
    "INDICATOR_RULES",
    "scan_file",
    "scan_directory",
]

_EVIDENCE_MAX_LENGTH = 200
_BINARY_CHECK_BYTES = 8192

_PHP_COMMENT_BLOCK = re.compile(r"/\*.*?\*/", re.DOTALL)
_PHP_COMMENT_LINE = re.compile(r"//[^\n]*")
_PHP_COMMENT_HASH = re.compile(r"#[^\n]*")


# ---------------------------------------------------------------------------
# Location check predicates
# ---------------------------------------------------------------------------


def _in_uploads(rel_path: str) -> bool:
    """Return True if *rel_path* is inside wp-content/uploads/ (not siblings)."""
    if not isinstance(rel_path, str):
        rel_path = str(rel_path)
    normalized = rel_path.replace("\\", "/").lower()
    # Match wp-content/uploads/ as a directory component (with / or at end)
    return "wp-content/uploads/" in normalized or normalized == "wp-content/uploads"


def _in_webroot(rel_path: str) -> bool:
    """Return True if *rel_path* is directly in the web root (no subdir)."""
    normalized = rel_path.replace("\\", "/")
    return "/" not in normalized


# ---------------------------------------------------------------------------
# Indicator rules
# ---------------------------------------------------------------------------


@dataclass
class IndicatorRule:
    """A single detection rule for the indicators engine.

    Attributes:
        indicator_id: Stable unique identifier, e.g. ``"IND-EVAL"``.
        category: Grouping label, e.g. ``"code_execution"``.
        pattern: Compiled regex or raw string (compiled at module load).
        severity: One of the ``SEVERITY_*`` constants.
        confidence: One of the ``CONFIDENCE_*`` constants.
        explanation: Human-readable description of why the rule fires.
        file_types: Extensions (without dot) this rule applies to.
            Empty tuple means all text files. Only used for content rules.
        scan_path: If True, match *pattern* against the file path rather
            than file content.
        location_check: Optional callable that takes a POSIX relative path
            and returns True if the file is in a location this rule cares
            about (e.g. inside uploads).
    """

    indicator_id: str
    category: str
    pattern: str
    severity: str
    confidence: str
    explanation: str
    file_types: tuple[str, ...] = ()
    scan_path: bool = False
    location_check: Callable[[str], bool] | None = None
    _compiled: re.Pattern = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        self._compiled = re.compile(self.pattern, re.IGNORECASE)

    def matches_path(self, rel_path: str) -> bool:
        """Check if the file path is in scope for this rule."""
        if self.location_check is not None:
            if not self.location_check(rel_path):
                return False
        return True

    def match_content(self, text: str) -> list[tuple[int, str]]:
        """Find all matches of this rule's pattern in *text*.

        Returns a list of (line_number, evidence) tuples.
        Line numbers are 1-based. Evidence is the matching line,
        truncated to ``_EVIDENCE_MAX_LENGTH``.
        """
        results: list[tuple[int, str]] = []
        for match in self._compiled.finditer(text):
            line_no = _line_number(text, match.start())
            evidence = _extract_evidence(text, match.start(), match.end())
            results.append((line_no, evidence))
        return results

    def match_path(self, rel_path: str) -> bool:
        """Check if this rule's pattern matches the relative file path."""
        return self._compiled.search(rel_path) is not None


_indicators: list[IndicatorRule] = [
    # --- Content rules (scan content, not path) ---

    IndicatorRule(
        indicator_id="IND-EVAL",
        category="code_execution",
        pattern=r"\b(eval|assert)\s*\(",
        severity=SEVERITY_HIGH,
        confidence=CONFIDENCE_HIGH,
        explanation=(
            "Use of eval() or assert() enables arbitrary code execution; "
            "rare in legitimate WordPress code."
        ),
        file_types=("php",),
    ),
    IndicatorRule(
        indicator_id="IND-EVAL-BASE64",
        category="deobfuscation",
        pattern=r"\beval\s*\(\s*base64_decode\s*\(",
        severity=SEVERITY_CRITICAL,
        confidence=CONFIDENCE_HIGH,
        explanation=(
            "eval(base64_decode(...)) is a classic web shell pattern that "
            "executes attacker-supplied encoded payloads."
        ),
        file_types=("php",),
    ),
    IndicatorRule(
        indicator_id="IND-SYS-FUNC",
        category="code_execution",
        pattern=r"\b(system|exec|shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\(",
        severity=SEVERITY_HIGH,
        confidence=CONFIDENCE_MEDIUM,
        explanation=(
            "Shell execution functions can run arbitrary system commands; "
            "may be legitimate in some plugins but high-risk if unexpected."
        ),
        file_types=("php",),
    ),
    IndicatorRule(
        indicator_id="IND-PHP-WRAPPER",
        category="data_injection",
        pattern=r"php://(input|filter)",
        severity=SEVERITY_MEDIUM,
        confidence=CONFIDENCE_MEDIUM,
        explanation=(
            "php://input or php://filter can process attacker-controlled "
            "data; commonly used in web shells."
        ),
        file_types=("php",),
    ),
    IndicatorRule(
        indicator_id="IND-PREG-E",
        category="code_execution",
        pattern=r"preg_replace\s*\(\s*['\"][^'\"]*\/e['\"]",
        severity=SEVERITY_CRITICAL,
        confidence=CONFIDENCE_HIGH,
        explanation=(
            "preg_replace with the /e modifier evaluates the replacement "
            "string as PHP code. Deprecated in PHP 7 and removed in PHP 8, "
            "but dangerous if present."
        ),
        file_types=("php",),
    ),
    IndicatorRule(
        indicator_id="IND-GZ-EVAL",
        category="deobfuscation",
        pattern=r"\beval\s*\(\s*(?:\w+\s*\(\s*)?(gzinflate|gzuncompress|gzdecode)\s*\(",
        severity=SEVERITY_CRITICAL,
        confidence=CONFIDENCE_HIGH,
        explanation=(
            "eval() combined with a decompression function is a common "
            "web shell deobfuscation pattern."
        ),
        file_types=("php",),
    ),
    IndicatorRule(
        indicator_id="IND-DOUBLE-ROT13",
        category="obfuscation",
        pattern=r"\bstr_rot13\s*\(\s*str_rot13\s*\(",
        severity=SEVERITY_MEDIUM,
        confidence=CONFIDENCE_HIGH,
        explanation=(
            "Double str_rot13 encoding is a known obfuscation technique "
            "to hide payloads from simple inspection."
        ),
        file_types=("php",),
    ),
    IndicatorRule(
        indicator_id="IND-LONG-BASE64",
        category="obfuscation",
        pattern=r"base64_decode\s*\(\s*['\"][A-Za-z0-9+/]{500,}={0,2}['\"]",
        severity=SEVERITY_LOW,
        confidence=CONFIDENCE_LOW,
        explanation=(
            "Long base64-encoded string passed to base64_decode; "
            "low confidence — may be legitimate data encoding."
        ),
        file_types=("php",),
    ),
    IndicatorRule(
        indicator_id="IND-HEX2BIN",
        category="obfuscation",
        pattern=r"\bhex2bin\s*\(\s*['\"][0-9a-fA-F]{100,}['\"]",
        severity=SEVERITY_LOW,
        confidence=CONFIDENCE_MEDIUM,
        explanation=(
            "hex2bin with a long hex string can hide encoded payloads."
        ),
        file_types=("php",),
    ),
    IndicatorRule(
        indicator_id="IND-HTACCESS-PREPEND",
        category="code_injection",
        pattern=r"auto_prepend_file",
        severity=SEVERITY_HIGH,
        confidence=CONFIDENCE_HIGH,
        explanation=(
            "auto_prepend_file in .htaccess can execute arbitrary PHP on "
            "every request, a common persistent-injection technique."
        ),
        file_types=("htaccess",),
    ),

    # --- Path rules (scan_path=True, match against relative path) ---

    IndicatorRule(
        indicator_id="IND-PHP-IN-UPLOADS",
        category="suspicious_location",
        pattern=r"\.(php|phtml|pht|phar|php5|php4|php3|php7)$",
        severity=SEVERITY_HIGH,
        confidence=CONFIDENCE_HIGH,
        explanation=(
            "PHP file found in wp-content/uploads — uploads should contain "
            "only media files (images, videos, documents)."
        ),
        scan_path=True,
        location_check=_in_uploads,
    ),
    IndicatorRule(
        indicator_id="IND-SUSPICIOUS-UPLOAD-EXT",
        category="suspicious_location",
        pattern=r"\.(phtml|pht|phar|php5|php4|php3|php7)$",
        severity=SEVERITY_MEDIUM,
        confidence=CONFIDENCE_HIGH,
        explanation=(
            "Executable PHP-like file extension in uploads directory."
        ),
        scan_path=True,
        location_check=_in_uploads,
    ),
    IndicatorRule(
        indicator_id="IND-EXEC-IN-WEBROOT",
        category="suspicious_location",
        pattern=r"\.(exe|bat|cmd|sh|cgi|pl|py)$",
        severity=SEVERITY_MEDIUM,
        confidence=CONFIDENCE_HIGH,
        explanation=(
            "Executable file in web root — should not be directly accessible."
        ),
        scan_path=True,
        location_check=_in_webroot,
    ),
    IndicatorRule(
        indicator_id="IND-HTACCESS-UPLOADS",
        category="suspicious_location",
        pattern=r"/\.htaccess$",
        severity=SEVERITY_MEDIUM,
        confidence=CONFIDENCE_MEDIUM,
        explanation=(
            ".htaccess in uploads directory can override server configuration."
        ),
        scan_path=True,
        location_check=_in_uploads,
    ),
    IndicatorRule(
        indicator_id="IND-WEB-SHELL-NAME",
        category="suspicious_filename",
        pattern=r"(?:^|/)?(?:c99|r57|wso|b374k|b00k|remotemind|stresaz).*\.php$",
        severity=SEVERITY_HIGH,
        confidence=CONFIDENCE_HIGH,
        explanation=(
            "Filename matches known web shell naming patterns."
        ),
        scan_path=True,
    ),
]

INDICATOR_RULES: list[IndicatorRule] = _indicators


# Pre-index rules for efficient lookup by file type
_CONTENT_RULES_BY_TYPE: dict[str, list[IndicatorRule]] = {}
_PATH_RULES: list[IndicatorRule] = []

for _rule in INDICATOR_RULES:
    if _rule.scan_path:
        _PATH_RULES.append(_rule)
    else:
        if _rule.file_types:
            for ft in _rule.file_types:
                _CONTENT_RULES_BY_TYPE.setdefault(ft, []).append(_rule)
        else:
            _CONTENT_RULES_BY_TYPE.setdefault("", []).append(_rule)


# ---------------------------------------------------------------------------
# Text processing helpers
# ---------------------------------------------------------------------------


def _line_number(text: str, position: int) -> int:
    """Return the 1-based line number of *position* within *text*."""
    return text.count("\n", 0, position) + 1


def _extract_evidence(text: str, start: int, end: int) -> str:
    """Extract the line containing the match, truncated for evidence."""
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end == -1:
        line_end = len(text)
    line = text[line_start:line_end]
    line = line.strip()
    if len(line) > _EVIDENCE_MAX_LENGTH:
        return line[:_EVIDENCE_MAX_LENGTH] + "..."
    return line


def _is_binary(data: bytes) -> bool:
    """Detect binary content by checking for null bytes in the first 8 KB."""
    return b"\x00" in data[:_BINARY_CHECK_BYTES]


def _read_text(path: Path, max_bytes: int) -> tuple[str | None, bool, str | None]:
    """Read a file as text with bounded size and binary detection.

    Returns ``(text, is_binary, error)``.
    - On success: text is decoded, is_binary is False, error is None.
    - If binary: text is None, is_binary is True, error is None.
    - If too large: text is None, is_binary is False, error is a skip message.
    - If unreadable: text is None, is_binary is False, error is an error message.
    """
    try:
        file_size = path.stat().st_size
    except OSError:
        return None, False, "Could not stat file"

    if file_size > max_bytes:
        return None, False, None

    data = None
    for _attempt in range(5):
        try:
            with open(path, "rb") as f:
                data = f.read(max_bytes + 1)
            break
        except PermissionError:
            if _attempt < 4:
                time.sleep(0.5)
                continue
            return None, False, "Permission denied reading file"
        except IsADirectoryError:
            return None, False, "Path is a directory"
        except OSError:
            return None, False, "Could not read file"

    if len(data) > max_bytes:
        return None, False, None

    # Detect UTF-16 BOM before binary check: UTF-16 contains null bytes
    # between every ASCII character, which would otherwise trigger
    # _is_binary and cause the file to be skipped entirely.
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return data.decode("utf-16"), False, None
        except UnicodeDecodeError:
            return None, True, None

    if _is_binary(data):
        return None, True, None

    try:
        return data.decode("utf-8-sig"), False, None
    except UnicodeDecodeError:
        return data.decode("latin-1"), False, None


def _strip_php_comments(text: str) -> str:
    """Strip PHP comments while preserving line structure.

    Block comments (``/* ... */``) are replaced with newlines so that
    line numbers remain accurate. Line comments (``//`` and ``#``) are
    removed to the end of line.
    """
    def _block_replacer(match: re.Match) -> str:
        return "\n" * match.group(0).count("\n")

    text = _PHP_COMMENT_BLOCK.sub(_block_replacer, text)
    text = _PHP_COMMENT_LINE.sub("", text)
    text = _PHP_COMMENT_HASH.sub("", text)
    return text


def _get_file_type(path: Path) -> str:
    """Determine the file type for rule matching.

    Returns the extension without the dot (e.g. ``"php"``), ``"htaccess"``
    for ``.htaccess`` files, or an empty string for no extension.
    """
    name = path.name
    if name == ".htaccess":
        return "htaccess"
    suffix = path.suffix.lower()
    if suffix.startswith("."):
        return suffix[1:]
    return ""


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


def scan_file(
    file_path: Path | str,
    relative_path: str | None = None,
    config: ScanConfig | None = None,
) -> list[Finding]:
    """Scan a single file for suspicious indicators.

    Reads the file as bounded plain text (UTF-8 with latin-1 fallback).
    Binary files are detected via null bytes and skipped for content
    scanning — but path rules still apply. Never executes or interprets
    PHP.

    Args:
        file_path: Absolute or relative path to the file.
        relative_path: Posix-style relative path for reporting. If
            None, the path itself is used.
        config: Scan config for size limits. Defaults to ScanConfig().

    Returns:
        List of :class:`Finding` objects, possibly empty.
    """
    if config is None:
        config = ScanConfig()

    fpath = Path(file_path)
    if relative_path is None:
        relative_path = str(fpath)


    findings: list[Finding] = []


    # Path-based rules (no file reading needed)
    for rule in _PATH_RULES:
        if not rule.matches_path(relative_path):
            continue
        if rule.match_path(relative_path):
            _sha = hash_file(fpath, config.max_file_size_bytes)[0] if not fpath.is_symlink() else None
            findings.append(_make_finding(
                relative_path, rule, evidence=relative_path, sha256=_sha
            ))

    # Content-based rules
    ft = _get_file_type(fpath)
    content_rules = _CONTENT_RULES_BY_TYPE.get(ft, [])
    # Also check generic rules (file_types == ())
    generic_rules = _CONTENT_RULES_BY_TYPE.get("", [])


    if not content_rules and not generic_rules:
        return findings

    text, is_binary, read_error = _read_text(fpath, config.max_file_size_bytes)


    if read_error:
        # Record a finding only if it's a content rule for this file type?
        # No — read errors are non-fatal; the file is just skipped for content.
        return findings

    if is_binary or text is None:
        return findings

    text = _strip_php_comments(text)

    seen: set[tuple[str, int]] = set()

    for rule in content_rules + generic_rules:
        matches = rule.match_content(text)
        for line_no, evidence in matches:
            key = (rule.indicator_id, line_no)
            if key in seen:
                continue
            seen.add(key)
            findings.append(_make_finding(
                relative_path, rule, evidence=evidence, line_number=line_no, sha256=None
            ))

    # Compute SHA-256 for content-rule findings (lazily, only when needed)
    if findings and not fpath.is_symlink():
        sha = hash_file(fpath, config.max_file_size_bytes)[0]
        for f in findings:
            if f.file_sha256 is None and f.line_number is not None:
                f.file_sha256 = sha

    return findings


def scan_directory(
    root: Path | str,
    config: ScanConfig | None = None,
) -> ScanResult:
    """Scan a directory tree for suspicious indicators.

    Walks *root* recursively, applying indicator rules to every file.
    Respects config limits for file count, total size, per-file size,
    and timeout. Symlinks are not followed unless
    ``config.follow_symlinks`` is True.

    Returns a :class:`~wp_forensics.models.ScanResult`.
    """
    if config is None:
        config = ScanConfig()

    root_path = Path(root)
    start_time = time.monotonic()
    scan_timestamp = datetime.now(timezone.utc).isoformat()

    findings: list[Finding] = []
    errors: list[str] = []
    limitations: list[str] = []
    file_count = 0
    scanned_size = 0
    seen_findings: set[tuple[str, str, int | None]] = set()

    if not root_path.exists():
        return ScanResult(
            scan_time=scan_timestamp,
            scan_root=str(root_path),
            findings=[],
            file_count=0,
            scanned_size_bytes=0,
            config_used=config,
            errors=["Root directory does not exist"],
        )

    if not root_path.is_dir():
        return ScanResult(
            scan_time=scan_timestamp,
            scan_root=str(root_path),
            findings=[],
            file_count=0,
            scanned_size_bytes=0,
            config_used=config,
            errors=["Root path is not a directory"],
        )

    root_resolved = root_path.resolve()

    def _check_timeout() -> bool:
        if time.monotonic() - start_time > config.scan_timeout_seconds:
            limitations.append(
                f"Scan timeout ({config.scan_timeout_seconds}s) reached"
            )
            return False
        return True

    for dirpath, dirnames, filenames in os.walk(
        root_resolved, followlinks=config.follow_symlinks
    ):
        if not _check_timeout():
            break

        if config.follow_symlinks:
            safe_dirs: list[str] = []
            for d in dirnames:
                d_path = Path(dirpath) / d
                if d_path.is_symlink() and not is_symlink_safe(d_path, root_resolved):
                    errors.append(
                        f"Skipped unsafe symlink directory: "
                        f"{_safe_relpath(d_path, root_resolved)}"
                    )
                else:
                    safe_dirs.append(d)
            dirnames[:] = safe_dirs
        else:
            dirnames[:] = [
                d for d in dirnames
                if not os.path.islink(os.path.join(dirpath, d))
            ]

        for filename in sorted(filenames):
            if not _check_timeout():
                break

            if file_count >= config.max_file_count:
                limitations.append(
                    f"File count limit ({config.max_file_count}) reached"
                )
                break

            file_path = Path(dirpath) / filename

            if file_path.is_symlink():
                if not config.follow_symlinks:
                    continue
                if not is_symlink_safe(file_path, root_resolved):
                    errors.append(
                        f"Skipped unsafe symlink: "
                        f"{_safe_relpath(file_path, root_resolved)}"
                    )
                    continue

            try:
                file_stat = file_path.stat()
                file_size = file_stat.st_size
            except OSError as e:
                errors.append(
                    f"Could not stat file "
                    f"{_safe_relpath(file_path, root_resolved)}: {e}"
                )
                continue

            rel_path = _safe_relpath(file_path, root_resolved)

            if file_size > config.max_file_size_bytes:
                errors.append(
                    f"Skipped oversized file ({file_size} > "
                    f"{config.max_file_size_bytes}): {rel_path}"
                )
                continue

            if scanned_size + file_size > config.max_total_size_bytes:
                limitations.append(
                    f"Total size limit ({config.max_total_size_bytes} bytes) reached"
                )
                break

            file_count += 1
            scanned_size += file_size

            file_findings = scan_file(file_path, rel_path, config)

            for f in file_findings:
                dedup_key = (f.file_path, f.indicator, f.line_number)
                if dedup_key in seen_findings:
                    continue
                seen_findings.add(dedup_key)
                findings.append(f)

    findings.sort(key=lambda f: (f.file_path, f.indicator, f.line_number or 0))

    return ScanResult(
        scan_time=scan_timestamp,
        scan_root=str(root_path),
        findings=findings,
        file_count=file_count,
        scanned_size_bytes=scanned_size,
        config_used=config,
        errors=errors,
        limitations=limitations,
    )


def scan_files(
    file_paths: list[Path | str],
    config: ScanConfig | None = None,
) -> list[Finding]:
    """Scan a list of specific files (without directory walking).

    Convenience wrapper around :func:`scan_file` for callers that already
    have a list of file paths to check.
    """
    if config is None:
        config = ScanConfig()

    all_findings: list[Finding] = []
    seen: set[tuple[str, str, int | None]] = set()

    for fp in file_paths:
        fpath = Path(fp)
        findings = scan_file(fpath, None, config)
        for f in findings:
            key = (f.file_path, f.indicator, f.line_number)
            if key not in seen:
                seen.add(key)
                all_findings.append(f)

    return all_findings


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _safe_relpath(path: Path, root: Path) -> str:
    """Return a POSIX-style relative path, or absolute path on error."""
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _make_finding(
    file_path: str,
    rule: IndicatorRule,
    evidence: str,
    line_number: int | None = None,
    sha256: str | None = None,
) -> Finding:
    """Create a Finding from a rule and match details."""
    return Finding(
        file_path=file_path,
        indicator=rule.indicator_id,
        severity=rule.severity,
        confidence=rule.confidence,
        category=rule.category,
        explanation=rule.explanation,
        evidence=evidence,
        line_number=line_number,
        file_sha256=sha256,
        status=STATUS_SUSPICIOUS,
    )

"""WordPress core file verification against official checksums.

This module provides verification of WordPress core files by comparing
their SHA-256 hashes with the official checksums published by
WordPress.org for a given version and locale.

It respects scan limits and symlink safety, and handles network
errors, unsupported versions, and incomplete scans gracefully.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import json
import urllib.request
import urllib.error

from wp_forensics.config import ScanConfig
from wp_forensics.hashing import hash_directory, DirectoryHashes
from wp_forensics.models import (
    VerificationResult,
    FileVerification,
    VERIFICATION_MATCH,
    VERIFICATION_MISMATCH,
    VERIFICATION_MISSING,
    VERIFICATION_UNCHECKED,
    VERIF_RESULT_VERIFIED,
    VERIF_RESULT_MISMATCHES,
    VERIF_RESULT_MISSING,
    VERIF_RESULT_NETWORK_ERROR,
    VERIF_RESULT_UNSUPPORTED,
    VERIF_RESULT_NOT_DETECTED,
    VERIF_RESULT_INCOMPLETE,
)
from wp_forensics.version import detect_wordpress_info

_WP_CHECKSUMS_API = "https://api.wordpress.org/core/checksums/1.0/"
_MAX_RESPONSE_BYTES = 1024 * 1024  # 1 MB


def verify_core(root: Path | str, config: ScanConfig | None = None) -> VerificationResult:
    """Verify WordPress core files against official checksums.

    Args:
        root: Path to the WordPress installation root.
        config: ScanConfig with limits. If None, uses default ScanConfig.

    Returns:
        VerificationResult with the verification outcome.
    """
    if config is None:
        config = ScanConfig()

    # Step 1: Detect WordPress version and locale
    detection = detect_wordpress_info(root, config)
    if not detection.is_wordpress:
        return VerificationResult(
            version=None,
            locale=None,
            status=VERIF_RESULT_NOT_DETECTED,
            verified_matches=0,
            mismatches=0,
            missing=0,
            unchecked=0,
            files=[],
            error="; ".join(detection.errors) if detection.errors else "No WordPress installation markers found",
        )
    if detection.version is None:
        return VerificationResult(
            version=None,
            locale=None,
            status=VERIF_RESULT_NOT_DETECTED,
            verified_matches=0,
            mismatches=0,
            missing=0,
            unchecked=0,
            files=[],
            error="; ".join(detection.errors) if detection.errors else "Version not detected",
        )

    version = detection.version
    locale = detection.locale

    # Step 2: Fetch checksums from WordPress.org
    params = {"version": version}
    if locale:
        params["locale"] = locale
    # Build query string
    query = "&".join(f"{k}={v}" for k, v in params.items())
    url = f"{_WP_CHECKSUMS_API}?{query}"

    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=config.request_timeout_seconds) as response:
            # Check response size
            content_length = response.length
            if content_length is not None and content_length > _MAX_RESPONSE_BYTES:
                return VerificationResult(
                    version=version,
                    locale=locale,
                    status=VERIF_RESULT_NETWORK_ERROR,
                    verified_matches=0,
                    mismatches=0,
                    missing=0,
                    unchecked=0,
                    files=[],
                    error=f"Response too large: {content_length} bytes > {_MAX_RESPONSE_BYTES} bytes",
                )
            # Read response with size limit
            data = b""
            while True:
                chunk = response.read(8192)
                if not chunk:
                    break
                data += chunk
                if len(data) > _MAX_RESPONSE_BYTES:
                    return VerificationResult(
                        version=version,
                        locale=locale,
                        status=VERIF_RESULT_NETWORK_ERROR,
                        verified_matches=0,
                        mismatches=0,
                        missing=0,
                        unchecked=0,
                        files=[],
                        error=f"Response too large: > {_MAX_RESPONSE_BYTES} bytes",
                    )
    except urllib.error.HTTPError as e:
        return VerificationResult(
            version=version,
            locale=locale,
            status=VERIF_RESULT_NETWORK_ERROR,
            verified_matches=0,
            mismatches=0,
            missing=0,
            unchecked=0,
            files=[],
            error=f"HTTP error {e.code}: {e.reason}",
        )
    except urllib.error.URLError as e:
        return VerificationResult(
            version=version,
            locale=locale,
            status=VERIF_RESULT_NETWORK_ERROR,
            verified_matches=0,
            mismatches=0,
            missing=0,
            unchecked=0,
            files=[],
            error=f"URL error: {e.reason}",
        )
    except Exception as e:
        return VerificationResult(
            version=version,
            locale=locale,
            status=VERIF_RESULT_NETWORK_ERROR,
            verified_matches=0,
            mismatches=0,
            missing=0,
            unchecked=0,
            files=[],
            error=f"Unexpected error: {e}",
        )

    # Parse JSON
    try:
        checksums_data = json.loads(data.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        return VerificationResult(
            version=version,
            locale=locale,
            status=VERIF_RESULT_NETWORK_ERROR,
            verified_matches=0,
            mismatches=0,
            missing=0,
            unchecked=0,
            files=[],
            error=f"Invalid JSON response: {e}",
        )

    # Validate response structure
    if not isinstance(checksums_data, dict) or "checksums" not in checksums_data:
        return VerificationResult(
            version=version,
            locale=locale,
            status=VERIF_RESULT_NETWORK_ERROR,
            verified_matches=0,
            mismatches=0,
            missing=0,
            unchecked=0,
            files=[],
            error="Missing 'checksums' in response",
        )
    checksums = checksums_data["checksums"]
    if not isinstance(checksums, dict):
        return VerificationResult(
            version=version,
            locale=locale,
            status=VERIF_RESULT_NETWORK_ERROR,
            verified_matches=0,
            mismatches=0,
            missing=0,
            unchecked=0,
            files=[],
            error="'checksums' is not a dictionary",
        )

    # Step 3: Scan local directory (respecting limits)
    local_result = hash_directory(root, config)

    # Step 4: Compare each expected file
    verified_matches = 0
    mismatches = 0
    missing = 0
    unchecked = 0
    files: list[FileVerification] = []

    for rel_path, expected_hash in checksums.items():
        # Normalize path to use POSIX separators (as stored in hashes)
        rel_path = rel_path.replace("\\", "/")
        file_path = Path(root) / rel_path

        if not file_path.exists():
            status = VERIFICATION_MISSING
            missing += 1
        else:
            if rel_path in local_result.hashes:
                actual_hash = local_result.hashes[rel_path]
                if actual_hash == expected_hash:
                    status = VERIFICATION_MATCH
                    verified_matches += 1
                else:
                    status = VERIFICATION_MISMATCH
                    mismatches += 1
            elif rel_path in local_result.skipped:
                status = VERIFICATION_UNCHECKED
                unchecked += 1
            else:
                # File exists but not in hashes and not skipped -> we never visited it (due to limits)
                status = VERIFICATION_UNCHECKED
                unchecked += 1

        files.append(FileVerification(
            path=rel_path,
            expected_hash=expected_hash,
            actual_hash=local_result.hashes.get(rel_path) if rel_path in local_result.hashes else None,
            status=status,
        ))

    # Step 5: Determine overall status
    if mismatches > 0:
        status = VERIF_RESULT_MISMATCHES
    elif missing > 0:
        status = VERIF_RESULT_MISSING
    elif unchecked > 0:
        status = VERIF_RESULT_INCOMPLETE
    else:
        status = VERIF_RESULT_VERIFIED

    # Combine errors and limitations from local scan into error field
    error_parts = []
    if local_result.errors:
        error_parts.extend(local_result.errors)
    if local_result.limitations:
        error_parts.extend(local_result.limitations)
    error = "; ".join(error_parts) if error_parts else None

    return VerificationResult(
        version=version,
        locale=locale,
        status=status,
        verified_matches=verified_matches,
        mismatches=mismatches,
        missing=missing,
        unchecked=unchecked,
        files=files,
        error=error,
    )

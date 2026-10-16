# AGENTS.md — WP Forensics & Recovery Assistant

## Commands
- Install deps: `pip install -r requirements.txt`
- Run tests: `python -m pytest tests/ -v`
- Run tests (specific file): `python -m pytest tests/test_config.py -v`
- Launch app: `python -m streamlit run app.py`
- CLI scan: `python -m wp_forensics.cli scan <dir> -o <output>`

## Module Map
- `wp_forensics/` — scanning engine (no Streamlit dependency)
  - `config.py` — ScanConfig with safety limits (leaf module, no deps)
  - `models.py` — Finding, ScanResult, ComparisonResult, VerificationResult
  - `hashing.py` — SHA-256 file/directory hashing with symlink safety
  - `version.py` — WordPress version/locale detection from version.php (text parsing, no PHP execution)
  - `indicators.py` — Suspicious indicator scanner (regex-based, data-driven rules)
  - `archive.py` — Safe ZIP inspection and bounded extraction (no extraction to disk during inspection)
  - (additional modules added per milestone: zip_utils, comparison, checksums, reporting, cli, core_verify)
- `app.py` — Streamlit UI (created in Milestone 10)
- `wp_forensics/cli.py` — CLI entry point (created in Milestone 9)
- `tests/` — pytest tests + synthetic fixtures

## Safety Rules (NON-NEGOTIABLE)
1. NEVER execute, include, evaluate, or load PHP from scanned sites
2. NEVER modify, delete, or quarantine original files
3. Write reports to a separate output directory only
4. Network requests ONLY to api.wordpress.org (GET, no file content in requests)
5. Enforce file-count, total-size, per-file-size, and scan-time limits
6. Prevent ZIP path traversal, symlink escapes, and decompression bombs
7. HTML-escape all untrusted content in report output

## Milestone Plan
See full plan: `C:\Users\Golzar\.local\share\kilo\plans\1791944368687-wp-forensics-plan.md`

Milestone 1: Scaffolding & Models (complete)
- Create config.py, models.py, basic tests
- Verify: `python -m pytest tests/test_config.py tests/test_models.py -v`

Milestone 2: File Hashing (complete)
- Create hashing.py, test_hashing.py
- Verify: `python -m pytest tests/test_hashing.py -v`

Milestone 3: Version Detection (complete)
- Create version.py, test_version.py
- Verify: `python -m pytest tests/test_version.py -v`

Milestone 4: Suspicious Indicators Engine (complete)
- Create indicators.py, test_indicators.py
- Verify: `python -m pytest tests/test_indicators.py -v`

Milestone 5: Safe ZIP Archive Handling (complete)
- Create archive.py, test_archive.py
- Verify: `python -m pytest tests/test_archive.py -v`

## Python Version
Python 3.12+ required. Uses `X | None` union syntax and `int | None` annotations.

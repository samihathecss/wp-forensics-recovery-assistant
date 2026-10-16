# WP Forensics & Recovery Assistant

Read-only forensic scanner for WordPress backups. Detects suspicious indicators,
compares directory snapshots, verifies WordPress core integrity, and inspects ZIP
archives — without executing PHP or modifying original files.

## Installation

```bash
pip install -r requirements.txt
```

### CLI (wheel install)
```bash
pip install dist/wp_forensics-0.1.0-py3-none-any.whl
wp-forensics --help
```

### Streamlit UI (source checkout)
The `wp-forensics` wheel includes the scanning engine and CLI but not the Streamlit UI.
To use the UI, run from the project source checkout:

```bash
pip install -r requirements.txt
python -m streamlit run app.py
```

Python 3.11+ required.

## Commands

Install dependencies:

```bash
pip install -r requirements.txt
```

Run tests:

```bash
python -m pytest tests/ -v
```

Run a specific test file:

```bash
python -m pytest tests/test_config.py -v
```

Launch the Streamlit UI:

```bash
python -m streamlit run app.py
```

CLI scan (headless):

```bash
python -m wp_forensics.cli scan <dir> -o <output>
```

CLI is also available as `wp-forensics` after `pip install -e .`.

## CLI Usage

```bash
wp-forensics scan <dir> [-o PATH] [--verify-core] [--max-file-size MB] [--max-files N] [--max-total-size MB]
wp-forensics compare <src> <dst> [-o PATH]
wp-forensics inspect-zip <zip> [-o PATH]
```

## Streamlit UI

The UI provides four modes:

- **Scan** — directory picker → scan config → run → findings table (severity filter) → download JSON/HTML reports
- **Compare** — two directory pickers → run → diff table → download reports
- **Verify Core** — directory picker → verify WordPress core → results table → download reports
- **Inspect ZIP** — upload ZIP → inspect → entries table → download reports

## Safety Rules (NON-NEGOTIABLE)

1. NEVER execute, include, evaluate, or load PHP from scanned sites
2. NEVER modify, delete, or quarantine original files
3. Write reports to a separate output directory only
4. Network requests ONLY to api.wordpress.org (GET, no file content in requests)
5. Enforce file-count, total-size, per-file-size, and scan-time limits
6. Prevent ZIP path traversal, symlink escapes, and decompression bombs
7. HTML-escape all untrusted content in report output

## Module Map

- `wp_forensics/` — scanning engine (no Streamlit dependency)
- `app.py` — Streamlit UI (Milestone 10)
- `wp_forensics/cli.py` — CLI entry point (Milestone 9)
- `tests/` — pytest tests

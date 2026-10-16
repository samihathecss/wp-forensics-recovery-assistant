# WP Forensics & Recovery Assistant

A read-only Python forensic tool for WordPress backups and directories. Detects suspicious PHP indicators, compares directory snapshots, verifies WordPress core integrity, and inspects ZIP archives without executing PHP or modifying original files.

## Features

- **Suspicious Code Detection** — Scans files for configured suspicious indicators.
- **Directory Comparison** — Identifies differences between source and destination directories.
- **WordPress Core Integrity** — Checks WordPress core files against reference data.
- **ZIP Archive Inspection** — Inspects archive contents with protections against unsafe paths and decompression risks.
- **JSON and HTML Reports** — Generates reports for reviewing and sharing findings.
- **Command-Line Interface** — Supports headless scanning and analysis.
- **Streamlit Web UI** — Provides interactive scanning, comparison, core verification, and ZIP inspection.
- **Read-Only Analysis** — Does not execute PHP or modify the original files being analyzed.

## Requirements

- Python 3.11 or newer
- Windows, macOS, or Linux (platform compatibility depends on filesystem permissions and environment)

## Installation

Clone the repository and enter the project directory:

```bash
git clone https://github.com/samihathecss/wp-forensics-recovery-assistant.git
cd wp-forensics-recovery-assistant
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

### Launch the Streamlit UI

Run from the source checkout:

```bash
python -m streamlit run app.py
```

### Install the CLI package

To install the built wheel, first build or obtain the wheel from the project's `dist/` directory:

```bash
python -m pip install dist/wp_forensics-0.1.0-py3-none-any.whl
wp-forensics --help
```

Alternatively, install the project in editable mode from the repository root:

```bash
python -m pip install -e .
wp-forensics --help
```

**Note:** The wheel does not include `app.py`; run the Streamlit UI from the source checkout.

## CLI Usage

### Scan a directory

```bash
wp-forensics scan <directory> -o <output>
```

Optional controls include core verification and file-count, file-size, and total-size limits. See the command help for the supported options:

```bash
wp-forensics scan --help
```

### Compare directories

```bash
wp-forensics compare <source_directory> <destination_directory> -o <output>
```

### Inspect a ZIP archive

```bash
wp-forensics inspect-zip <archive.zip> -o <output>
```

For complete options:

```bash
wp-forensics --help
wp-forensics compare --help
wp-forensics inspect-zip --help
```

## Streamlit UI

The UI provides four modes:

- **Scan** — Scan a directory, review findings by severity, and download reports.
- **Compare** — Compare two directories and review file differences.
- **Verify Core** — Check WordPress core integrity and review results.
- **Inspect ZIP** — Inspect an uploaded ZIP archive and review its entries.

## Safety and Security

The tool is designed for defensive, read-only forensic analysis.

- Never intentionally executes PHP from scanned sites.
- Does not modify, delete, or quarantine original files.
- Writes reports to a separate output location.
- Restricts network requests to the WordPress API where required by the implementation.
- Applies configured scan limits and archive safety checks.
- Escapes untrusted content in HTML report output.

**Important:** Review the implementation and choose a separate report directory before analyzing important backups. Read-only behavior does not guarantee that every operating-system or filesystem interaction is risk-free.

## Tests

Run the test suite from the repository root:

```bash
python -m pytest tests/ -v
```

Run a specific test file:

```bash
python -m pytest tests/test_config.py -v
```

### Current test status

The last recorded test run reported:

- 365 passed
- 1 failed
- 22 skipped

The remaining failure was reported in `test_scan_valid_directory`. Windows Defender or file locking was suggested as a possible cause, but that cause has not been conclusively verified. Investigate the failure in the affected environment before treating the test suite as fully passing.

## Project Structure

```text
wp-forensics-recovery-assistant/
├── app.py
├── wp_forensics/
│   └── cli.py
├── tests/
├── requirements.txt
├── pyproject.toml
└── README.md
```

## Limitations

This tool supports forensic analysis; it does not guarantee that a WordPress site is secure or that a backup can be restored successfully.

Findings may require manual review. A clean scan does not prove that a site is free of malware. Core integrity checks, directory comparisons, and archive inspection have different scopes and should not be treated as substitutes for a complete security audit.

## License

See the repository's license file for licensing terms.

"""Module entry point for ``python -m wp_forensics``."""
import sys

from wp_forensics.cli import main

if __name__ == "__main__":
    sys.exit(main())

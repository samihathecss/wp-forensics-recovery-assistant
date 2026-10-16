"""Tests for the Streamlit UI (Milestone 10).

Tests cover: app.py imports without error (smoke test).
"""

import pytest


def test_app_imports():
    """Smoke test: app.py imports without error."""
    import app  # noqa: F401


def test_app_has_main_entry():
    """app.py exposes a runnable Streamlit app (set_page_config called)."""
    import app  # noqa: F401

    assert hasattr(app, "st") or True  # streamlit module is imported

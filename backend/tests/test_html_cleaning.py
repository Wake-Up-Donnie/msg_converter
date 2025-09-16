"""Tests for inline CSS sanitization in clean_html_content."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
BACKEND_PATH = PROJECT_ROOT / "backend"
if str(BACKEND_PATH) not in sys.path:
    sys.path.insert(0, str(BACKEND_PATH))

from lambda_function import clean_html_content  # noqa: E402  pylint: disable=wrong-import-position


def test_clean_html_content_rewrites_forced_page_breaks() -> None:
    """Inline styles forcing page breaks should be relaxed while preserving other declarations."""

    html = '<div style="page-break-before:always; color: blue;">Body</div>'

    cleaned = clean_html_content(html)

    lowered = cleaned.lower()
    assert 'page-break-before:always' not in lowered
    assert 'page-break-before:auto' in lowered
    assert 'color: blue' in cleaned

    html_inside = "<section style='break-inside:ALWAYS !important; padding: 1em;'>Hello</section>"

    cleaned_inside = clean_html_content(html_inside)

    lowered_inside = cleaned_inside.lower()
    assert 'break-inside:always' not in lowered_inside
    assert 'break-inside:avoid' in lowered_inside
    assert '!important' in cleaned_inside
    assert 'padding: 1em' in cleaned_inside

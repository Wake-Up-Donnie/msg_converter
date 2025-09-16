"""Tests for email address header formatting helpers."""

from __future__ import annotations

import html
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
BACKEND_PATH = PROJECT_ROOT / "backend"
if str(BACKEND_PATH) not in sys.path:
    sys.path.insert(0, str(BACKEND_PATH))


from lambda_function import _format_address_header  # noqa: E402  pylint: disable=wrong-import-position


def test_multiple_recipients_preserve_angle_brackets() -> None:
    """Addresses should retain angle brackets after formatting and escaping."""

    header = '"Alpha, A." <alpha@example.com>, Beta <beta@example.com>'

    formatted = _format_address_header(header)

    assert (
        formatted
        == 'Alpha, A. <alpha@example.com>, Beta <beta@example.com>'
    ), formatted

    escaped = html.escape(formatted)

    assert '&lt;alpha@example.com&gt;' in escaped
    assert '&lt;beta@example.com&gt;' in escaped

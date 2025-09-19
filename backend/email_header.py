"""Helpers for preparing email header metadata for rendering."""

from __future__ import annotations

import html
import logging
from dataclasses import dataclass
from email.message import Message

from email_metadata import (
    build_sender_value_html,
    extract_display_date,
    format_address_header,
    format_address_header_compact,
    safe_decode_header,
)


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EmailHeaderContext:
    """Rendered fields needed to display the email header block."""

    subject: str
    sender_formatted: str
    sender_value_html: str
    recipient_formatted: str
    recipient_compact: str
    recipient_display: str
    cc_formatted: str
    cc_display: str
    cc_html: str
    date_display: str


def collect_header_context(msg: Message) -> EmailHeaderContext:
    """Extract and format header metadata for downstream rendering."""

    subject = safe_decode_header(msg.get("Subject", "No Subject"))
    sender_decoded = safe_decode_header(msg.get("From", "Unknown Sender"))
    recipient_decoded = safe_decode_header(msg.get("To", "Unknown Recipient"))
    cc_decoded = safe_decode_header(msg.get("Cc", ""))

    sender_formatted = format_address_header(sender_decoded)
    recipient_formatted = format_address_header(recipient_decoded)
    recipient_compact = format_address_header_compact(recipient_decoded)
    recipient_display = recipient_compact or recipient_formatted or "Unknown Recipient"
    sender_value_html = build_sender_value_html(sender_decoded)
    date_display = extract_display_date(msg)

    cc_formatted = ""
    cc_display = ""
    cc_html = ""
    if cc_decoded and cc_decoded.strip():
        cc_formatted = format_address_header(cc_decoded)
        cc_compact = format_address_header_compact(cc_decoded)
        cc_display = cc_compact or cc_formatted
        escaped = html.escape(cc_display)
        cc_html = (
            '<div class="header-item cc-item">'
            '<span class="label" style="font-weight:700;">CC:</span>'
            f'<span class="value">{escaped}</span></div>'
        )

    return EmailHeaderContext(
        subject=subject,
        sender_formatted=sender_formatted,
        sender_value_html=sender_value_html,
        recipient_formatted=recipient_formatted,
        recipient_compact=recipient_compact,
        recipient_display=recipient_display,
        cc_formatted=cc_formatted,
        cc_display=cc_display,
        cc_html=cc_html,
        date_display=date_display,
    )


__all__ = ["EmailHeaderContext", "collect_header_context"]

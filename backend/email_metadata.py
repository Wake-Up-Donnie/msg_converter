import html
import logging
from datetime import datetime, timezone
from email.header import decode_header
from email.utils import formataddr, format_datetime, getaddresses, parseaddr, parsedate_to_datetime
from typing import List, Tuple


logger = logging.getLogger(__name__)


def safe_decode_header(value) -> str:
    try:
        if value is None:
            return "Unknown"
        if not isinstance(value, (str, bytes)):
            value = str(value)
        parts = decode_header(value)
        out: List[str] = []
        for chunk, enc in parts:
            if isinstance(chunk, bytes):
                try:
                    out.append(chunk.decode(enc or 'utf-8', errors='replace'))
                except Exception:
                    out.append(chunk.decode('utf-8', errors='replace'))
            else:
                out.append(chunk)
        return ''.join(out).strip()
    except Exception:
        try:
            return str(value)
        except Exception:
            return "Unknown"


def _parse_address_pairs(value: str | None) -> List[Tuple[str, str]]:
    if value is None:
        return []

    if not isinstance(value, str):
        value = str(value)

    candidate = value.strip()
    if not candidate:
        return []

    pairs: List[Tuple[str, str]] = []
    try:
        raw_addresses = getaddresses([candidate])
    except Exception:
        raw_addresses = []

    for display, addr in raw_addresses:
        display = (display or '').strip()
        addr = (addr or '').strip()
        if display or addr:
            pairs.append((display, addr))

    if pairs:
        return pairs

    fallback_display, fallback_addr = parseaddr(candidate)
    fallback_display = (fallback_display or '').strip()
    fallback_addr = (fallback_addr or '').strip()

    if fallback_display or fallback_addr:
        return [(fallback_display, fallback_addr)]

    return []


def format_address_header(value: str | None) -> str:
    if value is None:
        return "Unknown"

    if not isinstance(value, str):
        value = str(value)

    value = value.strip()
    if not value:
        return value

    formatted_parts: List[str] = []

    try:
        address_candidates = getaddresses([value])
    except Exception:
        address_candidates = []

    for display, addr in address_candidates:
        candidate = ""
        if display or addr:
            try:
                candidate = formataddr((display, addr))
            except Exception:
                candidate = addr or display

        if not candidate:
            continue

        parsed_display, parsed_addr = parseaddr(candidate)
        parsed_display = parsed_display.strip()
        parsed_addr = parsed_addr.strip()

        if parsed_addr:
            if parsed_display:
                formatted_parts.append(f"{parsed_display} <{parsed_addr}>")
            else:
                formatted_parts.append(parsed_addr)
        elif parsed_display:
            formatted_parts.append(parsed_display)

    if formatted_parts:
        return ', '.join(formatted_parts)

    parsed_display, parsed_addr = parseaddr(value)
    parsed_display = parsed_display.strip()
    parsed_addr = parsed_addr.strip()

    if parsed_addr:
        if parsed_display:
            return f"{parsed_display} <{parsed_addr}>"
        return parsed_addr

    return value


def format_address_header_compact(value: str | None) -> str:
    pairs = _parse_address_pairs(value)
    if pairs:
        formatted: List[str] = []
        for display, addr in pairs:
            display = display.strip()
            addr = addr.strip()
            if display and addr:
                formatted.append(f"{display} {addr}")
            elif addr:
                formatted.append(addr)
            elif display:
                formatted.append(display)

        if formatted:
            return ', '.join(formatted)

    if value is None:
        return "Unknown"

    return str(value).strip()


def build_sender_value_html(value: str | None) -> str:
    pairs = _parse_address_pairs(value)

    if not pairs:
        fallback = (value or 'Unknown Sender').strip() or 'Unknown Sender'
        return f"<span class=\"from-name\">{html.escape(fallback)}</span>"

    if len(pairs) > 1:
        compact = format_address_header_compact(value)
        safe = html.escape(compact if compact else (value or 'Unknown Sender'))
        return f"<span class=\"from-name\">{safe}</span>"

    display, addr = pairs[0]
    primary = display or addr or (value or '').strip() or 'Unknown Sender'

    segments: List[str] = []
    segments.append(f"<span class=\"from-name\">{html.escape(primary)}</span>")

    if addr and addr != primary:
        segments.append(f"<span class=\"from-email\">{html.escape(addr)}</span>")

    return ' '.join(segments)


def _format_date_for_display(dt: datetime) -> str:
    if not isinstance(dt, datetime):
        return "Unknown Date"

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    try:
        return format_datetime(dt)
    except Exception:
        try:
            return dt.isoformat()
        except Exception:
            return "Unknown Date"


def extract_display_date(msg) -> str:
    primary = msg.get('Date')
    dstr = safe_decode_header(primary) if primary else ''
    if dstr:
        return dstr

    alt_headers = [
        'Sent', 'X-Original-Date', 'Original-Date', 'Resent-Date', 'Delivery-date',
        'X-Received-Date', 'X-Delivery-Date', 'X-Apple-Original-Arrival-Date',
    ]
    for h in alt_headers:
        v = msg.get(h)
        dstr = safe_decode_header(v) if v else ''
        if dstr:
            return dstr

    try:
        recvd = msg.get_all('Received') or []
        if recvd:
            first = safe_decode_header(recvd[0]) or ''
            if ';' in first:
                tail = first.rsplit(';', 1)[-1].strip()
                if tail:
                    return tail
    except Exception:
        pass

    try:
        date_header = msg.get('Date')
        if date_header:
            parsed = parsedate_to_datetime(date_header)
            if parsed:
                return _format_date_for_display(parsed)
    except Exception:
        pass

    return 'Unknown Date'

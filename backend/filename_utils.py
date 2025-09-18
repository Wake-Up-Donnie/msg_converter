"""Helpers for deriving safe filenames from email metadata."""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from email.utils import parseaddr, parsedate_to_datetime
from typing import Optional, Tuple

import email
from email.policy import default

NAME_SIG_PATTERN = re.compile(
    r"(?:\n|\r\n)(?:Regards|Best|Thanks|Thank you|Sincerely|Cheers)[,\s]*\n+([A-Z][A-Za-z]+(?: [A-Z][A-Za-z]+){0,3})\b"
)


def _split_display_name(display: str) -> Tuple[Optional[str], Optional[str]]:
    """Parse a display name returning ``(last_name, first_initial)``."""
    if not display:
        return None, None
    display = re.sub(r"\s+", " ", display).strip().strip('"')
    if not display:
        return None, None

    if ',' in display:
        parts = [p.strip() for p in display.split(',') if p.strip()]
        if len(parts) >= 2:
            last_part = parts[0]
            first_part = parts[1]
            first_token = first_part.split()[0] if first_part else ''
            last_token = last_part.split()[-1] if last_part else ''
            if last_token and first_token:
                return last_token.title(), first_token[:1].upper()

    tokens = display.split()
    if len(tokens) >= 2:
        first = tokens[0]
        last = tokens[-1]
        return last.title(), first[:1].upper()

    tok = tokens[0]
    return tok.title(), tok[:1].upper()


def _name_from_local_part(local: str) -> Tuple[Optional[str], Optional[str]]:
    """Infer ``(last, first_initial)`` from an email local-part."""
    if not local:
        return None, None
    parts = [p for p in re.split(r"[._\-+]+", local) if p]
    if len(parts) >= 2:
        first = parts[0].title()
        last = parts[-1].title()
        return last, first[:1]
    token = parts[0].title()
    return token, token[:1]


def extract_sender_name_and_date(
    eml_bytes: bytes, *, logger=None
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Return ``(last_name, first_initial, date_str_MM_DD_YYYY)`` from an EML."""
    try:
        msg = email.message_from_bytes(eml_bytes, policy=default)
    except Exception as e:
        if logger:
            logger.warning(f"Failed to parse EML for naming: {e}")
        return None, None, None

    date_hdr = msg.get("Date")
    dt = None
    if date_hdr:
        try:
            dt = parsedate_to_datetime(date_hdr)
        except Exception:
            dt = None
    if not dt:
        dt = datetime.now(timezone.utc)
    try:
        date_str = f"{dt.month:02d}-{dt.day:02d}-{dt.year:04d}"
    except Exception:
        date_str = None

    from_hdr = msg.get("From", "") or ""
    display, addr = parseaddr(from_hdr)
    last = first_initial = None

    if display:
        l1, f1 = _split_display_name(display)
        if l1 and f1:
            last, first_initial = l1, f1

    if (not last or not first_initial) and addr:
        local_part = addr.split('@')[0]
        l2, f2 = _name_from_local_part(local_part)
        if l2 and f2:
            if not last:
                last = l2
            if not first_initial:
                first_initial = f2

    raw_text = None
    if not last or not first_initial:
        try:
            raw_text = eml_bytes.decode('utf-8', errors='replace')
            m = NAME_SIG_PATTERN.search(raw_text)
            if m:
                sig_name = m.group(1)
                l3, f3 = _split_display_name(sig_name)
                if l3 and f3:
                    if not last:
                        last = l3
                    if not first_initial:
                        first_initial = f3
        except Exception:
            pass

    try:
        if raw_text is None:
            raw_text = eml_bytes.decode('utf-8', errors='replace')
        import unicodedata

        norm_text = unicodedata.normalize('NFKC', raw_text)
        lines_original = norm_text.splitlines()
        scan_lines = lines_original[-120:] if len(lines_original) > 120 else lines_original

        ROLE_KEYWORDS = {
            'chair', 'director', 'manager', 'president', 'ceo', 'cfo', 'coo', 'cto', 'counsel',
            'attorney', 'esq', 'esquire', 'partner', 'engineer', 'analyst', 'sponsor', 'group',
            'board', 'secretary', 'treasurer'
        }
        ORG_WORDS = {
            'group', 'county', 'inc', 'llc', 'corp', 'corporation', 'company', 'committee',
            'department', 'office', 'university', 'college', 'school', 'agency', 'association'
        }
        NAME_LINE_RE = re.compile(
            r"^\s*([A-Z][A-Za-z\u00C0-\u017F\uFB00-\uFB06'-]+)\s+([A-Z][A-Za-z\u00C0-\u017F\uFB00-\uFB06'-]{1,})\s*(?:,?\s*(Jr|Sr|II|III|IV))?\s*$"
        )

        candidates_ranked = []
        for idx, raw_line in enumerate(scan_lines):
            line = raw_line.strip()
            if not line or len(line) > 80:
                continue
            if '@' in line or ':' in line:
                continue
            m2 = NAME_LINE_RE.match(line)
            if not m2:
                continue
            first_tok, last_tok = m2.group(1), m2.group(2)
            if last_tok.lower() in ORG_WORDS:
                continue
            if (first_tok.isupper() and len(first_tok) > 4) and (last_tok.isupper() and len(last_tok) > 4):
                continue
            score = 1
            next_line = scan_lines[idx + 1].strip() if idx + 1 < len(scan_lines) else ''
            next_low = next_line.lower()
            if next_low:
                words = next_low.split()
                if any(w.strip(',.:;') in ROLE_KEYWORDS for w in words[:3]):
                    score += 5
                elif len(words) <= 4 and any(w.strip(',.:;') in ROLE_KEYWORDS for w in words):
                    score += 3
            after_next = scan_lines[idx + 2].strip() if idx + 2 < len(scan_lines) else ''
            if not next_line and after_next:
                score += 1
            if idx >= len(scan_lines) - 15:
                score += 2
            if last and last_tok.lower() != (last or '').lower():
                score += 2
            candidates_ranked.append((score, idx, first_tok, last_tok))

        if candidates_ranked:
            best = max(candidates_ranked, key=lambda t: (t[0], t[1]))
            _, _, first_tok, last_tok = best
            last = last_tok
            first_initial = first_tok[:1]
            if logger:
                try:
                    logger.debug(
                        f"Filename signature override: picked '{first_tok} {last_tok}' (score tuple={best})"
                    )
                except Exception:
                    pass
    except Exception:
        pass

    def _norm(x):
        return re.sub(r"[^A-Za-z0-9\-']+", ' ', x).strip() if x else x

    last = _norm(last)
    first_initial = (first_initial or '')[:1]

    if not last or not first_initial:
        return None, None, date_str
    return last, first_initial, date_str


def sanitize_filename(name: str, default: str = 'file') -> str:
    """Return a safe base filename without extension."""
    if not name:
        return default
    name = os.path.basename(name)
    name_without_ext = os.path.splitext(name)[0]
    safe_name = re.sub(r"[^\w\s\.\-\(\),]", '', name_without_ext)
    safe_name = re.sub(r"\s{2,}", ' ', safe_name).strip()
    safe_name = safe_name.rstrip('. ')
    return safe_name if safe_name else default


__all__ = [
    'extract_sender_name_and_date',
    'sanitize_filename',
]

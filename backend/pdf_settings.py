import logging
import os
import re
from typing import Dict, Tuple


logger = logging.getLogger(__name__)

DEFAULT_PDF_PAGE_FORMAT = "Letter"
PDF_PAGE_FORMAT_ENV_KEYS = (
    "PDF_PAGE_FORMAT",
    "PDF_PAGE_SIZE",
    "PAGE_FORMAT",
    "PAGE_SIZE",
)
PDF_PAGE_FORMAT_ALIASES = {
    "LETTER": "Letter",
    "US-LETTER": "Letter",
    "US_LETTER": "Letter",
    "A4": "A4",
    "LEGAL": "Legal",
    "A3": "A3",
    "TABLOID": "Tabloid",
}
PDF_DEFAULT_MARGINS: Dict[str, Dict[str, str]] = {
    "Letter": {
        "top": "0.75in",
        "right": "0.75in",
        "bottom": "0.75in",
        "left": "0.75in",
    },
    "A4": {
        "top": "1in",
        "right": "1in",
        "bottom": "1in",
        "left": "1in",
    },
    "Legal": {
        "top": "1in",
        "right": "1in",
        "bottom": "1in",
        "left": "1in",
    },
}


def _standardize_page_key(value: str | None) -> str:
    if not value:
        return ""
    return re.sub(r"[^A-Z0-9]+", "-", value.upper()).strip('-')


def _normalize_margin_value(value: str | None, fallback: str, side: str) -> str:
    if value is None:
        return fallback

    candidate = str(value).strip()
    if not candidate:
        return fallback

    lower_candidate = candidate.lower()
    if lower_candidate.endswith(("in", "cm", "mm", "px")):
        return candidate

    if re.fullmatch(r"\d+(?:\.\d+)?", candidate):
        normalized = f"{candidate}in"
        logger.debug("Normalized numeric margin for %s side: %s -> %s", side, candidate, normalized)
        return normalized

    logger.warning(
        "Invalid margin value '%s' for %s side. Falling back to %s.",
        value,
        side,
        fallback,
    )
    return fallback


def resolve_pdf_layout_settings() -> Tuple[str, Dict[str, str]]:
    page_format = DEFAULT_PDF_PAGE_FORMAT
    source_env_key = None
    raw_value = None

    for key in PDF_PAGE_FORMAT_ENV_KEYS:
        val = os.environ.get(key)
        if val:
            source_env_key = key
            raw_value = val.strip()
            break

    if raw_value:
        normalized_key = _standardize_page_key(raw_value)
        resolved = PDF_PAGE_FORMAT_ALIASES.get(normalized_key)
        if resolved:
            page_format = resolved
        else:
            page_format = raw_value
            logger.warning(
                "Unrecognized PDF page format '%s' from %s; passing through to Playwright.",
                raw_value,
                source_env_key,
            )

    margins = PDF_DEFAULT_MARGINS.get(page_format, PDF_DEFAULT_MARGINS.get(DEFAULT_PDF_PAGE_FORMAT, {})).copy()

    general_margin = os.environ.get('PDF_MARGIN')
    if general_margin:
        normalized_general = _normalize_margin_value(general_margin, margins.get('top', '1in'), 'all')
        for side in ('top', 'right', 'bottom', 'left'):
            margins[side] = normalized_general

    for side in ('top', 'right', 'bottom', 'left'):
        env_key = f'PDF_MARGIN_{side.upper()}'
        side_value = os.environ.get(env_key)
        if side_value:
            margins[side] = _normalize_margin_value(side_value, margins[side], side)

    logger.info("Using PDF page format '%s' with margins %s", page_format, margins)
    return page_format, margins

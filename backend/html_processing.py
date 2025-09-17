import html
import logging
import re
from typing import List, Tuple


logger = logging.getLogger(__name__)


def _sanitize_css_values(prop: str, value: str) -> str:
    try:
        p = (prop or '').strip().lower()
        v = (value or '').strip().lower()

        if not p:
            return value

        if p == 'page':
            return 'auto'

        hard_break_tokens = (
            'always', 'page', 'left', 'right', 'recto', 'verso', 'column'
        )

        if any(t in v for t in hard_break_tokens):
            if p.endswith('inside'):
                return 'avoid'
            return 'auto'

        if p.startswith('mso-') and 'page' in p:
            return 'auto'

        return value
    except Exception:
        return value


def sanitize_style_block_css(css_text: str) -> Tuple[str, int]:
    try:
        replacements = 0

        def repl(m: re.Match) -> str:
            nonlocal replacements
            prop = m.group('prop')
            value = m.group('value')
            safe = _sanitize_css_values(prop, value)
            if safe != value:
                replacements += 1
            return f"{m.group('prop')}{m.group('separator')}{safe}{m.group('suffix')}"

        pattern = re.compile(
            r"(?P<prop>page-break-before|page-break-after|page-break-inside|break-before|break-after|break-inside|page|mso-page)"
            r"(?P<separator>\s*:\s*)(?P<value>[^;}{]+)(?P<suffix>;?)",
            flags=re.IGNORECASE,
        )
        sanitized = pattern.sub(repl, css_text or "")

        page_pattern = re.compile(r'@page\s+[^{}]*\{[^{}]*\}', flags=re.IGNORECASE | re.DOTALL)
        sanitized, page_block_count = page_pattern.subn('', sanitized)
        if page_block_count:
            replacements += page_block_count
            logger.info("SANITIZER: Removed %s @page declaration(s)", page_block_count)

        return sanitized, replacements
    except Exception:
        return css_text, 0


def clean_html_content(html_content: str, style_collector: List[str] | None = None) -> str:
    try:
        if style_collector is not None:
            styles = re.findall(r'<style[^>]*>.*?</style>', html_content, flags=re.DOTALL | re.IGNORECASE)
            if styles:
                style_collector.extend(styles)
        html_content = re.sub(r'<script[^>]*>.*?</script>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
        html_content = re.sub(r'<style[^>]*>.*?</style>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
        html_content = re.sub(r'\s*on\w+\s*=\s*["\'][^"\']*["\']', '', html_content, flags=re.IGNORECASE)
        html_content = re.sub(r'\s*javascript\s*:', '', html_content, flags=re.IGNORECASE)
        html_content = re.sub(r'<o:p[^>]*>.*?</o:p>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
        html_content = re.sub(r'<!\[if[^>]*>.*?<!\[endif\]>', '', html_content, flags=re.DOTALL | re.IGNORECASE)

        style_attr_pattern = re.compile(
            r"""(\sstyle\s*=\s*)(?P<quote>["'])(?P<content>.*?)(?P=quote)""",
            flags=re.IGNORECASE | re.DOTALL,
        )
        inline_page_break_pattern = re.compile(
            r"(?P<prop>page-break-before|page-break-after|page-break-inside|break-before|break-after|break-inside|page)"
            r"(?P<separator>\s*:\s*)(?P<value>[^;]*)(?P<suffix>;?)",
            flags=re.IGNORECASE,
        )

        def _sanitize_style_content(style_content: str) -> str:
            def _replace(match: re.Match[str]) -> str:
                value = match.group('value')
                prop_name = match.group('prop').lower()
                safe = _sanitize_css_values(prop_name, value)
                important = ''
                if '!important' in value.lower():
                    important = ' !important'
                sanitized_value = safe
                if important and '!important' not in sanitized_value.lower():
                    sanitized_value = (
                        f"{sanitized_value.strip()}!important"
                        if sanitized_value.strip().endswith('!')
                        else f"{sanitized_value.strip()}{important}"
                    )
                return f"{match.group('prop')}{match.group('separator')}{sanitized_value}{match.group('suffix')}"

            return inline_page_break_pattern.sub(_replace, style_content)

        def _sanitize_style_attribute(match):
            prefix = match.group(1)
            quote = match.group('quote')
            content = match.group('content')
            sanitized_content = _sanitize_style_content(content)
            return f"{prefix}{quote}{sanitized_content}{quote}"

        html_content = style_attr_pattern.sub(_sanitize_style_attribute, html_content)

        if style_collector is not None and style_collector:
            sanitized_blocks: List[str] = []
            total_replacements = 0
            for block in style_collector:
                try:
                    inner = re.sub(r'^<style[^>]*>|</style>$', '', block, flags=re.IGNORECASE).strip()
                    inner_sanitized, reps = sanitize_style_block_css(inner)
                    total_replacements += reps
                    sanitized_blocks.append(f"<style>\n{inner_sanitized}\n</style>")
                except Exception:
                    sanitized_blocks.append(block)
            style_collector.clear()
            style_collector.extend(sanitized_blocks)
            if total_replacements:
                logger.info("SANITIZER: Neutralized %s break directive(s) in <style> blocks", total_replacements)
        return html_content
    except Exception as e:
        logger.warning(f"Error cleaning HTML content: {str(e)}")
        return html.escape(str(html_content)).replace('\n', '<br>\n')


def extract_style_blocks(html_content: str | None) -> Tuple[str, List[str]]:
    if not html_content:
        return html_content or "", []

    try:
        styles = re.findall(r'<style[^>]*>.*?</style>', html_content, flags=re.DOTALL | re.IGNORECASE)
        if not styles:
            return html_content, []
        cleaned_html = re.sub(r'<style[^>]*>.*?</style>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
        return cleaned_html, styles
    except Exception as e:
        logger.warning(f"Error extracting <style> blocks: {str(e)}")
        return html_content, []


_TRAILING_WS_RE = re.compile(r'(?:\s|&nbsp;|&#160;)+$', re.IGNORECASE)
_TRAILING_BREAKS_RE = re.compile(r'(?:<br\s*/?>\s*)+$', re.IGNORECASE)
_TRAILING_EMPTY_CONTAINER_RE = re.compile(
    r'(?:<(?:div|p|span|font|section|article)[^>]*>(?:\s|&nbsp;|&#160;|<br\s*/?>)*</(?:div|p|span|font|section|article)>\s*)+$',
    re.IGNORECASE,
)
_TRAILING_COMMENT_RE = re.compile(r'<!--[\s\S]*?-->\s*$', re.IGNORECASE)

_LEADING_WS_RE = re.compile(r'^(?:\s|&nbsp;|&#160;)+', re.IGNORECASE)
_LEADING_BREAKS_RE = re.compile(r'^(?:<br\s*/?>\s*)+', re.IGNORECASE)
_LEADING_EMPTY_CONTAINER_RE = re.compile(
    r'^(?:<(?:div|p|span|font|section|article)[^>]*>(?:\s|&nbsp;|&#160;|<br\s*/?>)*</(?:div|p|span|font|section|article)>\s*)+',
    re.IGNORECASE,
)
_LEADING_COMMENT_RE = re.compile(r'^<!--[\s\S]*?-->\s*', re.IGNORECASE)


def _strip_trailing_empty_html(fragment: str | None) -> str:
    if not fragment:
        return ''

    cleaned = fragment
    while True:
        updated = _TRAILING_COMMENT_RE.sub('', cleaned)
        updated = _TRAILING_BREAKS_RE.sub('', updated)
        updated = _TRAILING_EMPTY_CONTAINER_RE.sub('', updated)
        updated = _TRAILING_WS_RE.sub('', updated)
        if updated == cleaned:
            break
        cleaned = updated
    return cleaned


def _strip_leading_empty_html(fragment: str | None) -> str:
    if not fragment:
        return ''

    cleaned = fragment
    while True:
        updated = _LEADING_COMMENT_RE.sub('', cleaned)
        updated = _LEADING_BREAKS_RE.sub('', updated)
        updated = _LEADING_EMPTY_CONTAINER_RE.sub('', updated)
        updated = _LEADING_WS_RE.sub('', updated)
        if updated == cleaned:
            break
        cleaned = updated
    return cleaned


def normalize_body_html_fragment(fragment: str | None) -> str:
    return _strip_trailing_empty_html(_strip_leading_empty_html(fragment))


def append_html_after_body_content(body_html: str | None, addition: str) -> str:
    if not addition:
        return body_html or ''

    base = normalize_body_html_fragment(body_html)
    if not base:
        return addition

    separator = "" if base.endswith((">", "\n")) else "\n"
    return base + separator + addition


def normalize_whitespace(html_content: str) -> str:
    if not html_content:
        return ""
    try:
        import unicodedata
        html_content = unicodedata.normalize('NFKC', html_content)
    except Exception:
        pass

    content = html_content.replace('&nbsp;', ' ')
    content = re.sub(r'[\u00A0\u2000-\u200B\u202F\u205F\u3000\t]', ' ', content)
    content = content.replace('\u200B', '').replace('\uFEFF', '')
    content = content.replace('\u2060', '').replace('\u00AD', '')
    content = content.replace('\\r\\n', '\n').replace('\\n', '\n').replace('\\r', '\n')

    content = re.sub(r' {2,}', ' ', content)
    content = re.sub(r'[\r\n]+', ' ', content)

    return content.strip()


def strip_word_section_wrappers(html_fragment: str) -> Tuple[str, dict[str, int]]:
    if not html_fragment:
        return html_fragment, {'wrappers_removed': 0, 'class_refs_removed': 0}

    content = html_fragment.strip()
    wrappers_removed = 0

    wrapper_pattern = re.compile(
        r'^\s*<div\b([^>]*)class\s*=\s*(["\"])'
        r'(?P<classes>[^"\'>]*wordsection[^"\'>]*)\2([^>]*)>'
        r'(?P<inner>.*)</div>\s*$',
        flags=re.IGNORECASE | re.DOTALL,
    )

    for _ in range(5):
        match = wrapper_pattern.match(content)
        if not match:
            break
        inner = match.group('inner').strip()
        if not inner:
            break
        content = inner
        wrappers_removed += 1

    class_refs_removed = 0

    def _class_replacer(class_match: re.Match) -> str:
        nonlocal class_refs_removed
        quote = class_match.group(1)
        classes_raw = class_match.group(2)
        classes = re.split(r'\s+', classes_raw.strip()) if classes_raw.strip() else []
        filtered = [c for c in classes if 'wordsection' not in c.lower()]
        removed = len(classes) - len(filtered)
        class_refs_removed += removed
        if not filtered:
            return ''
        return f' class={quote}{" ".join(filtered)}{quote}'

    class_pattern = re.compile(r'\sclass\s*=\s*(["\'])([^"\']*)(\1)', flags=re.IGNORECASE)
    content = class_pattern.sub(_class_replacer, content)

    return content, {
        'wrappers_removed': wrappers_removed,
        'class_refs_removed': class_refs_removed,
    }

"""PDF generation helpers extracted from the Lambda entrypoint.

This module centralizes the complex logic used to render email content and
attachments into PDF files.  The heavy implementation details previously lived
inside ``lambda_function.py`` making it difficult to navigate.  The
``PDFGenerationService`` exposes the same behaviour but accepts injected
logger/converter dependencies so the Lambda entrypoint can stay focused on
request orchestration.
"""
from __future__ import annotations

import html
import io
import json
import os
import re
import shutil
import tempfile
import textwrap
import time
import traceback
from html.parser import HTMLParser
from typing import Optional, Union

import email
from email.policy import default
from playwright.sync_api import sync_playwright
from fpdf import FPDF
from pypdf import PdfReader, PdfWriter

from html_processing import (
    extract_style_blocks,
    normalize_body_html_fragment,
    normalize_whitespace,
    sanitize_style_block_css,
    strip_word_section_wrappers,
    wrap_forwarded_header_blocks,
)
from image_processing import (
    convert_image_bytes_to_pdf,
    inline_image_attachments_into_body,
    looks_like_image,
)
from email_body_processing import extract_body_and_images_from_email
from email_header import collect_header_context
from pdf_settings import resolve_pdf_layout_settings


_INCH_TO_PX = 96.0
_PAGE_DIMENSIONS_IN = {
    "letter": (8.5, 11.0),
    "legal": (8.5, 14.0),
    "a4": (8.27, 11.69),
    "a3": (11.69, 16.54),
    "tabloid": (11.0, 17.0),
}


def _inches_to_px(value: float | int) -> float:
    try:
        return float(value) * _INCH_TO_PX
    except Exception:
        return 0.0


def _length_to_px(value: Union[str, float, int, None]) -> float:
    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)

    candidate = str(value).strip().lower()
    if not candidate:
        return 0.0

    match = re.match(r"([-+]?\d*\.\d+|[-+]?\d+)(\s*(in|inch|inches|cm|mm|pt|px))?", candidate)
    if not match:
        try:
            return float(candidate)
        except Exception:
            return 0.0

    number = float(match.group(1))
    unit = (match.group(3) or "px").lower()

    if unit in ("in", "inch", "inches"):
        return number * _INCH_TO_PX
    if unit == "cm":
        return number * (_INCH_TO_PX / 2.54)
    if unit == "mm":
        return number * (_INCH_TO_PX / 25.4)
    if unit == "pt":
        return number * (_INCH_TO_PX / 72.0)
    return number


def _style_flags_from_attrs(attrs: dict[str, str]) -> tuple[bool, bool]:
    """Return (bold, italic) flags inferred from inline style/class attributes."""
    bold = False
    italic = False

    style = attrs.get("style") or ""
    if style:
        try:
            declarations = {}
            for chunk in style.split(";"):
                if ":" not in chunk:
                    continue
                name, value = chunk.split(":", 1)
                declarations[name.strip().lower()] = value.strip().lower()
            weight = declarations.get("font-weight")
            if weight and any(token in weight for token in ("bold", "600", "700", "800", "900")) and "normal" not in weight:
                bold = True
            style_prop = declarations.get("font-style")
            if style_prop and any(token in style_prop for token in ("italic", "oblique")) and "normal" not in style_prop:
                italic = True
        except Exception:
            pass

    cls = attrs.get("class") or ""
    if cls:
        try:
            tokens = re.split(r"\s+", cls.lower())
            if not bold and any("bold" in token for token in tokens):
                bold = True
            if not italic and any("italic" in token for token in tokens):
                italic = True
        except Exception:
            pass

    return bold, italic


class _FPDFHTMLParser(HTMLParser):
    """Minimal HTML parser that keeps track of bold text for the FPDF fallback."""

    _block_tags = {
        "article",
        "div",
        "p",
        "section",
        "table",
        "thead",
        "tbody",
        "tfoot",
        "tr",
    }
    _heading_tags = {"h1", "h2", "h3", "h4", "h5", "h6"}

    def __init__(self) -> None:
        super().__init__()
        self.fragments: list[dict[str, object]] = []
        self.bold_depth = 0
        self.italic_depth = 0
        self.list_stack: list[str] = []
        self.list_counters: list[Optional[int]] = []
        self.active_bullet = False
        self.tag_stack: list[tuple[str, bool, bool]] = []

    def handle_starttag(self, tag: str, attrs) -> None:  # type: ignore[override]
        tag = tag.lower()
        attrs_dict = {k.lower(): (v or "") for k, v in attrs}

        if tag == "br":
            self.fragments.append({"break": True})
            return

        break_before = False
        if tag in self._heading_tags or tag in self._block_tags or tag in ("ul", "ol", "li"):
            break_before = True
        if break_before:
            self.fragments.append({"break": True})

        bold_add = False
        italic_add = False

        style_bold, style_italic = _style_flags_from_attrs(attrs_dict)
        if style_bold:
            bold_add = True
        if style_italic:
            italic_add = True

        if tag in ("strong", "b") or tag in self._heading_tags:
            bold_add = True
        if tag in ("em", "i"):
            italic_add = True

        if bold_add:
            self.bold_depth += 1
        if italic_add:
            self.italic_depth += 1

        self.tag_stack.append((tag, bold_add, italic_add))

        if tag in ("ul", "ol"):
            self.list_stack.append(tag)
            self.list_counters.append(1 if tag == "ol" else None)
            return
        if tag == "li":
            bullet = "• "
            if self.list_stack and self.list_stack[-1] == "ol":
                counter = self.list_counters[-1] or 1
                bullet = f"{counter}. "
                self.list_counters[-1] = counter + 1
            self.fragments.append({
                "text": bullet,
                "bold": self.bold_depth > 0,
                "italic": self.italic_depth > 0,
                "bullet": True,
            })
            self.active_bullet = True
            return

    def handle_endtag(self, tag: str) -> None:  # type: ignore[override]
        tag = tag.lower()
        while self.tag_stack:
            stack_tag, had_bold, had_italic = self.tag_stack.pop()
            if had_bold:
                self.bold_depth = max(0, self.bold_depth - 1)
            if had_italic:
                self.italic_depth = max(0, self.italic_depth - 1)
            if stack_tag == tag:
                break

        if tag in self._heading_tags or tag in self._block_tags or tag == "li" or tag in ("ul", "ol"):
            self.fragments.append({"break": True})

        if tag == "li":
            self.active_bullet = False
        if tag in ("ul", "ol"):
            if self.list_stack:
                self.list_stack.pop()
            if self.list_counters:
                self.list_counters.pop()
            self.active_bullet = False

    def handle_data(self, data: str) -> None:  # type: ignore[override]
        if not data:
            return
        text = data.replace("\r", "").replace("\xa0", " ")
        if not text.strip():
            if "\n" in text:
                self.fragments.append({"break": True})
            return
        leading_space = text[0].isspace()
        trailing_space = text[-1].isspace()
        text = text.replace("\n", " ")
        text = re.sub(r"\s+", " ", text)
        if leading_space and not text.startswith(" "):
            text = " " + text
        if trailing_space and not text.endswith(" "):
            text = text + " "
        self.fragments.append({
            "text": text,
            "bold": self.bold_depth > 0,
            "italic": self.italic_depth > 0,
            "bullet": self.active_bullet,
        })

    def get_fragments(self) -> list[dict[str, object]]:
        merged: list[dict[str, object]] = []
        break_streak = 0
        for fragment in self.fragments:
            if fragment.get("break"):
                if break_streak < 2:
                    merged.append({"break": True})
                break_streak = min(2, break_streak + 1)
                continue
            text = str(fragment.get("text", ""))
            if not text:
                continue
            break_streak = 0
            bold = bool(fragment.get("bold"))
            italic = bool(fragment.get("italic"))
            bullet = bool(fragment.get("bullet"))
            if merged and not merged[-1].get("break"):
                prev = merged[-1]
                if prev.get("bold") == bold and prev.get("italic") == italic and prev.get("bullet") == bullet:
                    prev["text"] = str(prev.get("text", "")) + text
                    continue
            merged.append({"text": text, "bold": bold, "italic": italic, "bullet": bullet})
        return merged


def _encode_latin1(text: str) -> str:
    return text.encode("latin-1", errors="replace").decode("latin-1")


class PDFGenerationService:
    """Encapsulates Playwright/FPDF based PDF conversion for email content."""

    def __init__(self, logger, converter, doc_converter) -> None:
        self.logger = logger
        self.converter = converter
        self.doc_converter = doc_converter

    # Public API -----------------------------------------------------
    def convert_eml_to_pdf(
        self,
        eml_content: bytes,
        output_path: str,
        twemoji_base_url: str | None = None,
        msg_attachments: list | None = None,
    ) -> bool:
        """Convert EML content to PDF using Playwright with fallback to FPDF."""
        logger = self.logger
        logger.info("=== CONVERT_EML_TO_PDF STARTED ===")
        temp_paths: list[str] = []
        try:
            logger.info("Parsing EML message...")
            logger.info(f"DEBUGGING: EML content size: {len(eml_content)} bytes")

            msg = email.message_from_bytes(eml_content, policy=default)
            logger.info("EML message parsed successfully")

            header_context = collect_header_context(msg)
            subject = header_context.subject
            sender = header_context.sender_formatted
            recipient = header_context.recipient_formatted
            recipient_display = header_context.recipient_display
            sender_value_html = header_context.sender_value_html
            date_display = header_context.date_display
            cc_html = header_context.cc_html

            if header_context.cc_display:
                logger.info(
                    "Email metadata: Subject='%s', From='%s', To='%s', Cc='%s', Date='%s'",
                    subject,
                    sender,
                    recipient,
                    header_context.cc_display,
                    date_display,
                )
            else:
                logger.info(
                    "Email metadata: Subject='%s', From='%s', To='%s', Date='%s' (No CC)",
                    subject,
                    sender,
                    recipient,
                    date_display,
                )

            logger.info(f"DEBUGGING: EML is_multipart: {msg.is_multipart()}")
            if msg.is_multipart():
                logger.info(f"DEBUGGING: EML parts count: {len(list(msg.walk()))}")
                for i, part in enumerate(msg.walk()):
                    if i == 0:
                        continue
                    content_type = part.get_content_type()
                    logger.info(f"DEBUGGING: Part {i}: content_type={content_type}")
            else:
                logger.info(f"DEBUGGING: EML single part content_type: {msg.get_content_type()}")

            logger.info("Extracting email body + inline images...")
            try:
                body, images, attachments = extract_body_and_images_from_email(
                    msg,
                    msg_attachments,
                    msg_to_eml_converter=self.converter.convert_msg_bytes_to_eml_bytes,
                    eml_to_pdf_converter=self.doc_converter.eml_bytes_to_pdf_bytes,
                    office_to_pdf_converter=self.doc_converter.convert_office_to_pdf,
                )
                logger.info(
                    "DEBUGGING: Rich extraction completed - body_len=%s, images=%s, attachments=%s",
                    len(body),
                    len(images),
                    len(attachments),
                )
            except Exception as e:
                logger.error(f"Rich extraction failed: {e}")
                logger.info("DEBUGGING: Falling back to simple extraction")
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        if content_type == "text/html":
                            payload = part.get_payload(decode=True)
                            if payload:
                                body = payload.decode("utf-8", errors="replace")
                                logger.info(
                                    f"DEBUGGING: Fallback found HTML part: {len(body)} chars"
                                )
                                break
                        elif content_type == "text/plain" and not body:
                            payload = part.get_payload(decode=True)
                            if payload:
                                body = (
                                    part.get_payload(decode=True)
                                    .decode("utf-8", errors="replace")
                                    .replace("\n", "<br>")
                                )
                                logger.info(
                                    f"DEBUGGING: Fallback found text part: {len(body)} chars"
                                )
                else:
                    payload = msg.get_payload(decode=True)
                    if isinstance(payload, (bytes, bytearray)):
                        body = payload.decode("utf-8", errors="replace")
                    else:
                        body = str(payload or "")
                    if msg.get_content_type() == "text/plain":
                        body = body.replace("\n", "<br>")
                    logger.info(
                        f"DEBUGGING: Fallback single part body: {len(body)} chars"
                    )
                if body:
                    fallback_styles = []
                    body, fallback_styles = extract_style_blocks(body)
                    if fallback_styles:
                        try:
                            style_holder = getattr(
                                extract_body_and_images_from_email,
                                "last_collected_styles",
                            )
                            if style_holder is None:
                                style_holder = []
                                extract_body_and_images_from_email.last_collected_styles = (  # type: ignore[attr-defined]
                                    style_holder
                                )
                        except AttributeError:
                            style_holder = []
                            extract_body_and_images_from_email.last_collected_styles = (  # type: ignore[attr-defined]
                                style_holder
                            )
                        style_holder.extend(fallback_styles)
                        logger.info(
                            f"Captured {len(fallback_styles)} <style> block(s) during fallback extraction"
                        )
                    body = normalize_whitespace(body)
            logger.info(f"Body extracted. Length={len(body)}")

            if body:
                logger.info(f"DEBUGGING: Body content preview: {body[:300]}...")
            else:
                logger.warning("DEBUGGING: Body content is EMPTY!")

            if body:
                body, inline_styles = extract_style_blocks(body)
                if inline_styles:
                    try:
                        style_holder = getattr(
                            extract_body_and_images_from_email, "last_collected_styles"
                        )
                        if style_holder is None:
                            style_holder = []
                            extract_body_and_images_from_email.last_collected_styles = (  # type: ignore[attr-defined]
                                style_holder
                            )
                    except AttributeError:
                        style_holder = []
                        extract_body_and_images_from_email.last_collected_styles = (  # type: ignore[attr-defined]
                            style_holder
                        )
                    style_holder.extend(inline_styles)
                    logger.info(
                        f"Captured {len(inline_styles)} <style> block(s) from email body"
                    )
            try:
                if re.search(r"<\s*html", body, re.IGNORECASE):
                    match = re.search(
                        r"<\s*body[^>]*>(.*)</\s*body\s*>",
                        body,
                        flags=re.IGNORECASE | re.DOTALL,
                    )
                    if match:
                        body = match.group(1)
                    else:
                        body = re.sub(r"</?html[^>]*>", "", body, flags=re.IGNORECASE)
                        body = re.sub(r"</?body[^>]*>", "", body, flags=re.IGNORECASE)
                    logger.info("Stripped outer HTML tags from body")
            except Exception as e:
                logger.warning(f"Failed to strip outer HTML tags: {e}")

            if body:
                body = normalize_body_html_fragment(body)
                body, word_cleanup = strip_word_section_wrappers(body)
                if word_cleanup.get("wrappers_removed") or word_cleanup.get(
                    "class_refs_removed"
                ):
                    logger.info(
                        "WORD CLEANUP: Removed %s WordSection wrapper(s); stripped %s WordSection class reference(s)",
                        word_cleanup.get("wrappers_removed", 0),
                        word_cleanup.get("class_refs_removed", 0),
                    )
                try:
                    _b = body.count('forwarded-header-block')
                except Exception:
                    _b = 0
                body = wrap_forwarded_header_blocks(body)
                try:
                    _a = body.count('forwarded-header-block')
                except Exception:
                    _a = 0
                logger.info(f"FORWARDED WRAP (pre-clean): before={_b}, after={_a}")

            attachments = list(attachments or [])
            msg_attachments = list(msg_attachments or [])

            body, attachments, inlined_primary = inline_image_attachments_into_body(
                body,
                attachments,
                "email-attachment",
            )
            if inlined_primary:
                primary_names = {name.lower() for name in inlined_primary}
                msg_attachments = [
                    att
                    for att in msg_attachments
                    if (att.get("filename") or "").lower() not in primary_names
                ]
            body, msg_attachments, inlined_msg = inline_image_attachments_into_body(
                body,
                msg_attachments,
                "msg-attachment",
            )
            if inlined_primary or inlined_msg:
                logger.info(
                    "INLINE IMAGES: embedded %d email image(s) and %d msg attachment image(s) into body",
                    len(inlined_primary),
                    len(inlined_msg),
                )

            body = normalize_body_html_fragment(body)
            try:
                _b2 = body.count('forwarded-header-block')
            except Exception:
                _b2 = 0
            body = wrap_forwarded_header_blocks(body)
            try:
                _a2 = body.count('forwarded-header-block')
            except Exception:
                _a2 = 0
            logger.info(f"FORWARDED WRAP (post-clean): before={_b2}, after={_a2}")

            try:
                _pdf_att_meta = [
                    a
                    for a in (attachments or [])
                    if a.get("content_type") == "application/pdf"
                    or str(a.get("filename", "")).lower().endswith(".pdf")
                ]
            except Exception:
                _pdf_att_meta = []
            attachment_inline_note = ""
            if _pdf_att_meta and str(os.environ.get("ATTACHMENT_INLINE_NOTE", "")).lower() in (
                "1",
                "true",
                "yes",
                "on",
            ):
                try:
                    names = ", ".join(
                        html.escape(a.get("filename") or f"attachment-{i+1}.pdf")
                        for i, a in enumerate(_pdf_att_meta)
                    )
                    plural = "s" if len(_pdf_att_meta) != 1 else ""
                    attachment_inline_note = f"""
                    <div style=\"margin-top:24px; padding:10px 12px; background:#fafafa; border-left:3px solid #d0d0d0; font-size:11pt; color:#555;\">
                        Attached PDF{plural}: {names}
                    </div>
                    """
                except Exception as _e:
                    logger.warning(f"Failed building attachment inline note: {_e}")
                    attachment_inline_note = ""

            original_style_blocks = (
                getattr(extract_body_and_images_from_email, "last_collected_styles", [])
                or []
            )
            additional_style_markup = ""
            if original_style_blocks:
                unique_styles: list[str] = []
                seen_styles = set()
                total_replacements_css = 0
                for block in original_style_blocks:
                    normalized_block = (block or "").strip()
                    if not normalized_block or normalized_block in seen_styles:
                        continue
                    seen_styles.add(normalized_block)
                    try:
                        inner = re.sub(
                            r"^<style[^>]*>|</style>$",
                            "",
                            normalized_block,
                            flags=re.IGNORECASE,
                        ).strip()
                        inner_sanitized, reps = sanitize_style_block_css(inner)
                        total_replacements_css += reps
                        unique_styles.append(f"<style>\n{inner_sanitized}\n</style>")
                    except Exception:
                        unique_styles.append(normalized_block)
                if unique_styles:
                    combined_styles = "\n".join(unique_styles)
                    additional_style_markup = "\n" + textwrap.indent(
                        combined_styles, "            "
                    ) + "\n"

            word_html_detected = False
            body_metrics = {
                "total_chars": len(body or ""),
                "line_breaks": 0,
            }
            try:
                if body:
                    if any(
                        token in body
                        for token in (
                            'xmlns:w="urn:schemas-microsoft-com:office:word"',
                            "Microsoft Word",
                            "WordSection",
                            "MsoNormal",
                        )
                    ):
                        word_html_detected = True
                    body_metrics["line_breaks"] = body.count("<br>") + body.count("<p>")
            except Exception:
                pass

            inline_blocks = len(inlined_primary) + len(inlined_msg)
            remaining_attachments = len(attachments or []) + len(msg_attachments or [])
            logger.info(
                "CONTENT FLOW: chars=%d, inline_blocks=%d, word_html=%s, remaining_attachments=%d",
                body_metrics["total_chars"],
                inline_blocks,
                word_html_detected,
                remaining_attachments,
            )

            logger.info("Creating HTML content for PDF generation...")
            html_content = f"""
            <!DOCTYPE html>
            <html lang=\"en\">
            <head>
                <meta charset=\"UTF-8\">
                <title>{html.escape(subject)}</title>
                <style>
                    body {{
                        font-family: "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                        line-height: 1.2;
                        margin: 0;
                        padding: 0;
                        color: #333;
                        word-wrap: break-word;
                        text-align: left;
                        text-justify: auto;
                        letter-spacing: normal;
                        word-spacing: normal;
                        white-space: normal;
                        overflow-wrap: anywhere;
                        word-break: normal;
                        -webkit-hyphens: none;
                        hyphens: none;
                        -webkit-font-smoothing: antialiased;
                        -moz-osx-font-smoothing: grayscale;
                        text-rendering: optimizeLegibility;
                        font-feature-settings: "kern" 1, "liga" 1;
                    }}
                    p {{ margin: 0 0 8px; }}
                    li {{ margin: 0 0 4px; }}
                    h1, h2, h3, h4, h5, h6 {{ margin: 12px 0 6px; }}
                    ul, ol {{ margin: 0 0 10px 20px; padding-left: 18px; }}
                    .email-header {{
                        margin: 0;
                        padding: 0;
                        font-size: 10px;
                        line-height: 1.15;
                        color: #1f1f1f;
                        page-break-before: avoid !important;
                        break-before: avoid !important;
                        page-break-after: auto !important;
                        break-after: auto !important;
                        page-break-inside: avoid !important;
                        break-inside: avoid !important;
                        display: block !important;
                    }}
                    .email-header .header-item {{
                        margin: 0;
                        page-break-before: avoid !important;
                        break-before: avoid !important;
                        page-break-inside: avoid !important;
                        break-inside: avoid !important;
                    }}
                    .email-header .header-item + .header-item {{
                        margin-top: 3px;
                    }}
                    .email-header .header-item.cc-item {{
                        page-break-before: avoid !important;
                        break-before: avoid !important;
                    }}
                    .email-header .label {{
                        font-weight: 700 !important;
                        color: #000 !important;
                        margin-right: 6px;
                        display: inline-block;
                    }}
                    .email-header .value {{
                        display: inline;
                    }}
                    .email-header .from-value .from-name {{
                        font-weight: 700 !important;
                    }}
                    .email-header .from-value .from-email {{
                        margin-left: 6px;
                    }}
                    .email-header .subject-value {{
                        font-weight: 600 !important;
                    }}
                    .forwarded-header-block {{
                        margin: 8px 0 10px;
                        padding: 0;
                        display: inline-block; /* Chromium tends to honor non-fragmentation better */
                        width: 100%;
                        vertical-align: top;
                        page-break-before: avoid !important;
                        break-before: avoid !important;
                        page-break-after: avoid !important;
                        break-after: avoid !important;
                        page-break-inside: avoid !important;
                        break-inside: avoid !important;
                    }}
                    .forwarded-header-block > * {{
                        page-break-inside: avoid !important;
                        break-inside: avoid !important;
                        margin: 0 !important;
                    }}
                    .email-body {{
                        margin: 0 !important;
                        padding: 0 !important;
                        display: block !important;
                        float: none !important;
                        clear: none !important;
                        position: static !important;
                    }}
                    .email-body > *:first-child {{
                        margin-top: 0 !important;
                        page-break-before: auto !important;
                        break-before: auto !important;
                    }}
                    .email-body, .email-body * {{
                        white-space: normal !important;
                        text-align: left !important;
                        text-justify: auto !important;
                        letter-spacing: normal !important;
                        word-spacing: normal !important;
                        text-align-last: left !important;
                        margin: 0 !important;
                        padding: 0 !important;
                        float: none !important;
                        clear: none !important;
                        position: static !important;
                        width: auto !important;
                        height: auto !important;
                        max-width: none !important;
                        max-height: none !important;
                        min-width: 0 !important;
                        min-height: 0 !important;
                    }}
                    .email-body p {{
                        margin: 0 0 4px 0 !important;
                        padding: 0 !important;
                        page-break-before: avoid !important;
                        break-before: avoid !important;
                    }}
                    .email-body div {{
                        margin: 0 !important;
                        padding: 0 !important;
                        page-break-before: avoid !important;
                        break-before: avoid !important;
                    }}
                    [style*=\"page-break\"], [style*=\"break-before\"], [style*=\"break-after\"] {{
                        page-break-before: avoid !important;
                        page-break-after: auto !important;
                        break-before: avoid !important;
                        break-after: auto !important;
                    }}
                    .email-body .WordSection1,
                    .email-body div[class^=\"WordSection\"],
                    .email-body div[class*=\"WordSection\"],
                    .email-body p.MsoNormal:first-child {{
                        page-break-before: avoid !important;
                        break-before: avoid !important;
                    }}
                    .image-attachments {{
                        display: block;
                        margin: 0 !important;
                        padding: 0 !important;
                        page-break-before: auto !important;
                        break-before: auto !important;
                        page-break-after: auto !important;
                        break-after: auto !important;
                        page-break-inside: auto !important;
                        break-inside: auto !important;
                    }}
                    .image-attachments img {{
                        max-width: 100%;
                        height: auto;
                        max-height: none;
                        width: auto;
                        object-fit: contain;
                        display: block;
                        margin: 8px auto 10px;
                        page-break-before: auto !important;
                        break-before: auto !important;
                        page-break-inside: auto;
                        break-inside: auto;
                    }}
                    .inline-attachment {{
                        margin: 8px 0 16px 0;
                        page-break-before: auto !important;
                        break-before: auto !important;
                        page-break-after: auto !important;
                        break-after: auto !important;
                        page-break-inside: auto;
                        break-inside: auto;
                    }}
                    .inline-attachment figcaption {{
                        font-size: 11px;
                        color: #555;
                        margin-top: 6px;
                        text-align: center;
                    }}
                </style>{additional_style_markup}
            </head>
            <body>
                <div class=\"email-header\">
                    <div class=\"header-item\"><span class=\"label\" style=\"font-weight:700;\">From:</span><span class=\"value from-value\">{sender_value_html}</span></div>
                    <div class=\"header-item\"><span class=\"label\" style=\"font-weight:700;\">To:</span><span class=\"value\">{html.escape(recipient_display or recipient)}</span></div>
                    <div class=\"header-item\"><span class=\"label\" style=\"font-weight:700;\">Subject:</span><span class=\"value subject-value\">{html.escape(subject)}</span></div>
                    <div class=\"header-item\"><span class=\"label\" style=\"font-weight:700;\">Date:</span><span class=\"value\">{html.escape(date_display)}</span></div>
                    {cc_html or ''}
                </div>
                <div class=\"email-body\">{body}</div>
                {attachment_inline_note}
            </body>
            </html>
            """

            if shutil.disk_usage("/tmp").free < 25 * 1024 * 1024:
                logger.error("Insufficient /tmp space for PDF generation")
                return False

            with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp_body:
                body_pdf_path = tmp_body.name
            temp_paths.append(body_pdf_path)
            logger.info(f"Temporary body PDF path: {body_pdf_path}")

            if os.environ.get("TEST_MODE", "").lower() == "true":
                logger.info("TEST_MODE enabled - using FPDF fallback for body")
                ok = self.fallback_html_to_pdf(html_content, body_pdf_path)
            else:
                logger.info("Attempting Playwright PDF generation for body...")
                try:
                    ok = self.html_to_pdf_playwright(
                        html_content, body_pdf_path, twemoji_base_url
                    )
                except Exception as e:
                    logger.error(f"Playwright body render failed: {e}")
                    logger.error(
                        "Playwright stack trace: %s", traceback.format_exc()
                    )
                    logger.info("Falling back to FPDF for body...")
                    ok = self.fallback_html_to_pdf(html_content, body_pdf_path)

            if not ok or not os.path.exists(body_pdf_path) or os.path.getsize(body_pdf_path) == 0:
                logger.error("Body PDF generation failed or empty")
                return False

            pdf_attachments = [
                a
                for a in (attachments or [])
                if a.get("content_type") == "application/pdf"
                or str(a.get("filename", "")).lower().endswith(".pdf")
            ]

            converted_image_keys: set[str] = set()

            def _append_image_attachments_as_pdf(source_list, label_prefix):
                if not source_list:
                    return
                for idx, att in enumerate(source_list, start=1):
                    fname = att.get("filename") or f"attachment-{idx}"
                    ctype = att.get("content_type") or ""
                    if not looks_like_image(ctype, fname):
                        continue
                    raw = att.get("data") or b""
                    if not isinstance(raw, (bytes, bytearray)):
                        try:
                            raw = bytes(raw)
                        except Exception:
                            logger.warning(
                                "%s image attachment %s has non-bytes payload; skipping",
                                label_prefix,
                                fname,
                            )
                            continue
                    if not raw:
                        logger.warning(
                            "%s image attachment %s is empty; skipping",
                            label_prefix,
                            fname,
                        )
                        continue

                    pdf_bytes, page_count = convert_image_bytes_to_pdf(raw, fname)
                    if not pdf_bytes:
                        logger.warning(
                            "%s image attachment %s could not be converted to PDF",
                            label_prefix,
                            fname,
                        )
                        continue

                    out_name = os.path.splitext(fname)[0] + ".pdf"
                    pdf_attachments.append(
                        {
                            "filename": out_name,
                            "content_type": "application/pdf",
                            "data": pdf_bytes,
                        }
                    )
                    converted_image_keys.add(out_name.lower())
                    logger.info(
                        "%s image attachment %s converted to PDF (%d page%s, %d bytes)",
                        label_prefix,
                        out_name,
                        page_count,
                        "s" if page_count != 1 else "",
                        len(pdf_bytes),
                    )

            _append_image_attachments_as_pdf(attachments, "Email")

            logger.info(
                f"MSG ATTACHMENTS PARAMETER: {msg_attachments is not None}, LENGTH: {len(msg_attachments) if msg_attachments else 0}"
            )
            if msg_attachments:
                logger.info(
                    f"PROCESSING {len(msg_attachments)} MSG ATTACHMENTS FOR PDF CONVERSION"
                )
                for i, att in enumerate(msg_attachments):
                    att_filename = att.get("filename", "unknown")
                    att_content_type = att.get("content_type", "unknown")
                    att_size = len(att.get("data", b""))
                    logger.info(
                        f"MSG ATTACHMENT {i+1}: {att_filename} (type: {att_content_type}, size: {att_size} bytes)"
                    )

                    if att.get("content_type") == "application/pdf" or str(
                        att.get("filename", "")
                    ).lower().endswith(".pdf"):
                        pdf_attachments.append(att)
                        logger.info(f"Added PDF attachment: {att_filename}")
                    elif (
                        str(att.get("content_type", "")).lower() == "message/rfc822"
                        or str(att.get("filename", "")).lower().endswith(".eml")
                    ) and att.get("data"):
                        try:
                            eml_bytes = att.get("data")
                            if not isinstance(eml_bytes, (bytes, bytearray)):
                                eml_bytes = bytes(eml_bytes)
                            nested_pdf = self.doc_converter.eml_bytes_to_pdf_bytes(
                                eml_bytes
                            )
                            if nested_pdf:
                                base_name = os.path.splitext(
                                    att_filename
                                    or f"attachment-{len(pdf_attachments) + 1}"
                                )[0]
                                out_name = f"{base_name}.pdf"
                                pdf_attachments.append(
                                    {
                                        "filename": out_name,
                                        "content_type": "application/pdf",
                                        "data": nested_pdf,
                                    }
                                )
                                logger.info(
                                    f"Converted embedded EML to PDF: {out_name} ({len(nested_pdf)} bytes)"
                                )
                            else:
                                logger.warning(
                                    f"Failed to convert embedded EML to PDF: {att_filename}"
                                )
                        except Exception as eml_e:
                            logger.warning(
                                f"Error converting embedded EML {att_filename} to PDF: {eml_e}"
                            )
                    elif looks_like_image(att_content_type, att_filename):
                        img_data = att.get("data") or b""
                        if not isinstance(img_data, (bytes, bytearray)):
                            try:
                                img_data = bytes(img_data)
                            except Exception:
                                logger.warning(
                                    "Skipping image attachment %s from msg_attachments; payload is not bytes",
                                    att_filename,
                                )
                                continue
                        if not img_data:
                            logger.warning(
                                f"Skipping empty image attachment {att_filename}"
                            )
                            continue
                        pdf_bytes, page_count = convert_image_bytes_to_pdf(
                            img_data, att_filename
                        )
                        if not pdf_bytes:
                            logger.warning(
                                f"Failed to convert image attachment {att_filename} to PDF"
                            )
                            continue

                        out_name = (
                            os.path.splitext(
                                att_filename or f"attachment-{len(pdf_attachments)+1}"
                            )[0]
                            + ".pdf"
                        )
                        if out_name.lower() in converted_image_keys:
                            logger.info(
                                "Skipping duplicate image attachment %s already converted to PDF",
                                out_name,
                            )
                            continue
                        pdf_attachments.append(
                            {
                                "filename": out_name,
                                "content_type": "application/pdf",
                                "data": pdf_bytes,
                            }
                        )
                        converted_image_keys.add(out_name.lower())
                        logger.info(
                            "Converted image attachment %s to PDF (%d page%s, %d bytes)",
                            out_name,
                            page_count,
                            "s" if page_count != 1 else "",
                            len(pdf_bytes),
                        )
                    elif att.get("content_type") == "text/plain" and str(
                        att.get("filename", "")
                    ).lower().endswith(".txt"):
                        try:
                            att_data = att.get("data", b"")
                            if isinstance(att_data, bytes):
                                text_content = att_data.decode(
                                    "utf-8", errors="replace"
                                )
                            else:
                                text_content = str(att_data)

                            if text_content.strip():
                                base_name = os.path.splitext(att_filename)[0]
                                if base_name.endswith(".msg"):
                                    base_name = base_name[:-4]

                                html_content = f"""
                                <!DOCTYPE html>
                                <html lang=\"en\">
                                <head>
                                    <meta charset=\"UTF-8\">
                                    <title>Embedded Message: {html.escape(base_name)}</title>
                                    <style>
                                        body {{
                                            font-family: "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                                            line-height: 1.4;
                                            margin: 20px;
                                            color: #333;
                                        }}
                                        .embedded-header {{
                                            background-color: #f0f8ff;
                                            border: 1px solid #4CAF50;
                                            border-radius: 5px;
                                            padding: 15px;
                                            margin-bottom: 20px;
                                        }}
                                        .embedded-content {{
                                            white-space: pre-wrap;
                                            word-wrap: break-word;
                                        }}
                                    </style>
                                </head>
                                <body>
                                    <div class=\"embedded-header\">
                                        <h2>📎 Embedded Message: {html.escape(base_name)}</h2>
                                    </div>
                                    <div class=\"embedded-content\">{html.escape(text_content)}</div>
                                </body>
                                </html>
                                """

                                with tempfile.NamedTemporaryFile(
                                    suffix=".pdf", delete=False
                                ) as tmp_nested:
                                    pdf_path = tmp_nested.name
                                temp_paths.append(pdf_path)

                                if os.environ.get("TEST_MODE", "").lower() == "true":
                                    nested_ok = self.fallback_html_to_pdf(
                                        html_content, pdf_path
                                    )
                                else:
                                    try:
                                        nested_ok = self.html_to_pdf_playwright(
                                            html_content,
                                            pdf_path,
                                            twemoji_base_url,
                                        )
                                    except Exception:
                                        nested_ok = self.fallback_html_to_pdf(
                                            html_content, pdf_path
                                        )

                                if (
                                    nested_ok
                                    and os.path.exists(pdf_path)
                                    and os.path.getsize(pdf_path) > 0
                                ):
                                    with open(pdf_path, "rb") as f:
                                        nested_pdf_bytes = f.read()

                                    pdf_attachments.append(
                                        {
                                            "filename": f"{base_name}.pdf",
                                            "content_type": "application/pdf",
                                            "data": nested_pdf_bytes,
                                        }
                                    )
                                    logger.info(
                                        f"Successfully converted text attachment to PDF: {base_name}.pdf ({len(nested_pdf_bytes)} bytes)"
                                    )
                                else:
                                    logger.warning(
                                        f"Failed to convert text attachment to PDF: {att_filename}"
                                    )

                        except Exception as text_e:
                            logger.warning(
                                f"Error converting text attachment {att_filename} to PDF: {text_e}"
                            )
                    else:
                        logger.info(
                            f"Skipping non-PDF attachment: {att_filename} (type: {att_content_type})"
                        )

            if not pdf_attachments:
                shutil.copyfile(body_pdf_path, output_path)
                logger.info("No PDF attachments found; body PDF copied to output")
                return True

            writer = PdfWriter()
            try:
                body_reader = PdfReader(body_pdf_path)
                body_pages = len(body_reader.pages)
                for page in body_reader.pages:
                    writer.add_page(page)
                logger.info(f"Body PDF pages appended: {body_pages}")
            except Exception as e:
                logger.error(f"Failed reading body PDF: {e}")
                shutil.copyfile(body_pdf_path, output_path)
                return True

            for idx, att in enumerate(pdf_attachments, start=1):
                fname = att.get("filename") or f"attachment-{idx}.pdf"
                try:
                    raw = att.get("data") or b""
                    if not raw:
                        logger.warning(f"Skipping empty PDF attachment '{fname}'")
                        continue
                    att_reader = PdfReader(io.BytesIO(raw))
                    apages = len(att_reader.pages)
                    for page in att_reader.pages:
                        writer.add_page(page)
                    logger.info(
                        f"Appended attachment '{fname}' ({apages} page{'s' if apages != 1 else ''})"
                    )
                except Exception as e:
                    logger.warning(
                        f"Skipping unreadable PDF attachment '{fname}': {e}"
                    )

            with open(output_path, "wb") as out_f:
                writer.write(out_f)
            logger.info(
                "Combined PDF (body + attachments) written successfully (no attachment title pages)"
            )
            return True
        except Exception as e:
            logger.error(f"Error converting EML to PDF: {e}")
            logger.error(f"EML conversion stack trace: {traceback.format_exc()}")
            return False
        finally:
            for p in temp_paths:
                try:
                    os.unlink(p)
                except Exception:
                    pass

    def html_to_pdf_playwright(
        self,
        html_content: str,
        output_path: str,
        twemoji_base_url: str | None = None,
    ) -> bool:
        logger = self.logger
        max_retries = 3
        twemoji_failed = False

        for attempt in range(max_retries):
            logger.info(
                f"=== Playwright PDF Generation Attempt {attempt + 1}/{max_retries} ==="
            )

            try:
                start_time = time.time()

                with sync_playwright() as p:
                    logger.info(
                        f"Playwright context started, available browsers: {p.chromium}"
                    )

                    browser_path = p.chromium.executable_path
                    logger.info(f"Browser executable path: {browser_path}")

                    chrome_args = [
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-accelerated-2d-canvas",
                        "--no-first-run",
                        "--no-zygote",
                        "--single-process",
                        "--disable-gpu",
                        "--disable-web-security",
                        "--disable-features=VizDisplayCompositor",
                        "--disable-extensions",
                        "--disable-plugins",
                        "--disable-ipc-flooding-protection",
                        "--disable-renderer-backgrounding",
                        "--disable-backgrounding-occluded-windows",
                        "--disable-background-timer-throttling",
                        "--disable-component-extensions-with-background-pages",
                        "--memory-pressure-off",
                        "--max_old_space_size=2048",
                        "--font-render-hinting=none",
                    ]

                    logger.info(
                        f"Launching browser with {len(chrome_args)} chrome flags"
                    )
                    logger.debug(f"Chrome args: {chrome_args}")

                    browser_start = time.time()
                    browser = p.chromium.launch(
                        headless=True,
                        args=chrome_args,
                        timeout=30000,
                        chromium_sandbox=False,
                    )
                    browser_launch_time = time.time() - browser_start
                    logger.info(
                        f"Browser launched successfully in {browser_launch_time:.2f}s"
                    )

                    page_start = time.time()
                    page = browser.new_page()
                    page_create_time = time.time() - page_start
                    logger.info(f"Page created in {page_create_time:.2f}s")

                    page.set_default_timeout(60000)
                    logger.info("Set page default timeout to 60 seconds")

                    page.set_viewport_size({"width": 1200, "height": 800})
                    logger.info("Set viewport to 1200x800")

                    content_start = time.time()
                    logger.info(
                        f"Setting page content ({len(html_content)} characters)"
                    )
                    page.set_content(
                        html_content, wait_until="domcontentloaded", timeout=30000
                    )
                    content_load_time = time.time() - content_start
                    logger.info(f"Content loaded in {content_load_time:.2f}s")

                    twemoji_injected = False
                    if not twemoji_failed:
                        try:
                            logger.info(
                                "Injecting Twemoji and inlining SVGs for consistent emoji rendering"
                            )
                            twemoji_path = os.path.join(
                                os.path.dirname(__file__), "static", "twemoji.min.js"
                            )
                            if os.path.exists(twemoji_path):
                                page.add_script_tag(path=twemoji_path)
                                twemoji_injected = True
                            else:
                                logger.warning(
                                    f"Twemoji script not found at {twemoji_path}; skipping injection"
                                )
                                twemoji_failed = True
                        except Exception as tw_error:
                            logger.warning(
                                f"Twemoji injection failed: {tw_error}"
                            )
                            logger.info(
                                "Continuing with system emoji fonts as fallback"
                            )
                            twemoji_failed = True

                    if twemoji_injected:
                        base_url = (
                            twemoji_base_url
                            or "https://cdnjs.cloudflare.com/ajax/libs/twemoji/14.0.2/svg/"
                        )
                        base_url_js = json.dumps(base_url)
                        script = """
                            async () => {
                              try {
                                if (typeof twemoji !== 'undefined') {
                                  const baseUrl = __BASE_URL__;
                                  twemoji.parse(document.body, {
                                    base: baseUrl,
                                    folder: '',
                                    ext: '.svg'
                                  });

                                  const emojiImages = Array.from(document.querySelectorAll('img.emoji'));
                                  console.log(`Found ${emojiImages.length} emoji images to inline`);

                                  await Promise.all(emojiImages.map(async (img) => {
                                    try {
                                      const src = img.getAttribute('src');
                                      if (!src || !src.includes('.svg')) return;

                                      const response = await fetch(src, { cache: 'force-cache' });
                                      if (!response.ok) {
                                        console.warn(`Failed to fetch ${src}: ${response.status}`);
                                        return;
                                      }

                                      const svg = await response.text();
                                      const wrapper = document.createElement('span');
                                      wrapper.innerHTML = svg;
                                      const svgEl = wrapper.firstElementChild;
                                      if (svgEl) {
                                        svgEl.setAttribute('width', img.width || '1em');
                                        svgEl.setAttribute('height', img.height || '1em');
                                        svgEl.style.verticalAlign = 'middle';
                                        img.replaceWith(svgEl);
                                      }
                                    } catch (error) {
                                      console.warn('Failed to inline emoji SVG', error);
                                    }
                                  }));
                                }
                              } catch (error) {
                                console.error('Twemoji injection error:', error);
                              }
                            }
                        """.replace("__BASE_URL__", base_url_js)
                        try:
                            page.evaluate(script)
                        except Exception as tw_error:
                            logger.warning(
                                f"Twemoji inline SVG injection failed: {tw_error}"
                            )

                    pdf_start = time.time()
                    logger.info(f"Starting PDF generation to: {output_path}")
                    page_format, page_margins = resolve_pdf_layout_settings()
                    pdf_margins = page_margins.copy()
                    pdf_margins["top"] = "0.3in"
                    pdf_margins["bottom"] = "0.3in"
                    pdf_margins["left"] = "0.5in"
                    pdf_margins["right"] = "0.5in"

                    margin_top_px = _length_to_px(pdf_margins.get("top"))
                    margin_bottom_px = _length_to_px(pdf_margins.get("bottom"))
                    format_key = str(page_format or "Letter").lower()
                    page_dims = _PAGE_DIMENSIONS_IN.get(format_key, _PAGE_DIMENSIONS_IN.get("letter", (8.5, 11.0)))
                    page_height_px = _inches_to_px(page_dims[1])
                    available_body_height_px = max(page_height_px - margin_top_px - margin_bottom_px, 0.0)
                    inline_image_padding_px = _inches_to_px(0.5)
                    min_inline_image_height_px = _inches_to_px(1.25)

                    logger.info(
                        "PAGE DIMENSIONS: format=%s height_px=%.2f available_body_px=%.2f",
                        page_format,
                        page_height_px,
                        available_body_height_px,
                    )

                    logger.info(
                        f"PAGE BREAK DIAGNOSTIC: Using minimal PDF margins: {pdf_margins}"
                    )

                    try:
                        page_info = page.evaluate(
                            """
                                () => {
                                    const header = document.querySelector('.email-header');
                                    const body = document.querySelector('.email-body');
                                    const first = body && body.firstElementChild ? body.firstElementChild : null;
                                    const cs = first ? window.getComputedStyle(first) : null;
                                    return {
                                        headerHeight: header ? header.offsetHeight : 0,
                                        bodyHeight: body ? body.offsetHeight : 0,
                                        totalHeight: document.body.scrollHeight,
                                        viewportHeight: window.innerHeight,
                                        headerDisplay: header ? window.getComputedStyle(header).display : 'none',
                                        bodyDisplay: body ? window.getComputedStyle(body).display : 'none',
                                        firstBodyTag: first ? first.tagName : null,
                                        firstBodyStyle: first ? (first.getAttribute('style') || '') : null,
                                        firstBreakBefore: cs ? (cs.breakBefore || cs.pageBreakBefore || null) : null,
                                        firstBreakAfter: cs ? (cs.breakAfter || cs.pageBreakAfter || null) : null
                                    };
                                }
                            """
                        )
                        logger.info(
                            f"PAGE BREAK DIAGNOSTIC: Page layout info: {page_info}"
                        )

                        # After diagnostics, enforce grouping of inline forwarded headers in DOM
                        page.evaluate(
                            """
                                () => {
                                  try {
                                    const body = document.querySelector('.email-body') || document.body;
                                    const candidates = Array.from(body.querySelectorAll('div, p, blockquote, td, span'));
                                    const pattern = /(From:)[\s\S]*?(Sent:|Date:)[\s\S]*?To:[\s\S]*?(?:Cc:[\s\S]*?)?Subject:/i;
                                    let wrappedCount = 0;
                                    for (const el of candidates) {
                                      if (!(el instanceof Element)) continue;
                                      if (el.closest('.forwarded-header-block')) continue;
                                      const html = el.innerHTML || '';
                                      if (!html) continue;
                                      if (pattern.test(html)) {
                                        const wrapper = document.createElement('div');
                                        wrapper.className = 'forwarded-header-block';
                                        wrapper.style.pageBreakInside = 'avoid';
                                        wrapper.style.breakInside = 'avoid';
                                        wrapper.style.display = 'inline-block';
                                        wrapper.style.width = '100%';
                                        el.style.pageBreakInside = 'avoid';
                                        el.style.breakInside = 'avoid';
                                        el.parentNode.insertBefore(wrapper, el);
                                        wrapper.appendChild(el);
                                        wrappedCount++;
                                      }
                                    }
                                    return { forwardedWrapped: wrappedCount };
                                  } catch (e) {
                                    return { error: String(e) };
                                  }
                                }
                            """
                        )

                        try:
                            image_adjustment = page.evaluate(
                                f"""
                                    () => {{
                                      try {{
                                        const header = document.querySelector('.email-header');
                                        const attachments = Array.from(document.querySelectorAll('.image-attachments img'));
                                        if (!attachments.length) {{
                                          return {{ adjusted: false, reason: 'no inline attachments' }};
                                        }}

                                        const available = {available_body_height_px:.2f};
                                        const padding = {inline_image_padding_px:.2f};
                                        const minHeight = {min_inline_image_height_px:.2f};
                                        const headerHeight = header ? header.getBoundingClientRect().height : 0;

                                        let candidate = available - headerHeight - padding;
                                        if (!Number.isFinite(candidate) || candidate <= 0) {{
                                          candidate = available - padding;
                                        }}
                                        if (!Number.isFinite(candidate) || candidate <= 0) {{
                                          candidate = available * 0.85;
                                        }}

                                        let maxHeight = Math.max(minHeight, Math.min(candidate, available - padding));
                                        if (!Number.isFinite(maxHeight) || maxHeight <= 0) {{
                                          maxHeight = Math.max(minHeight, available * 0.75);
                                        }}

                                        attachments.forEach((img) => {{
                                          img.style.maxHeight = `${{maxHeight}}px`;
                                          img.style.height = 'auto';
                                          img.style.width = 'auto';
                                          img.style.objectFit = 'contain';
                                          img.style.pageBreakBefore = 'auto';
                                          img.style.pageBreakInside = 'auto';
                                          img.style.pageBreakAfter = 'auto';
                                          img.style.breakBefore = 'auto';
                                          img.style.breakInside = 'auto';
                                          img.style.breakAfter = 'auto';
                                        }});

                                        return {{
                                          adjusted: true,
                                          attachmentCount: attachments.length,
                                          headerHeight,
                                          available,
                                          maxHeight,
                                        }};
                                      }} catch (error) {{
                                        console.warn('INLINE IMAGE ADJUSTMENT ERROR', error);
                                        return {{ adjusted: false, error: String(error) }};
                                      }}
                                    }}
                                """
                            )
                            logger.info(f"INLINE IMAGE ADJUSTMENT: {image_adjustment}")
                        except Exception as adjust_error:
                            logger.warning(
                                f"Failed to adjust inline image heights: {adjust_error}"
                            )
                    except Exception as eval_e:
                        logger.warning(f"Page evaluation failed: {eval_e}")

                    page.pdf(
                        path=output_path,
                        format=page_format,
                        margin=pdf_margins,
                        print_background=True,
                        prefer_css_page_size=False,
                        display_header_footer=False,
                    )
                    pdf_generation_time = time.time() - pdf_start
                    logger.info(
                        f"PDF generation completed in {pdf_generation_time:.2f}s"
                    )

                    if os.path.exists(output_path):
                        pdf_size = os.path.getsize(output_path)
                        logger.info(
                            f"PDF file created successfully: {output_path} ({pdf_size} bytes)"
                        )
                    else:
                        logger.error(
                            f"PDF file was not created: {output_path}"
                        )
                        return False

                    logger.info(
                        "Browser context cleanup handled by context manager"
                    )

                total_time = time.time() - start_time
                logger.info(
                    f"=== Playwright PDF generation successful in {total_time:.2f}s total ==="
                )
                return True

            except Exception as e:
                logger.error(
                    f"Playwright PDF generation attempt {attempt + 1} failed: {str(e)}"
                )
                logger.error(f"Exception type: {type(e).__name__}")
                logger.error(f"Stack trace: {traceback.format_exc()}")

                if attempt == max_retries - 1:
                    logger.error(
                        f"=== All Playwright attempts failed after {max_retries} tries ==="
                    )
                    raise

                retry_delay = 2**attempt
                logger.info(f"Waiting {retry_delay}s before retry...")
                time.sleep(retry_delay)

        logger.error("Unexpected exit from retry loop")
        return False

    def html_to_pdf_with_fallback(
        self, html_content: str, output_path: str
    ) -> bool:
        try:
            return self.html_to_pdf_playwright(html_content, output_path, None)
        except Exception as e:
            self.logger.error(
                f"Attachment HTML render failed with Playwright: {e}; falling back to FPDF"
            )
            return self.fallback_html_to_pdf(html_content, output_path)

    def fallback_html_to_pdf(self, html_content: str, output_path: str) -> bool:
        logger = self.logger
        try:
            parser = _FPDFHTMLParser()
            parser.feed(html_content or "")
            parser.close()
            fragments = parser.get_fragments()

            pdf = FPDF()
            pdf.set_auto_page_break(auto=True, margin=15)
            pdf.add_page()
            pdf.set_font("Arial", size=12)

            line_height = 6
            current_style = ""
            line_started = False

            for fragment in fragments:
                if fragment.get("break"):
                    pdf.ln(line_height)
                    line_started = False
                    continue

                text = str(fragment.get("text", ""))
                if not text:
                    continue

                style = ""
                if fragment.get("bold"):
                    style += "B"
                if fragment.get("italic"):
                    style += "I"
                if style != current_style:
                    pdf.set_font("Arial", style=style, size=12)
                    current_style = style

                if not line_started:
                    if fragment.get("bullet"):
                        pdf.set_x(pdf.l_margin + 4)
                    else:
                        pdf.set_x(pdf.l_margin)
                    line_started = True

                sanitized = _encode_latin1(text)
                pdf.write(line_height, sanitized)

            if not fragments:
                pdf.multi_cell(0, line_height, "")

            pdf.output(output_path)
            logger.info(
                f"Successfully generated PDF using fpdf fallback: {output_path}"
            )
            return True

        except Exception as e:
            logger.error(f"Fallback PDF generation failed: {e}")
            return False


__all__ = ["PDFGenerationService"]

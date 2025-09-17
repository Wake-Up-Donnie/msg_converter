import os
import json
import base64
import tempfile
import uuid
import boto3
import logging
from typing import Dict, Any
import email
from email.policy import default
from email.message import EmailMessage
from email.generator import BytesGenerator
from email.utils import parseaddr, parsedate_to_datetime
from datetime import datetime, timezone
import html
from html.parser import HTMLParser
import re
import textwrap
from playwright.sync_api import sync_playwright
from fpdf import FPDF
from pypdf import PdfReader, PdfWriter
import shutil
import subprocess
from pathlib import Path

from converter import EmailConverter
from router import LambdaRouter
from document_converter import DocumentConverter
from request_parser import RequestParser
from multipart_parser import MultipartParser

from logging_utils import configure_logging
from pdf_settings import resolve_pdf_layout_settings
from html_processing import (
    clean_html_content,
    extract_style_blocks,
    normalize_body_html_fragment,
    normalize_whitespace,
    sanitize_style_block_css,
    strip_word_section_wrappers,
)
from image_processing import (
    convert_image_bytes_to_pdf,
    ensure_displayable_image_bytes,
    inline_image_attachments_into_body,
    looks_like_image,
    normalize_lookup_key,
    normalize_url,
    replace_image_references,
)
from email_metadata import (
    build_sender_value_html,
    extract_display_date,
    format_address_header,
    format_address_header_compact,
    safe_decode_header,
)
from email_body_processing import extract_body_and_images_from_email, get_part_content
from email_header import collect_header_context


############################################
# Robust logging configuration
# In AWS Lambda the root logger may already have a handler at WARNING level
# (so logging.basicConfig will NO-OP). We explicitly adjust the root logger
# level and add a handler if none exists so INFO logs always reach CloudWatch.
############################################


configure_logging()
logger = logging.getLogger(__name__)
logger.debug("Logging configured: level=%s, handlers=%s", logging.getLevelName(logger.level), len(logging.getLogger().handlers))

converter = EmailConverter(logger)
doc_converter = DocumentConverter(logger)
multipart_parser = MultipartParser(logger)

# Backward compatibility aliases for legacy imports
_safe_decode_header = safe_decode_header
_format_address_header = format_address_header
_format_address_header_compact = format_address_header_compact
_build_sender_value_html = build_sender_value_html
_extract_display_date = extract_display_date
_sanitize_style_block_css = sanitize_style_block_css
_extract_style_blocks = extract_style_blocks
_strip_word_section_wrappers = strip_word_section_wrappers
_inline_image_attachments_into_body = inline_image_attachments_into_body
_ensure_displayable_image_bytes = ensure_displayable_image_bytes
_convert_image_bytes_to_pdf = convert_image_bytes_to_pdf
_normalize_key = normalize_lookup_key
_normalize_url = normalize_url
_looks_like_image = looks_like_image


def convert_msg_bytes_to_eml_bytes(msg_bytes: bytes) -> bytes:
    """Wrapper for EmailConverter.convert_msg_bytes_to_eml_bytes."""
    return converter.convert_msg_bytes_to_eml_bytes(msg_bytes)


def convert_msg_bytes_to_eml_bytes_with_attachments(msg_bytes: bytes) -> tuple[bytes, list]:
    """Wrapper providing backward compatibility for attachment extraction."""
    return converter.convert_msg_bytes_to_eml_bytes_with_attachments(msg_bytes)
# Initialize S3 client
s3_client = boto3.client('s3')
S3_BUCKET = os.environ.get('S3_BUCKET')

# =====================
# Helper utilities
# =====================


def convert_doc_with_pypandoc_and_images(doc_data: bytes, ext: str) -> str:
    return doc_converter.convert_doc_with_pypandoc_and_images(doc_data, ext)

def convert_docx_to_html_with_images(docx_data: bytes) -> str:
    return doc_converter.convert_docx_to_html_with_images(docx_data)

def convert_office_to_pdf(data: bytes, ext: str) -> bytes | None:
    return doc_converter.convert_office_to_pdf(data, ext)

def eml_bytes_to_pdf_bytes(eml_bytes: bytes) -> bytes | None:
    return doc_converter.eml_bytes_to_pdf_bytes(eml_bytes)

# =====================
# Conversion helpers
# =====================

# =====================
def convert_eml_to_pdf(eml_content: bytes, output_path: str, twemoji_base_url: str = None, msg_attachments: list = None) -> bool:
    """Convert EML content to PDF using Playwright with fallback to FPDF."""
    import html  # Import html module to avoid variable conflict
    import tempfile  # Import tempfile module to avoid variable conflict
    logger.info("=== CONVERT_EML_TO_PDF STARTED ===")
    temp_paths: list[str] = []
    try:
        logger.info("Parsing EML message...")
        logger.info(f"DEBUGGING: EML content size: {len(eml_content)} bytes")
        
        # Parse the EML
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

        # Debug: Check if the EML has multipart structure
        logger.info(f"DEBUGGING: EML is_multipart: {msg.is_multipart()}")
        if msg.is_multipart():
            logger.info(f"DEBUGGING: EML parts count: {len(list(msg.walk()))}")
            for i, part in enumerate(msg.walk()):
                if i == 0:
                    continue  # Skip the main message container
                content_type = part.get_content_type()
                logger.info(f"DEBUGGING: Part {i}: content_type={content_type}")
        else:
            logger.info(f"DEBUGGING: EML single part content_type: {msg.get_content_type()}")

        # Rich extraction: body + inline images
        logger.info("Extracting email body + inline images...")
        try:
            body, images, attachments = extract_body_and_images_from_email(
                msg,
                msg_attachments,
                msg_to_eml_converter=converter.convert_msg_bytes_to_eml_bytes,
                eml_to_pdf_converter=doc_converter.eml_bytes_to_pdf_bytes,
                office_to_pdf_converter=doc_converter.convert_office_to_pdf,
            )
            logger.info(f"DEBUGGING: Rich extraction completed - body_len={len(body)}, images={len(images)}, attachments={len(attachments)}")
        except Exception as e:
            logger.error(f"Rich extraction failed: {e}")
            logger.info(f"DEBUGGING: Falling back to simple extraction")
            # Fallback to simple logic
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    if content_type == "text/html":
                        payload = part.get_payload(decode=True)
                        if payload:
                            body = payload.decode('utf-8', errors='replace')
                            logger.info(f"DEBUGGING: Fallback found HTML part: {len(body)} chars")
                            break
                    elif content_type == "text/plain" and not body:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body = payload.decode('utf-8', errors='replace').replace('\n', '<br>')
                            logger.info(f"DEBUGGING: Fallback found text part: {len(body)} chars")
            else:
                payload = msg.get_payload(decode=True)
                if isinstance(payload, (bytes, bytearray)):
                    body = payload.decode('utf-8', errors='replace')
                else:
                    body = str(payload or '')
                if msg.get_content_type() == "text/plain":
                    body = body.replace('\n', '<br>')
                logger.info(f"DEBUGGING: Fallback single part body: {len(body)} chars")
            if body:
                fallback_styles = []
                body, fallback_styles = extract_style_blocks(body)
                if fallback_styles:
                    try:
                        style_holder = getattr(extract_body_and_images_from_email, "last_collected_styles")
                        if style_holder is None:
                            style_holder = []
                            extract_body_and_images_from_email.last_collected_styles = style_holder
                    except AttributeError:
                        style_holder = []
                        extract_body_and_images_from_email.last_collected_styles = style_holder
                    style_holder.extend(fallback_styles)
                    logger.info(f"Captured {len(fallback_styles)} <style> block(s) during fallback extraction")
                body = normalize_whitespace(body)
        logger.info(f"Body extracted. Length={len(body)}")
        
        # Debug: Show body content preview
        if body:
            logger.info(f"DEBUGGING: Body content preview: {body[:300]}...")
        else:
            logger.warning(f"DEBUGGING: Body content is EMPTY!")
        # Capture <style> blocks before removing wrapping HTML so we can reattach them later
        if body:
            body, inline_styles = extract_style_blocks(body)
            if inline_styles:
                try:
                    style_holder = getattr(extract_body_and_images_from_email, "last_collected_styles")
                    if style_holder is None:
                        style_holder = []
                        extract_body_and_images_from_email.last_collected_styles = style_holder
                except AttributeError:
                    style_holder = []
                    extract_body_and_images_from_email.last_collected_styles = style_holder
                style_holder.extend(inline_styles)
                logger.info(f"Captured {len(inline_styles)} <style> block(s) from email body")
        # Strip outer HTML tags if body is a full HTML document to preserve layout
        try:
            if re.search(r"<\s*html", body, re.IGNORECASE):
                match = re.search(r"<\s*body[^>]*>(.*)</\s*body\s*>", body, flags=re.IGNORECASE | re.DOTALL)
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
            if word_cleanup.get('wrappers_removed') or word_cleanup.get('class_refs_removed'):
                logger.info(
                    "WORD CLEANUP: Removed %s WordSection wrapper(s); stripped %s WordSection class reference(s)",
                    word_cleanup.get('wrappers_removed', 0),
                    word_cleanup.get('class_refs_removed', 0),
                )

        attachments = list(attachments or [])
        msg_attachments = list(msg_attachments or [])

        body, attachments, inlined_primary = inline_image_attachments_into_body(
            body,
            attachments,
            'email-attachment',
        )
        if inlined_primary:
            primary_names = {name.lower() for name in inlined_primary}
            msg_attachments = [
                att for att in msg_attachments
                if (att.get('filename') or '').lower() not in primary_names
            ]
        body, msg_attachments, inlined_msg = inline_image_attachments_into_body(
            body,
            msg_attachments,
            'msg-attachment',
        )
        if inlined_primary or inlined_msg:
            logger.info(
                "INLINE IMAGES: embedded %d email image(s) and %d msg attachment image(s) into body",
                len(inlined_primary),
                len(inlined_msg),
            )

        body = normalize_body_html_fragment(body)

        try:
            _pdf_att_meta = [
                a for a in (attachments or [])
                if a.get('content_type') == 'application/pdf' or str(a.get('filename','')).lower().endswith('.pdf')
            ]
        except Exception:
            _pdf_att_meta = []
        attachment_inline_note = ""
        if _pdf_att_meta and str(os.environ.get('ATTACHMENT_INLINE_NOTE','')).lower() in ("1","true","yes","on"):
            try:
                names = ", ".join(html.escape(a.get('filename') or f'attachment-{i+1}.pdf') for i,a in enumerate(_pdf_att_meta))
                plural = 's' if len(_pdf_att_meta) != 1 else ''
                attachment_inline_note = f"""
                <div style=\"margin-top:24px; padding:10px 12px; background:#fafafa; border-left:3px solid #d0d0d0; font-size:11pt; color:#555;\">
                    Attached PDF{plural}: {names}
                </div>
                """
            except Exception as _e:
                logger.warning(f"Failed building attachment inline note: {_e}")
                attachment_inline_note = ""

        original_style_blocks = getattr(extract_body_and_images_from_email, "last_collected_styles", []) or []
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
                    inner = re.sub(r'^<style[^>]*>|</style>$', '', normalized_block, flags=re.IGNORECASE).strip()
                    inner_sanitized, reps = sanitize_style_block_css(inner)
                    total_replacements_css += reps
                    unique_styles.append(f"<style>\n{inner_sanitized}\n</style>")
                except Exception:
                    unique_styles.append(normalized_block)
            if unique_styles:
                combined_styles = "\n".join(unique_styles)
                additional_style_markup = "\n" + textwrap.indent(combined_styles, "            ") + "\n"

        word_html_detected = False
        body_metrics = {
            'total_chars': len(body or ''),
            'line_breaks': 0,
        }
        try:
            if body:
                if any(token in body for token in (
                    'xmlns:w="urn:schemas-microsoft-com:office:word"',
                    'Microsoft Word',
                    'WordSection',
                    'MsoNormal',
                )):
                    word_html_detected = True
                body_metrics['line_breaks'] = body.count('<br>') + body.count('<p>')
        except Exception:
            pass

        inline_blocks = len(inlined_primary) + len(inlined_msg)
        remaining_attachments = len(attachments or []) + len(msg_attachments or [])
        logger.info(
            "CONTENT FLOW: chars=%d, inline_blocks=%d, word_html=%s, remaining_attachments=%d",
            body_metrics['total_chars'],
            inline_blocks,
            word_html_detected,
            remaining_attachments,
        )

        # Create HTML content (emoji-capable fonts and image styling)
        logger.info("Creating HTML content for PDF generation...")
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>{html.escape(subject)}</title>
            <style>
                body {{
                    font-family: "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                    line-height: 1.2; /* Reduced from 1.35 to prevent overflow */
                    margin: 0;
                    padding: 0;
                    color: #333;
                    word-wrap: break-word;
                    /* --- FIX FOR WORD SPACING --- */
                    text-align: left; /* Default alignment */
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
                /* CRITICAL: Ensure email header is NOT affected by email-body overrides */
                .email-header {{
                    margin: 0; /* No margin to ensure tight layout */
                    padding: 0;
                    font-size: 10px; /* Reduced font size */
                    line-height: 1.15; /* Tighter line height */
                    color: #1f1f1f;
                    page-break-after: avoid !important; /* Prevent page break after header */
                    break-after: avoid !important; /* Modern CSS for avoiding breaks */
                    page-break-inside: avoid !important;
                    break-inside: avoid !important;
                    display: block !important;
                }}
                .email-header .header-item {{
                    margin: 0;
                }}
                .email-header .header-item + .header-item {{
                    margin-top: 3px; /* Increased from 2px for better spacing */
                }}
                .email-header .label {{
                    font-weight: 700 !important; /* Make bold more explicit */
                    color: #000 !important;
                    margin-right: 6px;
                    display: inline-block;
                }}
                .email-header .value {{
                    display: inline;
                }}
                .email-header .from-value .from-name {{
                    font-weight: 700 !important; /* Make bold more explicit */
                }}
                .email-header .from-value .from-email {{
                    margin-left: 6px;
                }}
                .email-header .subject-value {{
                    font-weight: 600 !important; /* Make bold more explicit */
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
                    /* Forcefully override justification from email inline styles */
                    white-space: normal !important; /* Override Outlook's 'pre' on spans */
                    text-align: left !important;
                    text-justify: auto !important;
                    letter-spacing: normal !important;
                    word-spacing: normal !important;
                    text-align-last: left !important;
                    /* CRITICAL: Override Microsoft Word spacing */
                    margin: 0 !important;
                    padding: 0 !important;
                    /* Override any Word HTML layout properties */
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
                /* Ultra-aggressive Microsoft Word HTML cleanup */
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
                /* Remove any Word-specific page break styles */
                [style*="page-break"], [style*="break-before"], [style*="break-after"] {{
                    page-break-before: avoid !important;
                    page-break-after: auto !important;
                    break-before: avoid !important;
                    break-after: auto !important;
                }}
                /* Word HTML containers occasionally trigger a first-page break; neutralize */
                .email-body .WordSection1,
                .email-body div[class^="WordSection"],
                .email-body div[class*="WordSection"],
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
                    page-break-inside: auto !important;
                    break-inside: auto !important;
                }}
                .unreferenced-inline-images {{
                    width: 100%;
                }}
                .inline-attachment {{
                    margin: 12px auto;
                    text-align: center;
                    page-break-inside: auto !important;
                    break-inside: auto !important;
                    max-width: 100%;
                }}
                .inline-attachment img {{
                    max-width: 100%;
                    height: auto;
                    display: block;
                    margin: 0 auto;
                }}
                .inline-attachment figcaption {{
                    font-size: 10px;
                    color: #666;
                    margin-top: 4px;
                    word-break: break-word;
                }}
                .email-body b, .email-body strong {{ font-weight: 700; }}
                [style*="text-align:justify"], [style*="text-align: justify"] {{
                  text-align: left !important;
                }}
                pre, code {{
                    white-space: pre-wrap !important; /* Ensure code blocks are not affected */
                }}
                .emoji {{
                    font-family: "Noto Color Emoji", "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol";
                }}
                img {{
                    max-width: 100%;
                    height: auto;
                    display: block;
                    margin: 8px 0;
                }}
                .inline-image {{
                    max-width: 100%;
                    height: auto;
                }}
                pre, code {{
                    white-space: pre-wrap;
                    word-break: break-word;
                }}
            </style>{additional_style_markup}
        </head>
        <body style="margin:0;padding:0;">
            <div class="email-header">
                <div class="header-item header-from"><span class="label">From:</span><span class="value from-value">{sender_value_html}</span></div>
                <div class="header-item"><span class="label">Subject:</span><span class="value subject-value">{html.escape(subject)}</span></div>
                <div class="header-item"><span class="label">Date:</span><span class="value">{html.escape(date_display)}</span></div>
                <div class="header-item"><span class="label">To:</span><span class="value">{html.escape(recipient_display)}</span></div>
                {cc_html}
            </div>
            <div class="email-body">
                {body}{attachment_inline_note}
            </div>
        </body>
        </html>
        """
        logger.info(f"HTML content created: {len(html_content)} characters")

        # Check available /tmp space before creating potentially large PDFs
        required_space = len(eml_content)
        required_space += sum(len(a.get('data', b'')) for a in (attachments or []))
        required_space += sum(len(a.get('data', b'')) for a in (msg_attachments or []))
        _, _, free_space = shutil.disk_usage('/tmp')
        logger.info(f"/tmp free space: {free_space} bytes; estimated need: {required_space} bytes")
        if free_space < required_space:
            logger.error("Insufficient /tmp space for PDF generation")
            return False

        # Generate body PDF to a temporary file, then merge PDF attachments (if any)
        logger.info("Preparing to generate body PDF and merge attachments if present...")
        body_pdf_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as tmp_body:
                body_pdf_path = tmp_body.name
            temp_paths.append(body_pdf_path)
            logger.info(f"Temporary body PDF path: {body_pdf_path}")

            # Decide rendering path
            if os.environ.get('TEST_MODE', '').lower() == 'true':
                logger.info("TEST_MODE enabled - using FPDF fallback for body")
                ok = fallback_html_to_pdf(html_content, body_pdf_path)
            else:
                logger.info("Attempting Playwright PDF generation for body...")
                try:
                    ok = html_to_pdf_playwright(html_content, body_pdf_path, twemoji_base_url)
                except Exception as e:
                    logger.error(f"Playwright body render failed: {e}")
                    import traceback
                    logger.error(f"Playwright stack trace: {traceback.format_exc()}")
                    logger.info("Falling back to FPDF for body...")
                    ok = fallback_html_to_pdf(html_content, body_pdf_path)

            if not ok or not os.path.exists(body_pdf_path) or os.path.getsize(body_pdf_path) == 0:
                logger.error("Body PDF generation failed or empty")
                return False

            # Collect PDF attachments from both EML parsing and extracted .msg attachments
            pdf_attachments = [
                a for a in (attachments or [])
                if a.get('content_type') == 'application/pdf' or str(a.get('filename','')).lower().endswith('.pdf')
            ]

            converted_image_keys: set[str] = set()

            def _append_image_attachments_as_pdf(source_list, label_prefix):
                if not source_list:
                    return
                for idx, att in enumerate(source_list, start=1):
                    fname = att.get('filename') or f'attachment-{idx}'
                    ctype = att.get('content_type') or ''
                    if not looks_like_image(ctype, fname):
                        continue
                    raw = att.get('data') or b''
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

                    out_name = os.path.splitext(fname)[0] + '.pdf'
                    pdf_attachments.append({
                        'filename': out_name,
                        'content_type': 'application/pdf',
                        'data': pdf_bytes,
                    })
                    converted_image_keys.add(out_name.lower())
                    logger.info(
                        "%s image attachment %s converted to PDF (%d page%s, %d bytes)",
                        label_prefix,
                        out_name,
                        page_count,
                        's' if page_count != 1 else '',
                        len(pdf_bytes),
                    )

            _append_image_attachments_as_pdf(attachments, 'Email')
            
            # Process .msg attachments (embedded .msg files and other PDFs from extract-msg)
            logger.info(f"MSG ATTACHMENTS PARAMETER: {msg_attachments is not None}, LENGTH: {len(msg_attachments) if msg_attachments else 0}")
            if msg_attachments:
                logger.info(f"PROCESSING {len(msg_attachments)} MSG ATTACHMENTS FOR PDF CONVERSION")
                for i, att in enumerate(msg_attachments):
                    att_filename = att.get('filename', 'unknown')
                    att_content_type = att.get('content_type', 'unknown')
                    att_size = len(att.get('data', b''))
                    logger.info(f"MSG ATTACHMENT {i+1}: {att_filename} (type: {att_content_type}, size: {att_size} bytes)")
                    
                    if att.get('content_type') == 'application/pdf' or str(att.get('filename','')).lower().endswith('.pdf'):
                        # Already a PDF - add directly to pdf_attachments
                        pdf_attachments.append(att)
                        logger.info(f"Added PDF attachment: {att_filename}")
                    elif (str(att.get('content_type','')).lower() == 'message/rfc822' or str(att.get('filename','')).lower().endswith('.eml')) and att.get('data'):
                        # Convert embedded EML into a PDF and append
                        try:
                            eml_bytes = att.get('data')
                            if not isinstance(eml_bytes, (bytes, bytearray)):
                                # In case something weird passed through
                                eml_bytes = bytes(eml_bytes)
                            nested_pdf = eml_bytes_to_pdf_bytes(eml_bytes)
                            if nested_pdf:
                                base_name = os.path.splitext(att_filename or f"attachment-{len(pdf_attachments)+1}")[0]
                                out_name = f"{base_name}.pdf"
                                pdf_attachments.append({
                                    'filename': out_name,
                                    'content_type': 'application/pdf',
                                    'data': nested_pdf
                                })
                                logger.info(f"Converted embedded EML to PDF: {out_name} ({len(nested_pdf)} bytes)")
                            else:
                                logger.warning(f"Failed to convert embedded EML to PDF: {att_filename}")
                        except Exception as eml_e:
                            logger.warning(f"Error converting embedded EML {att_filename} to PDF: {eml_e}")
                    elif looks_like_image(att_content_type, att_filename):
                        img_data = att.get('data') or b''
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
                            logger.warning(f"Skipping empty image attachment {att_filename}")
                            continue
                        pdf_bytes, page_count = convert_image_bytes_to_pdf(img_data, att_filename)
                        if not pdf_bytes:
                            logger.warning(f"Failed to convert image attachment {att_filename} to PDF")
                            continue

                        out_name = os.path.splitext(att_filename or f"attachment-{len(pdf_attachments)+1}")[0] + '.pdf'
                        if out_name.lower() in converted_image_keys:
                            logger.info(
                                "Skipping duplicate image attachment %s already converted to PDF",
                                out_name,
                            )
                            continue
                        pdf_attachments.append({
                            'filename': out_name,
                            'content_type': 'application/pdf',
                            'data': pdf_bytes
                        })
                        converted_image_keys.add(out_name.lower())
                        logger.info(
                            "Converted image attachment %s to PDF (%d page%s, %d bytes)",
                            out_name,
                            page_count,
                            's' if page_count != 1 else '',
                            len(pdf_bytes),
                        )
                    elif att.get('content_type') == 'text/plain' and str(att.get('filename', '')).lower().endswith('.txt'):
                        # Convert embedded message text to PDF
                        try:
                            att_data = att.get('data', b'')
                            if isinstance(att_data, bytes):
                                text_content = att_data.decode('utf-8', errors='replace')
                            else:
                                text_content = str(att_data)
                            
                            if text_content.strip():
                                # Create formatted HTML for the embedded message
                                base_name = os.path.splitext(att_filename)[0]
                                if base_name.endswith('.msg'):
                                    base_name = base_name[:-4]  # Remove .msg extension
                                    
                                html_content = f"""
                                <!DOCTYPE html>
                                <html lang="en">
                                <head>
                                    <meta charset="UTF-8">
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
                                    <div class="embedded-header">
                                        <h2>📎 Embedded Message: {html.escape(base_name)}</h2>
                                    </div>
                                    <div class="embedded-content">{html.escape(text_content)}</div>
                                </body>
                                </html>
                                """
                                
                                # Generate PDF from HTML
                                with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as tmp_nested:
                                    pdf_path = tmp_nested.name
                                temp_paths.append(pdf_path)

                                # Try Playwright first, fallback to FPDF
                                if os.environ.get('TEST_MODE', '').lower() == 'true':
                                    nested_ok = fallback_html_to_pdf(html_content, pdf_path)
                                else:
                                    try:
                                        nested_ok = html_to_pdf_playwright(html_content, pdf_path, twemoji_base_url)
                                    except Exception:
                                        nested_ok = fallback_html_to_pdf(html_content, pdf_path)

                                if nested_ok and os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 0:
                                    # Read the generated PDF and add to attachments
                                    with open(pdf_path, 'rb') as f:
                                        nested_pdf_bytes = f.read()

                                    pdf_attachments.append({
                                        'filename': f"{base_name}.pdf",
                                        'content_type': 'application/pdf',
                                        'data': nested_pdf_bytes
                                    })
                                    logger.info(f"Successfully converted text attachment to PDF: {base_name}.pdf ({len(nested_pdf_bytes)} bytes)")
                                else:
                                    logger.warning(f"Failed to convert text attachment to PDF: {att_filename}")
                                        
                        except Exception as text_e:
                            logger.warning(f"Error converting text attachment {att_filename} to PDF: {text_e}")
                    else:
                        logger.info(f"Skipping non-PDF attachment: {att_filename} (type: {att_content_type})")
            
            # If no PDF attachments after processing, move body to output and finish
            if not pdf_attachments:
                shutil.copyfile(body_pdf_path, output_path)
                logger.info("No PDF attachments found; body PDF copied to output")
                return True

            # Merge body + attachment PDFs (WITHOUT automated attachment cover pages)
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
                fname = att.get('filename') or f'attachment-{idx}.pdf'
                try:
                    raw = att.get('data') or b''
                    if not raw:
                        logger.warning(f"Skipping empty PDF attachment '{fname}'")
                        continue
                    att_reader = PdfReader(io.BytesIO(raw))
                    apages = len(att_reader.pages)
                    for page in att_reader.pages:
                        writer.add_page(page)
                    logger.info(f"Appended attachment '{fname}' ({apages} page{'s' if apages != 1 else ''})")
                except Exception as e:
                    logger.warning(f"Skipping unreadable PDF attachment '{fname}': {e}")

            with open(output_path, 'wb') as out_f:
                writer.write(out_f)
            logger.info("Combined PDF (body + attachments) written successfully (no attachment title pages)")
            return True
        finally:
            for p in temp_paths:
                try:
                    os.unlink(p)
                except Exception:
                    pass

    except Exception as e:
        logger.error(f"Error converting EML to PDF: {e}")
        import traceback
        logger.error(f"EML conversion stack trace: {traceback.format_exc()}")
        return False

doc_converter.eml_to_pdf = convert_eml_to_pdf

def html_to_pdf_playwright(html_content: str, output_path: str, twemoji_base_url: str = None) -> bool:
    """Convert HTML to PDF using Playwright (Chromium baked into the image)."""
    max_retries = 3
    twemoji_failed = False

    for attempt in range(max_retries):
        logger.info(f"=== Playwright PDF Generation Attempt {attempt + 1}/{max_retries} ===")
        
        try:
            import time
            start_time = time.time()
            
            with sync_playwright() as p:
                logger.info(f"Playwright context started, available browsers: {p.chromium}")
                
                # Log browser executable path
                browser_path = p.chromium.executable_path
                logger.info(f"Browser executable path: {browser_path}")
                
                # Comprehensive Chrome flags for Lambda environment
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
                    "--font-render-hinting=none"
                ]
                
                logger.info(f"Launching browser with {len(chrome_args)} chrome flags")
                logger.debug(f"Chrome args: {chrome_args}")
                
                # Launch browser with comprehensive error handling
                browser_start = time.time()
                browser = p.chromium.launch(
                    headless=True,
                    args=chrome_args,
                    timeout=30000,  # 30 second timeout
                    chromium_sandbox=False
                )
                browser_launch_time = time.time() - browser_start
                logger.info(f"Browser launched successfully in {browser_launch_time:.2f}s")
                
                # Create page with timeout
                page_start = time.time()
                page = browser.new_page()
                page_create_time = time.time() - page_start
                logger.info(f"Page created in {page_create_time:.2f}s")
                
                # Set page-level timeout (this is the correct way)
                page.set_default_timeout(60000)  # 60 second timeout for all operations
                logger.info("Set page default timeout to 60 seconds")
                
                # Set viewport for consistent rendering
                page.set_viewport_size({"width": 1200, "height": 800})
                logger.info("Set viewport to 1200x800")
                
                # Set content with timeout and wait conditions
                content_start = time.time()
                logger.info(f"Setting page content ({len(html_content)} characters)")
                page.set_content(html_content, wait_until="domcontentloaded", timeout=30000)
                content_load_time = time.time() - content_start
                logger.info(f"Content loaded in {content_load_time:.2f}s")

                # Inject Twemoji and inline emoji SVGs to make PDF self-contained
                twemoji_injected = False
                if not twemoji_failed:
                    try:
                        logger.info("Injecting Twemoji and inlining SVGs for consistent emoji rendering")
                        twemoji_path = os.path.join(os.path.dirname(__file__), 'static', 'twemoji.min.js')
                        if os.path.exists(twemoji_path):
                            page.add_script_tag(path=twemoji_path)
                            twemoji_injected = True
                        else:
                            logger.warning(f"Twemoji script not found at {twemoji_path}; skipping injection")
                            twemoji_failed = True
                    except Exception as tw_error:
                        logger.warning(f"Twemoji injection failed: {tw_error}")
                        logger.info("Continuing with system emoji fonts as fallback")
                        twemoji_failed = True

                if twemoji_injected:
                    base_url = twemoji_base_url or 'https://cdnjs.cloudflare.com/ajax/libs/twemoji/14.0.2/svg/'
                    base_url_js = json.dumps(base_url)
                    try:
                        page.evaluate(
                            f"""
                        async () => {{
                          try {{
                            if (typeof twemoji !== 'undefined') {{
                              // First parse emojis into img tags
                              const baseUrl = {base_url_js};
                              twemoji.parse(document.body, {{
                                base: baseUrl,
                                folder: '',
                                ext: '.svg'
                              }});

                              // Now replace all emoji img tags with inline SVGs
                              const emojiImages = Array.from(document.querySelectorAll('img.emoji'));
                              console.log(`Found ${emojiImages.length} emoji images to inline`);

                              await Promise.all(emojiImages.map(async (img) => {{
                                try {{
                                  const src = img.getAttribute('src');
                                  if (!src || !src.includes('.svg')) return;

                                  const response = await fetch(src, {{ cache: 'force-cache' }});
                                  if (!response.ok) {{
                                    console.warn(`Failed to fetch ${src}: ${response.status}`);
                                    return;
                                  }}

                                  const svgText = await response.text();
                                  const parser = new DOMParser();
                                  const svgDoc = parser.parseFromString(svgText, 'image/svg+xml');
                                  const svgElement = svgDoc.documentElement;

                                  if (svgElement && svgElement.tagName === 'svg') {{
                                    // Configure SVG for inline rendering
                                    svgElement.setAttribute('width', '1em');
                                    svgElement.setAttribute('height', '1em');
                                    svgElement.classList.add('emoji');
                                    svgElement.style.display = 'inline';
                                    svgElement.style.verticalAlign = 'middle';
                                    svgElement.style.fill = 'currentColor';

                                    // Copy any classes from the original img
                                    if (img.className) {{
                                      svgElement.classList.add(...img.className.split(' '));
                                    }}

                                    // Replace the img with the inline SVG
                                    img.replaceWith(svgElement);
                                    console.log(`Inlined emoji SVG: ${src}`);
                                  }}
                                }} catch (error) {{
                                  console.warn(`Error inlining emoji ${img.src}:`, error);
                                }}
                              }}));

                              console.log('Emoji SVG inlining completed');
                              return true;
                            }}
                            return false;
                          }} catch (error) {{
                            console.error('Twemoji injection error:', error);
                            return false;
                          }}
                        }}
                        """
                        )

                        # Wait for inlining to complete
                        logger.info("Waiting for emoji SVG inlining to complete...")
                        page.wait_for_timeout(1000)
                    except Exception as tw_error:
                        logger.warning(f"Twemoji SVG inlining failed: {tw_error}")
                        logger.info("Continuing with system emoji fonts as fallback")
                
                # Wait a bit for any dynamic content and image decoding
                logger.info("Waiting 1 second for dynamic content and resource fetches...")
                page.wait_for_timeout(1000)
                
                # Generate PDF with comprehensive options
                pdf_start = time.time()
                logger.info(f"Starting PDF generation to: {output_path}")
                page_format, page_margins = resolve_pdf_layout_settings()
                # Use minimal margins for better content flow
                pdf_margins = page_margins.copy()
                pdf_margins['top'] = '0.3in'  # Further reduced
                pdf_margins['bottom'] = '0.3in'  # Further reduced
                pdf_margins['left'] = '0.5in'  # Slightly reduced
                pdf_margins['right'] = '0.5in'  # Slightly reduced
                
                logger.info(f"PAGE BREAK DIAGNOSTIC: Using minimal PDF margins: {pdf_margins}")
                
                # Add page evaluation for debugging
                try:
                    page_info = page.evaluate("""
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
                    """)
                    logger.info(f"PAGE BREAK DIAGNOSTIC: Page layout info: {page_info}")
                except Exception as eval_e:
                    logger.warning(f"Page evaluation failed: {eval_e}")
                
                page.pdf(
                    path=output_path,
                    format=page_format,
                    margin=pdf_margins,
                    print_background=True,
                    prefer_css_page_size=False,
                    display_header_footer=False
                )
                pdf_generation_time = time.time() - pdf_start
                logger.info(f"PDF generation completed in {pdf_generation_time:.2f}s")
                
                # Verify PDF was created
                if os.path.exists(output_path):
                    pdf_size = os.path.getsize(output_path)
                    logger.info(f"PDF file created successfully: {output_path} ({pdf_size} bytes)")
                else:
                    logger.error(f"PDF file was not created: {output_path}")
                    return False
                
                logger.info("Browser context cleanup handled by context manager")
                
            total_time = time.time() - start_time
            logger.info(f"=== Playwright PDF generation successful in {total_time:.2f}s total ===")
            return True
            
        except Exception as e:
            logger.error(f"Playwright PDF generation attempt {attempt + 1} failed: {str(e)}")
            logger.error(f"Exception type: {type(e).__name__}")
            
            # Log stack trace for debugging
            import traceback
            logger.error(f"Stack trace: {traceback.format_exc()}")
            
            if attempt == max_retries - 1:
                logger.error(f"=== All Playwright attempts failed after {max_retries} tries ===")
                raise
            
            retry_delay = 2 ** attempt  # Exponential backoff: 1s, 2s, 4s
            logger.info(f"Waiting {retry_delay}s before retry...")
            time.sleep(retry_delay)
    
    logger.error("Unexpected exit from retry loop")
    return False

def _html_to_pdf_with_fallback(html_content: str, output_path: str) -> bool:
    try:
        return html_to_pdf_playwright(html_content, output_path, None)
    except Exception as e:
        logger.error(f"Attachment HTML render failed with Playwright: {e}; falling back to FPDF")
        return fallback_html_to_pdf(html_content, output_path)

doc_converter.html_to_pdf = _html_to_pdf_with_fallback


def _style_flags_from_attrs(attrs: dict[str, str]) -> tuple[bool, bool]:
    """Return (bold, italic) flags inferred from inline style/class attributes."""
    bold = False
    italic = False

    style = attrs.get('style') or ''
    if style:
        try:
            declarations = {}
            for chunk in style.split(';'):
                if ':' not in chunk:
                    continue
                name, value = chunk.split(':', 1)
                declarations[name.strip().lower()] = value.strip().lower()
            weight = declarations.get('font-weight')
            if weight and any(token in weight for token in ('bold', '600', '700', '800', '900')) and 'normal' not in weight:
                bold = True
            style_prop = declarations.get('font-style')
            if style_prop and any(token in style_prop for token in ('italic', 'oblique')) and 'normal' not in style_prop:
                italic = True
        except Exception:
            pass

    cls = attrs.get('class') or ''
    if cls:
        try:
            tokens = re.split(r'\s+', cls.lower())
            if not bold and any('bold' in token for token in tokens):
                bold = True
            if not italic and any('italic' in token for token in tokens):
                italic = True
        except Exception:
            pass

    return bold, italic


class _FPDFHTMLParser(HTMLParser):
    """Minimal HTML parser that keeps track of bold text for the FPDF fallback."""

    _block_tags = {
        'article', 'div', 'p', 'section', 'table', 'thead', 'tbody', 'tfoot', 'tr'
    }
    _heading_tags = {'h1', 'h2', 'h3', 'h4', 'h5', 'h6'}

    def __init__(self) -> None:
        super().__init__()
        self.fragments: list[dict[str, object]] = []
        self.bold_depth = 0
        self.italic_depth = 0
        self.list_stack: list[str] = []
        self.list_counters: list[int | None] = []
        self.active_bullet = False
        self.tag_stack: list[tuple[str, bool, bool]] = []

    def handle_starttag(self, tag: str, attrs) -> None:  # type: ignore[override]
        tag = tag.lower()
        attrs_dict = {k.lower(): (v or '') for k, v in attrs}

        if tag == 'br':
            self.fragments.append({'break': True})
            return

        break_before = False
        if tag in self._heading_tags or tag in self._block_tags or tag in ('ul', 'ol', 'li'):
            break_before = True
        if break_before:
            self.fragments.append({'break': True})

        bold_add = False
        italic_add = False

        style_bold, style_italic = _style_flags_from_attrs(attrs_dict)
        if style_bold:
            bold_add = True
        if style_italic:
            italic_add = True

        if tag in ('strong', 'b') or tag in self._heading_tags:
            bold_add = True
        if tag in ('em', 'i'):
            italic_add = True

        if bold_add:
            self.bold_depth += 1
        if italic_add:
            self.italic_depth += 1

        self.tag_stack.append((tag, bold_add, italic_add))

        if tag in ('ul', 'ol'):
            self.list_stack.append(tag)
            self.list_counters.append(1 if tag == 'ol' else None)
            return
        if tag == 'li':
            bullet = '• '
            if self.list_stack and self.list_stack[-1] == 'ol':
                counter = self.list_counters[-1] or 1
                bullet = f"{counter}. "
                self.list_counters[-1] = counter + 1
            self.fragments.append({
                'text': bullet,
                'bold': self.bold_depth > 0,
                'italic': self.italic_depth > 0,
                'bullet': True,
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

        if tag in self._heading_tags or tag in self._block_tags or tag == 'li' or tag in ('ul', 'ol'):
            self.fragments.append({'break': True})

        if tag == 'li':
            self.active_bullet = False
        if tag in ('ul', 'ol'):
            if self.list_stack:
                self.list_stack.pop()
            if self.list_counters:
                self.list_counters.pop()
            self.active_bullet = False

    def handle_data(self, data: str) -> None:  # type: ignore[override]
        if not data:
            return
        text = data.replace('\r', '').replace('\xa0', ' ')
        if not text.strip():
            if '\n' in text:
                self.fragments.append({'break': True})
            return
        leading_space = text[0].isspace()
        trailing_space = text[-1].isspace()
        text = text.replace('\n', ' ')
        text = re.sub(r'\s+', ' ', text)
        if leading_space and not text.startswith(' '):
            text = ' ' + text
        if trailing_space and not text.endswith(' '):
            text = text + ' '
        self.fragments.append({
            'text': text,
            'bold': self.bold_depth > 0,
            'italic': self.italic_depth > 0,
            'bullet': self.active_bullet,
        })

    def get_fragments(self) -> list[dict[str, object]]:
        merged: list[dict[str, object]] = []
        break_streak = 0
        for fragment in self.fragments:
            if fragment.get('break'):
                if break_streak < 2:
                    merged.append({'break': True})
                break_streak = min(2, break_streak + 1)
                continue
            text = str(fragment.get('text', ''))
            if not text:
                continue
            break_streak = 0
            bold = bool(fragment.get('bold'))
            italic = bool(fragment.get('italic'))
            bullet = bool(fragment.get('bullet'))
            if merged and not merged[-1].get('break'):
                prev = merged[-1]
                if prev.get('bold') == bold and prev.get('italic') == italic and prev.get('bullet') == bullet:
                    prev['text'] = str(prev.get('text', '')) + text
                    continue
            merged.append({'text': text, 'bold': bold, 'italic': italic, 'bullet': bullet})
        return merged


def _encode_latin1(text: str) -> str:
    return text.encode('latin-1', errors='replace').decode('latin-1')


def fallback_html_to_pdf(html_content: str, output_path: str) -> bool:
    """Fallback PDF generation using FPDF with basic formatting support."""
    try:
        parser = _FPDFHTMLParser()
        parser.feed(html_content or '')
        parser.close()
        fragments = parser.get_fragments()

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font('Arial', size=12)

        line_height = 6
        current_style = ''
        line_started = False

        for fragment in fragments:
            if fragment.get('break'):
                pdf.ln(line_height)
                line_started = False
                continue

            text = str(fragment.get('text', ''))
            if not text:
                continue

            style = ''
            if fragment.get('bold'):
                style += 'B'
            if fragment.get('italic'):
                style += 'I'
            if style != current_style:
                pdf.set_font('Arial', style=style, size=12)
                current_style = style

            if not line_started:
                if fragment.get('bullet'):
                    pdf.set_x(pdf.l_margin + 4)
                else:
                    pdf.set_x(pdf.l_margin)
                line_started = True

            sanitized = _encode_latin1(text)
            pdf.write(line_height, sanitized)

        if not fragments:
            pdf.multi_cell(0, line_height, '')

        pdf.output(output_path)
        logger.info(f"Successfully generated PDF using fpdf fallback: {output_path}")
        return True

    except Exception as e:
        logger.error(f"Fallback PDF generation failed: {e}")
        return False

# =====================
# Filename helper
# =====================

"""Enhanced filename derivation utilities.

Adds logic to derive filenames in the format:
  Lastname, F - MM-DD-YYYY.pdf
based on the email's From + Date headers (with fallbacks), while preserving
original behavior if extraction fails.
"""

# Signature block heuristic pattern (simple closers followed by a name line)
NAME_SIG_PATTERN = re.compile(
    r'(?:\n|\r\n)(?:Regards|Best|Thanks|Thank you|Sincerely|Cheers)[,\s]*\n+([A-Z][A-Za-z]+(?: [A-Z][A-Za-z]+){0,3})\b'
)

def _split_display_name(display: str) -> tuple[str | None, str | None]:
    """Parse display name returning (last_name, first_initial).
    Supports formats:
      - First Last
      - First M. Last
      - Last, First
    """
    if not display:
        return None, None
    display = re.sub(r'\s+', ' ', display).strip().strip('"')
    if not display:
        return None, None

    # Handle "Last, First (Middle ...)" form
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

    # Single token fallback
    tok = tokens[0]
    return tok.title(), tok[:1].upper()

def _name_from_local_part(local: str) -> tuple[str | None, str | None]:
    """Infer (last, first_initial) from email local-part such as 'john.q.public'."""
    if not local:
        return None, None
    parts = [p for p in re.split(r'[._\-+]+', local) if p]
    if len(parts) >= 2:
        first = parts[0].title()
        last = parts[-1].title()
        return last, first[:1]
    token = parts[0].title()
    return token, token[:1]

def extract_sender_name_and_date(eml_bytes: bytes) -> tuple[str | None, str | None, str | None]:
    """Return (last_name, first_initial, date_str_MM_DD_YYYY) or (None,...).

    Priority order for name:
      1. Signature block (end-of-email)
      2. Display name in From header
      3. Local-part of address
    Date fallback: current UTC date if header missing/unparseable.
    """
    try:
        msg = email.message_from_bytes(eml_bytes, policy=default)
    except Exception as e:
        logger.warning(f"Failed to parse EML for naming: {e}")
        return None, None, None

    # Date extraction
    date_hdr = msg.get('Date')
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

    from_hdr = msg.get('From', '') or ''
    display, addr = parseaddr(from_hdr)
    last = first_initial = None

    # 1. Display name
    if display:
        l1, f1 = _split_display_name(display)
        if l1 and f1:
            last, first_initial = l1, f1

    # 2. Local-part
    if (not last or not first_initial) and addr:
        local_part = addr.split('@')[0]
        l2, f2 = _name_from_local_part(local_part)
        if l2 and f2:
            if not last:
                last = l2
            if not first_initial:
                first_initial = f2

    # 3. Signature heuristic (scan raw bytes) - original pattern using closers
    raw_text = None
    if (not last or not first_initial):
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

    # 4. Advanced signature scanning override (prioritizes visible signature; handles forwarded emails & ligatures like 'Jeﬀ').
    try:
        if raw_text is None:
            raw_text = eml_bytes.decode('utf-8', errors='replace')
        import unicodedata
        norm_text = unicodedata.normalize('NFKC', raw_text)
        lines_original = norm_text.splitlines()
        # Consider last 120 lines to widen signature search window
        scan_lines = lines_original[-120:] if len(lines_original) > 120 else lines_original

        # Common role/title indicators to boost confidence
        ROLE_KEYWORDS = { 'chair', 'director', 'manager', 'president', 'ceo', 'cfo', 'coo', 'cto', 'counsel', 'attorney', 'esq', 'esquire', 'partner', 'engineer', 'analyst', 'sponsor', 'group', 'board', 'secretary', 'treasurer' }
        ORG_WORDS = { 'group', 'county', 'inc', 'llc', 'corp', 'corporation', 'company', 'committee', 'department', 'office', 'university', 'college', 'school', 'agency', 'association' }
        NAME_LINE_RE = re.compile(r"^\s*([A-Z][A-Za-z\u00C0-\u017F\uFB00-\uFB06'-]+)\s+([A-Z][A-Za-z\u00C0-\u017F\uFB00-\uFB06'-]{1,})\s*(?:,?\s*(Jr|Sr|II|III|IV))?\s*$")

        candidates_ranked = []  # list of (score, line_index, first, last)
        for idx, raw_line in enumerate(scan_lines):
            line = raw_line.strip()
            if not line or len(line) > 80:
                continue
            if '@' in line or ':' in line:
                continue  # skip header/address lines
            m2 = NAME_LINE_RE.match(line)
            if not m2:
                continue
            first_tok, last_tok = m2.group(1), m2.group(2)
            # Filter out obvious organization second tokens
            if last_tok.lower() in ORG_WORDS:
                continue
            # Exclude lines where both tokens very long (likely phrase) or all caps
            if (first_tok.isupper() and len(first_tok) > 4) and (last_tok.isupper() and len(last_tok) > 4):
                continue
            # Score: base 1
            score = 1
            # If following line is a role/title, boost score
            next_line = scan_lines[idx+1].strip() if idx+1 < len(scan_lines) else ''
            next_low = next_line.lower()
            if next_low:
                # Single or two-word title or contains a role keyword
                words = next_low.split()
                if any(w.strip(',.:;') in ROLE_KEYWORDS for w in words[:3]):
                    score += 5
                elif len(words) <= 4 and any(w.strip(',.:;') in ROLE_KEYWORDS for w in words):
                    score += 3
            # If there is a blank line after the name (common signature separation)
            after_next = scan_lines[idx+2].strip() if idx+2 < len(scan_lines) else ''
            if not next_line and after_next:
                score += 1
            # If line is near very bottom, small boost
            if idx >= len(scan_lines) - 15:
                score += 2
            # If we already have a header-derived name and this differs in last name, extra boost to encourage override
            if last and last_tok.lower() != (last or '').lower():
                score += 2
            candidates_ranked.append((score, idx, first_tok, last_tok))

        if candidates_ranked:
            # Pick highest scoring; if tie, choose the one appearing later (larger idx)
            best = max(candidates_ranked, key=lambda t: (t[0], t[1]))
            _, _, first_tok, last_tok = best
            # Override unconditionally to reflect visible signer
            last = last_tok
            first_initial = first_tok[:1]
            try:
                logger.debug(f"Filename signature override: picked '{first_tok} {last_tok}' (score tuple={best})")
            except Exception:
                pass
    except Exception:
        pass

    # Normalize: keep alnum / dash / apostrophe / space for last
    def _norm(x):
        return re.sub(r"[^A-Za-z0-9\-']+", ' ', x).strip() if x else x
    last = _norm(last)
    first_initial = (first_initial or '')[:1]

    if not last or not first_initial:
        return None, None, date_str
    return last, first_initial, date_str

def sanitize_filename(name: str, default: str = 'file') -> str:
    """Return a safe base filename without extension.

    Allows comma to support pattern: Lastname, F - MM-DD-YYYY
    """
    if not name:
        return default
    name = os.path.basename(name)
    name_without_ext = os.path.splitext(name)[0]
    # Allow word chars, whitespace, dot, dash, parentheses, comma
    safe_name = re.sub(r'[^\w\s\.\-\(\),]', '', name_without_ext)
    safe_name = re.sub(r'\s{2,}', ' ', safe_name).strip()
    safe_name = safe_name.rstrip('. ')
    return safe_name if safe_name else default

# =====================
# Handlers
# =====================

def handle_convert(event: Dict[str, Any]) -> Dict[str, Any]:
    """Handle EML to PDF conversion."""
    logger.info("=== HANDLE_CONVERT STARTED ===")

    try:
        parser = RequestParser(event)
        body = parser.body
        headers = parser.headers
        content_type = headers.get('content-type', '')
        logger.info(f"Content-Type: {content_type}")

        logger.info("=== Starting conversion request processing ===")

        # Parse the multipart/ or single-file body
        logger.info("About to parse multipart data...")
        try:
            files = multipart_parser.parse(body, content_type)
            logger.info(f"Multipart parsing completed. Found keys: {list(files.keys())}")
        except Exception as e:
            logger.error(f"Failed to parse multipart data: {e}")
            import traceback
            logger.error(f"Multipart parsing stack trace: {traceback.format_exc()}")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': f'Failed to parse upload data: {str(e)}'})
            }

        logger.info("Looking for uploaded file in parsed data...")
        
        # Select the uploaded .eml or message/rfc822 part robustly
        file_data = None
        # Gather candidates
        candidates = []
        for key, value in (files or {}).items():
            if isinstance(value, dict) and 'content' in value:
                ct = str(value.get('content_type', '')).lower()
                fn = str(value.get('filename', ''))
                candidates.append((key, fn, ct, value))
                try:
                    size = len(value.get('content') or b'')
                except Exception:
                    size = -1
                logger.info(f"Found candidate part key='{key}', filename='{fn}', content_type='{ct}', size={size}")
        # Prefer message/rfc822, then *.eml, else first file-like
        for key, fn, ct, val in candidates:
            if ct == 'message/rfc822':
                logger.info(f"Selecting message/rfc822 part from key '{key}'")
                file_data = val
                break
        if not file_data:
            for key, fn, ct, val in candidates:
                if fn.lower().endswith('.eml'):
                    logger.info(f"Selecting .eml filename part from key '{key}'")
                    file_data = val
                    break
        if not file_data:
            if 'file' in files and isinstance(files['file'], dict):
                logger.info("Selecting 'file' key as fallback")
                file_data = files['file']
            elif 'files' in files and isinstance(files['files'], dict):
                logger.info("Selecting 'files' key as fallback")
                file_data = files['files']
            elif candidates:
                logger.info(f"Selecting first candidate part '{candidates[0][0]}' as fallback")
                file_data = candidates[0][3]

        if not file_data or not isinstance(file_data, dict) or 'content' not in file_data:
            logger.error(f"No file found in upload. Available keys: {list(files.keys())}")
            logger.error(f"Files content preview: {str(files)[:500]}...")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'No file provided'})
            }

        filename = file_data.get('filename', 'upload.eml')
        file_content = file_data['content']
        logger.info(f"File data extracted: filename='{filename}', content_type='{file_data.get('content_type', 'unknown')}', content_size={len(file_content) if file_content else 0}")

        ext = os.path.splitext(filename)[1].lower()
        if ext not in ('.eml', '.msg'):
            logger.error(f"Invalid file type. Filename: {filename}")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'File must be a .eml or .msg file'})
            }

        # If .msg, convert to .eml bytes and extract attachments first
        msg_attachments = []
        if ext == '.msg':
            try:
                logger.info("Detected .msg file - converting to EML bytes and extracting attachments...")
                eml_source, msg_attachments = converter.convert_msg_bytes_to_eml_bytes_with_attachments(file_content)
                logger.info(f".msg converted to EML: {len(eml_source) if eml_source else 0} bytes")
                logger.info(f"Extracted {len(msg_attachments)} attachments from .msg file")
            except Exception as e:
                logger.error(f".msg conversion failed: {e}")
                return {
                    'statusCode': 400,
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps({'error': 'Failed to convert .msg to .eml'})
                }
        else:
            eml_source = file_content

        logger.info(f"=== File validation passed - Processing: {filename} ===")

        # Generate or accept provided session_id so a batch shares a prefix
        logger.info("Generating session ID and filenames...")
        query = event.get('queryStringParameters', {}) or {}
        provided_sid = str((query.get('session_id') or headers.get('x-session-id') or '').strip())
        if provided_sid and re.fullmatch(r'[A-Za-z0-9_\-]{8,100}', provided_sid):
            session_id = provided_sid
            logger.info(f"Using provided session_id: {session_id}")
        else:
            session_id = str(uuid.uuid4())
            logger.info(f"Generated new session_id: {session_id}")
        # Enhanced filename derivation: Lastname, F - MM-DD-YYYY
        enhanced_base = None
        try:
            last, fi, date_str = extract_sender_name_and_date(eml_source)
            if last and fi and date_str:
                candidate = f"{last}, {fi} - {date_str}"
                cand_sanitized = sanitize_filename(candidate, default=None)
                if cand_sanitized:
                    enhanced_base = cand_sanitized
                    logger.info(f"Enhanced filename derived: {enhanced_base}")
                else:
                    logger.info("Candidate filename sanitized to empty; ignoring enhanced name.")
            else:
                logger.info("Insufficient data for enhanced filename (need last, first initial, date).")
        except Exception as e_fn:
            logger.warning(f"Enhanced filename derivation failed: {e_fn}")

        if enhanced_base:
            safe_base = enhanced_base
        else:
            safe_base = sanitize_filename(filename, default='email')
            if safe_base == 'email':
                safe_base = f"email-{uuid.uuid4().hex[:8]}"
        pdf_filename = f"{safe_base}.pdf"
        logger.info(f"Generated session_id: {session_id}, pdf_filename: {pdf_filename}")

        # Create temporary file for PDF generation
        logger.info("Creating temporary file for PDF generation...")
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as tmp_pdf:
            tmp_pdf_path = tmp_pdf.name
        logger.info(f"Temporary PDF path created: {tmp_pdf_path}")

        try:
            logger.info("=== Starting EML to PDF conversion ===")
            # Determine Twemoji base URL pointing to our API proxy (same domain) for in-PDF fetches
            twemoji_base_url = None
            try:
                proto = headers.get('x-forwarded-proto') or 'https'
                host = headers.get('host') or ''
                if host:
                    twemoji_base_url = f"{proto}://{host}/api/twemoji/"
            except Exception:
                pass
            # Convert EML to PDF
            success = convert_eml_to_pdf(eml_source, tmp_pdf_path, twemoji_base_url, msg_attachments)
            logger.info(f"EML to PDF conversion result: success={success}")

            if not success:
                return {
                    'statusCode': 500,
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps({'error': 'PDF conversion failed'})
                }

            # Validate PDF was created and has content
            if not os.path.exists(tmp_pdf_path) or os.path.getsize(tmp_pdf_path) == 0:
                return {
                    'statusCode': 500,
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps({'error': 'PDF generation produced empty file'})
                }

            # Upload PDF to S3
            s3_key = f"{session_id}/{pdf_filename}"
            with open(tmp_pdf_path, 'rb') as pdf_file:
                s3_client.upload_fileobj(
                    pdf_file,
                    S3_BUCKET,
                    s3_key,
                    ExtraArgs={'ContentType': 'application/pdf'}
                )

            logger.info(f"Successfully uploaded PDF to S3: {s3_key}")

            return {
                'statusCode': 200,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({
                    'session_id': session_id,
                    'filename': pdf_filename,
                    'message': 'Conversion successful'
                })
            }

        finally:
            # Clean up temporary file
            try:
                os.unlink(tmp_pdf_path)
            except Exception:
                pass

    except Exception as e:
        logger.error(f"Error in handle_convert: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'error': f'Internal server error: {str(e)}'})
        }

def handle_download(event: Dict[str, Any]) -> Dict[str, Any]:
    """Handle PDF download."""
    try:
        # Extract path parameters
        path_params = event.get('pathParameters', {}) or {}
        session_id = path_params.get('session_id')
        filename = path_params.get('filename')

        if not session_id or not filename:
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Missing session_id or filename'})
            }

        # URL decode filename
        import urllib.parse
        filename = urllib.parse.unquote(filename)

        # Strip query parameters that might be included in the filename path
        if '?' in filename:
            filename = filename.split('?')[0]

        s3_key = f"{session_id}/{filename}"

        logger.info(f"Attempting to download: {s3_key}")

        # Get the file from S3
        try:
            response = s3_client.get_object(Bucket=S3_BUCKET, Key=s3_key)
            file_content = response['Body'].read()

        except s3_client.exceptions.NoSuchKey:
            logger.error(f"File not found in S3: {s3_key}")
            return {
                'statusCode': 404,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'File not found'})
            }

        # Decide delivery mode: redirect by default, optional streaming if ?stream=1
        query_params = event.get('queryStringParameters', {}) or {}
        stream_flag = str(query_params.get('stream', '')).lower() in ('1', 'true', 'yes')

        presigned_url = None
        if not stream_flag:
            # Generate presigned URL for direct S3 download (bypasses API Gateway base64 proxy)
            try:
                presigned_url = s3_client.generate_presigned_url(
                    'get_object',
                    Params={
                        'Bucket': S3_BUCKET,
                        'Key': s3_key,
                        'ResponseContentType': 'application/pdf',
                        'ResponseContentDisposition': f'attachment; filename="{filename}"'
                    },
                    ExpiresIn=300  # 5 minutes
                )
            except Exception as e:
                logger.error(f"Failed to generate presigned URL: {e}")
                # Fallback to streaming if presign fails
                stream_flag = True

        if not stream_flag and presigned_url:
            # Redirect the client to S3 for the actual download
            return {
                'statusCode': 302,
                'headers': {
                    'Location': presigned_url,
                    'Cache-Control': 'no-store'
                },
                'body': ''
            }

        # Streaming fallback with integrity headers
        import hashlib
        sha256 = hashlib.sha256(file_content).hexdigest()
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/pdf',
                'Content-Disposition': f'attachment; filename="{filename}"',
                # Do not set Content-Length for base64 responses; API Gateway will compute it
                'Content-Transfer-Encoding': 'binary',
                'Cache-Control': 'no-store',
                'X-Content-SHA256': sha256,
                'X-Original-Length': str(len(file_content)),
                'Accept-Ranges': 'bytes'
            },
            'body': base64.b64encode(file_content).decode('utf-8'),
            'isBase64Encoded': True
        }

    except Exception as e:
        logger.error(f"Error in handle_download: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'error': f'Download failed: {str(e)}'})
        }

def handle_download_all(event: Dict[str, Any]) -> Dict[str, Any]:
    """Create and return a ZIP containing all PDFs for a given session_id from S3."""
    try:
        # Extract session_id from pathParameters or parse from path
        path_params = event.get('pathParameters', {}) or {}
        session_id = path_params.get('session_id')
        if not session_id:
            path = event.get('path', '') or ''
            prefix = '/api/download-all/'
            if prefix in path:
                session_id = path.split(prefix, 1)[1].split('/', 1)[0]

        if not session_id:
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Missing session_id'})
            }

        # List PDFs under the session prefix
        prefix_key = f"{session_id}/"
        pdf_keys = []
        try:
            paginator = s3_client.get_paginator('list_objects_v2')
            for page in paginator.paginate(Bucket=S3_BUCKET, Prefix=prefix_key):
                for item in page.get('Contents', []) or []:
                    key = item.get('Key', '')
                    if key.lower().endswith('.pdf'):
                        pdf_keys.append(key)
        except Exception as e:
            logger.error(f"S3 list_objects failed for prefix {prefix_key}: {e}")
            return {
                'statusCode': 500,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Failed to list session files'})
            }

        if not pdf_keys:
            return {
                'statusCode': 404,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'No PDF files found for session'})
            }

        # Build ZIP in /tmp
        import zipfile, os as _os
        zip_filename = f"converted_pdfs_{session_id}.zip"
        zip_path = _os.path.join(tempfile.gettempdir(), zip_filename)

        try:
            with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
                for key in pdf_keys:
                    try:
                        obj = s3_client.get_object(Bucket=S3_BUCKET, Key=key)
                        data = obj['Body'].read()
                        arcname = _os.path.basename(key)
                        zf.writestr(arcname, data)
                    except Exception as e:
                        logger.warning(f"Skipping key {key} due to error: {e}")
        except Exception as e:
            logger.error(f"Failed to create ZIP: {e}")
            return {
                'statusCode': 500,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Failed to create ZIP'})
            }

        # Upload ZIP to S3
        out_key = f"{session_id}/{zip_filename}"
        try:
            with open(zip_path, 'rb') as f:
                s3_client.upload_fileobj(
                    f,
                    S3_BUCKET,
                    out_key,
                    ExtraArgs={
                        'ContentType': 'application/zip',
                        'ContentDisposition': f'attachment; filename="{zip_filename}"'
                    }
                )
        except Exception as e:
            logger.error(f"Failed to upload ZIP to S3: {e}")
            # Fallback: stream the ZIP directly (base64) if upload fails
            try:
                with open(zip_path, 'rb') as f:
                    data = f.read()
                import hashlib, base64 as _b64
                sha256 = hashlib.sha256(data).hexdigest()
                return {
                    'statusCode': 200,
                    'headers': {
                        'Content-Type': 'application/zip',
                        'Content-Disposition': f'attachment; filename="{zip_filename}"',
                        'Cache-Control': 'no-store',
                        'X-Content-SHA256': sha256,
                        'X-Original-Length': str(len(data))
                    },
                    'body': _b64.b64encode(data).decode('utf-8'),
                    'isBase64Encoded': True
                }
            except Exception as e2:
                logger.error(f"Failed to stream ZIP fallback: {e2}")
                return {
                    'statusCode': 500,
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps({'error': 'Failed to deliver ZIP'})
                }
        finally:
            # Cleanup local ZIP
            try:
                _os.unlink(zip_path)
            except Exception:
                pass

        # Generate presigned URL and redirect
        try:
            presigned_url = s3_client.generate_presigned_url(
                'get_object',
                Params={
                    'Bucket': S3_BUCKET,
                    'Key': out_key,
                    'ResponseContentType': 'application/zip',
                    'ResponseContentDisposition': f'attachment; filename="{zip_filename}"'
                },
                ExpiresIn=300
            )
            return {
                'statusCode': 302,
                'headers': {
                    'Location': presigned_url,
                    'Cache-Control': 'no-store'
                },
                'body': ''
            }
        except Exception as e:
            logger.error(f"Failed to presign ZIP URL: {e}")
            # Final fallback: 200 with a JSON link (client can follow)
            return {
                'statusCode': 200,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'key': out_key})
            }

    except Exception as e:
        logger.error(f"Error in handle_download_all: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'error': f'Download-all failed: {str(e)}'})
        }

def handle_health(event: Dict[str, Any]) -> Dict[str, Any]:
    """Handle health check."""
    return {
        'statusCode': 200,
        'headers': {'Content-Type': 'application/json'},
        'body': json.dumps({'status': 'healthy', 'service': 'eml-to-pdf-converter'})
    }

def handle_upload_url(event: Dict[str, Any]) -> Dict[str, Any]:
    """Return a presigned S3 PUT URL for direct browser upload (bypasses API GW 10MB limit)."""
    try:
        parser = RequestParser(event)
        data = parser.json()

        filename = str(data.get("filename") or "").strip()
        content_type = str(data.get("content_type") or "application/octet-stream")

        if not filename:
            return {
                "statusCode": 400,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": "filename is required"})
            }

        # Sanitize and ensure extension preserved
        base = sanitize_filename(filename, default="upload")
        ext = os.path.splitext(filename)[1].lower()
        if ext not in (".eml", ".msg"):
            return {
                "statusCode": 400,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": "File must be a .eml or .msg file"})
            }
        safe_filename = f"{base}{ext}"

        # Key under uploads/{uuid}/
        upload_id = str(uuid.uuid4())
        s3_key = f"uploads/{upload_id}/{safe_filename}"

        # Generate presigned PUT URL
        url = s3_client.generate_presigned_url(
            "put_object",
            Params={"Bucket": S3_BUCKET, "Key": s3_key, "ContentType": content_type},
            ExpiresIn=900  # 15 minutes
        )

        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"url": url, "key": s3_key})
        }
    except Exception as e:
        logger.error(f"Error in handle_upload_url: {e}")
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": f"Failed to generate upload URL: {str(e)}"})
        }

def handle_convert_s3(event: Dict[str, Any]) -> Dict[str, Any]:
    """Convert files that were uploaded directly to S3 (by key) and return batch results."""
    try:
        for p in Path('/tmp').glob('*'):
            if p.is_file() or p.is_symlink():
                p.unlink(missing_ok=True)
            else:
                shutil.rmtree(p, ignore_errors=True)

        parser = RequestParser(event)
        data = parser.json()
        if not data:
            data = {}

        keys = data.get("keys") or []
        if not isinstance(keys, list) or not keys:
            return {
                "statusCode": 400,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": "keys array is required"})
            }

        # Determine or accept provided session_id so all results share one prefix
        headers = parser.headers
        query = event.get('queryStringParameters', {}) or {}
        provided_sid = str((data.get('session_id') or query.get('session_id') or headers.get('x-session-id') or '').strip())
        if provided_sid and re.fullmatch(r'[A-Za-z0-9_\-]{8,100}', provided_sid):
            session_id = provided_sid
            logger.info(f"Using provided session_id (convert-s3): {session_id}")
        else:
            session_id = str(uuid.uuid4())
            logger.info(f"Generated new session_id (convert-s3): {session_id}")
        results = []

        for key in keys:
            try:
                s3_key = str(key)
                original_name = os.path.basename(s3_key)
                base_no_ext = sanitize_filename(original_name, default="email")
                ext = os.path.splitext(original_name)[1].lower()

                # Pull from S3
                obj = s3_client.get_object(Bucket=S3_BUCKET, Key=s3_key)
                file_bytes = obj["Body"].read()

                # Convert .msg to EML bytes and extract attachments if needed
                msg_attachments = []
                if ext == ".msg":
                    try:
                        eml_source, msg_attachments = converter.convert_msg_bytes_to_eml_bytes_with_attachments(file_bytes)
                        logger.info(f"Extracted {len(msg_attachments)} attachments from {s3_key}")
                    except Exception as e:
                        logger.error(f".msg conversion failed for {s3_key}: {e}")
                        results.append({
                            "filename": original_name,
                            "status": "error",
                            "message": "Failed to convert .msg to .eml",
                            "session_id": None,
                            "pdf_filename": None
                        })
                        continue
                elif ext == ".eml":
                    eml_source = file_bytes
                else:
                    results.append({
                        "filename": original_name,
                        "status": "error",
                        "message": "Unsupported file type",
                        "session_id": None,
                        "pdf_filename": None
                    })
                    continue

                # Generate a temp PDF and convert
                with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp_pdf:
                    tmp_pdf_path = tmp_pdf.name

                try:
                    ok = convert_eml_to_pdf(eml_source, tmp_pdf_path, None, msg_attachments)
                    if not ok or not os.path.exists(tmp_pdf_path) or os.path.getsize(tmp_pdf_path) == 0:
                        results.append({
                            "filename": original_name,
                            "status": "error",
                            "message": "PDF conversion failed",
                            "session_id": None,
                            "pdf_filename": None
                        })
                        continue

                    # Enhanced filename derivation for batch
                    enhanced_base = None
                    try:
                        last, fi, date_str = extract_sender_name_and_date(eml_source)
                        if last and fi and date_str:
                            candidate = f"{last}, {fi} - {date_str}"
                            cand_sanitized = sanitize_filename(candidate, default=None)
                            if cand_sanitized:
                                enhanced_base = cand_sanitized
                                logger.info(f"[convert-s3] Enhanced filename derived for {original_name}: {enhanced_base}")
                    except Exception as e_fn:
                        logger.warning(f"[convert-s3] Enhanced filename derivation failed for {original_name}: {e_fn}")
                    if enhanced_base:
                        base_no_ext = enhanced_base
                    else:
                        if base_no_ext == 'email':
                            base_no_ext = f"email-{uuid.uuid4().hex[:8]}"

                    # Upload PDF to S3
                    pdf_filename = f"{base_no_ext}.pdf"
                    out_key = f"{session_id}/{pdf_filename}"
                    with open(tmp_pdf_path, "rb") as f:
                        s3_client.upload_fileobj(
                            f,
                            S3_BUCKET,
                            out_key,
                            ExtraArgs={"ContentType": "application/pdf"}
                        )

                    results.append({
                        "filename": original_name,
                        "status": "success",
                        "session_id": session_id,
                        "pdf_filename": pdf_filename
                    })
                finally:
                    try:
                        os.unlink(tmp_pdf_path)
                    except Exception:
                        pass

            except Exception as e:
                logger.error(f"convert-s3 failed for key {key}: {e}")
                results.append({
                    "filename": os.path.basename(str(key)),
                    "status": "error",
                    "message": str(e),
                    "session_id": None,
                    "pdf_filename": None
                })

        total = len(keys)
        success_count = len([r for r in results if r.get("status") == "success"])
        failed_count = total - success_count

        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({
                "results": results,
                "total_files": total,
                "successful_conversions": success_count,
                "failed_conversions": failed_count,
                "session_id": session_id if success_count else None
            })
        }

    except Exception as e:
        logger.error(f"Error in handle_convert_s3: {e}")
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": f"convert-s3 failed: {str(e)}"})
        }

def handle_auth_check(event: Dict[str, Any]) -> Dict[str, Any]:
    """Handle authentication check."""
    app_password = os.environ.get('APP_PASSWORD')

    if not app_password:
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'ok': True, 'auth': 'not-required'})
        }

    # Check for password in headers or query parameters
    parser = RequestParser(event)
    headers = parser.headers
    query_params = event.get('queryStringParameters', {}) or {}

    provided_password = (
        headers.get('x-app-password') or
        query_params.get('auth')
    )

    if provided_password == app_password:
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'ok': True})
        }
    else:
        return {
            'statusCode': 401,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'ok': False})
        }

def cleanup_browser_processes():
    """Clean up any lingering browser processes using psutil."""
    try:
        import psutil
        import shutil
        
        # Kill any chrome/chromium processes that might be hanging
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    # Check if process name contains chrome/chromium
                    if proc.info['name'] and any(browser in proc.info['name'].lower() 
                                               for browser in ['chrome', 'chromium']):
                        logger.info(f"Terminating browser process: {proc.info['name']} (PID: {proc.info['pid']})")
                        proc.terminate()
                        # Wait for graceful termination
                        proc.wait(timeout=3)
                    # Also check command line for browser processes
                    elif proc.info['cmdline'] and any(browser in ' '.join(proc.info['cmdline']).lower() 
                                                    for browser in ['chrome', 'chromium']):
                        logger.info(f"Terminating browser process by cmdline: PID {proc.info['pid']}")
                        proc.terminate()
                        proc.wait(timeout=3)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
                    # Process may have already terminated or we don't have permission
                    pass
        except Exception as e:
            logger.warning(f"Failed to kill browser processes: {e}")
            
        # Clean up temporary playwright files
        temp_dirs = ['/tmp/.playwright', '/tmp/playwright-*']
        for pattern in temp_dirs:
            try:
                import glob
                for path in glob.glob(pattern):
                    if os.path.isdir(path):
                        shutil.rmtree(path, ignore_errors=True)
                    elif os.path.isfile(path):
                        os.unlink(path)
            except Exception as e:
                logger.warning(f"Failed to clean temp files {pattern}: {e}")
                
    except Exception as e:
        logger.warning(f"Browser cleanup failed: {e}")

def verify_playwright_installation():
    """Verify that Playwright browsers are properly installed."""
    try:
        from playwright.sync_api import sync_playwright
        
        with sync_playwright() as p:
            browser_path = p.chromium.executable_path
            logger.info(f"Playwright browser executable found at: {browser_path}")
            
            # Check if the executable actually exists
            if os.path.exists(browser_path):
                logger.info("Playwright browser verification: PASSED")
                return True
            else:
                logger.error(f"Playwright browser executable not found at: {browser_path}")
                return False
                
    except Exception as e:
        logger.error(f"Playwright browser verification failed: {e}")
        return False

def handle_twemoji(event: Dict[str, Any]) -> Dict[str, Any]:
    """Serve Twemoji SVGs via backend proxy to ensure emoji rendering in PDFs."""
    try:
        path = event.get('path', '') or ''
        # Expect /api/twemoji/<filename>.svg
        filename = path.rsplit('/', 1)[-1]
        import os as _os
        safe_name = _os.path.basename(filename or '')
        if not safe_name.lower().endswith('.svg'):
            return {'statusCode': 404, 'headers': {'Content-Type': 'application/json'}, 'body': json.dumps({'error': 'Not found'})}

        # Optional simple cache in /tmp
        cache_dir = '/tmp/twemoji_cache'
        try:
            _os.makedirs(cache_dir, exist_ok=True)
        except Exception:
            pass
        local_path = _os.path.join(cache_dir, safe_name)

        svg_bytes = None
        try:
            if _os.path.exists(local_path):
                with open(local_path, 'rb') as f:
                    svg_bytes = f.read()
        except Exception:
            svg_bytes = None

        if svg_bytes is None:
            import urllib.request
            cdn_url = f'https://cdnjs.cloudflare.com/ajax/libs/twemoji/14.0.2/svg/{safe_name}'
            with urllib.request.urlopen(cdn_url, timeout=10) as resp:
                svg_bytes = resp.read()
            try:
                with open(local_path, 'wb') as f:
                    f.write(svg_bytes)
            except Exception:
                pass

        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'image/svg+xml',
                'Cache-Control': 'public, max-age=31536000, immutable'
            },
            'body': svg_bytes.decode('utf-8', errors='replace')
        }
    except Exception as e:
        logger.error(f"Twemoji proxy error: {e}")
        return {
            'statusCode': 502,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'error': 'Emoji asset unavailable'})
        }

router = LambdaRouter(verify_playwright_installation)
HANDLERS = {
    ("POST", "/api/convert"): handle_convert,
    ("POST", "/api/upload-url"): handle_upload_url,
    ("POST", "/api/convert-s3"): handle_convert_s3,
    ("GET", "/api/health"): handle_health,
    ("GET", "/api/auth/check"): handle_auth_check,
    "download": handle_download,
    "download_all": handle_download_all,
    "twemoji": handle_twemoji,
}
def lambda_handler(event, context):
    """Main Lambda entry point."""
    try:
        return router.handle(event, HANDLERS)
    finally:
        cleanup_browser_processes()
        logger.info("Lambda handler completed")

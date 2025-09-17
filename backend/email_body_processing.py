"""Utilities for extracting rich email body content and inline images."""

from __future__ import annotations

import base64
import email
from email import policy as email_policy
import html
import logging
import os
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from html_processing import (
    clean_html_content,
    extract_style_blocks,
    normalize_body_html_fragment,
    normalize_whitespace,
    strip_word_section_wrappers,
)
from image_processing import (
    ensure_displayable_image_bytes,
    inline_image_attachments_into_body,
    normalize_lookup_key,
    normalize_url,
    replace_image_references,
)


logger = logging.getLogger(__name__)


def get_part_content(part) -> Optional[str]:
    """Safely extract content from email part with fallback methods."""

    try:
        if hasattr(part, "get_content"):
            return part.get_content()

        payload = part.get_payload(decode=True)
        if payload:
            charset = part.get_content_charset() or "utf-8"
            try:
                return payload.decode(charset)
            except (UnicodeDecodeError, LookupError):
                for enc in ["utf-8", "latin1", "cp1252", "iso-8859-1"]:
                    try:
                        return payload.decode(enc)
                    except (UnicodeDecodeError, LookupError):
                        continue
                return payload.decode("utf-8", errors="replace")

        payload = part.get_payload()
        if isinstance(payload, str):
            return payload
        return None
    except Exception as exc:  # pragma: no cover - defensive logging
        logger.warning("Error extracting content from email part: %s", exc)
        try:
            payload = part.get_payload()
            if isinstance(payload, str):
                return payload
            if isinstance(payload, (bytes, bytearray)):
                return payload.decode("utf-8", errors="replace")
        except Exception as fallback_exc:  # pragma: no cover - defensive logging
            logger.error("Failed to extract content with fallback: %s", fallback_exc)
        return None


def extract_body_and_images_from_email(
    msg,
    msg_attachments: Optional[Iterable[Dict]] = None,
    *,
    msg_to_eml_converter: Optional[Callable[[bytes], bytes]] = None,
    eml_to_pdf_converter: Optional[Callable[[bytes], Optional[bytes]]] = None,
    office_to_pdf_converter: Optional[Callable[[bytes, str], Optional[bytes]]] = None,
) -> Tuple[str, Dict[str, str], List[Dict]]:
    """Extract best HTML/plain body and inline images as data URLs."""

    images: Dict[str, str] = {}
    attachments: List[Dict] = []
    html_candidates: List[Tuple[int, str]] = []
    text_candidates: List[Tuple[int, str]] = []
    collected_styles: List[str] = []
    extract_body_and_images_from_email.last_collected_styles = collected_styles

    def process_part(part) -> None:
        try:
            ctype = part.get_content_type()
            cdisp = (part.get("Content-Disposition") or "").lower()
            cid = part.get("Content-ID")
            if cid:
                cid = cid.strip("<>")
            cloc = part.get("Content-Location")
            fname = part.get_filename()

            is_attachment = "attachment" in cdisp

            if ctype == "message/rfc822" or (fname and fname.lower().endswith((".eml", ".msg"))):
                payload = part.get_payload(decode=True) or part.get_payload()
                if "attachment" in cdisp or fname:
                    try:
                        data = payload
                        if not isinstance(data, (bytes, bytearray)) and hasattr(data, "as_bytes"):
                            data = data.as_bytes()
                        if data and fname and fname.lower().endswith(".msg") and msg_to_eml_converter:
                            data = msg_to_eml_converter(data)
                        pdf_data: Optional[bytes] = None
                        if data and eml_to_pdf_converter:
                            pdf_data = eml_to_pdf_converter(data)
                        if data and pdf_data:
                            att_name = os.path.splitext(fname or f"attachment-{len(attachments)+1}")[0] + ".pdf"
                            attachments.append(
                                {
                                    "filename": att_name,
                                    "content_type": "application/pdf",
                                    "data": pdf_data,
                                }
                            )
                    except Exception as exc:  # pragma: no cover - defensive logging
                        logger.warning("Failed to process attached message: %s", exc)
                    return
                try:
                    if isinstance(payload, (bytes, bytearray)):
                        nested = email.message_from_bytes(payload, policy=email_policy.default)
                        process_message(nested)
                    elif hasattr(payload, "walk"):
                        process_message(payload)
                except Exception as exc:  # pragma: no cover - defensive logging
                    logger.warning("Failed to process nested message/rfc822: %s", exc)
                return

            is_image = False
            ctype_for_data = ctype
            try:
                if ctype and ctype.startswith("image/"):
                    is_image = True
                else:
                    import mimetypes

                    guess_src = fname or cloc or ""
                    guessed, _ = mimetypes.guess_type(guess_src)
                    if guessed and guessed.startswith("image/"):
                        is_image = True
                        ctype_for_data = guessed
            except Exception:  # pragma: no cover - defensive logging
                pass
            if is_image:
                img_bytes = part.get_payload(decode=True)
                if not img_bytes:
                    payload = part.get_payload()
                    if isinstance(payload, (bytes, bytearray)):
                        img_bytes = payload
                if img_bytes:
                    if is_attachment:
                        att_name = fname or f"attachment-{len(attachments)+1}"
                        display_bytes, usable_type = ensure_displayable_image_bytes(
                            img_bytes,
                            ctype_for_data or ctype,
                            source_name=fname or cloc or cid,
                        )
                        attachments.append(
                            {
                                "filename": att_name,
                                "content_type": usable_type or ctype or "image/octet-stream",
                                "data": bytes(display_bytes or img_bytes),
                            }
                        )
                        logger.info(
                            "Captured image attachment %s (%s, %d bytes) for later PDF conversion",
                            att_name,
                            usable_type or ctype or "image",
                            len(display_bytes or img_bytes),
                        )
                    else:
                        display_bytes, ctype_for_data = ensure_displayable_image_bytes(
                            img_bytes,
                            ctype_for_data or ctype,
                            source_name=fname or cloc or cid,
                        )
                        if not ctype_for_data:
                            ctype_for_data = "image/png"
                        b64 = base64.b64encode(display_bytes or img_bytes).decode("utf-8")
                        data_url = f"data:{ctype_for_data};base64,{b64}"
                        keys = set()
                        if cid:
                            keys.add(f"cid:{cid}")
                            keys.add(cid)
                        if cloc:
                            keys.add(cloc)
                        if fname:
                            keys.add(fname)
                            try:
                                keys.add(f"cid:{fname}")
                            except Exception:
                                pass
                            try:
                                base = os.path.basename(fname)
                                if base:
                                    keys.add(base)
                                    keys.add(normalize_lookup_key(base))
                                    try:
                                        keys.add(f"cid:{base}")
                                    except Exception:
                                        pass
                            except Exception:
                                pass
                        for key in keys:
                            try:
                                images[key] = data_url
                                normalized = normalize_lookup_key(str(key))
                                images[normalized] = data_url
                                if str(key).lower().startswith(("http://", "https://")):
                                    images[normalize_url(str(key))] = data_url
                            except Exception:
                                images[key] = data_url
                        images.setdefault(f"__unref__:{len(images)}", data_url)
                return

            is_inline_pdf = (ctype == "application/pdf") or (fname and fname.lower().endswith(".pdf"))
            is_office = ctype in (
                "application/msword",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ) or (fname and fname.lower().endswith((".doc", ".docx")))
            if is_attachment or is_inline_pdf or is_office:
                try:
                    data = part.get_payload(decode=True)
                    if not data:
                        data = part.get_payload()
                    if data:
                        if ctype == "application/pdf" or (fname and fname.lower().endswith(".pdf")):
                            att_name = fname or f"attachment-{len(attachments)+1}.pdf"
                            if not att_name.lower().endswith(".pdf"):
                                att_name += ".pdf"
                            attachments.append(
                                {
                                    "filename": att_name,
                                    "content_type": "application/pdf",
                                    "data": data,
                                }
                            )
                            return
                        if is_office and office_to_pdf_converter:
                            ext = os.path.splitext(fname or "")[1] or ".docx"
                            pdf_data = office_to_pdf_converter(data, ext)
                            if pdf_data:
                                att_name = os.path.splitext(fname or f"attachment-{len(attachments)+1}")[0] + ".pdf"
                                attachments.append(
                                    {
                                        "filename": att_name,
                                        "content_type": "application/pdf",
                                        "data": pdf_data,
                                    }
                                )
                            return
                except Exception as exc:  # pragma: no cover - defensive logging
                    logger.warning("Error extracting attachment: %s", exc)
                    return

            if "attachment" in cdisp and not (ctype or "").startswith("text/"):
                return

            if ctype == "text/html":
                content = get_part_content(part)
                if content:
                    logger.info("DEBUGGING: Found HTML part with %s chars", len(content))
                    logger.info("DEBUGGING: HTML part preview: %s...", content[:300])
                    cleaned = clean_html_content(content, style_collector=collected_styles)
                    html_candidates.append((len(cleaned), cleaned))
                return

            if ctype == "text/plain":
                content = get_part_content(part)
                if content:
                    logger.info("DEBUGGING: Found text/plain part with %s chars", len(content))
                    logger.info("DEBUGGING: Text part preview: %s...", content[:300])
                    htmlized = html.escape(content).replace("\n", "<br>\n")
                    text_candidates.append((len(htmlized), htmlized))
                return
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.warning("Error processing part: %s", exc)

    def process_message(message) -> None:
        try:
            if message.is_multipart():
                for inner in message.walk():
                    if inner is not message:
                        process_part(inner)
            else:
                process_part(message)
        except Exception as exc:  # pragma: no cover - defensive logging
            logger.warning("Error walking message: %s", exc)

    process_message(msg)

    body: Optional[str] = None
    html_body: Optional[str] = None
    html_length = 0
    if html_candidates:
        html_length, html_body = max(html_candidates, key=lambda item: item[0])

    text_body: Optional[str] = None
    text_length = 0
    logger.info(
        "DEBUGGING: Body selection - HTML candidates: %d, Text candidates: %d",
        len(html_candidates),
        len(text_candidates),
    )

    if len(text_candidates) > 1:
        logger.info("DEBUGGING: Multiple text parts detected - analyzing for forwarded content")

        local_embedded = any(att.get("content_type") == "message/rfc822" for att in attachments)

        msg_embedded = False
        msg_attachments_list = list(msg_attachments or [])
        if msg_attachments_list:
            msg_embedded = any(
                att.get("content_type") == "message/rfc822"
                or str(att.get("filename", "")).lower().endswith(".eml")
                for att in msg_attachments_list
            )
            logger.info("DEBUGGING: msg_attachments contains %d items:", len(msg_attachments_list))
            for idx, att in enumerate(msg_attachments_list):
                logger.info("  - %d: %s (type: %s)", idx + 1, att.get("filename"), att.get("content_type"))
        else:
            msg_attachments_list = []

        has_embedded_msg = local_embedded or msg_embedded
        logger.info(
            "DEBUGGING: Has embedded message attachments: %s (local: %s, msg_attachments: %s)",
            has_embedded_msg,
            local_embedded,
            msg_embedded,
        )

        original_parts: List[Tuple[int, str]] = []

        for idx, (length, content) in enumerate(text_candidates):
            preview = content[:200].replace("<br>", " ").replace("\n", " ")
            logger.info("DEBUGGING: Analyzing text part %d (%d chars): %s...", idx + 1, length, preview)

            is_forwarded = (
                "---------- Forwarded message ---------" in content
                and not any(
                    phrase in content[:500]
                    for phrase in ["Good afternoon", "good afternoon", "I wanted to"]
                )
            )

            if is_forwarded:
                logger.info("DEBUGGING: Text part %d identified as FORWARDED content", idx + 1)
            else:
                logger.info("DEBUGGING: Text part %d identified as ORIGINAL content", idx + 1)
                original_parts.append((length, content))

        if has_embedded_msg and original_parts:
            logger.info(
                "DEBUGGING: Using only original parts (%d) - forwarded content will appear as attachment",
                len(original_parts),
            )
            combined_parts = [content for _, content in original_parts]
            text_body = "<br><br>".join(combined_parts)
            text_length = len(text_body)
            logger.info("DEBUGGING: Original-only body content: %d chars total", text_length)
        else:
            logger.info("DEBUGGING: No embedded attachments or no original parts - combining all text parts")
            sorted_text = sorted(
                text_candidates,
                key=lambda item: (
                    0
                    if any(
                        phrase in item[1][:300]
                        for phrase in ["Good afternoon", "good afternoon", "I wanted to"]
                    )
                    else 1,
                    -item[0],
                ),
            )
            combined_parts = [content for _, content in sorted_text]
            text_body = "<br><br>".join(combined_parts)
            text_length = len(text_body)
            logger.info("DEBUGGING: All-parts combined content: %d chars total", text_length)

    elif text_candidates:
        text_length, text_body = max(text_candidates, key=lambda item: item[0])
        logger.info("DEBUGGING: Selected single text body with %d chars", text_length)
    else:
        msg_attachments_list = list(msg_attachments or [])

    if html_body:
        if text_body and html_body != text_body:
            logger.info(
                "DEBUGGING: Preferring HTML body with %s chars over text body with %s chars to preserve formatting",
                html_length,
                text_length,
            )
        else:
            logger.info(
                "DEBUGGING: Using HTML body (%s chars); text was %s",
                html_length,
                text_length if text_body else "absent",
            )
        body = html_body
    elif text_body is not None:
        body = text_body

    if not body:
        body = "No content available"

    if body and "---------- Forwarded message ---------" in body:
        logger.info("DEBUGGING: Detected forwarded message in body")

        if not any(
            phrase in body[:500]
            for phrase in [
                "Good afternoon",
                "good afternoon",
                "Good morning",
                "good morning",
                "Hello",
                "hello",
                "Hi ",
                "hi ",
            ]
        ):
            logger.warning("DEBUGGING: Original content may be missing - body starts with forwarded content")

            for part in msg.walk():
                if part.get_content_type() in ["text/plain", "text/html"]:
                    full_content = get_part_content(part)
                    if full_content and len(full_content) > len(body):
                        has_greeting = any(
                            phrase in full_content
                            for phrase in [
                                "Good afternoon",
                                "good afternoon",
                                "I wanted to",
                                "afternoon, Nick",
                            ]
                        )
                        has_forwarded = "---------- Forwarded message ---------" in full_content

                        if has_greeting or len(full_content) > len(body) * 2:
                            logger.info(
                                "DEBUGGING: Found better content part: %d chars (has_greeting: %s, has_forwarded: %s)",
                                len(full_content),
                                has_greeting,
                                has_forwarded,
                            )
                            logger.info("DEBUGGING: Better content preview: %s...", full_content[:300])

                            if part.get_content_type() == "text/plain":
                                body = html.escape(full_content).replace("\n", "<br>\n")
                            else:
                                body = clean_html_content(full_content, style_collector=collected_styles)
                            break

    if images and body:
        body = replace_image_references(
            body,
            {k: v for k, v in images.items() if not str(k).startswith("__unref__:")},
        )

    if body:
        body, inline_styles = extract_style_blocks(body)
        if inline_styles:
            collected_styles.extend(inline_styles)
            logger.info("Captured %d <style> block(s) during body extraction", len(inline_styles))

    body = normalize_whitespace(body)

    logger.info(
        "Parsed email: body_len=%d, images_inlined=%d",
        len(body) if body else 0,
        sum(1 for key in images.keys() if not str(key).startswith("__unref__:")),
    )

    attachments = list(attachments or [])
    msg_attachments_list = list(msg_attachments or [])

    body, attachments, inlined_primary = inline_image_attachments_into_body(
        body,
        attachments,
        "email-attachment",
    )
    if inlined_primary:
        primary_names = {name.lower() for name in inlined_primary}
        msg_attachments_list = [
            att
            for att in msg_attachments_list
            if (att.get("filename") or "").lower() not in primary_names
        ]

    body, msg_attachments_list, inlined_msg = inline_image_attachments_into_body(
        body,
        msg_attachments_list,
        "msg-attachment",
    )
    if inlined_primary or inlined_msg:
        logger.info(
            "INLINE IMAGES: embedded %d email image(s) and %d msg attachment image(s) into body",
            len(inlined_primary),
            len(inlined_msg),
        )

    body = normalize_body_html_fragment(body)
    body, word_cleanup = strip_word_section_wrappers(body)
    if word_cleanup.get("wrappers_removed") or word_cleanup.get("class_refs_removed"):
        logger.info(
            "WORD CLEANUP: Removed %s WordSection wrapper(s); stripped %s WordSection class reference(s)",
            word_cleanup.get("wrappers_removed", 0),
            word_cleanup.get("class_refs_removed", 0),
        )

    extract_body_and_images_from_email.last_collected_styles = collected_styles
    return body, images, attachments


__all__ = [
    "extract_body_and_images_from_email",
    "get_part_content",
]


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
from email.header import decode_header
from email.message import EmailMessage
from email.generator import BytesGenerator
from email.utils import parseaddr, parsedate_to_datetime, format_datetime
from datetime import datetime, timezone
import io
import html
import re
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


############################################
# Robust logging configuration
# In AWS Lambda the root logger may already have a handler at WARNING level
# (so logging.basicConfig will NO-OP). We explicitly adjust the root logger
# level and add a handler if none exists so INFO logs always reach CloudWatch.
############################################


def _configure_logging():
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    root = logging.getLogger()

    # Always set the root level explicitly (Lambda default can be WARNING)
    try:
        root.setLevel(getattr(logging, log_level, logging.INFO))
    except Exception:
        root.setLevel(logging.INFO)

    # If there are no handlers (e.g., local run) add a StreamHandler
    if not root.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s %(levelname)s [%(name)s] %(message)s'
        )
        handler.setFormatter(formatter)
        root.addHandler(handler)

    # Quiet overly chatty libraries unless overridden
    logging.getLogger('boto3').setLevel(logging.WARNING)
    logging.getLogger('botocore').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)

_configure_logging()
logger = logging.getLogger(__name__)
logger.debug("Logging configured: level=%s, handlers=%s", logging.getLevelName(logger.level), len(logging.getLogger().handlers))

converter = EmailConverter(logger)
doc_converter = DocumentConverter(logger)
multipart_parser = MultipartParser(logger)


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

def get_part_content(part):
    """Safely extract content from email part with fallback methods"""
    try:
        if hasattr(part, 'get_content'):
            return part.get_content()

        payload = part.get_payload(decode=True)
        if payload:
            charset = part.get_content_charset() or 'utf-8'
            try:
                return payload.decode(charset)
            except (UnicodeDecodeError, LookupError):
                for enc in ['utf-8', 'latin1', 'cp1252', 'iso-8859-1']:
                    try:
                        return payload.decode(enc)
                    except (UnicodeDecodeError, LookupError):
                        continue
                return payload.decode('utf-8', errors='replace')

        payload = part.get_payload()
        if isinstance(payload, str):
            return payload
        return None
    except Exception as e:
        logger.warning(f"Error extracting content from email part: {str(e)}")
        try:
            payload = part.get_payload()
            if isinstance(payload, str):
                return payload
            elif isinstance(payload, bytes):
                return payload.decode('utf-8', errors='replace')
        except Exception as e2:
            logger.error(f"Failed to extract content with fallback: {str(e2)}")
        return None

def clean_html_content(html_content: str) -> str:
    """Basic HTML sanitation and cleanup."""
    try:
        html_content = re.sub(r'<script[^>]*>.*?</script>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
        html_content = re.sub(r'<style[^>]*>.*?</style>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
        html_content = re.sub(r'\s*on\w+\s*=\s*["\'][^"\']*["\']', '', html_content, flags=re.IGNORECASE)
        html_content = re.sub(r'\s*javascript\s*:', '', html_content, flags=re.IGNORECASE)
        html_content = re.sub(r'<o:p[^>]*>.*?</o:p>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
        html_content = re.sub(r'<!\[if[^>]*>.*?<!\[endif\]>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
        return html_content
    except Exception as e:
        logger.warning(f"Error cleaning HTML content: {str(e)}")
        return html.escape(str(html_content)).replace('\n', '<br>\n')

def normalize_whitespace(html_content: str) -> str:
    """Aggressively normalize whitespace to prevent rendering gaps and fix typography ligatures in URLs/text."""
    if not html_content:
        return ""
    # Stage 0: Normalize Unicode compatibility forms (e.g., turn 'ﬀ' into 'ff')
    try:
        import unicodedata
        html_content = unicodedata.normalize('NFKC', html_content)
    except Exception:
        pass
    # Stage 1: Normalize all forms of spaces and invisible characters
    # Replace non-breaking spaces, various Unicode spaces, and tabs with a regular space
    content = html_content.replace('&nbsp;', ' ')
    content = re.sub(r'[\u00A0\u2000-\u200B\u202F\u205F\u3000\t]', ' ', content)
    # Remove zero-width characters that can affect layout
    content = content.replace('\u200B', '').replace('\uFEFF', '')
    # Also strip WORD JOINER and SOFT HYPHEN
    content = content.replace('\u2060', '').replace('\u00AD', '')
    # Convert visible escape sequences into actual newlines before collapsing
    content = content.replace('\\r\\n', '\n').replace('\\n', '\n').replace('\\r', '\n')

    # Stage 2: Collapse spacing
    # Collapse multiple spaces into a single space
    content = re.sub(r' {2,}', ' ', content)
    # Replace newlines with a single space to prevent them from creating layout gaps
    content = re.sub(r'[\r\n]+', ' ', content)
    
    # Trim leading/trailing whitespace from the entire block
    return content.strip()


# --- Helper: normalize image lookup keys (NFKC, strip zero-width, collapse spaces) ---
def _normalize_key(s: str) -> str:
    """Normalize strings used as image lookup keys: NFKC + strip zero-width + collapse spaces."""
    try:
        import unicodedata, re
        x = unicodedata.normalize('NFKC', s or "")
        # Remove zero-width and soft hyphen characters
        x = x.replace("\u200B", "").replace("\uFEFF", "").replace("\u2060", "").replace("\u00AD", "")
        # Remove all whitespace
        x = re.sub(r"\s+", "", x)
        return x
    except Exception:
        return s or ""


def _normalize_url(u: str) -> str:
    """Decode percent-encodings, NFKC-normalize ligatures (e.g., \uFB00 -> 'ff'), strip zero-width chars, then re-encode.
    Keeps scheme/host untouched while cleaning path/query. Safe for problematic .gov links that contain ligatures.
    """
    try:
        import unicodedata, urllib.parse, re
        s = u or ""
        parsed = urllib.parse.urlsplit(s)
        # Decode path/query for normalization
        path = urllib.parse.unquote(parsed.path or "")
        query = urllib.parse.unquote(parsed.query or "")
        # Normalize ligatures and compatibility forms
        path = unicodedata.normalize('NFKC', path)
        query = unicodedata.normalize('NFKC', query)
        # Strip zero-width and soft hyphen
        zap = dict.fromkeys(map(ord, "\u200B\uFEFF\u2060\u00AD"), None)
        path = path.translate(zap)
        query = query.translate(zap)
        # Remove whitespace accidentally inserted inside URLs
        path = re.sub(r"\s+", "", path)
        query = re.sub(r"\s+", "", query)
        # Rebuild URL with safely quoted components
        new = urllib.parse.urlunsplit((
            parsed.scheme,
            parsed.netloc,
            urllib.parse.quote(path, safe="/:@-._~!$&'()*+,;="),
            urllib.parse.quote(query, safe="=&:@-._~!$'()*+,;"),
            parsed.fragment
        ))
        return new
    except Exception:
        return (u or "").replace("\u200B", "").replace("\uFEFF", "").replace("\u2060", "").replace("\u00AD", "")

def replace_image_references(html_content: str, images: Dict[str, str]) -> str:
    """Replace <img src> values (cid:, filenames, content-location) with data URLs.
    - Preserve unresolved external/data images
    - Sanitize external URLs (fix ligatures/zero-width chars/line breaks)
    - Optionally inline remote images as data URLs if INLINE_REMOTE_IMAGES=true
    - Append unreferenced embedded images at the end
    """
    try:
        used_data_urls = set()
        stats = {"sanitized": 0, "inlined": 0}

        # Build a normalized lookup that covers raw keys, NFKC/zero-width-stripped keys, and cleaned URLs
        norm_images: Dict[str, str] = {}
        for k, v in (images or {}).items():
            if not k:
                continue
            norm_images[k] = v
            nk = _normalize_key(str(k))
            norm_images[nk] = v
            kl = str(k).lower()
            if kl.startswith('http://') or kl.startswith('https://'):
                try:
                    norm_images[_normalize_url(str(k))] = v
                except Exception:
                    pass

        def sanitize_url(u: str) -> str:
            try:
                return _normalize_url(u or "")
            except Exception:
                return u or ""

        def fetch_image_as_data_url(url: str) -> str | None:
            """Fetch remote image and return as data URL; return None on any failure."""
            try:
                import urllib.request
                req = urllib.request.Request(
                    url,
                    headers={
                        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                                      "(KHTML, like Gecko) Chrome/118 Safari/537.36",
                        "Accept": "image/*"
                    }
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    # Validate content type
                    ctype = resp.headers.get("Content-Type", "")
                    if not ctype.lower().startswith("image/"):
                        return None
                    # Read with a hard cap (5 MB)
                    max_bytes = 5 * 1024 * 1024
                    data = resp.read(max_bytes + 1)
                    if len(data) > max_bytes:
                        return None
                    b64 = base64.b64encode(data).decode("utf-8")
                    return f"data:{ctype};base64,{b64}"
            except Exception:
                return None

        inline_remote_env = str(os.environ.get("INLINE_REMOTE_IMAGES", "true")).lower()
        inline_remote = inline_remote_env not in ("0", "false", "no", "off")

        def candidates_for(key: str):
            key = (key or '').strip()
            cands = []
            if not key:
                return cands
            cands.append(key)

            low = key.lower()
            raw = key[4:] if low.startswith('cid:') else key

            # Handle Outlook-style CIDs that include an "@suffix" (e.g., "image001.jpg@01DC...")
            if '@' in raw:
                base_at = raw.split('@', 1)[0]
                if base_at:
                    cands.append(base_at)
                    if low.startswith('cid:'):
                        cands.append(f'cid:{base_at}')

            # Existing behavior: include raw (no "cid:" prefix) when starting with cid:
            if low.startswith('cid:'):
                cands.append(raw)

            # Try to pull a filename; also consider pre-"@" base variant of that filename
            try:
                fname = key.split('?', 1)[0].split('#', 1)[0].split('/')[-1]
                if fname and fname != key:
                    cands.append(fname)
                    if '@' in fname:
                        fname_base = fname.split('@', 1)[0]
                        if fname_base and fname_base != fname:
                            cands.append(fname_base)
                            if low.startswith('cid:'):
                                cands.append(f'cid:{fname_base}')
            except Exception:
                pass

            return cands

        def replace_img_tag(m):
            tag = m.group(0)
            # Allow src to span multiple lines
            msrc = re.search(r'src\s*=\s*(["\'])([\s\S]*?)\1', tag, flags=re.IGNORECASE | re.DOTALL)
            if not msrc:
                # No src attribute found; keep original tag to avoid content loss
                return tag
            orig = (msrc.group(2) or "").strip()

            # First try to map to embedded images (cid/content-location/filename)
            for lookup in (orig, sanitize_url(orig)):
                for c in candidates_for(lookup):
                    if c in norm_images:
                        data_url = norm_images[c]
                        used_data_urls.add(data_url)
                        return re.sub(r'src\s*=\s*(["\'])([\s\S]*?)\1', f'src="{data_url}"', tag, flags=re.IGNORECASE | re.DOTALL)

            low = orig.lower()
            if low.startswith("http://") or low.startswith("https://"):
                sanitized = sanitize_url(orig)
                # Optionally inline remote images to make the PDF self-contained
                if inline_remote:
                    inlined = fetch_image_as_data_url(sanitized)
                    if inlined:
                        stats["inlined"] += 1
                        return re.sub(r'src\s*=\s*(["\'])([\s\S]*?)\1', f'src="{inlined}"', tag, flags=re.IGNORECASE | re.DOTALL)
                # Otherwise, keep external but sanitized URL
                if sanitized and sanitized != orig:
                    stats["sanitized"] += 1
                    return re.sub(r'src\s*=\s*(["\'])([\s\S]*?)\1', f'src="{sanitized}"', tag, flags=re.IGNORECASE | re.DOTALL)
                return tag

            # Keep data URLs or any other unresolved src as-is
            return tag

        # Replace <img> tags while preserving others
        html_new = re.sub(r'<img\b[^>]*>', replace_img_tag, html_content, flags=re.IGNORECASE)

        # Handle Outlook VML image references (e.g., <v:imagedata src="cid:..."/>)
        def replace_vml_tag(m):
            tag = m.group(0)
            # Replace src
            msrc = re.search(r'src\s*=\s*(["\'])([\s\S]*?)\1', tag, flags=re.IGNORECASE | re.DOTALL)
            if msrc:
                orig = (msrc.group(2) or '').strip()
                for lookup in (orig, sanitize_url(orig)):
                    for c in candidates_for(lookup):
                        if c in norm_images:
                            data_url = norm_images[c]
                            used_data_urls.add(data_url)
                            tag = re.sub(r'src\s*=\s*(["\'])([\s\S]*?)\1', f'src="{data_url}"', tag, flags=re.IGNORECASE | re.DOTALL)
                            break
            # Replace o:href fallback if present
            mhref = re.search(r'o:href\s*=\s*(["\'])([\s\S]*?)\1', tag, flags=re.IGNORECASE | re.DOTALL)
            if mhref:
                orig = (mhref.group(2) or '').strip()
                for lookup in (orig, sanitize_url(orig)):
                    for c in candidates_for(lookup):
                        if c in norm_images:
                            data_url = norm_images[c]
                            used_data_urls.add(data_url)
                            tag = re.sub(r'o:href\s*=\s*(["\'])([\s\S]*?)\1', f'o:href="{data_url}"', tag, flags=re.IGNORECASE | re.DOTALL)
                            break
            return tag

        html_new = re.sub(r'<v:imagedata\b[^>]*>', replace_vml_tag, html_new, flags=re.IGNORECASE)

        # Rewrite CSS url(...) references in inline styles (e.g., background-image:url('cid:...'))
        def css_url_replacer(m):
            orig = (m.group(2) or '').strip().strip('\'"')
            if not orig:
                return m.group(0)
            low = orig.lower()
            # Keep existing data URLs
            if low.startswith('data:'):
                return m.group(0)
            # Try to map to embedded images
            for lookup in (orig, sanitize_url(orig)):
                for c in candidates_for(lookup):
                    if c in norm_images:
                        data_url = norm_images[c]
                        used_data_urls.add(data_url)
                        return f'url("{data_url}")'
            # Sanitize external URLs
            if low.startswith('http://') or low.startswith('https://'):
                sanitized = sanitize_url(orig)
                if sanitized and sanitized != orig:
                    return f'url("{sanitized}")'
            return m.group(0)

        html_new = re.sub(r'url\(\s*(["\']?)([\s\S]*?)\1\s*\)', css_url_replacer, html_new, flags=re.IGNORECASE)

        # Remove stray filename-only artifacts
        fname_pat = r'(?:[A-Za-z0-9_\-]{6,}|[A-F0-9\-]{12,})\.(?:jpg|jpeg|png|gif|bmp|webp)'
        html_new = re.sub(rf'<(p|div|span)[^>]*>\s*{fname_pat}\s*</\1>', '', html_new, flags=re.IGNORECASE)
        html_new = re.sub(rf'<li[^>]*>\s*{fname_pat}\s*</li>', '', html_new, flags=re.IGNORECASE)
        html_new = re.sub(rf'<a[^>]*>\s*{fname_pat}\s*</a>\s*(?:<br\s*/?>)?', '', html_new, flags=re.IGNORECASE)
        html_new = re.sub(rf'(^|[>\n\r])\s*{fname_pat}\s*(?:<br\s*/?>)?\s*(?=[<\n\r]|$)', r'\1', html_new, flags=re.IGNORECASE)

        # Append truly unreferenced embedded images once
        unique_data_urls = []
        seen = set()
        for v in images.values():
            if v not in seen:
                seen.add(v)
                unique_data_urls.append(v)

        to_append = [u for u in unique_data_urls if u not in used_data_urls and u not in html_new]
        if to_append:
            imgs = ''.join([f'<img src="{u}" alt="attachment" class="inline-image" />' for u in to_append])
            html_new += '<div style="margin-top:20px"><h4>Attached Images:</h4>' + imgs + '</div>'

        # Diagnostics (safe counts only)
        try:
            logger.info(f"Image rewrite: embedded_used={len(used_data_urls)}, sanitized_external={stats['sanitized']}, inlined_external={stats['inlined']}")
        except Exception:
            pass

        return html_new
    except Exception as e:
        logger.warning(f"Error replacing image references: {str(e)}")
        return html_content

def extract_body_and_images_from_email(msg, msg_attachments=None):
    """Extract best HTML/plain body and inline images as data URLs."""
    images = {}
    attachments = []
    html_candidates = []
    text_candidates = []

    supported_inline_image_types = {
        'image/png',
        'image/jpeg',
        'image/jpg',
        'image/gif',
        'image/webp',
        'image/bmp',
        'image/svg+xml',
    }

    def ensure_displayable_image(img_bytes, content_type, source_name=None):
        """Convert unsupported inline image formats (e.g., TIFF) into browser-friendly PNG."""
        if not isinstance(img_bytes, (bytes, bytearray)) or not img_bytes:
            return img_bytes, content_type

        normalized_ct = (content_type or '').lower()
        if normalized_ct in supported_inline_image_types:
            return bytes(img_bytes), normalized_ct or 'image/png'

        source_label = source_name or 'inline image'
        try:
            from PIL import Image
        except Exception as import_err:
            logger.warning(
                f"Unable to import Pillow for converting {source_label} ({normalized_ct or 'unknown'}); rendering may fail: {import_err}"
            )
            return bytes(img_bytes), content_type or 'application/octet-stream'

        try:
            with Image.open(io.BytesIO(img_bytes)) as pil_img:
                try:
                    if getattr(pil_img, 'n_frames', 1) > 1:
                        pil_img.seek(0)
                except Exception:
                    pass

                if pil_img.mode in ('P', 'PA', 'LA', 'RGBA'):
                    pil_img = pil_img.convert('RGBA')
                elif pil_img.mode not in ('RGB', 'L'):
                    pil_img = pil_img.convert('RGB')

                buffer = io.BytesIO()
                pil_img.save(buffer, format='PNG')
                converted = buffer.getvalue()
                logger.info(
                    f"Converted inline image {source_label} from {normalized_ct or 'unknown'} to image/png for browser rendering"
                )
                return converted, 'image/png'
        except Exception as convert_err:
            logger.warning(
                f"Failed to convert inline image {source_label} ({normalized_ct or 'unknown'}) to PNG: {convert_err}"
            )
        return bytes(img_bytes), content_type or 'application/octet-stream'

    def process_part(part):
        try:
            ctype = part.get_content_type()
            cdisp = (part.get('Content-Disposition') or '').lower()
            cid = part.get('Content-ID')
            if cid:
                cid = cid.strip('<>')
            cloc = part.get('Content-Location')
            fname = part.get_filename()

            if ctype == 'message/rfc822' or (fname and fname.lower().endswith(('.eml', '.msg'))):
                payload = part.get_payload(decode=True) or part.get_payload()
                if 'attachment' in cdisp or fname:
                    try:
                        data = payload
                        if not isinstance(data, (bytes, bytearray)) and hasattr(data, 'as_bytes'):
                            data = data.as_bytes()
                        if data and fname and fname.lower().endswith('.msg'):
                            data = converter.convert_msg_bytes_to_eml_bytes(data)
                        if data:
                            pdf_data = eml_bytes_to_pdf_bytes(data)
                            if pdf_data:
                                att_name = os.path.splitext(fname or f"attachment-{len(attachments)+1}")[0] + '.pdf'
                                attachments.append({'filename': att_name, 'content_type': 'application/pdf', 'data': pdf_data})
                    except Exception as e:
                        logger.warning(f"Failed to process attached message: {e}")
                    return
                try:
                    if isinstance(payload, (bytes, bytearray)):
                        nested = email.message_from_bytes(payload, policy=email.policy.default)
                        process_message(nested)
                    elif hasattr(payload, 'walk'):
                        process_message(payload)
                except Exception as e:
                    logger.warning(f"Failed to process nested message/rfc822: {e}")
                return

            # Treat as image if content-type is image/* or filename/content-location indicate an image
            is_image = False
            ctype_for_data = ctype
            try:
                if ctype and ctype.startswith('image/'):
                    is_image = True
                else:
                    import mimetypes
                    guess_src = fname or cloc or ''
                    guessed, _ = mimetypes.guess_type(guess_src)
                    if guessed and guessed.startswith('image/'):
                        is_image = True
                        ctype_for_data = guessed
            except Exception:
                pass
            if is_image:
                img_bytes = part.get_payload(decode=True)
                if not img_bytes:
                    payload = part.get_payload()
                    if isinstance(payload, (bytes, bytearray)):
                        img_bytes = payload
                if img_bytes:
                    img_bytes, ctype_for_data = ensure_displayable_image(
                        img_bytes,
                        ctype_for_data or ctype,
                        source_name=fname or cloc or cid,
                    )
                    if not ctype_for_data:
                        ctype_for_data = 'image/png'
                    b64 = base64.b64encode(img_bytes).decode('utf-8')
                    data_url = f"data:{ctype_for_data};base64,{b64}"
                    keys = set()
                    if cid:
                        keys.add(f"cid:{cid}")
                        keys.add(cid)
                    if cloc:
                        keys.add(cloc)
                    if fname:
                        keys.add(fname)
                        # Also add cid: filename variants so "cid:image001.jpg@..." can resolve via "cid:image001.jpg"
                        try:
                            keys.add(f"cid:{fname}")
                        except Exception:
                            pass
                        try:
                            base = os.path.basename(fname)
                            if base:
                                keys.add(base)
                                keys.add(_normalize_key(base))
                                try:
                                    keys.add(f"cid:{base}")
                                except Exception:
                                    pass
                        except Exception:
                            pass
                    for k in keys:
                        try:
                            images[k] = data_url
                            # Add normalized variants for reliable matching
                            nk = _normalize_key(str(k))
                            images[nk] = data_url
                            if str(k).lower().startswith(('http://', 'https://')):
                                images[_normalize_url(str(k))] = data_url
                        except Exception:
                            images[k] = data_url
                    images.setdefault(f"__unref__:{len(images)}", data_url)
                return

            # PDF or other attachments
            is_attachment = 'attachment' in cdisp
            is_inline_pdf = (ctype == 'application/pdf') or (fname and fname.lower().endswith('.pdf'))
            is_office = ctype in (
                'application/msword',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            ) or (fname and fname.lower().endswith(('.doc', '.docx')))
            if is_attachment or is_inline_pdf or is_office:
                try:
                    data = part.get_payload(decode=True)
                    if not data:
                        data = part.get_payload()
                    if data:
                        if ctype == 'application/pdf' or (fname and fname.lower().endswith('.pdf')):
                            att_name = fname or f"attachment-{len(attachments)+1}.pdf"
                            if not att_name.lower().endswith('.pdf'):
                                att_name += '.pdf'
                            attachments.append({
                                'filename': att_name,
                                'content_type': 'application/pdf',
                                'data': data,
                            })
                            return
                        if is_office:
                            ext = os.path.splitext(fname or '')[1] or '.docx'
                            pdf_data = convert_office_to_pdf(data, ext)
                            if pdf_data:
                                att_name = os.path.splitext(fname or f"attachment-{len(attachments)+1}")[0] + '.pdf'
                                attachments.append({
                                    'filename': att_name,
                                    'content_type': 'application/pdf',
                                    'data': pdf_data,
                                })
                            return
                except Exception as e:
                    logger.warning(f"Error extracting attachment: {e}")
                    return

            # Skip non-text attachments
            if 'attachment' in cdisp and not ctype.startswith('text/'):
                return

            if ctype == 'text/html':
                content = get_part_content(part)
                if content:
                    logger.info(f"DEBUGGING: Found HTML part with {len(content)} chars")
                    logger.info(f"DEBUGGING: HTML part preview: {content[:300]}...")
                    cleaned = clean_html_content(content)
                    html_candidates.append((len(cleaned), cleaned))
                return

            if ctype == 'text/plain':
                content = get_part_content(part)
                if content:
                    logger.info(f"DEBUGGING: Found text/plain part with {len(content)} chars")
                    logger.info(f"DEBUGGING: Text part preview: {content[:300]}...")
                    htmlized = html.escape(content).replace('\n', '<br>\n')
                    text_candidates.append((len(htmlized), htmlized))
                return
        except Exception as e:
            logger.warning(f"Error processing part: {e}")

    def process_message(message):
        try:
            if message.is_multipart():
                for p in message.walk():
                    if p is not message:
                        process_part(p)
            else:
                process_part(message)
        except Exception as e:
            logger.warning(f"Error walking message: {e}")

    process_message(msg)

    body = None
    logger.info(f"DEBUGGING: Body selection - HTML candidates: {len(html_candidates)}, Text candidates: {len(text_candidates)}")
    
    # CRITICAL FIX: Analyze text parts to avoid duplication with embedded attachments
    if len(text_candidates) > 1:
        logger.info(f"DEBUGGING: Multiple text parts detected - analyzing for forwarded content")
        
        # Check if there are embedded message attachments that might duplicate forwarded content
        local_embedded = any(a.get('content_type') == 'message/rfc822' for a in attachments)
        
        # Check msg_attachments parameter more thoroughly
        msg_embedded = False
        if msg_attachments:
            msg_embedded = any(
                a.get('content_type') == 'message/rfc822' or
                str(a.get('filename', '')).lower().endswith('.eml')
                for a in msg_attachments
            )
            logger.info(f"DEBUGGING: msg_attachments contains {len(msg_attachments)} items:")
            for i, att in enumerate(msg_attachments):
                logger.info(f"  - {i+1}: {att.get('filename')} (type: {att.get('content_type')})")
        
        has_embedded_msg = local_embedded or msg_embedded
        logger.info(f"DEBUGGING: Has embedded message attachments: {has_embedded_msg} (local: {local_embedded}, msg_attachments: {msg_embedded})")
        
        # Analyze each text part for forwarded vs original content
        original_parts = []
        forwarded_parts = []
        
        for i, (length, content) in enumerate(text_candidates):
            preview = content[:200].replace('<br>', ' ').replace('\n', ' ')
            logger.info(f"DEBUGGING: Analyzing text part {i+1} ({length} chars): {preview}...")
            
            # Check if this part contains forwarded message markers
            is_forwarded = (
                '---------- Forwarded message ---------' in content and
                not any(phrase in content[:500] for phrase in ["Good afternoon", "good afternoon", "I wanted to"])
            )
            
            if is_forwarded:
                logger.info(f"DEBUGGING: Text part {i+1} identified as FORWARDED content (will appear as attachment)")
                forwarded_parts.append((length, content))
            else:
                logger.info(f"DEBUGGING: Text part {i+1} identified as ORIGINAL content")
                original_parts.append((length, content))
        
        # If we have embedded attachments, only use original parts to avoid duplication
        if has_embedded_msg and original_parts:
            logger.info(f"DEBUGGING: Using only original parts ({len(original_parts)}) - forwarded content will appear as attachment")
            combined_parts = [content for length, content in original_parts]
            body = '<br><br>'.join(combined_parts)
            logger.info(f"DEBUGGING: Original-only body content: {len(body)} chars total")
        else:
            # No embedded attachments or no original parts found - combine all
            logger.info(f"DEBUGGING: No embedded attachments or no original parts - combining all text parts")
            sorted_text = sorted(text_candidates, key=lambda t: (
                0 if any(phrase in t[1][:300] for phrase in ["Good afternoon", "good afternoon", "I wanted to"]) else 1,
                -t[0]
            ))
            combined_parts = [content for length, content in sorted_text]
            body = '<br><br>'.join(combined_parts)
            logger.info(f"DEBUGGING: All-parts combined content: {len(body)} chars total")
        
    elif text_candidates:
        body = max(text_candidates, key=lambda t: t[0])[1]
        logger.info(f"DEBUGGING: Selected single text body with {len(body)} chars")
    elif html_candidates:
        body = max(html_candidates, key=lambda t: t[0])[1]
        logger.info(f"DEBUGGING: Selected HTML body with {len(body)} chars")
    
    if not body:
        body = "No content available"
    
    # CRITICAL FIX: Check if body contains forwarded message but missing original content
    if body and "---------- Forwarded message ---------" in body:
        logger.info(f"DEBUGGING: Detected forwarded message in body")
        
        # Look for patterns that suggest the original content before forwarded message is missing
        if not any(phrase in body[:500] for phrase in ["Good afternoon", "good afternoon", "Good morning", "good morning", "Hello", "hello", "Hi ", "hi "]):
            logger.warning(f"DEBUGGING: Original content may be missing - body starts with forwarded content")
            
            # Try to find the complete content by examining all parts more thoroughly
            logger.info(f"DEBUGGING: Searching for complete content in all EML parts")
            complete_content_found = False
            
            for part in msg.walk():
                if part.get_content_type() in ['text/plain', 'text/html']:
                    full_content = get_part_content(part)
                    if full_content and len(full_content) > len(body):
                        # Check if this part contains both original greeting AND forwarded content
                        has_greeting = any(phrase in full_content for phrase in ["Good afternoon", "good afternoon", "I wanted to", "afternoon, Nick"])
                        has_forwarded = "---------- Forwarded message ---------" in full_content
                        
                        if has_greeting or len(full_content) > len(body) * 2:  # Much larger content
                            logger.info(f"DEBUGGING: Found better content part: {len(full_content)} chars (has_greeting: {has_greeting}, has_forwarded: {has_forwarded})")
                            logger.info(f"DEBUGGING: Better content preview: {full_content[:300]}...")
                            
                            if part.get_content_type() == 'text/plain':
                                body = html.escape(full_content).replace('\n', '<br>\n')
                            else:
                                body = clean_html_content(full_content)
                            complete_content_found = True
                            break
            
            if not complete_content_found:
                logger.warning(f"DEBUGGING: Could not find complete content - using existing body")

    if images and body:
        body = replace_image_references(body, {k: v for k, v in images.items() if not str(k).startswith('__unref__:')})
    
    # Normalize whitespace in the final body
    body = normalize_whitespace(body)

    logger.info(f"Parsed email: body_len={len(body) if body else 0}, images_inlined={sum(1 for k in images.keys() if not str(k).startswith('__unref__:'))}")
    return body, images, attachments

def _safe_decode_header(value) -> str:
    """Decode RFC 2047/2231 encoded header values to a readable string."""
    try:
        if value is None:
            return "Unknown"
        # Coerce header objects to string first
        if not isinstance(value, (str, bytes)):
            value = str(value)
        parts = decode_header(value)
        out = []
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


def _extract_display_date(msg) -> str:
    """Return a human-readable date for the message with sensible fallbacks.
    Prefers the Date header as-is; falls back to common alternative headers or the trailing
    timestamp from the first Received header. Never returns an empty string.
    """
    # Prefer standard Date header
    primary = msg.get('Date')
    dstr = _safe_decode_header(primary) if primary else ''
    if dstr:
        return dstr

    # Common alternates seen in various clients/gateways
    alt_headers = [
        'Sent', 'X-Original-Date', 'Original-Date', 'Resent-Date', 'Delivery-date',
        'X-Received-Date', 'X-Delivery-Date', 'X-Apple-Original-Arrival-Date',
    ]
    for h in alt_headers:
        v = msg.get(h)
        dstr = _safe_decode_header(v) if v else ''
        if dstr:
            return dstr

    # Parse from the topmost Received header (date appears after the last semicolon)
    try:
        recvd = msg.get_all('Received') or []
        if recvd:
            first = _safe_decode_header(recvd[0]) or ''
            if ';' in first:
                tail = first.rsplit(';', 1)[-1].strip()
                if tail:
                    return tail
    except Exception:
        pass

    return 'Unknown Date'


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

        # Extract basic email information (decode safely)
        subject = _safe_decode_header(msg.get('Subject', 'No Subject'))
        sender = _safe_decode_header(msg.get('From', 'Unknown Sender'))
        recipient = _safe_decode_header(msg.get('To', 'Unknown Recipient'))
        date_display = _extract_display_date(msg)
        logger.info(f"Email metadata: Subject='{subject}', From='{sender}', To='{recipient}', Date='{date_display}'")

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
            body, images, attachments = extract_body_and_images_from_email(msg, msg_attachments)
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
            body = normalize_whitespace(body)
        logger.info(f"Body extracted. Length={len(body)}")
        
        # Debug: Show body content preview
        if body:
            logger.info(f"DEBUGGING: Body content preview: {body[:300]}...")
        else:
            logger.warning(f"DEBUGGING: Body content is EMPTY!")
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
        # Prepare optional inline attachment note (avoid automated-looking header pages in final PDF)
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
                    line-height: 1.35;
                    margin: 20px;
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
                .email-body, .email-body * {{
                    /* Forcefully override justification from email inline styles */
                    white-space: normal !important; /* Override Outlook's 'pre' on spans */
                    text-align: left !important;
                    text-justify: auto !important;
                    letter-spacing: normal !important;
                    word-spacing: normal !important;
                    text-align-last: left !important;
                }}
                [style*="text-align:justify"], [style*="text-align: justify"] {{
                  text-align: left !important;
                }}
                pre, code {{
                    white-space: pre-wrap !important; /* Ensure code blocks are not affected */
                }}
                .emoji {{
                    font-family: "Noto Color Emoji", "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol";
                }}
                .email-header {{
                    background-color: #f5f5f5;
                    padding: 10px;
                    margin-bottom: 20px;
                    border-left: 4px solid #007cba;
                }}
                .email-body {{ padding: 10px; }}
                .header-item {{ margin-bottom: 5px; }}
                .label {{ font-weight: bold; }}
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
            </style>
        </head>
        <body>
            <div class="email-header">
                <div class="header-item"><span class="label">From:</span> {html.escape(sender)}</div>
                <div class="header-item"><span class="label">To:</span> {html.escape(recipient)}</div>
                <div class="header-item"><span class="label">Subject:</span> {html.escape(subject)}</div>
                <div class="header-item"><span class="label">Date:</span> {html.escape(date_display)}</div>
            </div>
            <div class="email-body wrap">
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
            pdf_attachments = [a for a in (attachments or []) if a.get('content_type') == 'application/pdf' or str(a.get('filename','')).lower().endswith('.pdf')]
            
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
                page.pdf(
                    path=output_path,
                    format='A4',
                    margin={'top': '1in', 'right': '1in', 'bottom': '1in', 'left': '1in'},
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

doc_converter.html_to_pdf = html_to_pdf_playwright

def fallback_html_to_pdf(html_content: str, output_path: str) -> bool:
    """Fallback PDF generation using FPDF for basic text content."""
    try:
        import re
        from html import unescape

        # Strip HTML tags and convert to plain text
        text_content = re.sub(r'<[^>]+>', '', html_content)
        text_content = unescape(text_content)

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font('Arial', size=12)

        lines = text_content.split('\n')
        for line in lines:
            # Wrap long lines to avoid overflow
            if len(line) > 80:
                words = line.split(' ')
                current_line = ''
                for word in words:
                    if len(current_line + word) > 80:
                        if current_line:
                            pdf.cell(0, 10, current_line.encode('latin1', errors='replace').decode('latin1'), ln=True)
                        current_line = word + ' '
                    else:
                        current_line += word + ' '
                if current_line:
                    pdf.cell(0, 10, current_line.encode('latin1', errors='replace').decode('latin1'), ln=True)
            else:
                pdf.cell(0, 10, line.encode('latin1', errors='replace').decode('latin1'), ln=True)

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

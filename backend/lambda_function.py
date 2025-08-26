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
import io
import html
import re
from playwright.sync_api import sync_playwright
from fpdf import FPDF
from pypdf import PdfReader, PdfWriter
import shutil

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

# Initialize S3 client
s3_client = boto3.client('s3')
S3_BUCKET = os.environ.get('S3_BUCKET')

# =====================
# Helper utilities
# =====================

def _lower_headers(headers: Dict[str, Any]) -> Dict[str, str]:
    """Return a lowercase-keyed copy of headers for case-insensitive access."""
    return {str(k).lower(): v for k, v in (headers or {}).items()}

def _get_body_bytes(event: Dict[str, Any]) -> bytes:
    """Return the request body as bytes, respecting isBase64Encoded."""
    body = event.get("body", b"")
    if event.get("isBase64Encoded"):
        if isinstance(body, str):
            return base64.b64decode(body)
        return base64.b64decode(body or b"")
    if isinstance(body, str):
        return body.encode("utf-8", errors="ignore")
    return body or b""

# =====================
# Multipart parsing
# =====================

def _extract_boundary(content_type: str, body: bytes) -> str | None:
    """
    Try to extract multipart boundary from the Content-Type header, or sniff it from the body.
    Returns the boundary token WITHOUT the leading '--'.
    """
    try:
        import re
        # 1) From header (case-insensitive), e.g. boundary=----WebKitFormBoundaryabc123 or "----WebKit..."
        m = re.search(r'boundary=(?:"?)([^;"]+)', content_type or "", re.IGNORECASE)
        if m:
            b = m.group(1).strip()
            if b:
                return b

        # 2) Sniff from body (look for leading boundary line)
        sample = (body or b"")[:4096]
        if sample.startswith(b"--"):
            line_end = sample.find(b"\r\n")
            if line_end == -1:
                line_end = sample.find(b"\n")
            if line_end != -1 and line_end > 2:
                first_line = sample[2:line_end]  # skip the initial '--'
                token = first_line.decode("utf-8", "ignore").strip()
                if token:
                    return token

        # 3) Common WebKit token present somewhere in body
        m2 = re.search(rb'----WebKitFormBoundary[0-9A-Za-z]+', sample)
        if m2:
            token = m2.group(0).decode("utf-8", "ignore")
            # Strip leading dashes for boundary token; when used, we prepend '--'
            return token.lstrip("-")
    except Exception:
        pass
    return None

def parse_multipart_data_strict(body: bytes, content_type: str) -> Dict[str, Any]:
    """
    Parse multipart/form-data using python-multipart (import path 'multipart').
    Falls back to single-file mode when boundary is missing.
    """
    # First, attempt robust boundary extraction from header or body
    boundary = _extract_boundary(content_type or "", body or b"")
    if boundary:
        logger.info("Multipart: using manual parser with extracted boundary")
        return parse_multipart_manual(body, boundary)

    try:
        # Try multiple import paths for multipart library compatibility
        try:
            from multipart import MultipartParser
            from multipart.multipart import parse_options_header
        except ImportError:
            try:
                from multipart import MultipartParser, parse_options_header
            except ImportError:
                # Fallback import method
                import multipart
                MultipartParser = multipart.MultipartParser
                parse_options_header = multipart.parse_options_header

        ctype, params = parse_options_header(content_type or "")
        boundary = params.get("boundary")
        if ctype != "multipart/form-data" or not boundary:
            logger.warning("No boundary in Content-Type; using single-file fallback")
            return parse_single_file_fallback(body, content_type)

        parser = MultipartParser(body, boundary)
        files: Dict[str, Any] = {}
        for part in parser.parts():
            disp = part.headers.get(b"Content-Disposition", b"").decode("utf-8", "replace")
            _, opts = parse_options_header(disp)
            name = (opts.get("name") or "").strip('"')
            filename = opts.get("filename")
            if filename:
                files[name or "file"] = {
                    "filename": filename.strip('"'),
                    "content": part.raw,
                    "content_type": part.headers.get(b"Content-Type", b"application/octet-stream").decode("utf-8", "replace"),
                }
            else:
                files[name] = part.text
        return files

    except Exception as e:
        logger.warning(f"multipart parser failed: {e}")
        if "boundary=" in (content_type or ""):
            try:
                boundary = content_type.split("boundary=", 1)[1].split(";", 1)[0].strip()
                return parse_multipart_manual(body, boundary)
            except Exception as e2:
                logger.error(f"Manual parsing also failed: {e2}")
        return parse_single_file_fallback(body, content_type)

def parse_multipart_manual(body: bytes, boundary: str) -> Dict[str, Any]:
    """Manual multipart parsing when library parsing fails."""
    boundary_bytes = f"--{boundary}".encode("utf-8")
    parts = body.split(boundary_bytes)

    files: Dict[str, Any] = {}
    for part in parts[1:-1]:  # Skip first empty and last closing parts
        if not part.strip():
            continue

        # Split headers and content
        if b"\r\n\r\n" in part:
            headers_section, content = part.split(b"\r\n\r\n", 1)
        elif b"\n\n" in part:
            headers_section, content = part.split(b"\n\n", 1)
        else:
            continue

        content = content.rstrip(b"\r\n--")

        # Parse headers
        headers = {}
        for line in headers_section.decode("utf-8", errors="replace").split("\n"):
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()

        # Extract field name and filename
        content_disposition = headers.get("content-disposition", "")
        if "name=" in content_disposition:
            name_match = content_disposition.split("name=", 1)[1].split(";", 1)[0].strip('"')

            if "filename=" in content_disposition:
                filename_match = content_disposition.split("filename=", 1)[1].split(";", 1)[0].strip('"')
                files[name_match] = {
                    "filename": filename_match,
                    "content": content,
                    "content_type": headers.get("content-type", "application/octet-stream"),
                }
            else:
                files[name_match] = content.decode("utf-8", errors="replace")

    # Prefer message/rfc822 or *.eml for the primary file key
    try:
        best_key = None
        for k, v in files.items():
            if isinstance(v, dict) and 'content' in v:
                ct = str(v.get('content_type', '')).lower()
                fn = str(v.get('filename', ''))
                if ct == 'message/rfc822' or fn.lower().endswith('.eml'):
                    best_key = k
                    break
        if best_key and 'file' not in files:
            files['file'] = files[best_key]
    except Exception as e:
        logger.warning(f"Failed to select best multipart file part: {e}")

    return files

def parse_single_file_fallback(body: bytes, content_type: str) -> Dict[str, Any]:
    """
    Fallback for single file uploads when boundary is missing.
    Treat the entire body as the file content.
    """
    logger.info("Using single file fallback parser")
    # If the body looks like multipart but header was missing, try to recover by sniffing boundary
    try:
        if (body or b"").lstrip().startswith(b"--") or b"WebKitFormBoundary" in (body or b""):
            boundary = _extract_boundary(content_type or "", body or b"")
            if boundary:
                logger.info("Fallback: detected multipart body, attempting manual parse via sniffed boundary")
                files = parse_multipart_manual(body, boundary)
                if isinstance(files, dict) and isinstance(files.get("file"), dict):
                    return files
    except Exception as e:
        logger.warning(f"Fallback multipart sniff failed: {e}")

    filename = "uploaded_file.eml"  # Default filename

    # Heuristic: does body look like EML?
    try:
        body_str = body.decode('utf-8', errors='replace')
        if any(h in body_str[:1000] for h in ['From:', 'To:', 'Subject:', 'Date:']):
            filename = f"upload_{uuid.uuid4().hex[:8]}.eml"
    except Exception:
        pass

    return {
        "file": {
            "filename": filename,
            "content": body,
            "content_type": content_type if "eml" in (content_type or "") else "message/rfc822",
        }
    }

# =====================
# Conversion helpers
# =====================

def convert_msg_bytes_to_eml_bytes(msg_bytes: bytes) -> bytes:
    """Convert Outlook .msg bytes into RFC 822 EML bytes."""
    import tempfile
    try:
        import extract_msg
        # Write to a temporary .msg file because extract_msg expects a path
        with tempfile.NamedTemporaryFile(suffix='.msg', delete=False) as tmpf:
            tmp_path = tmpf.name
            tmpf.write(msg_bytes)

        try:
            m = extract_msg.Message(tmp_path)
            # Prefer native conversion if available
            em = None
            if hasattr(m, 'as_email'):
                try:
                    em = m.as_email()
                except Exception:
                    em = None
            if em is None:
                # Manual construction
                em = EmailMessage()
                # Basic headers
                subj = getattr(m, 'subject', None) or ''
                sender = getattr(m, 'sender', None) or getattr(m, 'sender_email', None) or ''
                to_list = getattr(m, 'to', None) or []
                cc_list = getattr(m, 'cc', None) or []
                bcc_list = getattr(m, 'bcc', None) or []

                em['Subject'] = subj
                if sender:
                    em['From'] = sender
                if to_list:
                    em['To'] = ', '.join(to_list if isinstance(to_list, list) else [str(to_list)])
                if cc_list:
                    em['Cc'] = ', '.join(cc_list if isinstance(cc_list, list) else [str(cc_list)])
                if bcc_list:
                    em['Bcc'] = ', '.join(bcc_list if isinstance(bcc_list, list) else [str(bcc_list)])

                # Date if available
                try:
                    date_str = getattr(m, 'date', None)
                    if date_str:
                        em['Date'] = str(date_str)
                except Exception:
                    pass

                # Body: prefer HTML
                def _decode_to_str(val):
                    if val is None:
                        return ''
                    if isinstance(val, str):
                        return val
                    if isinstance(val, (bytes, bytearray)):
                        for enc in ('utf-8', 'cp1252', 'latin1', 'iso-8859-1'):
                            try:
                                return val.decode(enc)
                            except Exception:
                                continue
                        return val.decode('utf-8', errors='replace')
                    try:
                        return str(val)
                    except Exception:
                        return ''
                
                html_body = _decode_to_str(getattr(m, 'htmlBody', None) or getattr(m, 'html', None))
                text_body = _decode_to_str(getattr(m, 'body', None) or '')
                
                # Normalize line endings in plain text to avoid CR artifacts
                if text_body:
                    text_body = text_body.replace('\r\n', '\n').replace('\r', '\n')
                
                if html_body:
                    # Set plain part too if available
                    if text_body:
                        em.set_content(text_body)
                        em.add_alternative(html_body, subtype='html')
                    else:
                        em.add_alternative(html_body, subtype='html')
                else:
                    em.set_content(text_body)

                # Attachments (best-effort) with inline-image CID wiring for HTML
                try:
                    # Collect any cid: tokens from html to map inline images
                    cids_in_html = set(re.findall(r'cid:([^"\'>\s]+)', html_body, flags=re.IGNORECASE)) if html_body else set()
                    cids_iter = iter(cids_in_html)
                    atts = getattr(m, 'attachments', []) or []
                    for att in atts:
                        try:
                            data = getattr(att, 'data', None)
                            if not data:
                                # Some versions use .binary
                                data = getattr(att, 'binary', None)
                            if data is None:
                                continue
                            filename = getattr(att, 'longFilename', None) or getattr(att, 'shortFilename', None) or 'attachment'
                            mime = getattr(att, 'mimeType', None)
                            # Infer MIME type from filename when missing or generic
                            if not mime or str(mime).lower() == 'application/octet-stream':
                                try:
                                    import mimetypes
                                    guessed, _ = mimetypes.guess_type(filename or '')
                                    if guessed:
                                        mime = guessed
                                    else:
                                        mime = 'application/octet-stream'
                                except Exception:
                                    mime = 'application/octet-stream'
                            maintype, subtype = (str(mime).split('/', 1) + ['octet-stream'])[:2]

                            if maintype.lower() == 'image':
                                # Try to obtain or synthesize a CID
                                cid = (
                                    getattr(att, 'cid', None)
                                    or getattr(att, 'contentId', None)
                                    or getattr(att, 'content_id', None)
                                )
                                if not cid:
                                    try:
                                        # If HTML references CIDs, assign them in order
                                        cid = next(cids_iter)
                                    except StopIteration:
                                        # Fall back to filename-based CID or a generated one
                                        base = os.path.basename(filename or 'image')
                                        base = re.sub(r'[^A-Za-z0-9_.-]+', '', base) or 'image'
                                        cid = f"{base}-{uuid.uuid4().hex[:8]}"
                                # Add image as attachment and then set headers to hint inline usage
                                prev_len = len(em.get_payload() or [])
                                em.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
                                try:
                                    new_part = em.get_payload()[-1] if (em.get_payload() and len(em.get_payload()) > prev_len) else None
                                    if new_part is not None:
                                        # Content-ID must be in angle brackets
                                        new_part.add_header('Content-ID', f"<{cid}>")
                                        # Prefer inline disposition
                                        try:
                                            new_part.replace_header('Content-Disposition', f'inline; filename="{filename}"')
                                        except Exception:
                                            new_part.add_header('Content-Disposition', f'inline; filename="{filename}"')
                                        # Propagate Content-Location if present on the MSG attachment
                                        try:
                                            cloc = getattr(att, 'contentLocation', None) or getattr(att, 'content_location', None) or getattr(att, 'ContentLocation', None)
                                            if cloc:
                                                new_part.add_header('Content-Location', str(cloc))
                                        except Exception:
                                            pass
                                except Exception:
                                    pass
                            else:
                                # Non-image attachments unchanged
                                em.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
                        except Exception:
                            continue
                except Exception:
                    pass

            # Harmonize/ensure inline image attachments present even when using as_email()
            try:
                def _dec_str(val):
                    try:
                        if val is None:
                            return ''
                        if isinstance(val, str):
                            return val
                        if isinstance(val, (bytes, bytearray)):
                            for enc in ('utf-8', 'cp1252', 'latin1', 'iso-8859-1'):
                                try:
                                    return val.decode(enc)
                                except Exception:
                                    continue
                            return val.decode('utf-8', errors='replace')
                        return str(val)
                    except Exception:
                        return ''
                html_body_for_cid = ''
                try:
                    html_body_for_cid = html_body if 'html_body' in locals() and html_body else _dec_str(getattr(m, 'htmlBody', None) or getattr(m, 'html', None))
                except Exception:
                    html_body_for_cid = ''
                cids_in_html = set(re.findall(r'cid:([^"\'>\s]+)', html_body_for_cid, flags=re.IGNORECASE)) if html_body_for_cid else set()
                existing_cids = set()
                existing_filenames = set()
                try:
                    for part_exist in (em.walk() if hasattr(em, 'walk') else []):
                        try:
                            cidv = part_exist.get('Content-ID')
                            if cidv:
                                existing_cids.add(cidv.strip('<>'))
                            fnv = part_exist.get_filename()
                            if fnv:
                                existing_filenames.add(os.path.basename(fnv))
                        except Exception:
                            continue
                except Exception:
                    pass
                cids_iter = iter([c for c in cids_in_html if c not in existing_cids])
                atts = getattr(m, 'attachments', []) or []
                for att in atts:
                    try:
                        data = getattr(att, 'data', None) or getattr(att, 'binary', None)
                        if data is None:
                            continue
                        filename = getattr(att, 'longFilename', None) or getattr(att, 'shortFilename', None) or 'attachment'
                        mime = getattr(att, 'mimeType', None)
                        # Infer MIME type from filename when missing or generic
                        if not mime or str(mime).lower() == 'application/octet-stream':
                            try:
                                import mimetypes
                                guessed, _ = mimetypes.guess_type(filename or '')
                                if guessed:
                                    mime = guessed
                                else:
                                    mime = 'application/octet-stream'
                            except Exception:
                                mime = 'application/octet-stream'
                        maintype, subtype = (str(mime).split('/', 1) + ['octet-stream'])[:2]
                        # If still not categorized as image, skip
                        if maintype.lower() != 'image':
                            continue
                        cid = getattr(att, 'cid', None) or getattr(att, 'contentId', None) or getattr(att, 'content_id', None)
                        if not cid:
                            try:
                                cid = next(cids_iter)
                            except StopIteration:
                                base = os.path.basename(filename or 'image')
                                base = re.sub(r'[^A-Za-z0-9_.-]+', '', base) or 'image'
                                cid = f"{base}-{uuid.uuid4().hex[:8]}"
                        # Avoid duplicates by CID or filename
                        if cid in existing_cids or os.path.basename(filename or '') in existing_filenames:
                            continue
                        prev_len = len(em.get_payload() or [])
                        em.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
                        try:
                            new_part = em.get_payload()[-1] if (em.get_payload() and len(em.get_payload()) > prev_len) else None
                            if new_part is not None:
                                new_part.add_header('Content-ID', f"<{cid}>")
                                try:
                                    new_part.replace_header('Content-Disposition', f'inline; filename="{filename}"')
                                except Exception:
                                    new_part.add_header('Content-Disposition', f'inline; filename="{filename}"')
                                # Propagate Content-Location if present on the MSG attachment
                                try:
                                    cloc = getattr(att, 'contentLocation', None) or getattr(att, 'content_location', None) or getattr(att, 'ContentLocation', None)
                                    if cloc:
                                        new_part.add_header('Content-Location', str(cloc))
                                except Exception:
                                    pass
                            existing_cids.add(cid)
                            if filename:
                                existing_filenames.add(os.path.basename(filename))
                        except Exception:
                            pass
                    except Exception:
                        continue
            except Exception:
                pass

            # Serialize to bytes
            buf = io.BytesIO()
            BytesGenerator(buf, policy=default).flatten(em)
            return buf.getvalue()
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
    except Exception as e:
        logger.error(f".msg to .eml conversion failed: {e}")
        raise

# =====================
# Rich EML extraction helpers (images + emoji support)
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

def extract_body_and_images_from_email(msg):
    """Extract best HTML/plain body and inline images as data URLs."""
    images = {}
    attachments = []
    html_candidates = []
    text_candidates = []

    def process_part(part):
        try:
            ctype = part.get_content_type()
            cdisp = (part.get('Content-Disposition') or '').lower()
            cid = part.get('Content-ID')
            if cid:
                cid = cid.strip('<>')
            cloc = part.get('Content-Location')
            fname = part.get_filename()

            if ctype == 'message/rfc822':
                payload = part.get_payload(decode=True) or part.get_payload()
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
                            import os
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
            if is_attachment or is_inline_pdf:
                try:
                    data = part.get_payload(decode=True)
                    if data and (ctype == 'application/pdf' or (fname and fname.lower().endswith('.pdf'))):
                        att_name = fname or f"attachment-{len(attachments)+1}.pdf"
                        if not att_name.lower().endswith('.pdf'):
                            att_name += '.pdf'
                        attachments.append({
                            'filename': att_name,
                            'content_type': 'application/pdf',
                            'data': data,
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
                    cleaned = clean_html_content(content)
                    html_candidates.append((len(cleaned), cleaned))
                return

            if ctype == 'text/plain':
                content = get_part_content(part)
                if content:
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
    if html_candidates:
        body = max(html_candidates, key=lambda t: t[0])[1]
    elif text_candidates:
        body = max(text_candidates, key=lambda t: t[0])[1]
    if not body:
        body = "No content available"

    if images and body:
        body = replace_image_references(body, {k: v for k, v in images.items() if not str(k).startswith('__unref__:')})
    
    # Normalize whitespace in the final body
    body = normalize_whitespace(body)

    logger.info(f"Parsed email: body_len={len(body) if body else 0}, images_inlined={sum(1 for k in images.keys() if not str(k).startswith('__unref__:'))}")
    return body, images, attachments

def convert_eml_to_pdf(eml_content: bytes, output_path: str, twemoji_base_url: str = None) -> bool:
    """Convert EML content to PDF using Playwright with fallback to FPDF."""
    logger.info("=== CONVERT_EML_TO_PDF STARTED ===")
    
    try:
        logger.info("Parsing EML message...")
        # Parse the EML
        msg = email.message_from_bytes(eml_content, policy=default)
        logger.info("EML message parsed successfully")

        # Extract basic email information
        subject = msg.get('Subject', 'No Subject')
        sender = msg.get('From', 'Unknown Sender')
        recipient = msg.get('To', 'Unknown Recipient')
        date = msg.get('Date', 'Unknown Date')
        logger.info(f"Email metadata: Subject='{subject}', From='{sender}', To='{recipient}', Date='{date}'")

        # Rich extraction: body + inline images
        logger.info("Extracting email body + inline images...")
        try:
            body, images, attachments = extract_body_and_images_from_email(msg)
        except Exception as e:
            logger.error(f"Rich extraction failed: {e}")
            # Fallback to simple logic
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    if content_type == "text/html":
                        payload = part.get_payload(decode=True)
                        if payload:
                            body = payload.decode('utf-8', errors='replace')
                            break
                    elif content_type == "text/plain" and not body:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body = payload.decode('utf-8', errors='replace').replace('\n', '<br>')
            else:
                payload = msg.get_payload(decode=True)
                if isinstance(payload, (bytes, bytearray)):
                    body = payload.decode('utf-8', errors='replace')
                else:
                    body = str(payload or '')
                if msg.get_content_type() == "text/plain":
                    body = body.replace('\n', '<br>')
            body = normalize_whitespace(body)
        logger.info(f"Body extracted. Length={len(body)}")
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
                <div class="header-item"><span class="label">Date:</span> {html.escape(date)}</div>
            </div>
            <div class="email-body wrap">
                {body}{attachment_inline_note}
            </div>
        </body>
        </html>
        """
        logger.info(f"HTML content created: {len(html_content)} characters")

        # Generate body PDF to a temporary file, then merge PDF attachments (if any)
        logger.info("Preparing to generate body PDF and merge attachments if present...")
        body_pdf_path = None
        try:
            with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as tmp_body:
                body_pdf_path = tmp_body.name
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

            # If no PDF attachments, move body to output and finish
            pdf_attachments = [a for a in (attachments or []) if a.get('content_type') == 'application/pdf' or str(a.get('filename','')).lower().endswith('.pdf')]
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
            if body_pdf_path:
                try:
                    os.unlink(body_pdf_path)
                except Exception:
                    pass

    except Exception as e:
        logger.error(f"Error converting EML to PDF: {e}")
        import traceback
        logger.error(f"EML conversion stack trace: {traceback.format_exc()}")
        return False

def html_to_pdf_playwright(html_content: str, output_path: str, twemoji_base_url: str = None) -> bool:
    """Convert HTML to PDF using Playwright (Chromium baked into the image)."""
    max_retries = 3
    
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
                try:
                    logger.info("Injecting Twemoji and inlining SVGs for consistent emoji rendering")
                    # Load Twemoji library
                    page.add_script_tag(url='https://cdnjs.cloudflare.com/ajax/libs/twemoji/14.0.2/twemoji.min.js')
                    
                    # Parse emojis and inline fetched SVGs into the DOM
                    page.evaluate(
                        """
                        async () => {
                          try {
                            if (typeof twemoji !== 'undefined') {
                              // First parse emojis into img tags
                              const baseUrl = 'https://cdnjs.cloudflare.com/ajax/libs/twemoji/14.0.2/svg/';
                              twemoji.parse(document.body, { 
                                base: baseUrl,
                                folder: '', 
                                ext: '.svg' 
                              });
                              
                              // Now replace all emoji img tags with inline SVGs
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
                                  
                                  const svgText = await response.text();
                                  const parser = new DOMParser();
                                  const svgDoc = parser.parseFromString(svgText, 'image/svg+xml');
                                  const svgElement = svgDoc.documentElement;
                                  
                                  if (svgElement && svgElement.tagName === 'svg') {
                                    // Configure SVG for inline rendering
                                    svgElement.setAttribute('width', '1em');
                                    svgElement.setAttribute('height', '1em');
                                    svgElement.classList.add('emoji');
                                    svgElement.style.display = 'inline';
                                    svgElement.style.verticalAlign = 'middle';
                                    svgElement.style.fill = 'currentColor';
                                    
                                    // Copy any classes from the original img
                                    if (img.className) {
                                      svgElement.classList.add(...img.className.split(' '));
                                    }
                                    
                                    // Replace the img with the inline SVG
                                    img.replaceWith(svgElement);
                                    console.log(`Inlined emoji SVG: ${src}`);
                                  }
                                } catch (error) {
                                  console.warn(`Error inlining emoji ${img.src}:`, error);
                                }
                              }));
                              
                              console.log('Emoji SVG inlining completed');
                              return true;
                            }
                            return false;
                          } catch (error) {
                            console.error('Twemoji injection error:', error);
                            return false;
                          }
                        }
                        """
                    )
                    
                    # Wait for inlining to complete
                    logger.info("Waiting for emoji SVG inlining to complete...")
                    page.wait_for_timeout(1000)
                    
                except Exception as tw_error:
                    logger.warning(f"Twemoji injection failed: {tw_error}")
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

def sanitize_filename(name: str, default: str = 'file') -> str:
    """Return a safe base filename without extension."""
    if not name:
        return default

    # Remove path components and get basename
    name = os.path.basename(name)

    # Remove extension
    name_without_ext = os.path.splitext(name)[0]

    # Keep only safe characters
    import re
    safe_name = re.sub(r'[^\w\s\.\-\(\)]', '', name_without_ext)

    # Replace multiple spaces with single space and strip
    safe_name = ' '.join(safe_name.split())

    return safe_name if safe_name else default

# =====================
# Handlers
# =====================

def handle_convert(event: Dict[str, Any]) -> Dict[str, Any]:
    """Handle EML to PDF conversion."""
    logger.info("=== HANDLE_CONVERT STARTED ===")
    
    try:
        logger.info("Getting body bytes from event...")
        body = _get_body_bytes(event)
        logger.info(f"Body bytes retrieved: {len(body) if body else 0} bytes")
        
        logger.info("Processing headers...")
        headers = _lower_headers(event.get('headers', {}))
        content_type = headers.get('content-type', '')
        logger.info(f"Content-Type: {content_type}")
        logger.info(f"Headers processed: {list(headers.keys())}")

        logger.info(f"=== Starting conversion request processing ===")

        # Parse the multipart/ or single-file body
        logger.info("About to parse multipart data...")
        try:
            files = parse_multipart_data_strict(body, content_type)
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

        # If .msg, convert to .eml bytes first
        if ext == '.msg':
            try:
                logger.info("Detected .msg file - converting to EML bytes...")
                eml_source = convert_msg_bytes_to_eml_bytes(file_content)
                logger.info(f".msg converted to EML: {len(eml_source) if eml_source else 0} bytes")
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
        safe_base = sanitize_filename(filename, default='email')
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
            success = convert_eml_to_pdf(eml_source, tmp_pdf_path, twemoji_base_url)
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
        body_bytes = _get_body_bytes(event)
        try:
            data = json.loads((body_bytes or b"").decode("utf-8", "ignore") or "{}")
        except Exception:
            data = {}

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
        body_bytes = _get_body_bytes(event)
        try:
            data = json.loads((body_bytes or b"").decode("utf-8", "ignore") or "{}")
        except Exception as e:
            logger.error(f"convert-s3 invalid JSON: {e}")
            data = {}

        keys = data.get("keys") or []
        if not isinstance(keys, list) or not keys:
            return {
                "statusCode": 400,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"error": "keys array is required"})
            }

        # Determine or accept provided session_id so all results share one prefix
        headers = _lower_headers(event.get('headers', {}) or {})
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

                # Convert .msg to EML bytes if needed
                if ext == ".msg":
                    try:
                        eml_source = convert_msg_bytes_to_eml_bytes(file_bytes)
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
                    ok = convert_eml_to_pdf(eml_source, tmp_pdf_path)
                    if not ok or not os.path.exists(tmp_pdf_path) or os.path.getsize(tmp_pdf_path) == 0:
                        results.append({
                            "filename": original_name,
                            "status": "error",
                            "message": "PDF conversion failed",
                            "session_id": None,
                            "pdf_filename": None
                        })
                        continue

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
    headers = _lower_headers(event.get('headers', {}) or {})
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

def lambda_handler(event, context):
    """Main Lambda handler."""
    logger.info("Lambda handler started")
    
    try:
        # Log memory usage and environment info
        import psutil
        memory_info = psutil.virtual_memory()
        logger.info(f"Available memory: {memory_info.available / 1024 / 1024:.1f} MB")
        logger.info(f"PLAYWRIGHT_BROWSERS_PATH env var: {os.environ.get('PLAYWRIGHT_BROWSERS_PATH', 'Not set')}")
        
        # Verify Playwright installation on first conversion request only
        path = event.get('path', '') or ''
        method = event.get('httpMethod', '') or ''
        
        if path == '/api/convert' and method == 'POST':
            # Check browser installation before processing
            if not verify_playwright_installation():
                logger.error("Playwright browser verification failed - using fallback PDF generation")
        
        # Add CORS headers
        cors_headers = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type, X-App-Password, Authorization',
            'Access-Control-Allow-Methods': 'OPTIONS, POST, GET'
        }

        # Handle OPTIONS preflight requests
        if event.get('httpMethod') == 'OPTIONS':
            return {
                'statusCode': 200,
                'headers': cors_headers,
                'body': ''
            }

        logger.info(f"Processing request: {method} {path}")

        # Route to appropriate handler
        if path == '/api/convert' and method == 'POST':
            response = handle_convert(event)
        elif path == '/api/upload-url' and method == 'POST':
            response = handle_upload_url(event)
        elif path == '/api/convert-s3' and method == 'POST':
            response = handle_convert_s3(event)
        elif path.startswith('/api/download/') and method == 'GET':
            response = handle_download(event)
        elif path.startswith('/api/download-all/') and method == 'GET':
            response = handle_download_all(event)
        elif path == '/api/health' and method == 'GET':
            response = handle_health(event)
        elif path == '/api/auth/check' and method == 'GET':
            response = handle_auth_check(event)
        elif path.startswith('/api/twemoji/') and method == 'GET':
            response = handle_twemoji(event)
        else:
            response = {
                'statusCode': 404,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Not found'})
            }

        # Add CORS headers to response
        if 'headers' not in response:
            response['headers'] = {}
        response['headers'].update(cors_headers)

        return response

    except Exception as e:
        logger.error(f"Lambda handler error: {str(e)}")
        cors_headers = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type, X-App-Password, Authorization',
            'Access-Control-Allow-Methods': 'OPTIONS, POST, GET'
        }
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                **cors_headers
            },
            'body': json.dumps({'error': f'Internal server error: {str(e)}'})
        }
    finally:
        # Always clean up browser resources at the end
        cleanup_browser_processes()
        logger.info("Lambda handler completed")

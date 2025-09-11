import os
import tempfile
import uuid
import base64
import io
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import email
from email.parser import Parser
from email.policy import default
from playwright.sync_api import sync_playwright
from pypdf import PdfReader, PdfWriter
import boto3
from datetime import datetime
import logging
import html
import re
import zipfile
import shutil
import urllib.request
import urllib.error
import logging
import html
import re
import zipfile
import shutil
import urllib.request
import urllib.error


app = Flask(__name__)
# Allow custom auth header and file download headers
CORS(
    app,
    resources={r"/*": {"origins": "*"}},
    supports_credentials=False,
    expose_headers=["Content-Disposition"],
    allow_headers=["Content-Type", "X-App-Password"]
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# AWS S3 configuration (for production)
S3_BUCKET = os.environ.get('S3_BUCKET', 'msg-converter-temp')
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')

# Simple password protection
APP_PASSWORD = os.environ.get('APP_PASSWORD')  # if set, all API routes (except health and twemoji) require it
if APP_PASSWORD:
    logger.info("Password protection: ENABLED (APP_PASSWORD is set)")
else:
    logger.info("Password protection: DISABLED (APP_PASSWORD not set)")

# Create a persistent storage directory for converted files
STORAGE_DIR = os.path.join(os.getcwd(), 'converted_files')
if not os.path.exists(STORAGE_DIR):
    os.makedirs(STORAGE_DIR)

# Cache directory for Twemoji SVGs (downloaded on-demand)
TWEMOJI_CACHE_DIR = os.path.join(STORAGE_DIR, 'twemoji_cache')
os.makedirs(TWEMOJI_CACHE_DIR, exist_ok=True)

# -------- Filename helpers --------
def sanitize_filename(name: str, default: str = 'file') -> str:
    """Return a safe base filename without extension (keeps letters, numbers, spaces, _ . - ())."""
    try:
        base, _ = os.path.splitext(name or '')
        base = re.sub(r'[^A-Za-z0-9 _().\-]', '_', base).strip()
        if not base:
            base = default
        # collapse multiple spaces/underscores
        base = re.sub(r'[ _]+', ' ', base).strip()
        return base
    except Exception:
        return default

def unique_filename(directory: str, filename: str) -> str:
    """Ensure filename is unique within directory by appending (1), (2), ... if needed."""
    base, ext = os.path.splitext(filename)
    candidate = f"{base}{ext}"
    i = 1
    while os.path.exists(os.path.join(directory, candidate)):
        candidate = f"{base} ({i}){ext}"
        i += 1
    return candidate

class EMLToPDFConverter:
    def __init__(self):
        self.s3_client = None
        if os.environ.get('AWS_EXECUTION_ENV'):  # Running in Lambda
            self.s3_client = boto3.client('s3')
    
    def get_display_date(self, msg) -> str:
        """Return a human-readable date from the message with fallbacks.
        Prefer the Date header as provided; fall back to common alternates or
        the trailing timestamp of the first Received header. Never empty.
        """
        try:
            def dec(v):
                return self.safe_decode_header(v) if v is not None else ''

            # Primary Date header
            d = dec(msg.get('Date'))
            if d:
                return d

            # Alternate headers sometimes used by clients/gateways
            for h in (
                'Sent', 'X-Original-Date', 'Original-Date', 'Resent-Date', 'Delivery-date',
                'X-Received-Date', 'X-Delivery-Date', 'X-Apple-Original-Arrival-Date',
            ):
                d = dec(msg.get(h))
                if d:
                    return d

            # Fallback: parse the date portion from the first Received header
            try:
                recvd = msg.get_all('Received') or []
                if recvd:
                    first = dec(recvd[0])
                    if ';' in first:
                        tail = first.rsplit(';', 1)[-1].strip()
                        if tail:
                            return tail
            except Exception:
                pass

            return 'Unknown Date'
        except Exception:
            return 'Unknown Date'
    
    def extract_eml_content(self, eml_path):
        """Extract content from EML file including images"""
        try:
            with open(eml_path, 'rb') as f:
                raw_email = f.read()
            
            # Try different parsing methods for better compatibility
            msg = None
            try:
                # First try with the default policy (more modern)
                msg = email.message_from_bytes(raw_email, policy=email.policy.default)
            except Exception as e:
                logger.warning(f"Failed to parse with default policy: {str(e)}")
                try:
                    # Fallback to compat32 policy for older emails
                    msg = email.message_from_bytes(raw_email, policy=email.policy.compat32)
                except Exception as e2:
                    logger.warning(f"Failed to parse with compat32 policy: {str(e2)}")
                    # Last resort - basic parsing without policy
                    msg = email.message_from_bytes(raw_email)
            
            if not msg:
                raise Exception("Could not parse email message")
            
            # Extract basic headers with safe decoding and robust date fallback
            subject = self.safe_decode_header(msg.get('Subject', 'No Subject'))
            sender = self.safe_decode_header(msg.get('From', 'Unknown Sender'))
            recipient = self.safe_decode_header(msg.get('To', 'Unknown Recipient'))
            date_display = self.get_display_date(msg)
            
            # Extract body content and images
            try:
                body, images, attachments = self.extract_body_and_images_from_email(msg)
            except Exception as e:
                logger.error(f"Error extracting body and images: {str(e)}")
                # Fallback to simple text extraction
                body = self.extract_simple_text_content(msg)
                images = {}
                attachments = []
            
            # Leave native emoji characters in the HTML; we'll convert them to
            # inline SVGs via Twemoji inside the browser before generating the PDF
            # for consistent cross-viewer rendering.
            pass

            # Create HTML content
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <title>{html.escape(subject)}</title>
                <style>
                    body {{
                        /* Include emoji-capable fonts for proper emoji rendering */
                        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, "Apple Color Emoji", "Segoe UI Emoji", "Noto Color Emoji", sans-serif;
                        line-height: 1.6;
                        margin: 20px;
                        color: #333;
                    }}
                    img.emoji, svg.emoji {{
                        display: inline-block;
                        width: 1em;
                        height: 1em;
                        vertical-align: -0.1em;
                    }}
                    .email-header {{
                        background: #f5f5f5;
                        padding: 15px;
                        margin-bottom: 20px;
                        border-left: 4px solid #007cba;
                    }}
                    .email-header h2 {{
                        margin: 0 0 10px 0;
                        color: #007cba;
                    }}
                    .email-meta {{
                        font-size: 0.9em;
                        color: #666;
                    }}
                    .content {{
                        max-width: 100%;
                        word-wrap: break-word;
                    }}
                    img {{
                        max-width: 100%;
                        height: auto;
                        display: block;
                        margin: 10px 0;
                    }}
                    .inline-image {{
                        max-width: 100%;
                        height: auto;
                    }}
                </style>
            </head>
            <body>
                <div class="email-header">
                    <h2>{html.escape(subject)}</h2>
                    <div class="email-meta">
                        <strong>From:</strong> {html.escape(sender)}<br>
                        <strong>To:</strong> {html.escape(recipient)}<br>
                        <strong>Date:</strong> {html.escape(date_display)}
                    </div>
                </div>
                <div class="content">
                    {body}
                </div>
            </body>
            </html>
            """
            
            return html_content, subject, attachments
            
        except Exception as e:
            logger.error(f"Error extracting EML content: {str(e)}")
            raise Exception(f"Failed to extract EML file: {str(e)}")

    def replace_emojis_with_images(self, html_content: str) -> str:
        """Replace unicode emoji characters in the HTML with inline emoji images.
        Uses a fallback approach for common emojis to avoid network dependencies.
        """
        try:
            # Lazy import to avoid hard dependency if not needed
            import emoji as emoji_lib
            import re
        except Exception:
            # If the emoji package isn't available, return original content
            logger.info("'emoji' package not installed; skipping emoji replacement.")
            return html_content

        # Common emoji to CSS-friendly Unicode mapping
        emoji_mappings = {
            # Original emojis
            '😀': '&#128512;',  # grinning face
            '😃': '&#128515;',  # grinning face with big eyes
            '😄': '&#128516;',  # grinning face with smiling eyes
            '😁': '&#128513;',  # beaming face with smiling eyes
            '😊': '&#128522;',  # smiling face with smiling eyes
            '😍': '&#128525;',  # smiling face with heart-eyes
            '🌟': '&#127775;',  # glowing star
            '⭐': '&#11088;',   # star
            '🚀': '&#128640;',  # rocket
            '✨': '&#10024;',   # sparkles
            '🎉': '&#127881;',  # party popper
            '👍': '&#128077;',  # thumbs up
            '❤️': '&#10084;&#65039;',  # red heart
            '💖': '&#128150;',  # sparkling heart
            '🔥': '&#128293;',  # fire
            '💯': '&#128175;',  # hundred points
            '😂': '&#128514;',  # face with tears of joy
            '🤣': '&#129315;',  # rolling on the floor laughing
            '😭': '&#128557;',  # loudly crying face
            '🥰': '&#129392;',  # smiling face with hearts
            
            # User's specific emojis
            '🔍': '&#128269;',  # magnifying glass tilted left
            '💧': '&#128167;',  # droplet
            '🌡️': '&#127777;&#65039;',  # thermometer
            '🐾': '&#128062;',  # paw prints
            '💦': '&#128166;',  # sweat droplets
            '🎧': '&#127911;',  # headphone
            '🏞️': '&#127774;&#65039;',  # national park
            '🏘️': '&#127960;&#65039;',  # houses
        }

        try:
            # Use emoji.analyze() to find emoji positions and replace them
            emojis_found = list(emoji_lib.analyze(html_content))  # Convert to list
            if not emojis_found:
                return html_content
            
            # Process in reverse order to maintain string positions
            result = html_content
            for emoji_token in reversed(emojis_found):
                emoji_char = emoji_token.chars
                start_pos = emoji_token.value.start
                end_pos = emoji_token.value.end
                
                # Use predefined mapping for common emojis
                if emoji_char in emoji_mappings:
                    replacement = emoji_mappings[emoji_char]
                    result = result[:start_pos] + replacement + result[end_pos:]
                    logger.debug(f"Replaced emoji {emoji_char} with HTML entity")
                else:
                    # For other emojis, convert to HTML entity
                    html_entity = ''.join(f'&#x{ord(c):x};' for c in emoji_char)
                    result = result[:start_pos] + html_entity + result[end_pos:]
                    logger.debug(f"Replaced emoji {emoji_char} with generic HTML entity")
            
            return result
        except Exception as e:
            logger.warning(f"Error during emoji substitution: {e}")
            return html_content
    
    def extract_body_and_images_from_email(self, msg):
        """Extract the body content and images from email message.
        - Chooses the largest HTML (or plaintext) body
        - Handles nested message/rfc822 parts
        - Captures images by Content-ID, Content-Location, and filename
        - Rewrites <img src> to data: URLs and appends unreferenced images
        """
        images = {}
        attachments = []  # list of dicts: {filename, content_type, data}
        html_candidates = []  # list of (length, content)
        text_candidates = []  # list of (length, content)

        def process_part(part):
            try:
                ctype = part.get_content_type()
                cdisp = (part.get('Content-Disposition') or '').lower()
                cid = part.get('Content-ID')
                if cid:
                    cid = cid.strip('<>')
                cloc = part.get('Content-Location')
                fname = part.get_filename()

                # Recurse into nested message/rfc822
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

                # Images
                if ctype.startswith('image/'):
                    img_bytes = part.get_payload(decode=True)
                    if img_bytes:
                        b64 = base64.b64encode(img_bytes).decode('utf-8')
                        data_url = f"data:{ctype};base64,{b64}"
                        keys = set()
                        if cid:
                            keys.add(f"cid:{cid}")
                            keys.add(cid)
                        if cloc:
                            keys.add(cloc)
                        if fname:
                            keys.add(fname)
                        # Register all keys pointing to this data URL
                        for k in keys:
                            images[k] = data_url
                        # Also store by synthesized index to allow appending unreferenced
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
                        # Non-PDF attachments are ignored for merge purposes
                    except Exception as e:
                        logger.warning(f"Error extracting attachment: {e}")
                        return

                # Skip non-text attachments
                if 'attachment' in cdisp and not ctype.startswith('text/'):
                    return

                # Text/HTML
                if ctype == 'text/html':
                    content = self.get_part_content(part)
                    if content:
                        cleaned = self.clean_html_content(content)
                        html_candidates.append((len(cleaned), cleaned))
                    return

                # Plain text
                if ctype == 'text/plain':
                    content = self.get_part_content(part)
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
                        # walk() includes container itself sometimes; filter only real parts
                        if p is not message:
                            process_part(p)
                else:
                    process_part(message)
            except Exception as e:
                logger.warning(f"Error walking message: {e}")

        # Start processing
        process_message(msg)

        # Choose best body
        body = None
        if html_candidates:
            body = max(html_candidates, key=lambda t: t[0])[1]
        elif text_candidates:
            body = max(text_candidates, key=lambda t: t[0])[1]

        if not body:
            body = "No content available"

        # Replace image references
        if images and body:
            body = self.replace_image_references(body, images)

        logger.info(f"Parsed email: body_len={len(body) if body else 0}, images={sum(1 for k in images.keys() if not str(k).startswith('__unref__:'))}, attachments={len(attachments)}")
        return body, {k: v for k, v in images.items() if not str(k).startswith('__unref__:')}, attachments
    
    def get_part_content(self, part):
        """Safely extract content from email part with fallback methods"""
        try:
            # Try the modern get_content() method first
            if hasattr(part, 'get_content'):
                return part.get_content()
            
            # Fallback to get_payload() for older email formats
            payload = part.get_payload(decode=True)
            if payload:
                # Try to decode based on charset
                charset = part.get_content_charset() or 'utf-8'
                try:
                    return payload.decode(charset)
                except (UnicodeDecodeError, LookupError):
                    # Try common encodings as fallback
                    for encoding in ['utf-8', 'latin1', 'cp1252', 'iso-8859-1']:
                        try:
                            return payload.decode(encoding)
                        except (UnicodeDecodeError, LookupError):
                            continue
                    # If all else fails, decode with errors='replace'
                    return payload.decode('utf-8', errors='replace')
            
            # If payload is already a string (non-multipart text)
            payload = part.get_payload()
            if isinstance(payload, str):
                return payload
                
            return None
            
        except Exception as e:
            logger.warning(f"Error extracting content from email part: {str(e)}")
            try:
                # Last resort - try to get raw payload as string
                payload = part.get_payload()
                if isinstance(payload, str):
                    return payload
                elif isinstance(payload, bytes):
                    return payload.decode('utf-8', errors='replace')
            except Exception as e2:
                logger.error(f"Failed to extract content with fallback: {str(e2)}")
            return None
    
    def safe_decode_header(self, header_value):
        """Safely decode email headers that may be encoded"""
        try:
            if header_value is None:
                return "Unknown"
            
            # If it's already a string, return it
            if isinstance(header_value, str):
                return header_value
            
            # Try to decode header if it's encoded
            from email.header import decode_header
            decoded_parts = decode_header(header_value)
            
            result = ""
            for part, encoding in decoded_parts:
                if isinstance(part, bytes):
                    if encoding:
                        try:
                            result += part.decode(encoding)
                        except (UnicodeDecodeError, LookupError):
                            result += part.decode('utf-8', errors='replace')
                    else:
                        result += part.decode('utf-8', errors='replace')
                else:
                    result += str(part)
            
            return result.strip()
            
        except Exception as e:
            logger.warning(f"Error decoding header: {str(e)}")
            return str(header_value) if header_value else "Unknown"
    
    def extract_simple_text_content(self, msg):
        """Simple fallback method to extract text content from problematic emails"""
        try:
            # Try to get plain text parts
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        try:
                            payload = part.get_payload(decode=True)
                            if payload:
                                charset = part.get_content_charset() or 'utf-8'
                                text = payload.decode(charset, errors='replace')
                                return html.escape(text).replace('\n', '<br>\n')
                        except Exception as e:
                            logger.warning(f"Error extracting part content: {str(e)}")
                            continue
            else:
                # Non-multipart message
                try:
                    payload = msg.get_payload(decode=True)
                    if payload:
                        charset = msg.get_content_charset() or 'utf-8'
                        text = payload.decode(charset, errors='replace')
                        return html.escape(text).replace('\n', '<br>\n')
                except Exception as e:
                    logger.warning(f"Error extracting simple content: {str(e)}")
            
            # Last resort - try to get any string payload
            try:
                payload = msg.get_payload()
                if isinstance(payload, str):
                    return html.escape(payload).replace('\n', '<br>\n')
                elif isinstance(payload, list) and payload:
                    # Take first text part from list
                    for item in payload:
                        if hasattr(item, 'get_payload'):
                            item_payload = item.get_payload()
                            if isinstance(item_payload, str):
                                return html.escape(item_payload).replace('\n', '<br>\n')
            except Exception as e:
                logger.warning(f"Error with fallback extraction: {str(e)}")
            
            return "Could not extract email content - email format may not be supported"
            
        except Exception as e:
            logger.error(f"Error in simple text extraction: {str(e)}")
            return "Error extracting email content"
    
    def replace_image_references(self, html_content, images):
        """Replace image references and clean artifacts.
        - Map <img src> values (cid:, filenames, content-location, paths) to base64 data URLs.
        - Remove <img> tags that cannot be resolved (prevents broken image icons).
        - Remove stray filename-only text nodes like "DE558...jpeg" that some clients insert.
        - Append any truly unreferenced images at the end under an "Attached Images" section.
        """
        try:
            import re

            used_data_urls = set()

            # Helper to compute candidate keys for lookup
            def candidates_for(key: str):
                key = (key or '').strip()
                cands = []
                if not key:
                    return cands
                cands.append(key)
                low = key.lower()
                if low.startswith('cid:'):
                    cands.append(key[4:])
                # filename component from URL or path
                try:
                    fname = key.split('?')[0].split('#')[0].split('/')[-1]
                    if fname and fname != key:
                        cands.append(fname)
                except Exception:
                    pass
                return cands

            # Replace entire <img ...> tags; drop if unresolved
            def replace_img_tag(m):
                tag = m.group(0)
                msrc = re.search(r'src\s*=\s*(["\'])(.*?)\1', tag, flags=re.IGNORECASE)
                if not msrc:
                    return ''  # no src: drop
                orig = msrc.group(2).strip()
                for c in candidates_for(orig):
                    if c in images:
                        data_url = images[c]
                        used_data_urls.add(data_url)
                        # replace only the src value, preserve other attributes
                        return re.sub(r'src\s*=\s*(["\'])(.*?)\1', f'src="{data_url}"', tag, flags=re.IGNORECASE)
                # Unresolved -> drop tag entirely to avoid broken image icons
                return ''

            html_new = re.sub(r'<img\b[^>]*>', replace_img_tag, html_content, flags=re.IGNORECASE)

            # Remove stray filename-only elements or lines (e.g., "DE558855-...jpeg")
            fname_pat = r'(?:[A-Za-z0-9_\-]{6,}|[A-F0-9\-]{12,})\.(?:jpg|jpeg|png|gif|bmp|webp)'
            # Remove <p>filename</p>, <div>filename</div>, <span>filename</span>
            html_new = re.sub(rf'<(p|div|span)[^>]*>\s*{fname_pat}\s*</\1>', '', html_new, flags=re.IGNORECASE)
            # Remove <li>filename</li>
            html_new = re.sub(rf'<li[^>]*>\s*{fname_pat}\s*</li>', '', html_new, flags=re.IGNORECASE)
            # Remove <a>filename</a> (optionally followed by <br>)
            html_new = re.sub(rf'<a[^>]*>\s*{fname_pat}\s*</a>\s*(?:<br\s*/?>)?', '', html_new, flags=re.IGNORECASE)
            # Remove standalone filename on its own line (optionally followed by <br>)
            html_new = re.sub(rf'(^|[>\n\r])\s*{fname_pat}\s*(?:<br\s*/?>)?\s*(?=[<\n\r]|$)', r'\1', html_new, flags=re.IGNORECASE)

            # Append truly unreferenced images once
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

            return html_new
        except Exception as e:
            logger.warning(f"Error replacing image references: {str(e)}")
            return html_content
    
    def clean_html_content(self, html_content):
        """Clean and sanitize HTML content"""
        try:
            # Remove dangerous tags and scripts
            html_content = re.sub(r'<script[^>]*>.*?</script>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
            html_content = re.sub(r'<style[^>]*>.*?</style>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
            
            # Remove dangerous attributes
            html_content = re.sub(r'\s*on\w+\s*=\s*["\'][^"\']*["\']', '', html_content, flags=re.IGNORECASE)
            html_content = re.sub(r'\s*javascript\s*:', '', html_content, flags=re.IGNORECASE)
            
            # Clean up common Outlook/Exchange artifacts
            html_content = re.sub(r'<o:p[^>]*>.*?</o:p>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
            html_content = re.sub(r'<!\[if[^>]*>.*?<!\[endif\]>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
            
            return html_content
        except Exception as e:
            logger.warning(f"Error cleaning HTML content: {str(e)}")
            return html.escape(str(html_content)).replace('\n', '<br>\n')
    
    def html_to_pdf(self, html_content, output_path):
        """Convert HTML content to PDF using Playwright"""
        try:
            with sync_playwright() as p:
                # Use chromium for PDF generation
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()

                # Set content
                page.set_content(html_content)

                # Convert emojis to Twemoji SVGs and inline them
                try:
                    page.add_script_tag(url='https://cdnjs.cloudflare.com/ajax/libs/twemoji/14.0.2/twemoji.min.js')
                    page.evaluate(
                        """
                        (async () => {
                            try {
                                if (typeof twemoji !== 'undefined') {
                                    // Point Twemoji <img> src to backend proxy for same-origin fetch with caching
                                    const base = `${location.origin}/twemoji/`;
                                    twemoji.parse(document.body, { base, folder: '', ext: '.svg' });
                                }
                                const imgs = Array.from(document.querySelectorAll('img.emoji'));
                                await Promise.all(imgs.map(async (img) => {
                                    try {
                                        const res = await fetch(img.src);
                                        const svgText = await res.text();
                                        const parser = new DOMParser();
                                        const doc = parser.parseFromString(svgText, 'image/svg+xml');
                                        const svg = doc.documentElement;
                                        svg.setAttribute('width', '1em');
                                        svg.setAttribute('height', '1em');
                                        svg.classList.add('emoji');
                                        img.replaceWith(svg);
                                    } catch (e) { /* ignore */ }
                                }));
                                return true;
                            } catch (e) {
                                return false;
                            }
                        })();
                        """
                    )
                except Exception as tw:
                    logger.info(f"Twemoji injection failed or skipped: {tw}")

                # Give time for resources
                page.wait_for_timeout(500)

                page.pdf(
                    path=output_path,
                    format='A4',
                    margin={
                        'top': '1in',
                        'right': '1in',
                        'bottom': '1in',
                        'left': '1in'
                    },
                    print_background=True,
                    prefer_css_page_size=False
                )

                browser.close()
        except Exception as e:
            logger.error(f"Error converting HTML to PDF: {str(e)}")
            raise Exception(f"Failed to generate PDF: {str(e)}")
    
    def convert_eml_to_pdf(self, eml_file_path, output_pdf_path):
        """Main conversion function"""
        try:
            # Extract content from EML file
            html_content, subject, attachments = self.extract_eml_content(eml_file_path)
            
            # Convert HTML to PDF (email body only) into a temporary file
            body_pdf_fd, body_pdf_path = tempfile.mkstemp(suffix='.pdf')
            os.close(body_pdf_fd)
            try:
                self.html_to_pdf(html_content, body_pdf_path)
            except Exception:
                # Ensure temp is removed on failure
                try:
                    os.remove(body_pdf_path)
                except Exception:
                    pass
                raise

            # If there are PDF attachments, merge them after the body
            pdf_attachments = [a for a in attachments if a.get('content_type') == 'application/pdf' or (a.get('filename','').lower().endswith('.pdf'))]
            if pdf_attachments:
                writer = PdfWriter()
                # Append body pages
                try:
                    reader = PdfReader(body_pdf_path)
                    for page in reader.pages:
                        writer.add_page(page)
                except Exception as e:
                    logger.error(f"Failed reading body PDF for merge: {e}")
                    # Fallback: copy body file directly
                    shutil.copyfile(body_pdf_path, output_pdf_path)
                    try:
                        os.remove(body_pdf_path)
                    except Exception:
                        pass
                    return subject

                # Append each attachment PDF directly (no header/cover page)
                for idx, att in enumerate(pdf_attachments, start=1):
                    fname = att.get('filename') or f'attachment-{idx}.pdf'
                    try:
                        att_reader = PdfReader(io.BytesIO(att['data']))
                        for page in att_reader.pages:
                            writer.add_page(page)
                    except Exception as e:
                        logger.warning(f"Skipping unreadable PDF attachment {fname}: {e}")

                # Write the final merged PDF
                with open(output_pdf_path, 'wb') as out_f:
                    writer.write(out_f)
            else:
                # No attachments: just move body PDF to destination
                shutil.copyfile(body_pdf_path, output_pdf_path)

            # Cleanup temp body file
            try:
                os.remove(body_pdf_path)
            except Exception:
                pass
            
            return subject
            
        except Exception as e:
            logger.error(f"Conversion failed: {str(e)}")
            raise

# Initialize converter
converter = EMLToPDFConverter()

@app.before_request
def require_password():
    try:
        # Allow health checks and Twemoji assets without password
        path = request.path or ''
        if path.startswith('/health') or path.startswith('/twemoji'):
            return None
        # Preflight requests
        if request.method == 'OPTIONS':
            return None
        # If no password configured, allow all
        if not APP_PASSWORD:
            return None
        # Check header or query param
        provided = request.headers.get('X-App-Password') or request.args.get('auth')
        if provided != APP_PASSWORD:
            return jsonify({'error': 'Unauthorized'}), 401
        return None
    except Exception as e:
        logger.warning(f"Password check error: {e}")
        return jsonify({'error': 'Unauthorized'}), 401

@app.route('/auth/check', methods=['POST'])
@app.route('/api/auth/check', methods=['POST'])
def auth_check():
    """Optional endpoint for clients to validate password"""
    if not APP_PASSWORD:
        return jsonify({'ok': True, 'auth': 'not-required'})
    provided = request.headers.get('X-App-Password') or (request.json or {}).get('password')
    if provided == APP_PASSWORD:
        return jsonify({'ok': True})
    return jsonify({'ok': False}), 401

@app.route('/health', methods=['GET'])
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'service': 'eml-to-pdf-converter'})

@app.route('/twemoji/<path:filename>', methods=['GET'])
def twemoji_proxy(filename):
    """Serve Twemoji SVGs via backend with on-disk caching.
    Expected filename format: '<codepoints>.svg' (e.g., '1f4a7.svg').
    """
    try:
        # Basic sanitization
        if not filename.lower().endswith('.svg'):
            return jsonify({'error': 'Not found'}), 404
        # Normalize to filename only
        safe_name = os.path.basename(filename)
        local_path = os.path.join(TWEMOJI_CACHE_DIR, safe_name)

        # Fetch and cache if missing
        if not os.path.exists(local_path):
            cdn_url = f'https://cdnjs.cloudflare.com/ajax/libs/twemoji/14.0.2/svg/{safe_name}'
            try:
                with urllib.request.urlopen(cdn_url, timeout=10) as resp, open(local_path, 'wb') as out:
                    out.write(resp.read())
            except Exception as e:
                logger.error(f"Twemoji fetch failed for {safe_name}: {e}")
                return jsonify({'error': 'Emoji asset unavailable'}), 502

        return send_file(local_path, mimetype='image/svg+xml', as_attachment=False, download_name=safe_name)
    except Exception as e:
        logger.error(f"Twemoji proxy error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/convert', methods=['POST'])
def convert_files():
    """Convert uploaded .eml files to PDF"""
    try:
        if 'files' not in request.files:
            return jsonify({'error': 'No files provided'}), 400

        files = request.files.getlist('files')
        if not files:
            return jsonify({'error': 'No files selected'}), 400

        results = []
        temp_dir = tempfile.mkdtemp()
        session_id = str(uuid.uuid4())
        session_dir = os.path.join(STORAGE_DIR, session_id)
        os.makedirs(session_dir, exist_ok=True)

        for file in files:
            if not file.filename.lower().endswith('.eml'):
                results.append({
                    'filename': file.filename,
                    'status': 'error',
                    'message': 'File must be a .eml file'
                })
                continue

            try:
                # Generate unique filenames
                safe_base = sanitize_filename(file.filename, default='email')
                # Save uploaded file temporarily with unique .eml name
                file_id = str(uuid.uuid4())
                eml_filename = f"{safe_base}__{file_id}.eml"

                # Save uploaded file temporarily
                eml_path = os.path.join(temp_dir, eml_filename)
                file.save(eml_path)

                # Convert to PDF and save to session directory
                # Target PDF should use the original .eml base name
                desired_pdf = f"{safe_base}.pdf"
                pdf_filename = unique_filename(session_dir, desired_pdf)
                pdf_path = os.path.join(session_dir, pdf_filename)
                subject = converter.convert_eml_to_pdf(eml_path, pdf_path)

                # For local development, return file directly
                if not converter.s3_client:
                    results.append({
                        'filename': file.filename,
                        'status': 'success',
                        'subject': subject,
                        'download_url': f'/download/{session_id}/{pdf_filename}',
                        'pdf_filename': pdf_filename,
                        'session_id': session_id
                    })
                else:
                    # Upload to S3 for production
                    s3_key = f"converted/{pdf_filename}"
                    converter.s3_client.upload_file(pdf_path, S3_BUCKET, s3_key)

                    # Generate presigned URL for download
                    download_url = converter.s3_client.generate_presigned_url(
                        'get_object',
                        Params={'Bucket': S3_BUCKET, 'Key': s3_key},
                        ExpiresIn=3600  # 1 hour
                    )

                    results.append({
                        'filename': file.filename,
                        'status': 'success',
                        'subject': subject,
                        'download_url': download_url
                    })

                # Clean up temp EML file
                os.remove(eml_path)

            except Exception as e:
                logger.error(f"Error converting {file.filename}: {str(e)}")
                results.append({
                    'filename': file.filename,
                    'status': 'error',
                    'message': str(e)
                })

        # Clean up temp directory
        shutil.rmtree(temp_dir, ignore_errors=True)

        success_count = len([r for r in results if r['status'] == 'success'])
        failed_count = len(files) - success_count

        return jsonify({
            'results': results,
            'total_files': len(files),
            'successful_conversions': success_count,
            'failed_conversions': failed_count,
            'session_id': session_id,
            'download_all_url': f'/download-all/{session_id}' if success_count >= 1 else None
        })

    except Exception as e:
        logger.error(f"Unexpected error in convert_files: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/download/<session_id>/<filename>', methods=['GET'])
@app.route('/api/download/<session_id>/<filename>', methods=['GET'])
def download_file(session_id, filename):
    """Download converted PDF file"""
    try:
        file_path = os.path.join(STORAGE_DIR, session_id, filename)
        
        if os.path.exists(file_path):
            return send_file(file_path, as_attachment=True, download_name=filename)
        else:
            return jsonify({'error': 'File not found'}), 404
            
    except Exception as e:
        logger.error(f"Error downloading file: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/download-all/<session_id>', methods=['GET'])
@app.route('/api/download-all/<session_id>', methods=['GET'])
def download_all_files(session_id):
    """Download all converted PDF files as a ZIP"""
    try:
        session_dir = os.path.join(STORAGE_DIR, session_id)
        
        if not os.path.exists(session_dir):
            return jsonify({'error': 'Session not found'}), 404
        
        # Create a temporary ZIP file
        zip_filename = f"converted_pdfs_{session_id}.zip"
        zip_path = os.path.join(tempfile.gettempdir(), zip_filename)

        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for filename in os.listdir(session_dir):
                if filename.endswith('.pdf'):
                    file_path = os.path.join(session_dir, filename)
                    # Use the actual filename as stored (already user-friendly)
                    arcname = filename
                    zipf.write(file_path, arcname)
        
        if os.path.exists(zip_path):
            return send_file(zip_path, as_attachment=True, download_name=zip_filename)
        else:
            return jsonify({'error': 'No PDF files found'}), 404
            
    except Exception as e:
        logger.error(f"Error creating ZIP file: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

# Lambda handler for AWS deployment
def lambda_handler(event, context):
    """AWS Lambda handler"""
    try:
        # This would handle API Gateway events in production
        # For now, return a simple response
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type, X-App-Password',
                'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
            },
            'body': '{"message": "MSG to PDF converter Lambda function"}'
        }
    except Exception as e:
        logger.error(f"Lambda error: {str(e)}")
        return {
            'statusCode': 500,
            'body': f'{{"error": "{str(e)}"}}'
        }

if __name__ == '__main__':
    # Install playwright browsers if needed
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            p.chromium.launch()
    except Exception:
        logger.info("Installing Playwright browsers...")
    import sys
    os.system(f"{sys.executable} -m playwright install chromium")
    
    app.run(debug=True, host='0.0.0.0', port=5002, threaded=True)

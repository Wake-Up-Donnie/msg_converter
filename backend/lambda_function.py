import os
import json
import base64
import tempfile
import uuid
import boto3
import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Any

from converter import EmailConverter
from router import LambdaRouter
from document_converter import DocumentConverter
from request_parser import RequestParser
from multipart_parser import MultipartParser

from logging_utils import configure_logging
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
from pdf_generation import PDFGenerationService
from filename_utils import extract_sender_name_and_date, sanitize_filename
from playwright_environment import (
    cleanup_browser_processes as cleanup_playwright_artifacts,
    verify_playwright_installation as verify_playwright_env,
)
from twemoji_proxy import handle_twemoji as proxy_twemoji_handler


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

pdf_service = PDFGenerationService(logger, converter, doc_converter)
convert_eml_to_pdf = pdf_service.convert_eml_to_pdf
html_to_pdf_playwright = pdf_service.html_to_pdf_playwright
fallback_html_to_pdf = pdf_service.fallback_html_to_pdf

doc_converter.eml_to_pdf = pdf_service.convert_eml_to_pdf
doc_converter.html_to_pdf = pdf_service.html_to_pdf_with_fallback

# =====================
# Request handlers
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
            last, fi, date_str = extract_sender_name_and_date(eml_source, logger=logger)
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
                        last, fi, date_str = extract_sender_name_and_date(eml_source, logger=logger)
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

def cleanup_browser_processes() -> None:
    cleanup_playwright_artifacts(logger)


def verify_playwright_installation() -> bool:
    return verify_playwright_env(logger)


def handle_twemoji(event: Dict[str, Any]) -> Dict[str, Any]:
    return proxy_twemoji_handler(event, logger)


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

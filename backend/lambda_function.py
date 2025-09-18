import os
import json
import boto3
import logging
from typing import Dict, Any

from converter import EmailConverter
from router import LambdaRouter
from document_converter import DocumentConverter
from multipart_parser import MultipartParser
from handlers import (
    create_auth_check_handler,
    create_convert_handler,
    create_convert_s3_handler,
    create_download_all_handler,
    create_download_handler,
    create_upload_url_handler,
)

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
from pdf_generation import PDFGenerationService
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

handle_convert = create_convert_handler(
    logger=logger,
    multipart_parser=multipart_parser,
    email_converter=converter,
    convert_eml_to_pdf=pdf_service.convert_eml_to_pdf,
    s3_client=s3_client,
    bucket=S3_BUCKET,
)

handle_download = create_download_handler(
    logger=logger,
    s3_client=s3_client,
    bucket=S3_BUCKET,
)

handle_download_all = create_download_all_handler(
    logger=logger,
    s3_client=s3_client,
    bucket=S3_BUCKET,
)

handle_upload_url = create_upload_url_handler(
    logger=logger,
    s3_client=s3_client,
    bucket=S3_BUCKET,
)

handle_convert_s3 = create_convert_s3_handler(
    logger=logger,
    email_converter=converter,
    convert_eml_to_pdf=pdf_service.convert_eml_to_pdf,
    s3_client=s3_client,
    bucket=S3_BUCKET,
)

handle_auth_check = create_auth_check_handler(logger=logger)


def handle_health(event: Dict[str, Any]) -> Dict[str, Any]:
    """Handle health check."""
    return {
        'statusCode': 200,
        'headers': {'Content-Type': 'application/json'},
        'body': json.dumps({'status': 'healthy', 'service': 'eml-to-pdf-converter'})
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

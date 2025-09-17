"""AWS Lambda handler for converting Outlook .msg files to PDF using msgconvert."""

from __future__ import annotations

import html
import json
import logging
import os
import re
import subprocess
import tempfile
from datetime import datetime
from typing import Any

import boto3
import mailparser
from bs4 import BeautifulSoup
from email import message_from_bytes
from email.policy import default as default_policy
from email.utils import formataddr, getaddresses, parseaddr, parsedate_to_datetime


LOGGER = logging.getLogger(__name__)
if not LOGGER.handlers:
    logging.basicConfig(level=logging.INFO)
LOGGER.setLevel(getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO))


WKHTML = "/usr/local/bin/wkhtmltopdf"
S3_CLIENT = boto3.client("s3")
UPLOAD_EML = os.environ.get("UPLOAD_EML_COPY", "true").lower() in {"1", "true", "yes", "on"}


def _safe(name: str, fallback: str = "email") -> str:
    """Return a filesystem-safe filename stem."""
    if not name:
        return fallback
    cleaned = re.sub(r"[^\w\-.]+", "_", name.strip())[:180]
    return cleaned or fallback


def _run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Execute a subprocess and capture output."""
    LOGGER.debug("Running command: %s", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def msg_to_eml(msg_path: str, eml_path: str) -> None:
    """Convert an Outlook .msg file to .eml using msgconvert."""
    try:
        _run(["msgconvert", "--outfile", eml_path, msg_path])
    except subprocess.CalledProcessError as exc:  # pragma: no cover - logged for debugging
        LOGGER.error("msgconvert failed: stdout=%s stderr=%s", exc.stdout, exc.stderr)
        raise


PAGE_BREAK_DEFAULTS = {
    "page-break-before": "auto",
    "page-break-after": "auto",
    "break-before": "auto",
    "break-after": "auto",
    "page-break-inside": "avoid",
    "break-inside": "avoid",
}


_STYLE_ATTR_PATTERN = re.compile(
    r"(\sstyle\s*=\s*)(?P<quote>[\"'])(?P<content>.*?)(?P=quote)",
    flags=re.IGNORECASE | re.DOTALL,
)
_INLINE_BREAK_PATTERN = re.compile(
    r"(?P<prop>page-break-before|page-break-after|page-break-inside|break-before|break-after|break-inside)"
    r"(?P<separator>\s*:\s*)(?P<value>[^;]*)(?P<suffix>;?)",
    flags=re.IGNORECASE,
)


def _sanitize_style_content(content: str) -> str:
    def _replace(match: re.Match[str]) -> str:
        prop = match.group("prop")
        value = match.group("value")
        if not re.search(r"\balways\b", value, flags=re.IGNORECASE):
            return match.group(0)
        default = PAGE_BREAK_DEFAULTS.get(prop.lower(), "auto")
        sanitized = re.sub(r"\balways\b", default, value, flags=re.IGNORECASE)
        return f"{match.group('prop')}{match.group('separator')}{sanitized}{match.group('suffix')}"

    return _INLINE_BREAK_PATTERN.sub(_replace, content)


def clean_html_content(html_content: str, style_collector: list[str] | None = None) -> str:
    """Remove unsafe markup and neutralize hard page breaks."""
    if not html_content:
        return ""

    try:
        cleaned = re.sub(r"<script[^>]*>.*?</script>", "", html_content, flags=re.DOTALL | re.IGNORECASE)
        styles = re.findall(r"<style[^>]*>.*?</style>", cleaned, flags=re.DOTALL | re.IGNORECASE)
        if style_collector is not None:
            style_collector.extend(styles)
        cleaned = re.sub(r"<style[^>]*>.*?</style>", "", cleaned, flags=re.DOTALL | re.IGNORECASE)
        cleaned = re.sub(r"\s*on\w+\s*=\s*[\"'][^\"']*[\"']", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*javascript\s*:", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"<o:p[^>]*>.*?</o:p>", "", cleaned, flags=re.DOTALL | re.IGNORECASE)
        cleaned = re.sub(r"<!\[if[^>]*>.*?<!\[endif\]>", "", cleaned, flags=re.DOTALL | re.IGNORECASE)

        def _rewrite_style_attribute(match: re.Match[str]) -> str:
            prefix = match.group(1)
            quote = match.group("quote")
            content = match.group("content")
            sanitized = _sanitize_style_content(content)
            return f"{prefix}{quote}{sanitized}{quote}"

        cleaned = _STYLE_ATTR_PATTERN.sub(_rewrite_style_attribute, cleaned)
        return cleaned
    except Exception:  # pragma: no cover - defensive fallback
        return html.escape(str(html_content)).replace("\n", "<br>\n")


def _format_address_header(value: str | None) -> str:
    """Normalize an address header to "Name <addr>" tokens when possible."""
    if value is None:
        return "Unknown"

    if not isinstance(value, str):
        value = str(value)

    value = value.strip()
    if not value:
        return value

    formatted_parts: list[str] = []

    try:
        address_candidates = getaddresses([value])
    except Exception:
        address_candidates = []

    for display, addr in address_candidates:
        candidate = ""
        if display or addr:
            try:
                candidate = formataddr((display, addr))
            except Exception:
                candidate = addr or display

        if not candidate:
            continue

        parsed_display, parsed_addr = parseaddr(candidate)
        parsed_display = parsed_display.strip()
        parsed_addr = parsed_addr.strip()

        if parsed_addr:
            if parsed_display:
                formatted_parts.append(f"{parsed_display} <{parsed_addr}>")
            else:
                formatted_parts.append(parsed_addr)
        elif parsed_display:
            formatted_parts.append(parsed_display)

    if formatted_parts:
        return ", ".join(formatted_parts)

    parsed_display, parsed_addr = parseaddr(value)
    parsed_display = parsed_display.strip()
    parsed_addr = parsed_addr.strip()

    if parsed_addr:
        if parsed_display:
            return f"{parsed_display} <{parsed_addr}>"
        return parsed_addr

    return value


def eml_to_html(eml_bytes: bytes) -> str:
    """Transform EML bytes into printable HTML."""
    parser = mailparser.MailParser()
    parser.parse_from_bytes(eml_bytes)
    msg = message_from_bytes(eml_bytes, policy=default_policy)

    subject = (parser.subject or msg.get("subject") or "(no subject)").strip()
    from_header = _format_address_header(msg.get("from")) if msg.get("from") else ""
    to_header = _format_address_header(msg.get("to")) if msg.get("to") else ""
    cc_header = _format_address_header(msg.get("cc")) if msg.get("cc") else ""

    date_display = ""
    if parser.date and isinstance(parser.date, datetime):
        date_display = parser.date.strftime("%Y-%m-%d %H:%M:%S %Z")
    elif msg.get("date"):
        try:
            parsed = parsedate_to_datetime(msg["date"])
            if parsed:
                date_display = parsed.strftime("%Y-%m-%d %H:%M:%S %Z")
        except (TypeError, ValueError):
            date_display = msg["date"]
    else:
        date_display = ""

    html_body = parser.body_html
    if html_body:
        html_body = clean_html_content(html_body)
    if not html_body:
        text = parser.body or msg.get_body(preferencelist=("plain",))
        if hasattr(text, "get_content"):
            text = text.get_content()
        text = text or ""
        escaped = html.escape(str(text))
        html_body = (
            "<pre style='white-space:pre-wrap; font-family:ui-monospace,monospace'>"
            f"{escaped}"
            "</pre>"
        )

    soup = BeautifulSoup(html_body, "lxml")
    body_content = str(soup.body or soup)

    header_rows = [
        ("Subject", subject),
        ("From", from_header),
        ("To", to_header),
    ]
    if cc_header:
        header_rows.append(("Cc", cc_header))
    if date_display:
        header_rows.append(("Date", date_display))

    header_html = "".join(
        f"<div><b>{label}:</b> {value}</div>" for label, value in header_rows if value
    )

    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>{html.escape(subject)}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <style>
    html,body{{margin:0;padding:24px;background:#fff;color:#111;font:15px/1.6 -apple-system, Segoe UI, Roboto, Arial}}
    img{{max-width:100%;height:auto}}
    table{{border-collapse:collapse;max-width:100%}}
    blockquote{{margin:0 0 0 12px;padding-left:12px;border-left:3px solid #ddd;color:#444}}
    pre,code{{font-family:ui-monospace,Menlo,Consolas,monospace}}
  </style>
</head>
<body>
  <div style="font:14px/1.4 -apple-system,Segoe UI,Arial;border-bottom:1px solid #ddd;margin-bottom:16px;padding-bottom:8px">
    {header_html}
  </div>
  {body_content}
</body>
</html>"""


def html_to_pdf(html_str: str, out_pdf_path: str) -> None:
    """Render HTML to PDF using wkhtmltopdf."""
    if not os.path.exists(WKHTML):
        raise FileNotFoundError(f"wkhtmltopdf not found at {WKHTML}")

    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as temp_html:
        temp_html.write(html_str.encode("utf-8", errors="ignore"))
        temp_html.flush()
        html_fp = temp_html.name

    try:
        _run(
            [
                WKHTML,
                "--enable-local-file-access",
                "--print-media-type",
                "--margin-top",
                "10mm",
                "--margin-right",
                "10mm",
                "--margin-bottom",
                "12mm",
                "--margin-left",
                "10mm",
                html_fp,
                out_pdf_path,
            ]
        )
    finally:
        try:
            os.unlink(html_fp)
        except OSError:  # pragma: no cover - best effort cleanup
            pass


def _s3_put_pdf(pdf_path: str, bucket: str, key: str) -> None:
    LOGGER.info("Uploading PDF to s3://%s/%s", bucket, key)
    S3_CLIENT.upload_file(pdf_path, bucket, key, ExtraArgs={"ContentType": "application/pdf"})


def _s3_put_eml(eml_bytes: bytes, bucket: str, key: str) -> None:
    LOGGER.info("Uploading EML to s3://%s/%s", bucket, key)
    S3_CLIENT.put_object(Bucket=bucket, Key=key, Body=eml_bytes, ContentType="message/rfc822")


def _convert_record(record: dict[str, Any]) -> dict[str, str]:
    bucket = record.get("s3", {}).get("bucket", {}).get("name")
    key = record.get("s3", {}).get("object", {}).get("key")
    if not bucket or not key:
        raise ValueError("Record is missing bucket or key information")

    base_name = os.path.splitext(os.path.basename(key))[0]
    safe_base = _safe(base_name)
    msg_tmp_path = os.path.join("/tmp", f"{safe_base}.msg")

    LOGGER.info("Downloading s3://%s/%s to %s", bucket, key, msg_tmp_path)
    S3_CLIENT.download_file(bucket, key, msg_tmp_path)

    try:
        with tempfile.TemporaryDirectory() as tmp_dir:
            eml_path = os.path.join(tmp_dir, f"{safe_base}.eml")
            msg_to_eml(msg_tmp_path, eml_path)

            with open(eml_path, "rb") as eml_file:
                eml_bytes = eml_file.read()

            html_str = eml_to_html(eml_bytes)
            pdf_path = os.path.join(tmp_dir, f"{safe_base}.pdf")
            html_to_pdf(html_str, pdf_path)

            pdf_key = f"{os.path.splitext(key)[0]}.pdf"
            _s3_put_pdf(pdf_path, bucket, pdf_key)

            eml_key = f"{os.path.splitext(key)[0]}.eml"
            if UPLOAD_EML:
                _s3_put_eml(eml_bytes, bucket, eml_key)

        return {"pdf": pdf_key, "eml": eml_key if UPLOAD_EML else ""}
    finally:
        try:
            os.unlink(msg_tmp_path)
        except OSError:
            pass


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Lambda entry point for S3 Put events."""
    LOGGER.info("Received event: %s", json.dumps(event)[:500])
    records = event.get("Records")
    if not records:
        return {"statusCode": 400, "body": json.dumps({"error": "No S3 records in event"})}

    converted: list[dict[str, str]] = []
    errors: list[str] = []

    for record in records:
        try:
            converted.append(_convert_record(record))
        except Exception as exc:  # pragma: no cover - runtime safety
            LOGGER.exception("Failed to convert record: %s", exc)
            errors.append(str(exc))

    status = 200 if not errors else 500
    body = {"converted": converted}
    if errors:
        body["errors"] = errors

    return {"statusCode": status, "body": json.dumps(body)}


lambda_handler = handler

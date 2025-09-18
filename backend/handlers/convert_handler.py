"""Request handler for /api/convert events."""

from __future__ import annotations

import json
import os
import re
import tempfile
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Optional, Tuple

from filename_utils import extract_sender_name_and_date, sanitize_filename
from request_parser import RequestParser


UploadedFile = Dict[str, Any]
MultipartMap = Dict[str, UploadedFile]


class ConversionInputError(Exception):
    """Raised when the request payload is invalid for conversion."""


@dataclass
class SelectedUpload:
    """Represents the uploaded email content selected for conversion."""

    filename: str
    content: bytes
    content_type: str
    attachments: list[Any]
    eml_bytes: bytes


class ConvertHandler:
    """Encapsulates the multi-step EML/MSG -> PDF conversion workflow."""

    def __init__(
        self,
        logger,
        multipart_parser,
        email_converter,
        convert_eml_to_pdf: Callable[[bytes, str, Optional[str], Optional[list[Any]]], bool],
        s3_client,
        bucket: Optional[str],
    ) -> None:
        self._logger = logger
        self._multipart_parser = multipart_parser
        self._email_converter = email_converter
        self._convert_eml_to_pdf = convert_eml_to_pdf
        self._s3_client = s3_client
        self._bucket = bucket

    # Public API ---------------------------------------------------------

    def handle(self, event: Dict[str, Any]) -> Dict[str, Any]:
        self._logger.info("=== HANDLE_CONVERT STARTED ===")

        try:
            parser = RequestParser(event)
            headers = parser.headers
            body = parser.body
            content_type = headers.get("content-type", "")
            self._logger.info("Content-Type: %s", content_type)
            self._logger.info("=== Starting conversion request processing ===")

            try:
                files = self._parse_multipart(body, content_type)
            except ConversionInputError as exc:
                return self._bad_request(str(exc))

            try:
                selection = self._select_uploaded_email(files)
            except ConversionInputError as exc:
                return self._bad_request(str(exc))
            if selection is None:
                return self._bad_request("No file provided")

            self._logger.info("=== File validation passed - Processing: %s ===", selection.filename)
            session_id = self._determine_session_id(event, headers)
            pdf_filename = self._determine_pdf_filename(selection.eml_bytes, selection.filename)
            self._logger.info("Generated session_id: %s, pdf_filename: %s", session_id, pdf_filename)

            tmp_pdf_path = self._create_temp_pdf_path()
            try:
                twemoji_base = self._infer_twemoji_base(headers)
                success = self._convert_eml_to_pdf(
                    selection.eml_bytes,
                    tmp_pdf_path,
                    twemoji_base,
                    selection.attachments or None,
                )
                self._logger.info("EML to PDF conversion result: success=%s", success)

                if not success:
                    return self._server_error("PDF conversion failed")

                if not os.path.exists(tmp_pdf_path) or os.path.getsize(tmp_pdf_path) == 0:
                    return self._server_error("PDF generation produced empty file")

                s3_key = f"{session_id}/{pdf_filename}"
                with open(tmp_pdf_path, "rb") as pdf_file:
                    self._s3_client.upload_fileobj(
                        pdf_file,
                        self._bucket,
                        s3_key,
                        ExtraArgs={"ContentType": "application/pdf"},
                    )

                self._logger.info("Successfully uploaded PDF to S3: %s", s3_key)
                return {
                    "statusCode": 200,
                    "headers": {"Content-Type": "application/json"},
                    "body": json.dumps(
                        {
                            "session_id": session_id,
                            "filename": pdf_filename,
                            "message": "Conversion successful",
                        }
                    ),
                }
            finally:
                try:
                    os.unlink(tmp_pdf_path)
                except Exception:
                    pass

        except Exception as exc:  # pragma: no cover - defensive
            self._logger.error("Error in handle_convert: %s", exc)
            return self._server_error(f"Internal server error: {exc}")

    # Internal helpers ---------------------------------------------------

    def _parse_multipart(self, body: bytes, content_type: str) -> MultipartMap:
        self._logger.info("About to parse multipart data...")
        try:
            files = self._multipart_parser.parse(body, content_type)
        except Exception as exc:
            self._logger.error("Failed to parse multipart data: %s", exc)
            import traceback

            self._logger.error("Multipart parsing stack trace: %s", traceback.format_exc())
            raise ConversionInputError(f"Failed to parse upload data: {exc}") from exc

        self._logger.info("Multipart parsing completed. Found keys: %s", list((files or {}).keys()))
        return files or {}

    def _select_uploaded_email(self, files: MultipartMap) -> Optional[SelectedUpload]:
        self._logger.info("Looking for uploaded file in parsed data...")
        candidates: list[Tuple[str, str, str, UploadedFile]] = []
        for key, value in files.items():
            if isinstance(value, dict) and "content" in value:
                content_type = str(value.get("content_type", "")).lower()
                filename = str(value.get("filename", ""))
                candidates.append((key, filename, content_type, value))
                try:
                    size = len(value.get("content") or b"")
                except Exception:
                    size = -1
                self._logger.info(
                    "Found candidate part key='%s', filename='%s', content_type='%s', size=%s",
                    key,
                    filename,
                    content_type,
                    size,
                )

        selected = self._prioritize_candidate(candidates)
        if not selected:
            if "file" in files and isinstance(files["file"], dict):
                self._logger.info("Selecting 'file' key as fallback")
                selected = files["file"]
            elif "files" in files and isinstance(files["files"], dict):
                self._logger.info("Selecting 'files' key as fallback")
                selected = files["files"]
            elif candidates:
                self._logger.info("Selecting first candidate part '%s' as fallback", candidates[0][0])
                selected = candidates[0][3]

        if not selected or not isinstance(selected, dict) or "content" not in selected:
            self._logger.error("No file found in upload. Available keys: %s", list(files.keys()))
            preview = str(files)
            self._logger.error("Files content preview: %s...", preview[:500])
            return None

        filename = selected.get("filename", "upload.eml")
        content = selected["content"]
        self._logger.info(
            "File data extracted: filename='%s', content_type='%s', content_size=%s",
            filename,
            selected.get("content_type", "unknown"),
            len(content) if content else 0,
        )

        ext = os.path.splitext(filename)[1].lower()
        if ext not in (".eml", ".msg"):
            self._logger.error("Invalid file type. Filename: %s", filename)
            raise ConversionInputError("File must be a .eml or .msg file")

        if ext == ".msg":
            try:
                self._logger.info("Detected .msg file - converting to EML bytes and extracting attachments...")
                eml_bytes, attachments = self._email_converter.convert_msg_bytes_to_eml_bytes_with_attachments(content)
                self._logger.info(".msg converted to EML: %s bytes", len(eml_bytes) if eml_bytes else 0)
                self._logger.info("Extracted %s attachments from .msg file", len(attachments))
            except Exception as exc:
                self._logger.error(".msg conversion failed: %s", exc)
                raise ConversionInputError("Failed to convert .msg to .eml")
        else:
            eml_bytes = content
            attachments = []

        return SelectedUpload(
            filename=filename,
            content=content,
            content_type=str(selected.get("content_type", "unknown")),
            attachments=attachments,
            eml_bytes=eml_bytes,
        )

    def _prioritize_candidate(
        self, candidates: Iterable[Tuple[str, str, str, UploadedFile]]
    ) -> Optional[UploadedFile]:
        for key, filename, content_type, candidate in candidates:
            if content_type == "message/rfc822":
                self._logger.info("Selecting message/rfc822 part from key '%s'", key)
                return candidate
        for key, filename, content_type, candidate in candidates:
            if filename.lower().endswith(".eml"):
                self._logger.info("Selecting .eml filename part from key '%s'", key)
                return candidate
        return None

    def _determine_session_id(self, event: Dict[str, Any], headers: Dict[str, Any]) -> str:
        self._logger.info("Generating session ID and filenames...")
        query = event.get("queryStringParameters", {}) or {}
        provided_sid = str(
            (query.get("session_id") or headers.get("x-session-id") or "").strip()
        )
        if provided_sid and re.fullmatch(r"[A-Za-z0-9_\-]{8,100}", provided_sid):
            self._logger.info("Using provided session_id: %s", provided_sid)
            return provided_sid
        session_id = str(uuid.uuid4())
        self._logger.info("Generated new session_id: %s", session_id)
        return session_id

    def _determine_pdf_filename(self, eml_bytes: bytes, original_filename: str) -> str:
        self._logger.info("Deriving PDF filename for %s", original_filename)
        enhanced_base: Optional[str] = None
        try:
            last, first_initial, date_str = extract_sender_name_and_date(eml_bytes, logger=self._logger)
            if last and first_initial and date_str:
                candidate = f"{last}, {first_initial} - {date_str}"
                sanitized = sanitize_filename(candidate, default=None)
                if sanitized:
                    enhanced_base = sanitized
                    self._logger.info("Enhanced filename derived: %s", enhanced_base)
                else:
                    self._logger.info("Candidate filename sanitized to empty; ignoring enhanced name.")
            else:
                self._logger.info("Insufficient data for enhanced filename (need last, first initial, date).")
        except Exception as exc:
            self._logger.warning("Enhanced filename derivation failed: %s", exc)

        if enhanced_base:
            safe_base = enhanced_base
        else:
            safe_base = sanitize_filename(original_filename, default="email")
            if safe_base == "email":
                safe_base = f"email-{uuid.uuid4().hex[:8]}"
        return f"{safe_base}.pdf"

    def _create_temp_pdf_path(self) -> str:
        self._logger.info("Creating temporary file for PDF generation...")
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp_pdf:
            tmp_path = tmp_pdf.name
        self._logger.info("Temporary PDF path created: %s", tmp_path)
        return tmp_path

    def _infer_twemoji_base(self, headers: Dict[str, Any]) -> Optional[str]:
        try:
            proto = headers.get("x-forwarded-proto") or "https"
            host = headers.get("host") or ""
            if host:
                return f"{proto}://{host}/api/twemoji/"
        except Exception:  # pragma: no cover - defensive
            pass
        return None

    # Response helpers ---------------------------------------------------

    @staticmethod
    def _bad_request(message: str) -> Dict[str, Any]:
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": message}),
        }

    @staticmethod
    def _server_error(message: str) -> Dict[str, Any]:
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": message}),
        }


def create_convert_handler(
    logger,
    multipart_parser,
    email_converter,
    convert_eml_to_pdf: Callable[[bytes, str, Optional[str], Optional[list[Any]]], bool],
    s3_client,
    bucket: Optional[str],
) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
    """Factory to build a handler compatible with the Lambda router."""

    handler = ConvertHandler(
        logger=logger,
        multipart_parser=multipart_parser,
        email_converter=email_converter,
        convert_eml_to_pdf=convert_eml_to_pdf,
        s3_client=s3_client,
        bucket=bucket,
    )
    return handler.handle

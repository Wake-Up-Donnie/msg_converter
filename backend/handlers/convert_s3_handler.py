"""Handler for converting files that were uploaded directly to S3."""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from filename_utils import extract_sender_name_and_date, sanitize_filename
from request_parser import RequestParser


class ConvertS3Handler:
    def __init__(
        self,
        logger,
        email_converter,
        convert_eml_to_pdf: Callable[[bytes, str, Optional[str], Optional[List[Any]]], bool],
        s3_client,
        bucket: Optional[str],
    ) -> None:
        self._logger = logger
        self._email_converter = email_converter
        self._convert_eml_to_pdf = convert_eml_to_pdf
        self._s3 = s3_client
        self._bucket = bucket

    def handle(self, event: Dict[str, Any]) -> Dict[str, Any]:
        try:
            self._purge_tmp_directory()

            parser = RequestParser(event)
            data = parser.json() or {}
            keys = data.get("keys") or []
            if not isinstance(keys, list) or not keys:
                return self._bad_request("keys array is required")

            headers = parser.headers
            query = event.get("queryStringParameters", {}) or {}
            provided_sid = str(
                (data.get("session_id") or query.get("session_id") or headers.get("x-session-id") or "").strip()
            )
            if provided_sid and re.fullmatch(r"[A-Za-z0-9_\-]{8,100}", provided_sid):
                session_id = provided_sid
                self._logger.info("Using provided session_id (convert-s3): %s", session_id)
            else:
                session_id = str(uuid.uuid4())
                self._logger.info("Generated new session_id (convert-s3): %s", session_id)

            results: list[Dict[str, Any]] = []
            for key in keys:
                result = self._process_single_key(str(key), session_id)
                results.append(result)

            total = len(keys)
            success_count = sum(1 for r in results if r.get("status") == "success")
            failed_count = total - success_count

            return {
                "statusCode": 200,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps(
                    {
                        "results": results,
                        "total_files": total,
                        "successful_conversions": success_count,
                        "failed_conversions": failed_count,
                        "session_id": session_id if success_count else None,
                    }
                ),
            }
        except Exception as exc:  # pragma: no cover - defensive
            self._logger.error("Error in handle_convert_s3: %s", exc)
            return self._server_error(f"convert-s3 failed: {exc}")

    # Internal helpers ---------------------------------------------------

    def _purge_tmp_directory(self) -> None:
        tmp_path = Path("/tmp")
        for path in tmp_path.glob("*"):
            try:
                if path.is_file() or path.is_symlink():
                    path.unlink()
                else:
                    shutil.rmtree(path, ignore_errors=True)
            except Exception:
                pass

    def _process_single_key(self, s3_key: str, session_id: str) -> Dict[str, Any]:
        original_name = os.path.basename(s3_key)
        base_no_ext = sanitize_filename(original_name, default="email")
        ext = os.path.splitext(original_name)[1].lower()

        try:
            obj = self._s3.get_object(Bucket=self._bucket, Key=s3_key)
            file_bytes = obj["Body"].read()
        except Exception as exc:
            self._logger.error("Failed to download %s: %s", s3_key, exc)
            return self._error_result(original_name, str(exc))

        msg_attachments: List[Any] = []
        if ext == ".msg":
            try:
                eml_source, msg_attachments = self._email_converter.convert_msg_bytes_to_eml_bytes_with_attachments(file_bytes)
                self._logger.info("Extracted %s attachments from %s", len(msg_attachments), s3_key)
            except Exception as exc:
                self._logger.error(".msg conversion failed for %s: %s", s3_key, exc)
                return self._error_result(original_name, "Failed to convert .msg to .eml")
        elif ext == ".eml":
            eml_source = file_bytes
        else:
            return self._error_result(original_name, "Unsupported file type")

        tmp_pdf_path = self._create_temp_file()
        try:
            ok = self._convert_eml_to_pdf(eml_source, tmp_pdf_path, None, msg_attachments or None)
            if not ok or not os.path.exists(tmp_pdf_path) or os.path.getsize(tmp_pdf_path) == 0:
                return self._error_result(original_name, "PDF conversion failed")

            enhanced_base = self._derive_enhanced_filename(eml_source, original_name)
            base_name = enhanced_base or base_no_ext
            if base_name == "email":
                base_name = f"email-{uuid.uuid4().hex[:8]}"

            pdf_filename = f"{base_name}.pdf"
            out_key = f"{session_id}/{pdf_filename}"
            with open(tmp_pdf_path, "rb") as pdf_file:
                self._s3.upload_fileobj(
                    pdf_file,
                    self._bucket,
                    out_key,
                    ExtraArgs={"ContentType": "application/pdf"},
                )

            return {
                "filename": original_name,
                "status": "success",
                "session_id": session_id,
                "pdf_filename": pdf_filename,
            }
        except Exception as exc:
            self._logger.error("convert-s3 failed for key %s: %s", s3_key, exc)
            return self._error_result(original_name, str(exc))
        finally:
            try:
                os.unlink(tmp_pdf_path)
            except Exception:
                pass

    def _create_temp_file(self) -> str:
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp_pdf:
            return tmp_pdf.name

    def _derive_enhanced_filename(self, eml_source: bytes, original_name: str) -> Optional[str]:
        try:
            last, first_initial, date_str = extract_sender_name_and_date(eml_source, logger=self._logger)
            if last and first_initial and date_str:
                candidate = f"{last}, {first_initial} - {date_str}"
                sanitized = sanitize_filename(candidate, default=None)
                if sanitized:
                    self._logger.info("[convert-s3] Enhanced filename derived for %s: %s", original_name, sanitized)
                    return sanitized
        except Exception as exc:
            self._logger.warning("[convert-s3] Enhanced filename derivation failed for %s: %s", original_name, exc)
        return None

    @staticmethod
    def _error_result(filename: str, message: str) -> Dict[str, Any]:
        return {
            "filename": filename,
            "status": "error",
            "message": message,
            "session_id": None,
            "pdf_filename": None,
        }

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


def create_convert_s3_handler(
    logger,
    email_converter,
    convert_eml_to_pdf: Callable[[bytes, str, Optional[str], Optional[List[Any]]], bool],
    s3_client,
    bucket: Optional[str],
):
    handler = ConvertS3Handler(
        logger=logger,
        email_converter=email_converter,
        convert_eml_to_pdf=convert_eml_to_pdf,
        s3_client=s3_client,
        bucket=bucket,
    )
    return handler.handle

"""Handler for bundling all session PDFs into a ZIP archive."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import zipfile
from typing import Any, Dict, Optional


class DownloadAllHandler:
    def __init__(self, logger, s3_client, bucket: Optional[str]) -> None:
        self._logger = logger
        self._s3 = s3_client
        self._bucket = bucket

    def handle(self, event: Dict[str, Any]) -> Dict[str, Any]:
        try:
            session_id = self._extract_session_id(event)
            if not session_id:
                return self._bad_request("Missing session_id")

            pdf_keys = self._list_session_pdfs(session_id)
            if pdf_keys is None:
                return self._server_error("Failed to list session files")
            if not pdf_keys:
                return self._not_found("No PDF files found for session")

            zip_filename = f"converted_pdfs_{session_id}.zip"
            zip_path = os.path.join(tempfile.gettempdir(), zip_filename)

            if not self._write_zip(zip_path, pdf_keys):
                return self._server_error("Failed to create ZIP")

            out_key = f"{session_id}/{zip_filename}"
            upload_error = self._upload_zip(zip_path, out_key, zip_filename)
            if upload_error:
                return upload_error

            presigned_url = self._presign_zip(out_key, zip_filename)
            if presigned_url:
                return {
                    "statusCode": 302,
                    "headers": {"Location": presigned_url, "Cache-Control": "no-store"},
                    "body": "",
                }

            self._logger.error("Failed to presign ZIP URL for %s", out_key)
            return {
                "statusCode": 200,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"key": out_key}),
            }
        except Exception as exc:  # pragma: no cover - defensive
            self._logger.error("Error in handle_download_all: %s", exc)
            return self._server_error(f"Download-all failed: {exc}")
        finally:
            try:
                if "zip_path" in locals() and os.path.exists(zip_path):
                    os.unlink(zip_path)
            except Exception:
                pass

    # Internal helpers ---------------------------------------------------

    def _extract_session_id(self, event: Dict[str, Any]) -> Optional[str]:
        path_params = event.get("pathParameters", {}) or {}
        session_id = path_params.get("session_id")
        if session_id:
            return session_id

        path = event.get("path", "") or ""
        prefix = "/api/download-all/"
        if prefix in path:
            return path.split(prefix, 1)[1].split("/", 1)[0]
        return None

    def _list_session_pdfs(self, session_id: str) -> Optional[list[str]]:
        prefix_key = f"{session_id}/"
        pdf_keys: list[str] = []
        try:
            paginator = self._s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=self._bucket, Prefix=prefix_key):
                for item in page.get("Contents", []) or []:
                    key = item.get("Key", "")
                    if key.lower().endswith(".pdf"):
                        pdf_keys.append(key)
        except Exception as exc:
            self._logger.error("S3 list_objects failed for prefix %s: %s", prefix_key, exc)
            return None
        return pdf_keys

    def _write_zip(self, zip_path: str, pdf_keys: list[str]) -> bool:
        try:
            with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for key in pdf_keys:
                    try:
                        obj = self._s3.get_object(Bucket=self._bucket, Key=key)
                        data = obj["Body"].read()
                        archive.writestr(os.path.basename(key), data)
                    except Exception as exc:
                        self._logger.warning("Skipping key %s due to error: %s", key, exc)
            return True
        except Exception as exc:
            self._logger.error("Failed to create ZIP: %s", exc)
            return False

    def _upload_zip(self, zip_path: str, out_key: str, zip_filename: str) -> Optional[Dict[str, Any]]:
        try:
            with open(zip_path, "rb") as zip_file:
                self._s3.upload_fileobj(
                    zip_file,
                    self._bucket,
                    out_key,
                    ExtraArgs={
                        "ContentType": "application/zip",
                        "ContentDisposition": f'attachment; filename="{zip_filename}"',
                    },
                )
            return None
        except Exception as exc:
            self._logger.error("Failed to upload ZIP to S3: %s", exc)
            return self._stream_zip_fallback(zip_path, zip_filename)

    def _stream_zip_fallback(self, zip_path: str, zip_filename: str) -> Dict[str, Any]:
        try:
            with open(zip_path, "rb") as zip_file:
                data = zip_file.read()
            sha256 = hashlib.sha256(data).hexdigest()
            return {
                "statusCode": 200,
                "headers": {
                    "Content-Type": "application/zip",
                    "Content-Disposition": f'attachment; filename="{zip_filename}"',
                    "Cache-Control": "no-store",
                    "X-Content-SHA256": sha256,
                    "X-Original-Length": str(len(data)),
                },
                "body": base64.b64encode(data).decode("utf-8"),
                "isBase64Encoded": True,
            }
        except Exception as exc:
            self._logger.error("Failed to stream ZIP fallback: %s", exc)
            return self._server_error("Failed to deliver ZIP")

    def _presign_zip(self, out_key: str, zip_filename: str) -> Optional[str]:
        try:
            return self._s3.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self._bucket,
                    "Key": out_key,
                    "ResponseContentType": "application/zip",
                    "ResponseContentDisposition": f'attachment; filename="{zip_filename}"',
                },
                ExpiresIn=300,
            )
        except Exception as exc:
            self._logger.error("Failed to presign ZIP URL: %s", exc)
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
    def _not_found(message: str) -> Dict[str, Any]:
        return {
            "statusCode": 404,
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


def create_download_all_handler(logger, s3_client, bucket: Optional[str]):
    handler = DownloadAllHandler(logger=logger, s3_client=s3_client, bucket=bucket)
    return handler.handle

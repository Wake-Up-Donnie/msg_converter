"""Handler for generating presigned S3 upload URLs."""

from __future__ import annotations

import json
import os
import uuid
from typing import Any, Dict, Optional

from filename_utils import sanitize_filename
from request_parser import RequestParser


class UploadUrlHandler:
    def __init__(self, logger, s3_client, bucket: Optional[str]) -> None:
        self._logger = logger
        self._s3 = s3_client
        self._bucket = bucket

    def handle(self, event: Dict[str, Any]) -> Dict[str, Any]:
        try:
            parser = RequestParser(event)
            data = parser.json() or {}

            filename = str(data.get("filename") or "").strip()
            content_type = str(data.get("content_type") or "application/octet-stream")

            if not filename:
                return self._bad_request("filename is required")

            base = sanitize_filename(filename, default="upload")
            ext = os.path.splitext(filename)[1].lower()
            if ext not in (".eml", ".msg"):
                return self._bad_request("File must be a .eml or .msg file")

            safe_filename = f"{base}{ext}"
            upload_id = str(uuid.uuid4())
            s3_key = f"uploads/{upload_id}/{safe_filename}"

            url = self._s3.generate_presigned_url(
                "put_object",
                Params={"Bucket": self._bucket, "Key": s3_key, "ContentType": content_type},
                ExpiresIn=900,
            )

            return {
                "statusCode": 200,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"url": url, "key": s3_key}),
            }
        except Exception as exc:  # pragma: no cover - defensive
            self._logger.error("Error in handle_upload_url: %s", exc)
            return self._server_error(f"Failed to generate upload URL: {exc}")

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


def create_upload_url_handler(logger, s3_client, bucket: Optional[str]):
    handler = UploadUrlHandler(logger=logger, s3_client=s3_client, bucket=bucket)
    return handler.handle

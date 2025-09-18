"""Handler for retrieving individual converted PDFs from S3."""

from __future__ import annotations

import base64
import hashlib
import json
import urllib.parse
from typing import Any, Dict, Optional


class DownloadHandler:
    def __init__(self, logger, s3_client, bucket: Optional[str]) -> None:
        self._logger = logger
        self._s3 = s3_client
        self._bucket = bucket

    def handle(self, event: Dict[str, Any]) -> Dict[str, Any]:
        try:
            session_id, filename = self._extract_identifiers(event)
            if not session_id or not filename:
                return self._bad_request("Missing session_id or filename")

            s3_key = f"{session_id}/{filename}"
            self._logger.info("Attempting to download: %s", s3_key)

            try:
                response = self._s3.get_object(Bucket=self._bucket, Key=s3_key)
                file_content = response["Body"].read()
            except self._s3.exceptions.NoSuchKey:
                self._logger.error("File not found in S3: %s", s3_key)
                return self._not_found("File not found")

            if not self._should_stream(event):
                presigned_url = self._create_presigned_url(s3_key, filename)
                if presigned_url:
                    return {
                        "statusCode": 302,
                        "headers": {"Location": presigned_url, "Cache-Control": "no-store"},
                        "body": "",
                    }

            sha256 = hashlib.sha256(file_content).hexdigest()
            return {
                "statusCode": 200,
                "headers": {
                    "Content-Type": "application/pdf",
                    "Content-Disposition": f'attachment; filename="{filename}"',
                    "Content-Transfer-Encoding": "binary",
                    "Cache-Control": "no-store",
                    "X-Content-SHA256": sha256,
                    "X-Original-Length": str(len(file_content)),
                    "Accept-Ranges": "bytes",
                },
                "body": base64.b64encode(file_content).decode("utf-8"),
                "isBase64Encoded": True,
            }
        except Exception as exc:  # pragma: no cover - defensive
            self._logger.error("Error in handle_download: %s", exc)
            return self._server_error(f"Download failed: {exc}")

    # Internal helpers ---------------------------------------------------

    def _extract_identifiers(self, event: Dict[str, Any]) -> tuple[Optional[str], Optional[str]]:
        path_params = event.get("pathParameters", {}) or {}
        session_id = path_params.get("session_id")
        filename = path_params.get("filename")

        if not filename:
            return session_id, None

        filename = urllib.parse.unquote(filename)
        if "?" in filename:
            filename = filename.split("?", 1)[0]
        return session_id, filename

    def _should_stream(self, event: Dict[str, Any]) -> bool:
        query_params = event.get("queryStringParameters", {}) or {}
        flag = str(query_params.get("stream", "")).lower()
        return flag in {"1", "true", "yes"}

    def _create_presigned_url(self, s3_key: str, filename: str) -> Optional[str]:
        try:
            return self._s3.generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self._bucket,
                    "Key": s3_key,
                    "ResponseContentType": "application/pdf",
                    "ResponseContentDisposition": f'attachment; filename="{filename}"',
                },
                ExpiresIn=300,
            )
        except Exception as exc:
            self._logger.error("Failed to generate presigned URL: %s", exc)
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


def create_download_handler(logger, s3_client, bucket: Optional[str]):
    handler = DownloadHandler(logger=logger, s3_client=s3_client, bucket=bucket)
    return handler.handle

import base64
import json
from typing import Any, Dict


class RequestParser:
    """Utility for working with API Gateway events."""

    def __init__(self, event: Dict[str, Any]):
        self.event = event or {}
        self.headers = self._lower_headers(self.event.get("headers", {}))
        self.body = self._get_body_bytes(self.event)

    @staticmethod
    def _lower_headers(headers: Dict[str, Any]) -> Dict[str, str]:
        return {str(k).lower(): v for k, v in (headers or {}).items()}

    @staticmethod
    def _get_body_bytes(event: Dict[str, Any]) -> bytes:
        body = event.get("body", b"")
        if event.get("isBase64Encoded"):
            if isinstance(body, str):
                return base64.b64decode(body)
            return base64.b64decode(body or b"")
        if isinstance(body, str):
            return body.encode("utf-8", errors="ignore")
        return body or b""

    def json(self) -> Dict[str, Any]:
        """Return parsed JSON body if present."""
        try:
            return json.loads((self.body or b"").decode("utf-8", "ignore") or "{}")
        except Exception:
            return {}

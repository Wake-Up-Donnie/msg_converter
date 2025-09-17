"""Handler responsible for the lightweight auth check endpoint."""

from __future__ import annotations

import json
import os
from typing import Any, Dict

from request_parser import RequestParser


class AuthCheckHandler:
    def __init__(self, logger) -> None:
        self._logger = logger

    def handle(self, event: Dict[str, Any]) -> Dict[str, Any]:
        app_password = os.environ.get("APP_PASSWORD")
        if not app_password:
            return self._json_response({"ok": True, "auth": "not-required"})

        parser = RequestParser(event)
        headers = parser.headers
        query_params = event.get("queryStringParameters", {}) or {}

        provided_password = headers.get("x-app-password") or query_params.get("auth")
        if provided_password == app_password:
            return self._json_response({"ok": True})
        return {
            "statusCode": 401,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"ok": False}),
        }

    @staticmethod
    def _json_response(payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(payload),
        }


def create_auth_check_handler(logger):
    handler = AuthCheckHandler(logger=logger)
    return handler.handle

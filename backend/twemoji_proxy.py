"""Serve Twemoji SVG assets via the Lambda backend."""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Protocol


class LoggerLike(Protocol):
    def info(self, msg: str, *args, **kwargs) -> None: ...
    def warning(self, msg: str, *args, **kwargs) -> None: ...
    def error(self, msg: str, *args, **kwargs) -> None: ...


def handle_twemoji(event, logger: LoggerLike):
    """Serve Twemoji SVGs via backend proxy to ensure emoji rendering in PDFs."""
    try:
        path = event.get('path', '') or ''
        filename = path.rsplit('/', 1)[-1]
        safe_name = os.path.basename(filename or '')
        if not safe_name.lower().endswith('.svg'):
            return {
                'statusCode': 404,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Not found'})
            }

        cache_dir = '/tmp/twemoji_cache'
        try:
            os.makedirs(cache_dir, exist_ok=True)
        except Exception:
            pass
        local_path = os.path.join(cache_dir, safe_name)

        svg_bytes = None
        try:
            if os.path.exists(local_path):
                with open(local_path, 'rb') as f:
                    svg_bytes = f.read()
        except Exception:
            svg_bytes = None

        if svg_bytes is None:
            cdn_url = f'https://cdnjs.cloudflare.com/ajax/libs/twemoji/14.0.2/svg/{safe_name}'
            with urllib.request.urlopen(cdn_url, timeout=10) as resp:
                svg_bytes = resp.read()
            try:
                with open(local_path, 'wb') as f:
                    f.write(svg_bytes)
            except Exception:
                pass

        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'image/svg+xml',
                'Cache-Control': 'public, max-age=31536000, immutable'
            },
            'body': svg_bytes.decode('utf-8', errors='replace')
        }
    except Exception as e:
        logger.error(f"Twemoji proxy error: {e}")
        return {
            'statusCode': 502,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'error': 'Emoji asset unavailable'})
        }


__all__ = ['handle_twemoji']

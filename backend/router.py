import os
import json
import logging
from typing import Callable, Dict, Any, Tuple

class LambdaRouter:
    """Simple router for API Gateway events."""

    def __init__(self, verify_browser: Callable[[], bool]):
        self.verify_browser = verify_browser
        self.logger = logging.getLogger(__name__)
        self.cors_headers = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type, X-App-Password, Authorization',
            'Access-Control-Allow-Methods': 'OPTIONS, POST, GET'
        }

    def handle(self, event: Dict[str, Any], handlers: Dict[Tuple[str, str] | str, Callable[[Dict[str, Any]], Dict[str, Any]]]) -> Dict[str, Any]:
        try:
            import psutil
            memory_info = psutil.virtual_memory()
            self.logger.info(f"Available memory: {memory_info.available / 1024 / 1024:.1f} MB")
            self.logger.info(f"PLAYWRIGHT_BROWSERS_PATH env var: {os.environ.get('PLAYWRIGHT_BROWSERS_PATH', 'Not set')}")

            path = event.get('path', '') or ''
            method = event.get('httpMethod', '') or ''

            if path == '/api/convert' and method == 'POST':
                if not self.verify_browser():
                    self.logger.error("Playwright browser verification failed - using fallback PDF generation")

            if method == 'OPTIONS':
                return {'statusCode': 200, 'headers': self.cors_headers, 'body': ''}

            self.logger.info(f"Processing request: {method} {path}")

            if path.startswith('/api/download-all/') and method == 'GET':
                response = handlers['download_all'](event)
            elif path.startswith('/api/download/') and method == 'GET':
                response = handlers['download'](event)
            elif path.startswith('/api/twemoji/') and method == 'GET':
                response = handlers['twemoji'](event)
            else:
                func = handlers.get((method, path))
                if func:
                    response = func(event)
                else:
                    response = {
                        'statusCode': 404,
                        'headers': {'Content-Type': 'application/json'},
                        'body': json.dumps({'error': 'Not found'})
                    }

            if 'headers' not in response:
                response['headers'] = {}
            response['headers'].update(self.cors_headers)
            return response

        except Exception as e:
            self.logger.error(f"Lambda handler error: {str(e)}")
            return {
                'statusCode': 500,
                'headers': {'Content-Type': 'application/json', **self.cors_headers},
                'body': json.dumps({'error': f'Internal server error: {str(e)}'})
            }

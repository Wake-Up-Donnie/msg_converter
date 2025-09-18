import logging
import os


LOG_FORMAT = '%(asctime)s %(levelname)s [%(name)s] %(message)s'


def configure_logging() -> None:
    """Configure logging consistently for Lambda and local execution."""
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    root = logging.getLogger()

    try:
        root.setLevel(getattr(logging, log_level, logging.INFO))
    except Exception:
        root.setLevel(logging.INFO)

    if not root.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(LOG_FORMAT))
        root.addHandler(handler)

    logging.getLogger('boto3').setLevel(logging.WARNING)
    logging.getLogger('botocore').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)

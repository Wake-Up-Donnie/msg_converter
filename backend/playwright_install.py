"""Utility helpers for ensuring Playwright browsers are available."""

from __future__ import annotations

import logging
import subprocess
import sys
from typing import Iterable

# Known fragments that indicate the Playwright browser executable is missing.
_MISSING_BROWSER_MARKERS: tuple[str, ...] = (
    "executable doesn't exist at",
    "playwright install",
    "download new browsers",
)


def is_missing_browser_error(exc: BaseException | None) -> bool:
    """Return ``True`` when *exc* suggests the Playwright browser is missing."""
    if exc is None:
        return False
    message = str(exc) or ""
    lowered = message.lower()
    return any(marker in lowered for marker in _MISSING_BROWSER_MARKERS)


def _run_install_command(command: Iterable[str], logger: logging.Logger | None) -> bool:
    """Execute *command* and report success, capturing stdout/stderr for logs."""
    try:
        completed = subprocess.run(
            list(command),
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        if logger:
            logger.debug("Playwright CLI not found when running %s", " ".join(command))
        return False
    except subprocess.CalledProcessError as err:
        if logger:
            stderr = (err.stderr or err.stdout or str(err)).strip()
            logger.error("Playwright install command failed (%s): %s", " ".join(command), stderr)
        return False

    if logger:
        stdout = (completed.stdout or "").strip()
        stderr = (completed.stderr or "").strip()
        logger.info("Successfully executed '%s'", " ".join(command))
        if stdout:
            logger.debug(stdout)
        if stderr:
            logger.debug(stderr)
    return True


def ensure_playwright_browsers_installed(
    logger: logging.Logger | None = None,
    browser: str = "chromium",
) -> bool:
    """Ensure the Playwright *browser* binaries are installed.

    Returns ``True`` if the installation command completed successfully.
    """
    commands = [
        ("playwright", "install", "--with-deps", browser),
        ("playwright", "install", browser),
        (sys.executable, "-m", "playwright", "install", "--with-deps", browser),
        (sys.executable, "-m", "playwright", "install", browser),
    ]

    for command in commands:
        if _run_install_command(command, logger):
            return True

    if logger:
        logger.error("Unable to install Playwright %s browser automatically", browser)
    return False

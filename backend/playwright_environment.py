"""Utilities for managing Playwright's runtime environment in Lambda."""
from __future__ import annotations

import glob
import os
import shutil
from typing import Protocol

from playwright.sync_api import sync_playwright


class LoggerLike(Protocol):
    def info(self, msg: str, *args, **kwargs) -> None: ...
    def warning(self, msg: str, *args, **kwargs) -> None: ...
    def error(self, msg: str, *args, **kwargs) -> None: ...


def cleanup_browser_processes(logger: LoggerLike) -> None:
    """Clean up lingering Chromium processes and temporary artifacts."""
    try:
        import psutil

        try:
            for proc in psutil.process_iter(["pid", "name", "cmdline"]):
                try:
                    name = proc.info.get("name") or ""
                    cmdline = " ".join(proc.info.get("cmdline") or [])
                    if name and any(b in name.lower() for b in ["chrome", "chromium"]):
                        logger.info(
                            "Terminating browser process: %s (PID: %s)",
                            name,
                            proc.info.get("pid"),
                        )
                        proc.terminate()
                        proc.wait(timeout=3)
                    elif cmdline and any(
                        b in cmdline.lower() for b in ["chrome", "chromium"]
                    ):
                        logger.info(
                            "Terminating browser process by cmdline: PID %s",
                            proc.info.get("pid"),
                        )
                        proc.terminate()
                        proc.wait(timeout=3)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
                    pass
        except Exception as e:
            logger.warning(f"Failed to kill browser processes: {e}")

        for pattern in ("/tmp/.playwright", "/tmp/playwright-*"):
            try:
                for path in glob.glob(pattern):
                    if os.path.isdir(path):
                        shutil.rmtree(path, ignore_errors=True)
                    elif os.path.isfile(path):
                        os.unlink(path)
            except Exception as e:
                logger.warning(f"Failed to clean temp files {pattern}: {e}")
    except Exception as e:
        logger.warning(f"Browser cleanup failed: {e}")


def verify_playwright_installation(logger: LoggerLike) -> bool:
    """Verify that Playwright browsers are properly installed."""
    try:
        with sync_playwright() as p:
            browser_path = p.chromium.executable_path
            logger.info(f"Playwright browser executable found at: {browser_path}")
            if os.path.exists(browser_path):
                logger.info("Playwright browser verification: PASSED")
                return True
            logger.error(f"Playwright browser executable not found at: {browser_path}")
            return False
    except Exception as e:
        logger.error(f"Playwright browser verification failed: {e}")
        return False


__all__ = ["cleanup_browser_processes", "verify_playwright_installation"]

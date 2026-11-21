"""
Playwright/Chromium browser dependency manager.
Handles detection, consent flow hooks, and installation.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable, Optional


def _get_default_browser_dir() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or Path.home() / "AppData" / "Local")
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "WebRipper" / "browsers"


class BrowserManager:
    """Manages the Playwright Chromium browser lifecycle."""

    BROWSER_DIR = _get_default_browser_dir()
    _MARKER_FILE = "chromium_installed.marker"

    def __init__(self):
        self.BROWSER_DIR.mkdir(parents=True, exist_ok=True)
        # Set env so Playwright uses our managed location if not already overridden
        if "PLAYWRIGHT_BROWSERS_PATH" not in os.environ:
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(self.BROWSER_DIR)

    def is_chromium_installed(self) -> bool:
        """Check whether Playwright Chromium is available."""
        exe = self.get_browser_path()
        return exe is not None and exe.is_file()

    def get_install_size_estimate(self) -> str:
        """Return estimated download size for user consent."""
        return "~180 MB"

    def install_chromium(
        self, progress_callback: Optional[Callable[[str], None]] = None
    ) -> bool:
        """
        Install Playwright Chromium browser.

        Args:
            progress_callback: Called with status lines during install.

        Returns:
            True if installation succeeded, False otherwise.
        """
        if progress_callback:
            progress_callback("Preparing Chromium download...")

        try:
            env = os.environ.copy()
            env["PLAYWRIGHT_BROWSERS_PATH"] = str(self.BROWSER_DIR)

            # Find the playwright executable or python launcher
            if getattr(sys, "frozen", False):
                py_bin = shutil.which("python") or shutil.which("python3")
                if not py_bin:
                    if progress_callback:
                        progress_callback("System Python not found for Playwright install.")
                    return False
                cmd = [py_bin, "-m", "playwright", "install", "chromium"]
            else:
                cmd = [sys.executable, "-m", "playwright", "install", "chromium"]

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=env,
                creationflags=subprocess.CREATE_NO_WINDOW
                if sys.platform == "win32"
                else 0,
            )

            for line in iter(process.stdout.readline, ""):
                line = line.strip()
                if line and progress_callback:
                    progress_callback(line)

            process.wait()

            if process.returncode == 0:
                # Write marker file
                marker = self.BROWSER_DIR / self._MARKER_FILE
                marker.write_text("installed")
                if progress_callback:
                    progress_callback("Chromium installed successfully.")
                return True
            else:
                if progress_callback:
                    progress_callback(
                        f"Installation failed (exit code {process.returncode})."
                    )
                return False

        except FileNotFoundError:
            if progress_callback:
                progress_callback(
                    "Playwright not found. Install it with: pip install playwright"
                )
            return False
        except Exception as e:
            if progress_callback:
                progress_callback(f"Installation error: {e}")
            return False

    def get_browser_path(self) -> Optional[Path]:
        """Return the path to the installed Chromium executable binary, or None."""
        if sys.platform == "win32":
            exe_names = ["chrome.exe"]
        elif sys.platform == "darwin":
            exe_names = ["Chromium", "chrome"]
        else:
            exe_names = ["chrome", "chromium"]

        # Check managed directory
        chromium_dirs = sorted(self.BROWSER_DIR.glob("chromium-*"), reverse=True)
        for cdir in chromium_dirs:
            for name in exe_names:
                for p in cdir.rglob(name):
                    if p.is_file():
                        return p

        # Check default global Playwright paths if managed directory doesn't have it
        default_pw_paths = []
        if sys.platform == "win32":
            local_appdata = os.environ.get("LOCALAPPDATA")
            if local_appdata:
                default_pw_paths.append(Path(local_appdata) / "ms-playwright")
        elif sys.platform == "darwin":
            default_pw_paths.append(Path.home() / "Library" / "Caches" / "ms-playwright")
        else:
            default_pw_paths.append(Path.home() / ".cache" / "ms-playwright")

        for pw_dir in default_pw_paths:
            if pw_dir.is_dir():
                for name in exe_names:
                    for p in pw_dir.rglob(name):
                        if p.is_file():
                            return p

        return None

    def get_browser_env(self) -> dict:
        """Return environment variables needed for Playwright to find browsers."""
        return {"PLAYWRIGHT_BROWSERS_PATH": str(self.BROWSER_DIR)}

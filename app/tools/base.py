"""
Base tool wrapper and utility classes for external tool integration.

Provides BaseTool ABC, subprocess helpers, download/extract helpers,
and the tools directory management.
"""

from __future__ import annotations

import io
import os
import platform
import shutil
import subprocess
import zipfile
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Callable, Dict, List, Optional
from urllib.request import urlopen, Request

from ..models import Finding, Severity


def get_tools_dir() -> Path:
    """Return %APPDATA%/WebRipper/tools/ directory."""
    appdata = os.environ.get("APPDATA", os.path.expanduser("~"))
    d = Path(appdata) / "WebRipper" / "tools"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _download_file(
    url: str, dest: Path,
    progress_cb: Optional[Callable[[str], None]] = None,
) -> bool:
    """Download a file from URL to dest path streaming in chunks. Returns True on success."""
    cb = progress_cb or (lambda s: None)
    try:
        cb(f"Downloading {dest.name}...")
        req = Request(url, headers={"User-Agent": "WebRipper-Recon/5.0"})
        dest.parent.mkdir(parents=True, exist_ok=True)
        total_bytes = 0
        with urlopen(req, timeout=90) as resp, open(dest, "wb") as f:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                f.write(chunk)
                total_bytes += len(chunk)
        cb(f"Downloaded {dest.name} ({total_bytes} bytes)")
        return True
    except Exception as exc:
        cb(f"Download failed: {exc}")
        return False


def _extract_zip(zip_path: Path, dest_dir: Path) -> bool:
    """Extract a zip archive to dest_dir with Zip Slip protection. Returns True on success."""
    try:
        dest_path = dest_dir.resolve()
        dest_path.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(str(zip_path), "r") as zf:
            for member in zf.infolist():
                member_dest = (dest_path / member.filename).resolve()
                if not member_dest.is_relative_to(dest_path):
                    raise RuntimeError(f"Zip Slip attempt detected: {member.filename}")
            zf.extractall(str(dest_path))
        return True
    except Exception:
        return False


def _extract_tar(tar_path: Path, dest_dir: Path) -> bool:
    """Extract a tar archive to dest_dir with Tar Slip protection. Returns True on success."""
    import tarfile
    try:
        dest_path = dest_dir.resolve()
        dest_path.mkdir(parents=True, exist_ok=True)
        with tarfile.open(str(tar_path), "r:*") as tf:
            for member in tf.getmembers():
                member_dest = (dest_path / member.name).resolve()
                if not member_dest.is_relative_to(dest_path):
                    raise RuntimeError(f"Tar Slip attempt detected: {member.name}")
                if member.issym() or member.islnk():
                    link_dest = (dest_path / member.linkname).resolve()
                    if not link_dest.is_relative_to(dest_path):
                        raise RuntimeError(f"Tar Slip symlink attempt detected: {member.linkname}")
            if hasattr(tarfile, "data_filter"):
                tf.extractall(str(dest_path), filter="data")
            else:
                tf.extractall(str(dest_path))
        return True
    except Exception:
        return False


class BaseTool(ABC):
    """Abstract base class for external tool wrappers."""

    TOOL_NAME: str = ""
    DISPLAY_NAME: str = ""
    INSTALL_SIZE: str = ""
    INSTALLABLE: bool = False

    def __init__(self) -> None:
        self._tools_dir = get_tools_dir()

    @abstractmethod
    def is_installed(self) -> bool:
        """Check if the tool is available (PATH or tools_dir)."""
        ...

    @abstractmethod
    def get_version(self) -> str:
        """Return the installed version string."""
        ...

    def get_path(self) -> Optional[str]:
        """Return path to the tool executable, or None if not found."""
        # Check tools_dir first
        local = self._tools_dir / self.TOOL_NAME
        if local.is_file():
            return str(local)
        local_exe = self._tools_dir / f"{self.TOOL_NAME}.exe"
        if local_exe.is_file():
            return str(local_exe)
        # Check subdirectories
        if self._tools_dir.is_dir():
            for sub in self._tools_dir.iterdir():
                if sub.is_dir():
                    for candidate in (sub / self.TOOL_NAME, sub / f"{self.TOOL_NAME}.exe"):
                        if candidate.is_file():
                            return str(candidate)
        # Check system PATH
        which = shutil.which(self.TOOL_NAME)
        return which

    def install(self, progress_cb: Optional[Callable[[str], None]] = None) -> bool:
        """Download and install the tool. Override in subclasses."""
        return False

    @abstractmethod
    def run(self, target: str, output_dir: str, timeout: int = 120,
            progress_cb: Optional[Callable[[str], None]] = None) -> List[Finding]:
        """Run the tool and return findings."""
        ...

    @abstractmethod
    def generate_command(self, target: str) -> str:
        """Return the manual command string for copy-paste."""
        ...

    def _run_subprocess(
        self, cmd: List[str], timeout: int = 120,
        cwd: Optional[str] = None,
    ) -> subprocess.CompletedProcess:
        """Run a subprocess with timeout and capture output."""
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            shell=False,
            creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0,
        )

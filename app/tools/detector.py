"""
Tool detector — auto-detect installed security tools and manage installation.

Scans both system PATH and %APPDATA%/WebRipper/tools/ for known tools.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Callable, Dict, List, Optional
from urllib.request import urlopen, Request

from ..models import ToolStatus
from .base import get_tools_dir, _download_file, _extract_zip


# ---------------------------------------------------------------------------
# Tool definitions: name, detection command, installable, size, download logic
# ---------------------------------------------------------------------------

_TOOL_DEFS = {
    "nmap": {
        "display": "nmap", "check_args": ["--version"],
        "installable": False, "size": "~25MB",
        "url": "https://nmap.org/download.html",
        "note": "Requires installer (Npcap driver)",
    },
    "nikto": {
        "display": "nikto", "check_args": ["-Version"],
        "installable": False, "size": "~5MB",
        "url": "https://github.com/sullo/nikto",
        "note": "Requires Perl runtime",
    },
    "sqlmap": {
        "display": "sqlmap", "check_args": ["--version"],
        "installable": True, "size": "~15MB",
        "url": "https://github.com/sqlmapproject/sqlmap/archive/refs/heads/master.zip",
        "install_type": "zip_python",
    },
    "gobuster": {
        "display": "gobuster", "check_args": ["version"],
        "installable": True, "size": "~8MB",
        "url": "https://github.com/OJ/gobuster/releases/latest",
        "install_type": "github_release",
        "asset_pattern": "windows" if platform.system() == "Windows" else "linux",
    },
    "nuclei": {
        "display": "nuclei", "check_args": ["-version"],
        "installable": True, "size": "~30MB",
        "url": "https://github.com/projectdiscovery/nuclei/releases/latest",
        "install_type": "github_release",
        "asset_pattern": "windows" if platform.system() == "Windows" else "linux",
    },
    "sslscan": {
        "display": "sslscan", "check_args": ["--version"],
        "installable": True, "size": "~2MB",
        "url": "https://github.com/rbsec/sslscan/releases/latest",
        "install_type": "github_release",
        "asset_pattern": "win" if platform.system() == "Windows" else "linux",
    },
    "httpx": {
        "display": "httpx", "check_args": ["-version"],
        "installable": True, "size": "~15MB",
        "url": "https://github.com/projectdiscovery/httpx/releases/latest",
        "install_type": "github_release",
        "asset_pattern": "windows" if platform.system() == "Windows" else "linux",
    },
    "subfinder": {
        "display": "subfinder", "check_args": ["-version"],
        "installable": True, "size": "~15MB",
        "url": "https://github.com/projectdiscovery/subfinder/releases/latest",
        "install_type": "github_release",
        "asset_pattern": "windows" if platform.system() == "Windows" else "linux",
    },
    "burpsuite": {
        "display": "Burp Suite", "check_args": [],
        "installable": True, "size": "~300MB",
        "url": "https://portswigger.net",
        "install_type": "burp_custom",
    },
    "wpscan": {
        "display": "wpscan", "check_args": ["--version"],
        "installable": False, "size": "~50MB",
        "url": "https://wpscan.com",
        "note": "Requires Ruby runtime",
    },
    "whatweb": {
        "display": "whatweb", "check_args": ["--version"],
        "installable": False, "size": "~10MB",
        "url": "https://github.com/urbanadventurer/WhatWeb",
        "note": "Requires Ruby runtime",
    },
}


def _find_tool(name: str) -> Optional[str]:
    """Find a tool executable in PATH or tools dir."""
    if name in ("burp", "burpsuite"):
        from .burp import BurpManager
        burp_info = BurpManager().detect_burp()
        if burp_info.get("installed") and burp_info.get("path"):
            return burp_info["path"]

    if name == "nmap":
        from .installer import COMMON_NMAP_PATHS
        which = shutil.which("nmap")
        if which:
            return which
        for p in COMMON_NMAP_PATHS:
            if os.path.isfile(p):
                return p
        tools_dir = get_tools_dir()
        for cand in [tools_dir / "nmap" / "nmap.exe", tools_dir / "nmap" / "nmap"]:
            if cand.is_file():
                return str(cand)

    tools_dir = get_tools_dir()
    is_win = platform.system() == "Windows"
    exts = [".exe", ""] if is_win else [""]

    # Special case for Python/Perl scripts
    script_candidates = []
    if name == "sqlmap":
        script_candidates.extend(["sqlmap.py", "sqlmap-master/sqlmap.py"])
    elif name == "nikto":
        script_candidates.extend(["nikto.pl", "program/nikto.pl"])

    # 1. Check tools_dir root & direct subdir
    for ext in exts:
        for cand in [tools_dir / f"{name}{ext}", tools_dir / name / f"{name}{ext}"]:
            if cand.is_file():
                return str(cand)

    for sc in script_candidates:
        cand = tools_dir / name / sc
        if cand.is_file():
            return str(cand)
        cand_root = tools_dir / sc
        if cand_root.is_file():
            return str(cand_root)

    # 2. Walk one level of subdirs in tools_dir
    if tools_dir.is_dir():
        for sub in tools_dir.iterdir():
            if sub.is_dir():
                for ext in exts:
                    cand = sub / f"{name}{ext}"
                    if cand.is_file():
                        return str(cand)
                for sc in script_candidates:
                    cand = sub / sc
                    if cand.is_file():
                        return str(cand)

    # 3. Check common Windows installer paths (e.g. Nmap and Burp)
    if is_win:
        prog_files = [
            os.environ.get("ProgramFiles", r"C:\Program Files"),
            os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
            os.environ.get("LOCALAPPDATA", r"C:\Users\Default\AppData\Local"),
        ]
        if name == "nmap":
            for pf in prog_files:
                cand = Path(pf) / "Nmap" / "nmap.exe"
                if cand.is_file():
                    return str(cand)
        elif name in ("burp", "burpsuite"):
            for pf in prog_files:
                for cand in [
                    Path(pf) / "BurpSuitePro" / "BurpSuitePro.exe",
                    Path(pf) / "BurpSuiteCommunity" / "BurpSuiteCommunity.exe",
                    Path(pf) / "PortSwigger" / "BurpSuiteCommunity" / "BurpSuiteCommunity.exe",
                    Path(pf) / "PortSwigger" / "BurpSuitePro" / "BurpSuitePro.exe",
                ]:
                    if cand.is_file():
                        return str(cand)

    # 4. System PATH
    return shutil.which(name)


def _get_version(tool_path: str, check_args: List[str]) -> str:
    """Try to get version string from tool."""
    if not check_args:
        if tool_path.endswith(".jar"):
            return "Community (Portable JAR)"
        return "installed"
    try:
        flags = subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0
        cmd = [tool_path] + check_args
        if tool_path.endswith(".py"):
            cmd = [sys.executable, tool_path] + check_args
        elif tool_path.endswith(".pl"):
            perl = shutil.which("perl")
            if perl:
                cmd = [perl, tool_path] + check_args
            else:
                return "installed (perl required)"

        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=10,
            creationflags=flags, shell=False,
            stdin=subprocess.DEVNULL, encoding="utf-8", errors="replace",
        )
        output = (result.stdout + result.stderr).strip()
        # Clean ANSI color escape sequences
        clean_output = re.sub(r"\x1b\[[0-9;]*[mGKF]", "", output)
        m = re.search(r"(?:version|v)?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[\w.]+)?)\b", clean_output, re.IGNORECASE)
        return m.group(1) if m else "installed"
    except Exception:
        return ""


def detect_all_tools() -> List[ToolStatus]:
    """Detect all known tools and return their status."""
    results = []
    for name, info in _TOOL_DEFS.items():
        path = _find_tool(name)
        installed = path is not None
        version = ""
        if installed and path:
            version = _get_version(path, info["check_args"])

        results.append(ToolStatus(
            name=info["display"],
            installed=installed,
            version=version,
            path=path or "",
            installable=info["installable"],
            install_size=info["size"],
            install_url=info["url"],
        ))
    return results


def install_tool(
    tool_name: str,
    progress_cb: Optional[Callable[[str], None]] = None,
) -> bool:
    """Install a tool to the tools directory using the unified ToolInstaller."""
    from .installer import ToolInstaller
    installer = ToolInstaller(progress_cb=progress_cb)
    return installer.install_tool(tool_name)


def install_all_missing(
    progress_cb: Optional[Callable[[str], None]] = None,
) -> Dict[str, bool]:
    """Install all missing installable tools using the unified ToolInstaller."""
    from .installer import ToolInstaller
    installer = ToolInstaller(progress_cb=progress_cb)
    return installer.install_all_missing()

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
    """Install a tool to the tools directory. Returns True on success."""
    cb = progress_cb or (lambda s: None)

    if tool_name not in _TOOL_DEFS:
        cb(f"Unknown tool: {tool_name}")
        return False

    info = _TOOL_DEFS[tool_name]
    if not info["installable"]:
        cb(f"{tool_name} requires manual installation. Visit: {info['url']}")
        return False

    tools_dir = get_tools_dir()
    tool_dir = tools_dir / tool_name
    tool_dir.mkdir(parents=True, exist_ok=True)

    install_type = info.get("install_type", "")

    if install_type == "burp_custom":
        try:
            from .burp import BurpManager
            bm = BurpManager()
            ok, res = bm.download_installer(lambda msg, pct: cb(f"[Burp] {msg} ({pct}%)"))
            if ok:
                cb("Launching Burp Suite installer...")
                bm.launch_installer(res)
                return True
            cb(f"Burp download failed: {res}")
            return False
        except Exception as exc:
            cb(f"Burp installer error: {exc}")
            return False

    elif install_type == "zip_python":
        # Download zip and extract (sqlmap)
        zip_path = tool_dir / f"{tool_name}.zip"
        if _download_file(info["url"], zip_path, cb):
            cb(f"Extracting {tool_name}...")
            if _extract_zip(zip_path, tool_dir):
                zip_path.unlink(missing_ok=True)
                cb(f"{tool_name} installed successfully")
                return True
        return False

    elif install_type == "github_release":
        # For GitHub releases, we need to find the right asset URL
        # Download the release page and find the asset
        try:
            # Convert latest URL to API URL
            repo_parts = info["url"].replace("https://github.com/", "").replace("/releases/latest", "")
            api_url = f"https://api.github.com/repos/{repo_parts}/releases/latest"
            cb(f"Checking latest release for {tool_name}...")

            req = Request(api_url, headers={
                "User-Agent": "WebRipper-Recon/4.0",
                "Accept": "application/vnd.github.v3+json",
            })
            with urlopen(req, timeout=15) as resp:
                release_data = json.loads(resp.read())

            # Find matching asset
            pattern = info.get("asset_pattern", "")
            arch_patterns = ["amd64", "x86_64", "x64"]
            best_asset = None

            for asset in release_data.get("assets", []):
                aname = asset["name"].lower()
                if pattern in aname and any(a in aname for a in arch_patterns):
                    if aname.endswith(".zip"):
                        best_asset = asset
                        break

            if not best_asset:
                # Fallback: any zip matching pattern
                for asset in release_data.get("assets", []):
                    aname = asset["name"].lower()
                    if pattern in aname and aname.endswith(".zip"):
                        best_asset = asset
                        break

            if not best_asset:
                cb(f"Could not find suitable download for {tool_name}")
                return False

            download_url = best_asset["browser_download_url"]
            zip_path = tool_dir / best_asset["name"]

            if _download_file(download_url, zip_path, cb):
                cb(f"Extracting {tool_name}...")
                if _extract_zip(zip_path, tool_dir):
                    zip_path.unlink(missing_ok=True)
                    cb(f"{tool_name} installed successfully")
                    return True

        except Exception as exc:
            cb(f"Failed to install {tool_name}: {exc}")

        return False

    return False


def install_all_missing(
    progress_cb: Optional[Callable[[str], None]] = None,
) -> Dict[str, bool]:
    """Install all missing installable tools. Returns dict of name -> success."""
    cb = progress_cb or (lambda s: None)
    results = {}

    for name, info in _TOOL_DEFS.items():
        if not info["installable"]:
            continue
        path = _find_tool(name)
        if path:
            results[name] = True
            continue
        cb(f"\n--- Installing {name} ---")
        results[name] = install_tool(name, cb)

    return results

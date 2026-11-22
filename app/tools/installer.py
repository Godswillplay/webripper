"""
Tool auto-installer and manager for WebRipper Recon 5.0.

Downloads and installs external security tools to %APPDATA%/WebRipper/tools/.
Supports:
- GitHub releases: nuclei, gobuster, httpx, subfinder
- Pip packages: sqlmap, hashid
- System & GUI tools: Nmap (official installer + Npcap check), Burp Suite (Community installer + CA cert)
- Protected against Zip Slip directory traversal vulnerabilities
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple
from urllib.error import URLError
from urllib.request import Request, urlopen

from .burp import BurpManager
try:
    from .zap import ZAPManager
except ImportError:
    ZAPManager = None


def _get_tools_dir() -> str:
    """Return the tools directory path."""
    base = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "WebRipper", "tools")
    os.makedirs(base, exist_ok=True)
    return base


def _get_platform_info() -> Tuple[str, str]:
    """Return (os_name, arch) normalized for release asset matching."""
    sys_plat = platform.system().lower()
    machine = platform.machine().lower()
    if "arm" in machine or "aarch64" in machine:
        arch = "arm64"
    else:
        arch = "amd64"
    return sys_plat, arch


def _get_github_asset_pattern(tool: str) -> str:
    """Return platform-appropriate asset glob pattern for GitHub tool."""
    sys_plat, arch = _get_platform_info()
    is_win = (sys_plat == "windows")
    is_arm = (arch == "arm64")

    if is_win:
        patterns = {
            "nuclei": "nuclei_*_windows_amd64.zip",
            "gobuster": "gobuster_*_windows_x86_64.zip",
            "httpx": "httpx_*_windows_amd64.zip",
            "subfinder": "subfinder_*_windows_amd64.zip",
            "sslscan": "sslscan_*_windows64.zip",
        }
    else:
        arch_pd = "arm64" if is_arm else "amd64"
        arch_go = "arm64" if is_arm else "x86_64"
        patterns = {
            "nuclei": f"nuclei_*_linux_{arch_pd}.zip",
            "gobuster": f"gobuster_*_Linux_{arch_go}.tar.gz",
            "httpx": f"httpx_*_linux_{arch_pd}.zip",
            "subfinder": f"subfinder_*_linux_{arch_pd}.zip",
            "sslscan": "sslscan_*_linux*.tar.gz",
        }
    return patterns.get(tool, f"{tool}_*_{sys_plat}*.zip")


def get_linux_package_manager() -> Optional[Tuple[str, str]]:
    """Detect available Linux package manager and return (manager_name, install_cmd_prefix)."""
    managers = [
        ("apt-get", "sudo apt-get install -y"),
        ("apt", "sudo apt install -y"),
        ("pacman", "sudo pacman -S --noconfirm"),
        ("dnf", "sudo dnf install -y"),
        ("zypper", "sudo zypper install -y"),
        ("apk", "sudo apk add"),
    ]
    for mgr, cmd in managers:
        if shutil.which(mgr):
            return mgr, cmd
    return None


# Tool definitions: name -> (type, owner/repo or pip-name, default_asset_pattern)
_GITHUB_TOOLS = {
    "nuclei":    ("projectdiscovery", "nuclei",    "nuclei_*_windows_amd64.zip"),
    "gobuster":  ("OJ",               "gobuster",  "gobuster_*_windows_x86_64.zip"),
    "httpx":     ("projectdiscovery", "httpx",     "httpx_*_windows_amd64.zip"),
    "subfinder": ("projectdiscovery", "subfinder", "subfinder_*_windows_amd64.zip"),
    "sslscan":   ("rbsec",            "sslscan",   "sslscan_*_windows64.zip"),
}

_PIP_TOOLS = {
    "sqlmap": "sqlmap",
    "hashid": "hashid",
}

NMAP_DOWNLOAD_URL = "https://nmap.org/dist/nmap-7.95-setup.exe"
COMMON_NMAP_PATHS = [
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
    "/usr/bin/nmap",
    "/usr/local/bin/nmap",
    "/opt/nmap/bin/nmap",
]


def _safe_extract_zip(zf: zipfile.ZipFile, target_dir: str) -> None:
    """Extract zip archive safely, preventing Zip Slip directory traversal attacks."""
    target_path = Path(target_dir).resolve()
    target_path.mkdir(parents=True, exist_ok=True)
    for member in zf.infolist():
        # Resolve target destination
        member_dest = (target_path / member.filename).resolve()
        if not member_dest.is_relative_to(target_path):
            raise RuntimeError(f"Zip Slip attempt detected in archive member: {member.filename}")
    zf.extractall(target_path)


def _safe_extract_tar(tf: tarfile.TarFile, target_dir: str) -> None:
    """Extract tar archive safely, preventing Tar Slip directory traversal attacks."""
    target_path = Path(target_dir).resolve()
    target_path.mkdir(parents=True, exist_ok=True)
    for member in tf.getmembers():
        member_dest = (target_path / member.name).resolve()
        if not member_dest.is_relative_to(target_path):
            raise RuntimeError(f"Tar Slip attempt detected in archive member: {member.name}")
        if member.issym() or member.islnk():
            link_dest = (target_path / member.linkname).resolve()
            if not link_dest.is_relative_to(target_path):
                raise RuntimeError(f"Tar Slip symlink attempt detected: {member.linkname}")
    if hasattr(tarfile, "data_filter"):
        tf.extractall(target_path, filter="data")
    else:
        tf.extractall(target_path)


class ToolInstaller:
    """Downloads, installs, and manages all security tools."""

    def __init__(self, progress_cb: Optional[Callable[[str], None]] = None):
        self._progress = progress_cb or (lambda msg: None)
        self._tools_dir = _get_tools_dir()
        self.burp_manager = BurpManager()
        self.zap_manager = ZAPManager() if ZAPManager is not None else None

    @property
    def progress_cb(self) -> Callable[[str], None]:
        return self._progress

    @progress_cb.setter
    def progress_cb(self, cb: Optional[Callable[[str], None]]):
        self._progress = cb or (lambda msg: None)

    def install_tool(self, name: str) -> bool:
        """Install a single tool. Returns True on success."""
        name = name.lower()

        if name in _GITHUB_TOOLS:
            owner, repo, pattern = _GITHUB_TOOLS[name]
            return self._install_github(name, owner, repo, pattern)
        elif name in _PIP_TOOLS:
            return self._install_pip(name, _PIP_TOOLS[name])
        elif name == "burp" or name == "burpsuite":
            ok, res = self.burp_manager.download_installer(lambda msg, pct: self._progress(f"[Burp] {msg} ({pct}%)"))
            if ok:
                self._progress("Launching Burp Suite installer...")
                self.burp_manager.launch_installer(res)
                return True
            self._progress(f"Burp download failed: {res}")
            return False
        elif name == "nmap":
            return self._install_nmap()
        elif name in ("zaproxy", "zap"):
            return self._install_zap()
        else:
            self._progress(f"Unknown tool: {name}")
            return False

    def install_all_missing(self) -> Dict[str, bool]:
        """Install all portable tools that aren't already present."""
        results = {}
        portable_tools = list(_GITHUB_TOOLS.keys()) + list(_PIP_TOOLS.keys())

        for tool_name in portable_tools:
            if self._is_installed(tool_name):
                self._progress(f"✓ {tool_name} already installed")
                results[tool_name] = True
                continue

            self._progress(f"Installing {tool_name}...")
            try:
                results[tool_name] = self.install_tool(tool_name)
            except Exception as e:
                self._progress(f"✗ {tool_name} failed: {e}")
                results[tool_name] = False

        return results

    def get_installable_tools(self) -> Dict[str, Dict]:
        """Return comprehensive status about all tools."""
        tools = {}

        # 1. GitHub portable tools
        for name in _GITHUB_TOOLS:
            is_inst, path = self._get_tool_path(name)
            tools[name] = {
                "type": "portable_binary",
                "installed": is_inst,
                "path": path,
                "source": f"github.com/{_GITHUB_TOOLS[name][0]}/{_GITHUB_TOOLS[name][1]}",
                "can_auto_install": True,
            }

        # 2. Pip tools
        for name in _PIP_TOOLS:
            is_inst, path = self._get_tool_path(name)
            tools[name] = {
                "type": "python_package",
                "installed": is_inst,
                "path": path,
                "source": f"pypi.org/project/{_PIP_TOOLS[name]}",
                "can_auto_install": True,
            }

        # 3. Nmap
        nmap_path = self.get_nmap_path()
        tools["nmap"] = {
            "type": "system_scanner",
            "installed": nmap_path is not None,
            "path": nmap_path,
            "source": "nmap.org",
            "can_auto_install": True,
        }

        # 4. Burp Suite
        burp_info = self.burp_manager.detect_burp()
        tools["burpsuite"] = {
            "type": "gui_proxy",
            "installed": burp_info["installed"],
            "edition": burp_info["edition"],
            "path": burp_info["path"],
            "source": "portswigger.net",
            "proxy_active": self.burp_manager.is_proxy_running(),
            "can_auto_install": True,
        }

        # 5. OWASP ZAP
        zap_mgr = getattr(self, "zap_manager", None)
        if zap_mgr is not None:
            zap_info = zap_mgr.detect_zap()
            is_zap_running = zap_mgr.is_proxy_running()
        else:
            _zm_cls = ZAPManager
            if _zm_cls is None:
                try:
                    from .zap import ZAPManager as _zm_cls
                except Exception:
                    _zm_cls = None
            if _zm_cls is not None:
                _zm = _zm_cls()
                zap_info = _zm.detect_zap()
                is_zap_running = _zm.is_proxy_running()
            else:
                zap_info = {"installed": False, "path": None}
                is_zap_running = False

        tools["zaproxy"] = {
            "type": "gui_proxy",
            "installed": zap_info["installed"],
            "path": zap_info["path"],
            "source": "zaproxy.org",
            "proxy_active": is_zap_running,
            "can_auto_install": False,
        }

        return tools

    def get_nmap_path(self) -> Optional[str]:
        """Locate nmap executable on the system."""
        which = shutil.which("nmap")
        if which:
            return which
        for p in COMMON_NMAP_PATHS:
            if os.path.isfile(p):
                return p
        # Check tools dir (windows nmap.exe or linux nmap)
        for name in ("nmap.exe", "nmap"):
            local_nmap = os.path.join(self._tools_dir, "nmap", name)
            if os.path.isfile(local_nmap):
                return local_nmap
        return None

    def _get_tool_path(self, name: str) -> Tuple[bool, Optional[str]]:
        """Check if tool is in PATH or WebRipper tools dir."""
        if name in ("burp", "burpsuite"):
            burp_info = self.burp_manager.detect_burp()
            if burp_info.get("installed") and burp_info.get("path"):
                return True, burp_info["path"]
            return False, None

        if name in ("zaproxy", "zap"):
            zap_mgr = getattr(self, "zap_manager", None)
            if zap_mgr is None:
                _zm_cls = ZAPManager
                if _zm_cls is None:
                    try:
                        from .zap import ZAPManager as _zm_cls
                    except Exception:
                        _zm_cls = None
                if _zm_cls is not None:
                    try:
                        zap_mgr = _zm_cls()
                    except Exception:
                        zap_mgr = None
            if zap_mgr is not None:
                zap_info = zap_mgr.detect_zap()
                if zap_info.get("installed") and zap_info.get("path"):
                    return True, zap_info["path"]
                return False, None
            which = shutil.which("zaproxy") or shutil.which("zap")
            if which:
                return True, which
            return False, None

        if name == "nmap":
            nmap_path = self.get_nmap_path()
            if nmap_path:
                return True, nmap_path
            return False, None

        which = shutil.which(name)
        if which:
            return True, which

        tool_dir = os.path.join(self._tools_dir, name)
        if os.path.isdir(tool_dir):
            for root, _, files in os.walk(tool_dir):
                for f in files:
                    if f.lower() in (f"{name}.exe", f"{name}.bat", f"{name}.cmd", f"{name}.py", f"{name}"):
                        return True, os.path.join(root, f)
            # Check for binary in bin subfolder or scripts
            bin_dir = os.path.join(tool_dir, "bin")
            if os.path.isdir(bin_dir):
                for f in os.listdir(bin_dir):
                    if f.lower().startswith(name.lower()):
                        return True, os.path.join(bin_dir, f)
            # If folder has files, consider installed with entrypoint
            py_entry = os.path.join(tool_dir, f"{name}.py")
            if os.path.isfile(py_entry):
                return True, py_entry

        return False, None

    def _is_installed(self, name: str) -> bool:
        """Check if tool exists."""
        inst, _ = self._get_tool_path(name)
        return inst

    def _install_github(self, name: str, owner: str, repo: str, pattern: str) -> bool:
        """Download tool from GitHub releases safely."""
        try:
            self._progress(f"Fetching latest {name} release from {owner}/{repo}...")
            url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
            req = Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "WebRipper-Recon/5.0"})
            with urlopen(req, timeout=30) as resp:
                release = json.loads(resp.read().decode())

            download_url = None
            asset_name = None
            import fnmatch

            # Dynamically resolve platform-appropriate asset pattern
            effective_pattern = _get_github_asset_pattern(name) or pattern

            for asset in release.get("assets", []):
                a_name = asset["name"].lower()
                if fnmatch.fnmatch(a_name, effective_pattern.lower()):
                    download_url = asset["browser_download_url"]
                    asset_name = asset["name"]
                    break

            if not download_url:
                # Try provided default pattern
                for asset in release.get("assets", []):
                    a_name = asset["name"].lower()
                    if fnmatch.fnmatch(a_name, pattern.lower()):
                        download_url = asset["browser_download_url"]
                        asset_name = asset["name"]
                        break

            if not download_url:
                # Platform fallback
                sys_plat, arch = _get_platform_info()
                arch_tokens = ["amd64", "x86_64", "x64"] if arch == "amd64" else ["arm64", "aarch64"]
                if sys_plat == "windows":
                    plat_tokens = ["windows", "win"]
                    exts = (".zip",)
                else:
                    plat_tokens = ["linux"]
                    exts = (".tar.gz", ".tgz", ".zip")

                for asset in release.get("assets", []):
                    a_name = asset["name"].lower()
                    if any(p in a_name for p in plat_tokens) and any(a in a_name for a in arch_tokens) and any(a_name.endswith(e) for e in exts):
                        download_url = asset["browser_download_url"]
                        asset_name = asset["name"]
                        break

            if not download_url:
                self._progress(f"✗ No matching release asset found for {name}")
                return False

            tool_dir = os.path.join(self._tools_dir, name)
            os.makedirs(tool_dir, exist_ok=True)
            archive_path = os.path.join(tool_dir, asset_name)

            self._progress(f"Downloading {asset_name}...")
            self._download_file(download_url, archive_path)

            self._progress(f"Safely extracting {name}...")
            if asset_name.endswith((".tar.gz", ".tgz")):
                with tarfile.open(archive_path, "r:*") as tf:
                    _safe_extract_tar(tf, tool_dir)
            elif asset_name.endswith(".zip"):
                with zipfile.ZipFile(archive_path, "r") as zf:
                    _safe_extract_zip(zf, tool_dir)
            else:
                self._progress(f"✗ Unsupported archive format: {asset_name}")
                return False

            if os.path.exists(archive_path):
                os.remove(archive_path)

            if platform.system() != "Windows":
                for root, _, files in os.walk(tool_dir):
                    for fn in files:
                        fp = os.path.join(root, fn)
                        try:
                            st = os.stat(fp)
                            os.chmod(fp, st.st_mode | 0o755)
                        except Exception:
                            pass

            # If nuclei, also update templates
            if name == "nuclei":
                self._update_nuclei_templates(tool_dir)

            self._progress(f"✓ {name} installed successfully to {tool_dir}")
            return True

        except Exception as e:
            self._progress(f"✗ {name} install failed: {e}")
            return False

    def _update_nuclei_templates(self, tool_dir: str) -> None:
        """Run nuclei -update-templates if nuclei binary exists."""
        for f in os.listdir(tool_dir):
            if f.lower() in ("nuclei.exe", "nuclei"):
                try:
                    self._progress("Updating Nuclei vulnerability templates...")
                    flags = subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0
                    subprocess.run(
                        [os.path.join(tool_dir, f), "-update-templates"],
                        capture_output=True, timeout=90, creationflags=flags,
                    )
                except Exception:
                    pass
                break

    def _install_pip(self, name: str, package: str) -> bool:
        """Install Python package to tools dir."""
        try:
            tool_dir = os.path.join(self._tools_dir, name)
            os.makedirs(tool_dir, exist_ok=True)

            self._progress(f"Installing {package} via pip...")
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "--target", tool_dir, package],
                capture_output=True, text=True, timeout=180,
            )
            if result.returncode == 0:
                self._progress(f"✓ {name} installed to {tool_dir}")
                return True
            else:
                self._progress(f"✗ {name}: {result.stderr[:200]}")
                return False

        except Exception as e:
            self._progress(f"✗ {name} install failed: {e}")
            return False

    def _install_nmap(self) -> bool:
        """Download official Nmap Windows installer or provide Linux distro package instructions."""
        if platform.system() != "Windows":
            pkg_mgr = get_linux_package_manager()
            if pkg_mgr:
                mgr_name, install_cmd = pkg_mgr
                self._progress("Nmap on Linux requires system package installation.")
                self._progress(f"To install, run: {install_cmd} nmap")
            else:
                self._progress("Please install Nmap using your Linux distribution package manager (e.g. sudo apt install nmap).")
            return False

        try:
            dest_dir = os.path.join(self._tools_dir, "nmap")
            os.makedirs(dest_dir, exist_ok=True)
            installer_path = os.path.join(dest_dir, "nmap-setup.exe")

            self._progress("Downloading official Nmap installer (nmap.org)...")
            self._download_file(NMAP_DOWNLOAD_URL, installer_path)

            self._progress("Launching Nmap installer (ensure Npcap is checked during install)...")
            subprocess.Popen([installer_path], shell=False)
            return True
        except Exception as exc:
            self._progress(f"Nmap download failed: {exc}")
            return False

    def _install_zap(self) -> bool:
        """Provide installation instructions for OWASP ZAP (requires system installation)."""
        if platform.system() != "Windows":
            pkg_mgr = get_linux_package_manager()
            if pkg_mgr:
                mgr_name, install_cmd = pkg_mgr
                self._progress("OWASP ZAP on Linux requires system package installation.")
                self._progress(f"To install, run: {install_cmd} zaproxy")
            else:
                self._progress("Please install OWASP ZAP using your Linux distribution package manager (e.g. sudo apt-get install -y zaproxy or sudo pacman -S zaproxy).")
            return False

        self._progress("OWASP ZAP on Windows requires manual installer setup (Java 11+ runtime required).")
        self._progress("Download official installer from: https://www.zaproxy.org/download/")
        return False

    def _download_file(self, url: str, dest: str) -> None:
        """Download a file with progress updates."""
        req = Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebRipper/5.0"})
        with urlopen(req, timeout=120) as resp:
            total = int(resp.headers.get("Content-Length", 0))
            downloaded = 0
            with open(dest, "wb") as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total > 0:
                        pct = int(downloaded / total * 100)
                        if pct % 10 == 0:
                            self._progress(f"  {pct}% ({downloaded // 1024}KB / {total // 1024}KB)")

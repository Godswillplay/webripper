"""
Burp Suite integration manager for WebRipper Recon.

Provides:
- Auto-detection of Burp Suite Professional & Community editions
- Direct 1-click download of official Burp Suite Community installer from PortSwigger
- Automated PortSwigger CA certificate retrieval (http://127.0.0.1:8080/cert)
- Proxy connectivity testing and trust configuration
"""

from __future__ import annotations

import os
import shutil
import ssl
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Callable, Dict, Optional, Tuple
import urllib.request
from urllib.error import URLError
from urllib.request import Request, urlopen, build_opener, ProxyHandler

# Official PortSwigger download endpoints
BURP_COMMUNITY_WINDOWS_URL = (
    "https://portswigger.net/burp/releases/download?product=community&version=&type=WindowsX64"
)
BURP_COMMUNITY_JAR_URL = (
    "https://portswigger.net/burp/releases/download?product=community&version=&type=Jar"
)

# Standard Windows installation paths
COMMON_BURP_PATHS = [
    r"C:\Program Files\BurpSuiteCommunity\BurpSuiteCommunity.exe",
    r"C:\Program Files\BurpSuitePro\BurpSuitePro.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Programs\BurpSuiteCommunity\BurpSuiteCommunity.exe"),
    os.path.expandvars(r"%LOCALAPPDATA%\Programs\BurpSuitePro\BurpSuitePro.exe"),
]


class BurpManager:
    """Manages Burp Suite detection, downloading, proxy checking, and CA certificates."""

    ENV_PROXY_VARS = (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "http_proxy",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_FILE",
        "CURL_CA_BUNDLE",
    )

    def __init__(self, proxy_url: str = "http://127.0.0.1:8080"):
        self.proxy_url = proxy_url.rstrip("/")
        self.tools_dir = Path(os.environ.get("APPDATA", os.path.expanduser("~"))) / "WebRipper" / "tools" / "burp"
        self.tools_dir.mkdir(parents=True, exist_ok=True)
        self.ca_cert_path = self.tools_dir / "burp_cacert.pem"
        self._saved_env: Optional[Dict[str, Optional[str]]] = None

    def detect_burp(self) -> Dict[str, any]:
        """Detect if Burp Suite executable is present on the machine."""
        # 1. Check known directories
        for p in COMMON_BURP_PATHS:
            if os.path.isfile(p):
                edition = "Professional" if "pro" in p.lower() else "Community"
                return {
                    "installed": True,
                    "edition": edition,
                    "path": p,
                    "type": "native_exe",
                }

        # 2. Check PATH
        which_path = shutil.which("burpsuite") or shutil.which("burp")
        if which_path:
            return {
                "installed": True,
                "edition": "Custom (PATH)",
                "path": which_path,
                "type": "path",
            }

        # 3. Check WebRipper managed tools directory
        for item in self.tools_dir.glob("*.jar"):
            return {
                "installed": True,
                "edition": "Community (Portable JAR)",
                "path": str(item),
                "type": "jar",
            }

        return {
            "installed": False,
            "edition": "Not Installed",
            "path": None,
            "type": None,
        }

    def is_proxy_running(self, timeout: float = 0.3) -> bool:
        """Check if Burp Suite proxy is actively listening on proxy_url with minimal latency."""
        try:
            import socket
            from urllib.parse import urlparse
            parsed = urlparse(self.proxy_url)
            host = parsed.hostname or "127.0.0.1"
            port = parsed.port or 8080
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except Exception:
            return False

    def fetch_ca_certificate(self, timeout: float = 5.0) -> Tuple[bool, str]:
        """
        Fetch the PortSwigger root CA certificate from http://127.0.0.1:8080/cert
        and convert it to PEM format so Python/Playwright can trust it.
        """
        import urllib.request
        cert_url = f"{self.proxy_url}/cert"
        try:
            req = Request(cert_url, headers={"User-Agent": "WebRipper-CACertFetcher", "Host": "burp"})
            # Use empty ProxyHandler to avoid proxy loopback deadlocks
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(req, timeout=timeout) as resp:
                raw_cert = resp.read()

            if not raw_cert or len(raw_cert) < 100:
                return False, "Received empty certificate response from Burp proxy."

            # If response is DER, convert to PEM
            pem_content = ""
            if b"-----BEGIN CERTIFICATE-----" in raw_cert:
                pem_content = raw_cert.decode("utf-8", errors="ignore")
            elif raw_cert.startswith((b"\x30\x82", b"\x30\x81", b"\x30\x83", b"\x30\x84")):
                import ssl
                try:
                    pem_content = ssl.DER_cert_to_PEM_cert(raw_cert)
                except Exception:
                    import base64
                    b64 = base64.encodebytes(raw_cert).decode("ascii")
                    pem_content = f"-----BEGIN CERTIFICATE-----\n{b64}-----END CERTIFICATE-----\n"
            else:
                return False, f"Invalid certificate response from {cert_url}: Not a valid X.509 DER/PEM certificate."

            with open(self.ca_cert_path, "w", encoding="utf-8") as f:
                f.write(pem_content)

            return True, str(self.ca_cert_path)

        except Exception as exc:
            return False, f"Could not fetch certificate from {cert_url}: {exc}. Ensure Burp Suite is running."

    def get_playwright_proxy(self) -> Dict[str, str]:
        """Return Playwright proxy configuration dict."""
        return {"server": self.proxy_url}

    def set_environment_proxies(self, set_ca: bool = True) -> None:
        """Set environment variables for HTTP tools and Python libraries, saving existing values."""
        if self._saved_env is None:
            self._saved_env = {var: os.environ.get(var) for var in self.ENV_PROXY_VARS}

        os.environ["HTTP_PROXY"] = self.proxy_url
        os.environ["HTTPS_PROXY"] = self.proxy_url
        os.environ["http_proxy"] = self.proxy_url
        os.environ["https_proxy"] = self.proxy_url
        os.environ["ALL_PROXY"] = self.proxy_url
        os.environ["all_proxy"] = self.proxy_url
        os.environ["NO_PROXY"] = "localhost,127.0.0.1,::1"
        os.environ["no_proxy"] = "localhost,127.0.0.1,::1"
        if set_ca and self.ca_cert_path.is_file():
            os.environ["REQUESTS_CA_BUNDLE"] = str(self.ca_cert_path)
            os.environ["SSL_CERT_FILE"] = str(self.ca_cert_path)
            os.environ["CURL_CA_BUNDLE"] = str(self.ca_cert_path)

    def unset_environment_proxies(self) -> None:
        """Restore environment variables to their values prior to set_environment_proxies."""
        if self._saved_env is not None:
            for var, val in self._saved_env.items():
                if val is not None:
                    os.environ[var] = val
                else:
                    os.environ.pop(var, None)
            self._saved_env = None
        else:
            for var in self.ENV_PROXY_VARS:
                os.environ.pop(var, None)

    def download_installer(
        self,
        progress_cb: Optional[Callable[[str, int], None]] = None,
    ) -> Tuple[bool, str]:
        """Download official Burp Suite Community installer from PortSwigger."""
        cb = progress_cb or (lambda msg, pct: None)
        cb("Connecting to PortSwigger release servers...", 5)

        installer_dest = self.tools_dir / "burpsuite_community_setup.exe"
        try:
            req = Request(
                BURP_COMMUNITY_WINDOWS_URL,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebRipper/5.0"},
            )
            with urlopen(req, timeout=60) as resp:
                total = int(resp.headers.get("Content-Length", 0))
                downloaded = 0
                cb("Downloading Burp Suite Community Edition installer...", 10)

                with open(installer_dest, "wb") as f:
                    while True:
                        chunk = resp.read(256 * 1024)
                        if not chunk:
                            break
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total > 0:
                            pct = min(10 + int((downloaded / total) * 85), 95)
                            cb(f"Downloading: {downloaded // (1024*1024)}MB / {total // (1024*1024)}MB", pct)

            cb("Download complete! Ready to install.", 100)
            return True, str(installer_dest)

        except Exception as e:
            return False, f"Download failed: {e}"

    def launch_installer(self, installer_path: str) -> bool:
        """Launch the downloaded Burp installer executable."""
        try:
            if os.path.isfile(installer_path):
                subprocess.Popen([installer_path], shell=False)
                return True
            return False
        except Exception:
            return False

    def launch_burp(self) -> bool:
        """Launch installed Burp Suite."""
        info = self.detect_burp()
        if not info["installed"] or not info["path"]:
            return False
        try:
            path = info["path"]
            if info["type"] == "jar":
                java = shutil.which("java") or "java"
                subprocess.Popen([java, "-jar", path], shell=False)
            else:
                subprocess.Popen([path], shell=False)
            return True
        except Exception:
            return False


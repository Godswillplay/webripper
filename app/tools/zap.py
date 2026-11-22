"""
OWASP ZAP (Zed Attack Proxy) integration manager for WebRipper Recon.

Provides:
- Detection of OWASP ZAP across Linux and Windows paths, tools directory, and PATH
- Port probing and intelligent port selection (8090 fallback to 8091)
- Upstream Burp Suite chaining (auto-routing ZAP -> Burp when Burp is active on 8080)
- Daemon lifecycle management (headless, API key disabled, bounded heap memory)
- Dynamic Live Root CA Certificate retrieval and conversion to PEM format
- Session hygiene (clean session, rule pruning for IDs 10096/10027, context scoping)
- Passive scan queue draining with consecutive zero-record stabilization
- Alert harvesting and normalization (Risk x Confidence matrix mapping, strictly non-VERIFIED)
- Graceful shutdown and environment proxy management
- ZAPSessionContext manager for automated lifecycle execution
"""

from __future__ import annotations

import json
import logging
import os
import platform
import re
import shutil
import ssl
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
import urllib.error
import urllib.parse
import urllib.request

from ..models import Confidence, Finding, Severity

logger = logging.getLogger("webripper.zap")

# Standard OWASP ZAP installation paths across Windows and Linux
COMMON_ZAP_PATHS = [
    # Windows
    r"C:\Program Files\OWASP\Zed Attack Proxy\zap.bat",
    r"C:\Program Files (x86)\OWASP\Zed Attack Proxy\zap.bat",
    os.path.expandvars(r"%LOCALAPPDATA%\Programs\ZAP\zap.bat"),
    # Linux
    "/usr/bin/zaproxy",
    "/usr/share/zaproxy/zap.sh",
    "/opt/zaproxy/zap.sh",
    os.path.expanduser("~/zaproxy/zap.sh"),
    os.path.expanduser("~/ZAP/zap.sh"),
]


class ZAPManager:
    """Manages OWASP ZAP daemon lifecycle, proxy chaining, cert retrieval, and alert normalization."""

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

    def __init__(self, port: int = 8090, host: str = "127.0.0.1"):
        """Initialize ZAPManager instance."""
        self.host = host
        self.port = port
        self.proxy_url = f"http://{self.host}:{self.port}"
        self.tools_dir = (
            Path(os.environ.get("APPDATA", os.path.expanduser("~")))
            / "WebRipper"
            / "tools"
            / "zap"
        )
        self.tools_dir.mkdir(parents=True, exist_ok=True)
        self.ca_cert_path = self.tools_dir / "zap_cacert.pem"

        self._owns_daemon: bool = False
        self._process: Optional[subprocess.Popen] = None
        self._saved_env: Optional[Dict[str, Optional[str]]] = None
        self.burp_chaining: bool = False

    @property
    def owns_daemon(self) -> bool:
        """Return whether this manager spawned and owns the running ZAP daemon."""
        return self._owns_daemon

    def find_zap_binary(self) -> Optional[str]:
        """
        Locate the OWASP ZAP executable across tools directory, common OS install paths, and PATH.
        Returns the absolute string path or None if not found.
        """
        is_windows = platform.system() == "Windows"
        candidate_scripts = ["zap.bat", "zap.sh"] if is_windows else ["zap.sh", "zap.bat"]

        # 1. Check tools directory and subdirectories
        for script in candidate_scripts:
            # tools/zap/zap.bat or tools/zap/zap.sh
            p1 = self.tools_dir / script
            if p1.is_file():
                return str(p1)
            # tools/zap/zap/zap.bat or tools/zap/zap/zap.sh
            p2 = self.tools_dir / "zap" / script
            if p2.is_file():
                return str(p2)
            # tools/zap.bat or tools/zap.sh (tools root)
            p3 = self.tools_dir.parent / script
            if p3.is_file():
                return str(p3)
            # tools/zap/zap.bat from tools root
            p4 = self.tools_dir.parent / "zap" / script
            if p4.is_file():
                return str(p4)

        # 2. Check common operating system paths
        for p in COMMON_ZAP_PATHS:
            if os.path.isfile(p):
                return p

        # 3. Check system PATH
        search_names = (
            ["zap.bat", "zaproxy", "zap.sh", "zap"]
            if is_windows
            else ["zaproxy", "zap.sh", "zap", "zap.bat"]
        )
        for name in search_names:
            found = shutil.which(name)
            if found:
                return found

        return None

    def detect_zap(self) -> Dict[str, Any]:
        """Detect if OWASP ZAP is installed on the machine."""
        binary = self.find_zap_binary()
        if binary:
            return {
                "installed": True,
                "path": binary,
                "type": "binary",
            }
        return {
            "installed": False,
            "path": None,
            "type": None,
        }

    def probe_zap(self, port: int) -> Tuple[bool, bool]:
        """
        Probe given port to determine if it is open and running an unlocked ZAP instance.

        Calls http://127.0.0.1:<port>/JSON/core/view/version/ using a clean urllib opener.
        Returns:
            (is_open, is_unlocked_zap):
            - (True, True): 200 OK and response contains "version" -> accessible ZAP daemon.
            - (True, False): 401/403 (locked by API key) or other response -> port open, but not unlocked ZAP.
            - (False, False): connection refused or unreachable -> port closed.
        """
        url = f"http://127.0.0.1:{port}/JSON/core/view/version/"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "WebRipper-ZAP"},
        )
        try:
            resp = opener.open(req, timeout=1.5)
            try:
                status = getattr(resp, "status", getattr(resp, "code", None))
                if status is None and hasattr(resp, "getcode"):
                    status = resp.getcode()
                if status in (200, None):
                    body = resp.read()
                    if isinstance(body, bytes):
                        body = body.decode("utf-8", errors="ignore")
                    elif not isinstance(body, str):
                        body = str(body)
                    try:
                        data = json.loads(body)
                        if isinstance(data, dict) and "version" in data:
                            return True, True
                    except Exception:
                        pass
                    return True, False
                return True, False
            finally:
                if hasattr(resp, "close"):
                    resp.close()
        except urllib.error.HTTPError as exc:
            # 401 Unauthorized or 403 Forbidden indicates an active ZAP daemon requiring an API key
            # Other HTTP statuses also mean the port is actively listening
            if exc.code in (401, 403):
                return True, False
            return True, False
        except (urllib.error.URLError, ConnectionError, OSError, TimeoutError):
            return False, False
        except Exception:
            return False, False

    def is_proxy_running(self, timeout: float = 0.5) -> bool:
        """Check if ZAP proxy is actively listening on self.port."""
        is_open, _ = self.probe_zap(self.port)
        return is_open

    def _call_api(
        self,
        endpoint: str,
        params: Optional[Dict[str, str]] = None,
        timeout: float = 5.0,
    ) -> Dict[str, Any]:
        """
        Execute an HTTP GET request to the local ZAP JSON API using a clean proxy handler.
        Returns the parsed JSON response dictionary or raw string wrapped in dict.
        """
        query = ""
        if params:
            query = "?" + urllib.parse.urlencode(params)
        url = f"http://127.0.0.1:{self.port}{endpoint}{query}"

        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "WebRipper-ZAP"},
        )
        try:
            with opener.open(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", errors="ignore")
                if raw:
                    try:
                        return json.loads(raw)
                    except Exception:
                        return {"raw": raw}
                return {}
        except Exception as exc:
            logger.debug("ZAP API call error on %s: %s", endpoint, exc)
            return {}

    def _check_and_setup_burp_chaining(self) -> bool:
        """
        Check if Burp Suite proxy is actively running on 127.0.0.1:8080.
        If active, sets burp_chaining flag, logs notification, and configures upstream proxy.
        """
        burp_active = False
        try:
            from .burp import BurpManager
            burp_active = BurpManager().is_proxy_running()
        except Exception:
            burp_active = False

        self.burp_chaining = burp_active
        if burp_active:
            msg1 = "[ZAP] Active Burp Suite proxy detected on 127.0.0.1:8080 — chaining ZAP upstream -> Burp."
            msg2 = "[ZAP] Note: WebRipper crawl traffic will appear in your Burp HTTP history."
            print(msg1)
            print(msg2)
            logger.info(msg1)
            logger.info(msg2)

            # If ZAP is already responsive, dynamically configure upstream proxy via API
            try:
                # Network add-on endpoint (ZAP 2.12+)
                self._call_api("/JSON/network/action/setHttpProxy/", {
                    "host": "127.0.0.1",
                    "port": "8080",
                    "realm": "",
                    "username": "",
                    "password": "",
                })
                # Legacy core options endpoints
                self._call_api("/JSON/core/action/setOptionProxyChainName/", {"String": "127.0.0.1"})
                self._call_api("/JSON/core/action/setOptionProxyChainPort/", {"Integer": "8080"})
                self._call_api("/JSON/core/action/setOptionUseProxyChain/", {"Boolean": "true"})
            except Exception as e:
                logger.debug("Failed setting live upstream proxy on ZAP: %s", e)

        return burp_active

    def start_daemon(self, port: int = 8090, timeout: float = 35.0) -> bool:
        """
        Ensure a usable OWASP ZAP daemon is running on port or fallback port (8091).

        1. Probes initial port (8090). If unlocked ZAP is already running, reuses it (_owns_daemon = False).
        2. If port is occupied by someone else's locked ZAP or another service, falls back to 8091.
        3. If port is free, spawns a new daemon with _owns_daemon = True, API key disabled, and bounded memory.
        4. Detects Burp Suite and adds upstream proxy configuration if active.
        5. Polls /JSON/core/view/version/ until responsive or timeout expires.
        """
        target_port = port
        is_open, is_unlocked = self.probe_zap(target_port)

        if is_open and is_unlocked:
            self.port = target_port
            self.proxy_url = f"http://127.0.0.1:{target_port}"
            self._owns_daemon = False
            self._check_and_setup_burp_chaining()
            logger.info("Reusing existing unlocked OWASP ZAP daemon on port %d", self.port)
            return True

        if is_open and not is_unlocked:
            # Port occupied and not unlocked ZAP -> fallback to 8091
            fallback_port = 8091 if target_port == 8090 else target_port + 1
            logger.warning(
                "Port %d is occupied by locked ZAP or another service. Falling back to port %d.",
                target_port,
                fallback_port,
            )
            is_open_fb, is_unlocked_fb = self.probe_zap(fallback_port)
            if is_open_fb and is_unlocked_fb:
                self.port = fallback_port
                self.proxy_url = f"http://127.0.0.1:{fallback_port}"
                self._owns_daemon = False
                self._check_and_setup_burp_chaining()
                logger.info("Reusing existing unlocked OWASP ZAP daemon on fallback port %d", self.port)
                return True
            elif is_open_fb and not is_unlocked_fb:
                raise RuntimeError(
                    f"Ports {target_port} and {fallback_port} are both occupied and not unlocked ZAP instances."
                )
            else:
                target_port = fallback_port

        # target_port is free -> spawn daemon
        self.port = target_port
        self.proxy_url = f"http://127.0.0.1:{target_port}"
        self._owns_daemon = True

        zap_binary = self.find_zap_binary()
        if not zap_binary:
            raise FileNotFoundError(
                "OWASP ZAP binary not found. Please install ZAP or place zap.bat/zap.sh in PATH or tools directory."
            )

        # Check upstream Burp chaining before assembling CLI command
        self._check_and_setup_burp_chaining()

        cmd = [
            zap_binary,
            "-daemon",
            "-host", "127.0.0.1",
            "-port", str(self.port),
            "-config", "api.disablekey=true",
        ]

        if self.burp_chaining:
            cmd.extend([
                "-config", "connection.proxyChain.enabled=true",
                "-config", "connection.proxyChain.hostName=127.0.0.1",
                "-config", "connection.proxyChain.port=8080",
                "-config", "network.connection.httpProxy.enabled=true",
                "-config", "network.connection.httpProxy.host=127.0.0.1",
                "-config", "network.connection.httpProxy.port=8080",
            ])

        env = os.environ.copy()
        env["JAVA_OPTS"] = "-Xmx512m"
        env["_JAVA_OPTIONS"] = "-Xmx512m"

        creationflags = 0
        if platform.system() == "Windows":
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

        logger.info("Spawning OWASP ZAP daemon on 127.0.0.1:%d...", self.port)
        self._process = subprocess.Popen(
            cmd,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags,
        )

        # Poll version endpoint until responsive
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self._process is not None and self._process.poll() is not None:
                raise RuntimeError(
                    f"OWASP ZAP daemon process exited prematurely with code {self._process.returncode}"
                )
            is_open, is_unlocked = self.probe_zap(self.port)
            if is_open and is_unlocked:
                logger.info("OWASP ZAP daemon successfully started and responding on port %d", self.port)
                return True
            time.sleep(1.0)

        # Timeout reached
        self.stop_daemon()
        raise TimeoutError(f"OWASP ZAP daemon failed to respond on port {self.port} within {timeout}s")

    def fetch_ca_certificate(self, timeout: float = 5.0) -> Tuple[bool, str]:
        """
        Fetch the OWASP ZAP root CA certificate from http://127.0.0.1:<port>/OTHER/core/other/rootcert/
        and convert it to PEM format so Python/Playwright can trust it.
        Saves to self.ca_cert_path and sets up environment proxies.
        """
        cert_url = f"http://127.0.0.1:{self.port}/OTHER/core/other/rootcert/"
        try:
            req = urllib.request.Request(
                cert_url,
                headers={"User-Agent": "WebRipper-ZAPCertFetcher"},
            )
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            resp = opener.open(req, timeout=timeout)
            try:
                raw_cert = resp.read()
            finally:
                if hasattr(resp, "close"):
                    resp.close()

            if not raw_cert or len(raw_cert) < 50:
                return False, "Received empty certificate response from ZAP proxy."

            pem_content = ""
            if b"-----BEGIN CERTIFICATE-----" in raw_cert:
                pem_content = raw_cert.decode("utf-8", errors="ignore")
            elif raw_cert.startswith((b"\x30\x82", b"\x30\x81", b"\x30\x83", b"\x30\x84")):
                try:
                    pem_content = ssl.DER_cert_to_PEM_cert(raw_cert)
                except Exception:
                    import base64
                    b64 = base64.encodebytes(raw_cert).decode("ascii")
                    pem_content = f"-----BEGIN CERTIFICATE-----\n{b64}-----END CERTIFICATE-----\n"
            else:
                text = raw_cert.decode("utf-8", errors="ignore")
                if "-----BEGIN CERTIFICATE-----" in text:
                    pem_content = text
                else:
                    return False, f"Invalid certificate response from {cert_url}: Not a valid X.509 DER/PEM certificate."

            self.tools_dir.mkdir(parents=True, exist_ok=True)
            self.ca_cert_path.write_bytes(pem_content.replace("\r\n", "\n").encode("utf-8"))

            self.set_environment_proxies(set_ca=True)
            return True, str(self.ca_cert_path)

        except Exception as exc:
            return False, f"Could not fetch certificate from {cert_url}: {exc}. Ensure ZAP is running."

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

    def new_session(self, target_url: str) -> bool:
        """
        Reset and initialize a clean ZAP session configured specifically for target_url.

        1. Creates new session 'webripper_session' with overwrite=true.
        2. Disables noisy passive scan rules:
           - ID 10096: Timestamp Disclosure
           - ID 10027: Information Disclosure - Suspicious Comments
        3. Configures in-scope regex for target_url in 'Default Context'.
        4. Sets passive scanner to only scan traffic that is in scope.
        """
        # 1. New session
        self._call_api("/JSON/core/action/newSession/", {
            "name": "webripper_session",
            "overwrite": "true",
        })

        # 2. Disable noisy passive scan rules
        self._call_api("/JSON/pscan/action/disableScanners/", {
            "ids": "10096,10027",
        })

        # 3. Include in scope
        parsed = urllib.parse.urlparse(target_url)
        scheme = re.escape(parsed.scheme) if parsed.scheme else "https?"
        netloc = re.escape(parsed.netloc) if parsed.netloc else re.escape(target_url)
        scope_regex = f"^{scheme}://{netloc}.*"

        self._call_api("/JSON/context/action/includeInContext/", {
            "contextName": "Default Context",
            "regex": scope_regex,
        })

        # 4. Restrict passive scan to in-scope traffic only
        self._call_api("/JSON/pscan/action/setScanOnlyInScope/", {
            "onlyInScope": "true",
        })

        return True

    def drain_passive_scan(self, timeout: float = 20.0, settle_delay: float = 1.0) -> bool:
        """
        Poll /JSON/pscan/view/recordsToScan/ until recordsToScan == 0
        two consecutive times ~settle_delay apart within the timeout budget.
        Returns True if drained, False on timeout.
        """
        deadline = time.time() + timeout
        consecutive_zeros = 0

        while time.time() < deadline:
            try:
                res = self._call_api("/JSON/pscan/view/recordsToScan/")
                val = res.get("recordsToScan", "-1")
                records = int(val)
                if records == 0:
                    consecutive_zeros += 1
                    if consecutive_zeros >= 2:
                        return True
                    time.sleep(settle_delay)
                    continue
                else:
                    consecutive_zeros = 0
            except Exception:
                consecutive_zeros = 0

            time.sleep(settle_delay)

        return False

    def get_alerts(self, base_url: str = "") -> List[Finding]:
        """
        Harvest and normalize findings from OWASP ZAP.

        Fetches /JSON/alert/view/alerts/?baseurl=<base_url>&count=500.
        Applies intake filters:
        - Drops any alert where confidence is 'false positive' or '0'.

        Applies Risk x Confidence Matrix:
        - High Risk + High/Medium Confidence -> Severity.HIGH, Confidence.POSSIBLE
        - High Risk + Low Confidence         -> Severity.MEDIUM, Confidence.POSSIBLE
        - Medium Risk + High/Medium Conf     -> Severity.MEDIUM, Confidence.POSSIBLE
        - Medium Risk + Low Confidence       -> Severity.LOW, Confidence.POSSIBLE
        - Low Risk                           -> Severity.LOW, Confidence.POSSIBLE
        - Informational                      -> Severity.INFO, Confidence.INFO

        Strict Invariant: Under NO circumstances can ZAP assign Confidence.VERIFIED.
        """
        params: Dict[str, str] = {"count": "500"}
        if base_url:
            params["baseurl"] = base_url

        res = self._call_api("/JSON/alert/view/alerts/", params=params)
        raw_alerts = res.get("alerts", [])
        if not isinstance(raw_alerts, list):
            return []

        findings: List[Finding] = []

        for alert in raw_alerts:
            if not isinstance(alert, dict):
                continue

            # Intake filter: Drop false positives
            conf_raw = str(alert.get("confidence", "")).strip()
            conf_lower = conf_raw.lower()
            if conf_lower in ("false positive", "falsepositive", "0"):
                continue

            # Normalize Risk
            risk_raw = str(alert.get("risk", "")).strip().lower()
            if risk_raw in ("high", "3"):
                risk_level = "high"
            elif risk_raw in ("medium", "2"):
                risk_level = "medium"
            elif risk_raw in ("low", "1"):
                risk_level = "low"
            else:
                risk_level = "informational"

            # Normalize Confidence
            if conf_lower in ("high", "3"):
                conf_level = "high"
            elif conf_lower in ("medium", "2"):
                conf_level = "medium"
            else:
                conf_level = "low"

            # Risk x Confidence Matrix mapping
            if risk_level == "high":
                if conf_level in ("high", "medium"):
                    severity = Severity.HIGH
                    confidence = Confidence.POSSIBLE
                else:
                    severity = Severity.MEDIUM
                    confidence = Confidence.POSSIBLE
            elif risk_level == "medium":
                if conf_level in ("high", "medium"):
                    severity = Severity.MEDIUM
                    confidence = Confidence.POSSIBLE
                else:
                    severity = Severity.LOW
                    confidence = Confidence.POSSIBLE
            elif risk_level == "low":
                severity = Severity.LOW
                confidence = Confidence.POSSIBLE
            else:  # informational
                severity = Severity.INFO
                confidence = Confidence.INFO

            # Invariant check: ZAP output must never be marked VERIFIED
            if confidence == Confidence.VERIFIED or str(confidence) == "VERIFIED":
                confidence = Confidence.POSSIBLE

            # Build comprehensive evidence snippet
            evidence_parts: List[str] = []
            if alert.get("evidence"):
                evidence_parts.append(f"Evidence: {alert['evidence']}")
            if alert.get("param"):
                evidence_parts.append(f"Param: {alert['param']}")
            if alert.get("attack"):
                evidence_parts.append(f"Attack: {alert['attack']}")
            if alert.get("other"):
                evidence_parts.append(f"Other: {alert['other']}")
            if alert.get("requestHeader"):
                evidence_parts.append(f"Request Header:\n{alert['requestHeader']}")
            if alert.get("responseHeader"):
                evidence_parts.append(f"Response Header:\n{alert['responseHeader']}")
            if alert.get("requestBody"):
                body_snip = alert["requestBody"][:500]
                evidence_parts.append(f"Request Body Snippet:\n{body_snip}")
            if alert.get("responseBody"):
                body_snip = alert["responseBody"][:500]
                evidence_parts.append(f"Response Body Snippet:\n{body_snip}")

            evidence = "\n".join(evidence_parts) if evidence_parts else alert.get("evidence", "")

            # Format CWE and WASC identifiers
            cwe_raw = str(alert.get("cweid", "")).strip()
            cwe_str = ""
            if cwe_raw and cwe_raw not in ("-1", "0"):
                cwe_str = cwe_raw if cwe_raw.upper().startswith("CWE-") else f"CWE-{cwe_raw}"

            wasc_raw = str(alert.get("wascid", "")).strip()
            wasc_str = ""
            if wasc_raw and wasc_raw not in ("-1", "0"):
                wasc_str = wasc_raw if wasc_raw.upper().startswith("WASC-") else f"WASC-{wasc_raw}"

            plugin_id = str(alert.get("pluginId", ""))
            alert_id = str(alert.get("id", alert.get("alertId", "")))

            metadata: Dict[str, Any] = {
                "source": "zap",
                "plugin_id": plugin_id,
                "alert_id": alert_id,
                "cwe": cwe_str,
                "wasc": wasc_str,
                "risk_raw": alert.get("risk", ""),
                "confidence_raw": alert.get("confidence", ""),
                "param": alert.get("param", ""),
                "attack": alert.get("attack", ""),
            }
            if alert.get("solution"):
                metadata["solution"] = alert.get("solution")
            if alert.get("reference"):
                metadata["reference"] = alert.get("reference")
            if alert.get("method"):
                metadata["method"] = alert.get("method")

            finding = Finding(
                severity=severity,
                category="zap",
                title=alert.get("alert") or alert.get("name") or "ZAP Vulnerability Alert",
                description=alert.get("description", ""),
                evidence=evidence,
                url=alert.get("url", ""),
                remediation=alert.get("solution", ""),
                confidence=confidence,
                metadata=metadata,
            )
            findings.append(finding)

        return findings

    def stop_daemon(self, timeout: float = 8.0) -> None:
        """
        Gracefully stop the ZAP daemon if owned by this manager.
        If daemon is not owned, it is left running undisturbed.
        Always restores environment proxy variables.
        """
        try:
            if self._owns_daemon:
                logger.info("Stopping OWASP ZAP daemon on port %d...", self.port)
                try:
                    self._call_api("/JSON/core/action/shutdown/", timeout=3.0)
                except Exception:
                    pass

                if self._process is not None:
                    try:
                        self._process.wait(timeout=timeout)
                    except subprocess.TimeoutExpired:
                        logger.warning("ZAP daemon did not terminate within %0.1fs, killing process...", timeout)
                        try:
                            self._process.terminate()
                            self._process.wait(timeout=2.0)
                        except Exception:
                            try:
                                self._process.kill()
                            except Exception:
                                pass
                    finally:
                        self._process = None
                else:
                    deadline = time.time() + timeout
                    while time.time() < deadline:
                        is_open, _ = self.probe_zap(self.port)
                        if not is_open:
                            break
                        time.sleep(0.5)

                self._owns_daemon = False
        finally:
            self.unset_environment_proxies()


class ZAPSessionContext:
    """
    Context manager for an OWASP ZAP session.

    Automates starting the daemon, fetching CA certificates, configuring scope & hygiene,
    and ensuring graceful shutdown in finally block.
    """

    def __init__(
        self,
        target_url: str,
        port: int = 8090,
        progress_cb: Optional[Callable[[str, int], None]] = None,
        zap_manager: Optional[ZAPManager] = None,
    ):
        self.target_url = target_url
        self.port = port
        self.progress_cb = progress_cb or (lambda msg, pct: None)
        self.zap = zap_manager or ZAPManager(port=port)

    def __enter__(self) -> ZAPManager:
        self.progress_cb("Starting OWASP ZAP daemon...", 10)
        started = self.zap.start_daemon(port=self.port)
        if not started:
            raise RuntimeError(f"Failed to start OWASP ZAP daemon on port {self.port}")

        try:
            self.progress_cb("Fetching ZAP root CA certificate...", 35)
            ok, cert_msg = self.zap.fetch_ca_certificate()
            if ok:
                self.zap.set_environment_proxies(set_ca=True)
            else:
                self.zap.set_environment_proxies(set_ca=False)

            self.progress_cb("Configuring ZAP session and target scope...", 65)
            self.zap.new_session(self.target_url)
        except Exception:
            self.zap.stop_daemon()
            raise

        self.progress_cb("OWASP ZAP initialized and ready.", 100)
        return self.zap

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        try:
            self.progress_cb("Shutting down OWASP ZAP session...", 95)
            self.zap.stop_daemon()
        except Exception as e:
            logger.debug("Error during ZAP session cleanup: %s", e)
        return False

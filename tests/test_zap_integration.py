"""
Unit and integration tests for OWASP ZAP (Zed Attack Proxy) integration in WebRipper Recon.

Implements an in-memory ThreadingHTTPServer mock ZAP server fixture to deterministically
verify all ZAP REST API interactions, probe detection, session hygiene, dynamic CA certificate
retrieval, passive queue draining, Risk x Confidence alert matrix mapping, upstream Burp proxy
chaining, lifecycle daemon ownership, and downstream validator / dedup pipeline flow without
spawning a real Java process or requiring JRE.
"""

from __future__ import annotations

import json
import os
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

from app.dedup import DuplicateRiskScorer
from app.models import Confidence, Finding, ReconReport, ScanResult, Severity
from app.tools.burp import BurpManager
from app.tools.zap import ZAPManager, ZAPSessionContext
from app.validation import ValidationEngine

# Valid self-signed X.509 PEM certificate for mock rootcert endpoint testing
MOCK_ZAP_CA_PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDXTCCAkWgAwIBAgIJANbJz0N1k23VMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV\n"
    "BAYTAlVTMQswCQYDVQQIDAJXQTEQMA4GA1UEBwwHU2VhdHRsZTEYMBYGA1UEAwwP\n"
    "T1dBU1AgWkFQIFJvb3QgQ0EwHhcNMjQwMTAxMDAwMDAwWhcNMzQwMTAxMDAwMDAw\n"
    "WjBFMQswCQYDVQQGEwJVUzELMAkGA1UECAwCV0ExEDAOBgNVBAcMB1NlYXR0bGUx\n"
    "GDAWBgNVBAMMD09XQVNQIFpBUCBSb290IENBMIIBIjANBgkqhkiG9w0BAQEFAAOC\n"
    "AQ8AMIIBCgKCAQEAy1x7H0qB6gP7fW9yY3e7iE2aJj6kL9mOp8rTsVuWv1xYz4aB\n"
    "3dEf5gG6hJ8kL2mOp8rTsVuWv1xYz4aB3dEf5gG6hJ8kL2mOp8rTsVuWv1xYz4aB\n"
    "3dEf5gG6hJ8kL2mOp8rTsVuWv1xYz4aB3dEf5gG6hJ8kL2mOp8rTsVuWv1xYz4aB\n"
    "3dEf5gG6hJ8kL2mOp8rTsVuWv1xYz4aB3dEf5gG6hJ8kL2mOp8rTsVuWv1xYz4aB\n"
    "3dEf5gG6hJ8kL2mOp8rTsVuWv1xYz4aB3dEf5gG6hJ8kL2mOp8rTsVuWv1xYz4aB\n"
    "3dEf5gG6hJ8kL2mOp8rTsVuWv1xYz4aB3dEf5gIDAQABo1AwTjAdBgNVHQ4EFgQU\n"
    "1234567890abcdef1234567890abcdef12345678MB8GA1UdIwQYMBaAFDEyMzQ1\n"
    "Njc4OTBhYmNkZWYxMjM0NTY3ODkwYWIwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0B\n"
    "AQsFAAOCAQEAX1y2z3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6\n"
    "f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8\n"
    "b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0\n"
    "d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2\n"
    "f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4\n"
    "b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6\n"
    "-----END CERTIFICATE-----\n"
)

# Standard mock sample alerts testing Risk x Confidence matrix combinations
SAMPLE_MOCK_ALERTS: List[Dict[str, Any]] = [
    {
        "id": "1",
        "pluginId": "40018",
        "alert": "SQL Injection",
        "risk": "High",
        "confidence": "High",
        "url": "http://127.0.0.1:8000/api/users?id=1",
        "evidence": "syntax error in SQL statement",
        "cweid": "89",
        "wascid": "19",
        "param": "id",
        "attack": "1' OR '1'='1",
        "solution": "Use parameterized queries.",
        "description": "SQL injection vulnerability detected in id parameter.",
    },
    {
        "id": "2",
        "pluginId": "40020",
        "alert": "Remote Code Execution Candidate",
        "risk": "High",
        "confidence": "Low",
        "url": "http://127.0.0.1:8000/cmd?exec=test",
        "evidence": "response time delay heuristic",
        "cweid": "78",
        "wascid": "31",
        "param": "exec",
        "attack": "; sleep 5;",
        "solution": "Avoid executing user commands via shell.",
        "description": "Potential remote command execution candidate.",
    },
    {
        "id": "3",
        "pluginId": "40012",
        "alert": "Cross Site Scripting (Reflected)",
        "risk": "Medium",
        "confidence": "Medium",
        "url": "http://127.0.0.1:8000/search?q=test",
        "evidence": "<script>alert(1)</script>",
        "cweid": "79",
        "wascid": "8",
        "param": "q",
        "attack": "<script>alert(1)</script>",
        "solution": "Sanitize and contextualize HTML output.",
        "description": "Reflected XSS observed in query string.",
    },
    {
        "id": "4",
        "pluginId": "10054",
        "alert": "Cookie Without SameSite Attribute",
        "risk": "Low",
        "confidence": "Low",
        "url": "http://127.0.0.1:8000/login",
        "evidence": "Set-Cookie: session=xyz",
        "cweid": "1275",
        "wascid": "13",
        "param": "session",
        "attack": "",
        "solution": "Ensure all cookies specify SameSite=Lax or Strict.",
        "description": "Cookie missing SameSite attribute.",
    },
    {
        "id": "5",
        "pluginId": "10023",
        "alert": "Information Disclosure - Debug Headers",
        "risk": "Informational",
        "confidence": "Medium",
        "url": "http://127.0.0.1:8000/debug",
        "evidence": "X-Debug-Mode: True",
        "cweid": "200",
        "wascid": "13",
        "param": "",
        "attack": "",
        "solution": "Disable debug headers in production environments.",
        "description": "Application exposes internal debug information headers.",
    },
    {
        "id": "6",
        "pluginId": "90001",
        "alert": "High Risk False Positive Flagged by Scanner",
        "risk": "High",
        "confidence": "False Positive",
        "url": "http://127.0.0.1:8000/false_positive",
        "evidence": "known FP signature",
        "cweid": "200",
        "wascid": "13",
        "description": "Alert marked as false positive by scanner rule.",
    },
    {
        "id": "7",
        "pluginId": "90002",
        "alert": "Zero Confidence Anomaly",
        "risk": "Medium",
        "confidence": "0",
        "url": "http://127.0.0.1:8000/zero_conf",
        "evidence": "untrusted noise",
        "cweid": "200",
        "wascid": "13",
        "description": "Alert with numeric 0 confidence.",
    },
]


class MockZAPHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler implementing the OWASP ZAP REST API endpoints."""

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress standard HTTP server logging to keep test output clean."""
        pass

    def _send_json(self, status: int, data: Any) -> None:
        """Send JSON response with proper headers."""
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        """Handle GET requests across simulated ZAP API routes."""
        server: MockZAPServer = self.server  # type: ignore[assignment]
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # Record incoming request for verification in tests
        server.recorded_requests.append({
            "path": path,
            "query": query,
            "raw_path": self.path,
            "headers": dict(self.headers),
        })

        # 1. Version endpoint: supports 401 Unauthorized flag for alien process testing
        if path == "/JSON/core/view/version/":
            if server.unauthorized:
                self._send_json(401, {
                    "code": "unauthorized",
                    "message": "ZAP API key required or alien daemon detected",
                })
            else:
                self._send_json(200, {"version": "2.14.0"})
            return

        # 2. Session creation endpoint
        if path == "/JSON/core/action/newSession/":
            self._send_json(200, {"result": "OK"})
            return

        # 3. Disable noisy passive scan rules
        if path == "/JSON/pscan/action/disableScanners/":
            self._send_json(200, {"result": "OK"})
            return

        # 4. Context inclusion endpoint
        if path == "/JSON/context/action/includeInContext/":
            self._send_json(200, {"result": "OK"})
            return

        # 5. Set passive scan only in-scope
        if path == "/JSON/pscan/action/setScanOnlyInScope/":
            self._send_json(200, {"result": "OK"})
            return

        # 6. Root CA Certificate retrieval endpoint
        if path == "/OTHER/core/other/rootcert/":
            raw_cert = server.root_cert_bytes
            self.send_response(200)
            self.send_header("Content-Type", "application/x-x509-ca-cert")
            self.send_header("Content-Length", str(len(raw_cert)))
            self.end_headers()
            self.wfile.write(raw_cert)
            return

        # 7. Passive scan drain recordsToScan sequence
        if path == "/JSON/pscan/view/recordsToScan/":
            server.records_to_scan_calls.append(self.path)
            if server.records_sequence:
                count = server.records_sequence.pop(0)
            else:
                count = 0
            self._send_json(200, {"recordsToScan": str(count)})
            return

        # 8. Alert view endpoint
        if path == "/JSON/alert/view/alerts/":
            self._send_json(200, {"alerts": server.alerts})
            return

        # 9. Shutdown endpoint
        if path == "/JSON/core/action/shutdown/":
            server.shutdown_requested = True
            server.shutdown_count += 1
            self._send_json(200, {"result": "OK"})
            return

        # 10. Burp proxy chaining configuration endpoints
        if path in (
            "/JSON/network/action/setHttpProxy/",
            "/JSON/core/action/setOptionProxyChainName/",
            "/JSON/core/action/setOptionProxyChainPort/",
            "/JSON/core/action/setOptionUseProxyChain/",
        ):
            self._send_json(200, {"result": "OK"})
            return

        # Default fallback for unhandled endpoints
        self._send_json(200, {"result": "OK"})


class MockZAPServer(ThreadingHTTPServer):
    """In-memory ThreadingHTTPServer tracking mock ZAP state."""

    def __init__(self, server_address: Any, RequestHandlerClass: Any) -> None:
        super().__init__(server_address, RequestHandlerClass)
        self.unauthorized: bool = False
        self.shutdown_requested: bool = False
        self.shutdown_count: int = 0
        self.records_sequence: List[int] = [5, 0, 2, 0, 0]
        self.records_to_scan_calls: List[str] = []
        self.recorded_requests: List[Dict[str, Any]] = []
        self.alerts: List[Dict[str, Any]] = list(SAMPLE_MOCK_ALERTS)
        self.root_cert_bytes: bytes = MOCK_ZAP_CA_PEM.encode("utf-8")


@pytest.fixture
def mock_zap_server():
    """Fixture providing an active, in-memory ThreadingHTTPServer mock ZAP server."""
    server = MockZAPServer(("127.0.0.1", 0), MockZAPHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    server.port = server.server_address[1]
    # Update mock alert URLs to point to this active server instance
    for alert in server.alerts:
        if "127.0.0.1:8000" in alert.get("url", ""):
            alert["url"] = alert["url"].replace("127.0.0.1:8000", f"127.0.0.1:{server.port}")
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2.0)


# ===========================================================================
# Unit and Integration Tests for OWASP ZAP Subsystem
# ===========================================================================

class TestZAPIntegration:
    """Comprehensive test suite verifying OWASP ZAP integration components."""

    def test_zap_probe_unlocked_and_401_alien_fallback(self, mock_zap_server):
        """
        Verify probe_zap:
        - returns (True, True) on 200 OK
        - returns (True, False) on 401 Unauthorized
        - triggers fallback to alternate port 8091 when 8090 is occupied by an alien/locked daemon
        """
        zap = ZAPManager(port=mock_zap_server.port)

        # 1. 200 OK -> accessible, unlocked ZAP daemon
        mock_zap_server.unauthorized = False
        is_open, is_unlocked = zap.probe_zap(mock_zap_server.port)
        assert is_open is True
        assert is_unlocked is True

        # 2. 401 Unauthorized -> occupied by locked / alien ZAP daemon requiring API key
        mock_zap_server.unauthorized = True
        is_open, is_unlocked = zap.probe_zap(mock_zap_server.port)
        assert is_open is True
        assert is_unlocked is False

        # 3. Connection refused / unreachable -> (False, False)
        with patch("urllib.request.OpenerDirector.open", side_effect=ConnectionRefusedError("Connection refused")):
            is_open_closed, is_unlocked_closed = zap.probe_zap(8090)
            assert is_open_closed is False
            assert is_unlocked_closed is False

        # 4. Port fallback verification in start_daemon
        # Simulate: port 8090 returns (True, False) [locked], port 8091 returns (True, True) [unlocked]
        def simulated_probe(port: int) -> tuple[bool, bool]:
            if port == 8090:
                return True, False  # Alien daemon on default port
            elif port == 8091:
                return True, True   # Unlocked ZAP daemon on fallback port
            return False, False

        zap_fallback_mgr = ZAPManager(port=8090)
        with patch.object(zap_fallback_mgr, "probe_zap", side_effect=simulated_probe):
            with patch.object(zap_fallback_mgr, "_check_and_setup_burp_chaining", return_value=False):
                started = zap_fallback_mgr.start_daemon(port=8090)
                assert started is True
                assert zap_fallback_mgr.port == 8091
                assert zap_fallback_mgr.proxy_url == "http://127.0.0.1:8091"
                assert zap_fallback_mgr.owns_daemon is False

    def test_zap_session_hygiene_on_reuse(self, mock_zap_server):
        """
        Verify session hygiene when connecting to an existing ZAP daemon:
        - newSession requested with overwrite=true
        - noisy rules 10096 and 10027 disabled
        - target URL added to context scope
        - passive scan configured to scan only in-scope traffic
        """
        mock_zap_server.unauthorized = False
        mock_zap_server.recorded_requests.clear()

        zap = ZAPManager(port=mock_zap_server.port)
        target_url = "https://staging.targetcorp.io/api/v2"

        success = zap.new_session(target_url)
        assert success is True

        # Collect requests received by mock server indexed by path
        req_by_path = {r["path"]: r for r in mock_zap_server.recorded_requests}

        # 1. New session called with overwrite=true
        assert "/JSON/core/action/newSession/" in req_by_path
        new_sess_query = req_by_path["/JSON/core/action/newSession/"]["query"]
        assert new_sess_query.get("overwrite") == ["true"]
        assert new_sess_query.get("name") == ["webripper_session"]

        # 2. Noisy rules 10096 and 10027 disabled
        assert "/JSON/pscan/action/disableScanners/" in req_by_path
        disable_query = req_by_path["/JSON/pscan/action/disableScanners/"]["query"]
        assert disable_query.get("ids") == ["10096,10027"]

        # 3. Target URL included in context scope
        assert "/JSON/context/action/includeInContext/" in req_by_path
        scope_query = req_by_path["/JSON/context/action/includeInContext/"]["query"]
        assert scope_query.get("contextName") == ["Default Context"]
        regex_param = scope_query.get("regex", [""])[0]
        assert "staging\\.targetcorp\\.io" in regex_param

        # 4. In-scope restriction enabled
        assert "/JSON/pscan/action/setScanOnlyInScope/" in req_by_path
        in_scope_query = req_by_path["/JSON/pscan/action/setScanOnlyInScope/"]["query"]
        assert in_scope_query.get("onlyInScope") == ["true"]

    def test_zap_dynamic_ca_certificate_fetch(self, mock_zap_server, tmp_path):
        """
        Verify fetch_ca_certificate:
        - downloads root CA certificate dynamically from ZAP
        - saves PEM format to designated ca_cert_path
        - configures environment proxies (REQUESTS_CA_BUNDLE, SSL_CERT_FILE, CURL_CA_BUNDLE)
        """
        zap = ZAPManager(port=mock_zap_server.port)
        zap.tools_dir = tmp_path / "zap_tools"
        zap.ca_cert_path = zap.tools_dir / "zap_cacert.pem"

        try:
            ok, cert_path = zap.fetch_ca_certificate(timeout=5.0)
            assert ok is True
            assert cert_path == str(zap.ca_cert_path)
            assert os.path.isfile(cert_path)

            with open(cert_path, "r", encoding="utf-8") as f:
                content = f.read()

            assert "-----BEGIN CERTIFICATE-----" in content
            assert "-----END CERTIFICATE-----" in content

            # Verify environment variables were set
            assert os.environ.get("REQUESTS_CA_BUNDLE") == cert_path
            assert os.environ.get("SSL_CERT_FILE") == cert_path
            assert os.environ.get("CURL_CA_BUNDLE") == cert_path
            assert os.environ.get("HTTP_PROXY") == f"http://127.0.0.1:{mock_zap_server.port}"
        finally:
            zap.unset_environment_proxies()

        # Verify environment variables were restored
        assert os.environ.get("HTTP_PROXY") is None or "127.0.0.1" not in os.environ.get("HTTP_PROXY", "")

    def test_zap_passive_drain_settle_two_consecutive_zeros(self, mock_zap_server):
        """
        Verify drain_passive_scan:
        - handles fluctuating queue count (3 -> 0 -> 1 -> 0 -> 0)
        - requires two consecutive zeros ~1s apart before returning True
        - resets consecutive zero counter if count fluctuates back above zero
        """
        zap = ZAPManager(port=mock_zap_server.port)
        # Flickering sequence: 3 -> 0 (1st zero) -> 1 (reset!) -> 0 (1st zero) -> 0 (2nd zero -> done)
        mock_zap_server.records_sequence = [3, 0, 1, 0, 0]
        mock_zap_server.records_to_scan_calls.clear()

        slept_intervals: List[float] = []

        def tracked_sleep(seconds: float) -> None:
            slept_intervals.append(seconds)

        with patch("time.sleep", side_effect=tracked_sleep):
            drained = zap.drain_passive_scan(timeout=15.0, settle_delay=1.0)

        assert drained is True
        # All 5 values in the sequence were fetched
        assert len(mock_zap_server.records_to_scan_calls) == 5
        # Verified sleep was called with settle_delay=1.0 at least twice for the zeros
        assert len(slept_intervals) >= 2
        assert all(interval == 1.0 for interval in slept_intervals)

    def test_zap_risk_confidence_matrix_and_false_positive_drop(self, mock_zap_server):
        """
        Verify Risk x Confidence matrix alert mapping:
        - Alert 1: Risk 'High', Confidence 'High' -> Severity.HIGH, Confidence.POSSIBLE
        - Alert 2: Risk 'High', Confidence 'Low' -> Severity.MEDIUM (downgraded), Confidence.POSSIBLE
        - Alert 3: Risk 'Medium', Confidence 'Medium' -> Severity.MEDIUM, Confidence.POSSIBLE
        - Alert 4: Risk 'Low', Confidence 'Low' -> Severity.LOW, Confidence.POSSIBLE
        - Alert 5: Risk 'Informational', Confidence 'Medium' -> Severity.INFO, Confidence.INFO
        - Alert 6: Risk 'High', Confidence 'False Positive' -> MUST BE DROPPED
        - Alert 7: Confidence '0' -> MUST BE DROPPED
        - Strict Invariant: NO finding has Confidence.VERIFIED
        """
        zap = ZAPManager(port=mock_zap_server.port)
        findings = zap.get_alerts(base_url=f"http://127.0.0.1:{mock_zap_server.port}")

        # 7 raw alerts: 2 dropped (False Positive and Confidence 0), exactly 5 returned
        assert len(findings) == 5

        by_title = {f.title: f for f in findings}

        # Assert dropped alerts are NOT present
        assert "High Risk False Positive Flagged by Scanner" not in by_title
        assert "Zero Confidence Anomaly" not in by_title

        # Alert 1: High + High -> Severity.HIGH, Confidence.POSSIBLE
        f1 = by_title["SQL Injection"]
        assert f1.severity == Severity.HIGH
        assert f1.confidence == "POSSIBLE"
        assert f1.cwe == "CWE-89"
        assert f1.metadata.get("source") == "zap"
        assert f1.metadata.get("plugin_id") == "40018"

        # Alert 2: High + Low -> Severity.MEDIUM (downgraded due to low confidence), Confidence.POSSIBLE
        f2 = by_title["Remote Code Execution Candidate"]
        assert f2.severity == Severity.MEDIUM
        assert f2.confidence == "POSSIBLE"
        assert f2.cwe == "CWE-78"

        # Alert 3: Medium + Medium -> Severity.MEDIUM, Confidence.POSSIBLE
        f3 = by_title["Cross Site Scripting (Reflected)"]
        assert f3.severity == Severity.MEDIUM
        assert f3.confidence == "POSSIBLE"
        assert f3.cwe == "CWE-79"

        # Alert 4: Low + Low -> Severity.LOW, Confidence.POSSIBLE
        f4 = by_title["Cookie Without SameSite Attribute"]
        assert f4.severity == Severity.LOW
        assert f4.confidence == "POSSIBLE"

        # Alert 5: Informational + Medium -> Severity.INFO, Confidence.INFO
        f5 = by_title["Information Disclosure - Debug Headers"]
        assert f5.severity == Severity.INFO
        assert f5.confidence == "INFO"

        # Strict invariant verification: under NO circumstances should ZAP assign VERIFIED
        for f in findings:
            assert f.confidence != "VERIFIED"
            assert f.confidence != Confidence.VERIFIED

    def test_zap_burp_chaining_when_active(self, mock_zap_server, capsys):
        """
        Verify upstream proxy chaining:
        - When Burp is active on 8080: configures ZAP upstream proxy and logs notification
        - When Burp is inactive: no upstream proxy is configured
        """
        zap = ZAPManager(port=mock_zap_server.port)

        # 1. Burp is inactive
        mock_zap_server.recorded_requests.clear()
        with patch("app.tools.burp.BurpManager.is_proxy_running", return_value=False):
            active = zap._check_and_setup_burp_chaining()
            assert active is False
            assert zap.burp_chaining is False

            # No proxy chain configuration endpoints called
            proxy_endpoints = [
                r for r in mock_zap_server.recorded_requests
                if "proxy" in r["path"].lower() or "httpproxy" in r["path"].lower()
            ]
            assert len(proxy_endpoints) == 0

        # 2. Burp is active on 127.0.0.1:8080
        mock_zap_server.recorded_requests.clear()
        with patch("app.tools.burp.BurpManager.is_proxy_running", return_value=True):
            active = zap._check_and_setup_burp_chaining()
            assert active is True
            assert zap.burp_chaining is True

            # Notification emitted
            captured = capsys.readouterr()
            assert "Active Burp Suite proxy detected on 127.0.0.1:8080" in captured.out
            assert "chaining ZAP upstream -> Burp" in captured.out

            # Upstream proxy endpoints called on mock ZAP
            proxy_endpoints = [
                r for r in mock_zap_server.recorded_requests
                if "proxy" in r["path"].lower() or "httpproxy" in r["path"].lower()
            ]
            assert len(proxy_endpoints) > 0

    def test_zap_lifecycle_ownership(self, mock_zap_server, tmp_path):
        """
        Verify daemon lifecycle ownership:
        - When _owns_daemon=True: context manager / stop_daemon calls shutdown
        - When _owns_daemon=False (reused daemon): context manager does NOT call shutdown
        """
        mock_zap_server.unauthorized = False
        mock_zap_server.shutdown_count = 0

        # 1. Reused daemon (_owns_daemon=False)
        zap_reused = ZAPManager(port=mock_zap_server.port)
        zap_reused.tools_dir = tmp_path / "zap_reused"
        zap_reused.ca_cert_path = zap_reused.tools_dir / "zap_cacert.pem"

        with patch.object(zap_reused, "find_zap_binary", return_value="zap.bat"):
            with ZAPSessionContext(
                target_url="http://127.0.0.1:8000",
                port=mock_zap_server.port,
                zap_manager=zap_reused,
            ) as ctx_zap:
                assert ctx_zap.owns_daemon is False

        # As daemon was reused, shutdown was NOT called
        assert mock_zap_server.shutdown_count == 0

        # 2. Owned daemon (_owns_daemon=True)
        zap_owned = ZAPManager(port=mock_zap_server.port)
        zap_owned.tools_dir = tmp_path / "zap_owned"
        zap_owned.ca_cert_path = zap_owned.tools_dir / "zap_cacert.pem"
        zap_owned._owns_daemon = True
        mock_proc = MagicMock()
        mock_proc.poll.return_value = 0
        mock_proc.wait.return_value = 0
        zap_owned._process = mock_proc

        zap_owned.stop_daemon()
        # As daemon was owned, shutdown API was invoked
        assert mock_zap_server.shutdown_count == 1
        assert zap_owned.owns_daemon is False

    def test_zap_findings_flow_through_dedup_and_validators(self, mock_zap_server):
        """
        Verify ZAP findings flow through DuplicateRiskScorer and ValidationEngine:
        - DuplicateRiskScorer assigns duplicate risk score without throwing errors
        - ValidationEngine processes ZAP findings safely without modifying non-verifiable findings
        - Findings serialize cleanly into report structures
        """
        zap = ZAPManager(port=mock_zap_server.port)
        zap_findings = zap.get_alerts(base_url=f"http://127.0.0.1:{mock_zap_server.port}")
        assert len(zap_findings) == 5

        # 1. Flow through DuplicateRiskScorer
        scorer = DuplicateRiskScorer()
        for f in zap_findings:
            scored_finding = scorer.score_finding(f, tech_stack=["nginx", "python", "php"])
            assert scored_finding is f
            assert "duplicate_risk" in f.metadata
            risk_info = f.metadata["duplicate_risk"]
            assert isinstance(risk_info, dict)
            assert isinstance(risk_info["score"], float)
            assert 0.0 <= risk_info["score"] <= 1.0
            assert risk_info["risk_level"] in ("LOW", "MEDIUM", "HIGH")
            assert "submission_flags" in f.metadata

        # 2. Flow through ValidationEngine
        report = ReconReport(
            url=f"http://127.0.0.1:{mock_zap_server.port}",
            scan_results=[
                ScanResult(
                    scanner_name="zap",
                    description="OWASP ZAP passive audit findings",
                    findings=zap_findings,
                )
            ],
        )

        engine = ValidationEngine()
        validated_report = engine.validate_report(report)

        assert validated_report is report
        assert len(validated_report.scan_results) == 1
        processed_findings = validated_report.scan_results[0].findings
        assert len(processed_findings) == 5

        # All findings retain valid enum severity, string confidence, and can be serialized
        for f in processed_findings:
            assert isinstance(f.severity, Severity)
            assert isinstance(f.confidence, str)
            d = f.to_dict()
            assert "severity" in d
            assert "category" in d
            assert d["category"] == "zap"

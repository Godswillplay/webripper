"""
Unit tests for OWASP ZAP integration manager (app.tools.zap).
"""

from __future__ import annotations

import io
import json
import os
import platform
import subprocess
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.models import Confidence, Severity
from app.tools.zap import COMMON_ZAP_PATHS, ZAPManager, ZAPSessionContext


class TestZAPDetection:
    """Test ZAP executable detection across platforms and paths."""

    def test_find_zap_binary_in_tools_dir(self, tmp_path, monkeypatch):
        mgr = ZAPManager()
        mgr.tools_dir = tmp_path
        ext = "zap.bat" if platform.system() == "Windows" else "zap.sh"
        fake_binary = tmp_path / ext
        fake_binary.write_text("echo zap", encoding="utf-8")

        found = mgr.find_zap_binary()
        assert found == str(fake_binary)

    def test_find_zap_binary_in_tools_subdir(self, tmp_path, monkeypatch):
        mgr = ZAPManager()
        mgr.tools_dir = tmp_path
        ext = "zap.bat" if platform.system() == "Windows" else "zap.sh"
        sub = tmp_path / "zap"
        sub.mkdir()
        fake_binary = sub / ext
        fake_binary.write_text("echo zap", encoding="utf-8")

        found = mgr.find_zap_binary()
        assert found == str(fake_binary)

    def test_find_zap_binary_in_common_paths(self, tmp_path, monkeypatch):
        mgr = ZAPManager()
        mgr.tools_dir = tmp_path
        fake_path = str(tmp_path / "mock_zap.sh")
        Path(fake_path).write_text("echo zap", encoding="utf-8")

        monkeypatch.setattr("app.tools.zap.COMMON_ZAP_PATHS", [fake_path])
        found = mgr.find_zap_binary()
        assert found == fake_path

    def test_find_zap_binary_in_path(self, tmp_path, monkeypatch):
        mgr = ZAPManager()
        mgr.tools_dir = tmp_path
        monkeypatch.setattr("app.tools.zap.COMMON_ZAP_PATHS", [])
        monkeypatch.setattr("shutil.which", lambda name: f"/usr/bin/{name}" if "zap" in name else None)

        found = mgr.find_zap_binary()
        assert found is not None
        assert "zap" in found

    def test_find_zap_binary_detects_portable_jar(self, tmp_path, monkeypatch):
        mgr = ZAPManager()
        mgr.tools_dir = tmp_path
        jar_file = tmp_path / "zap-2.14.0.jar"
        jar_file.write_text("fake jar", encoding="utf-8")
        monkeypatch.setattr("app.tools.zap.COMMON_ZAP_PATHS", [])
        monkeypatch.setattr("shutil.which", lambda name: None)

        found = mgr.find_zap_binary()
        assert found == str(jar_file)

    def test_detect_zap_not_installed(self, tmp_path, monkeypatch):
        mgr = ZAPManager()
        mgr.tools_dir = tmp_path
        monkeypatch.setattr("app.tools.zap.COMMON_ZAP_PATHS", [])
        monkeypatch.setattr("shutil.which", lambda name: None)

        res = mgr.detect_zap()
        assert res["installed"] is False
        assert res["path"] is None


class TestZAPProbe:
    """Test ZAP port probing."""

    def test_probe_zap_unlocked_success(self):
        mgr = ZAPManager()
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({"version": "2.14.0"}).encode("utf-8")

        with patch("urllib.request.OpenerDirector.open", return_value=mock_resp):
            is_open, is_unlocked = mgr.probe_zap(8090)
            assert is_open is True
            assert is_unlocked is True

    def test_probe_zap_locked_401(self):
        mgr = ZAPManager()
        err = urllib.error.HTTPError(
            url="http://127.0.0.1:8090/JSON/core/view/version/",
            code=401,
            msg="Unauthorized",
            hdrs={},
            fp=io.BytesIO(b"API key required"),
        )
        with patch("urllib.request.OpenerDirector.open", side_effect=err):
            is_open, is_unlocked = mgr.probe_zap(8090)
            assert is_open is True
            assert is_unlocked is False

    def test_probe_zap_locked_403(self):
        mgr = ZAPManager()
        err = urllib.error.HTTPError(
            url="http://127.0.0.1:8090/JSON/core/view/version/",
            code=403,
            msg="Forbidden",
            hdrs={},
            fp=io.BytesIO(b"Forbidden"),
        )
        with patch("urllib.request.OpenerDirector.open", side_effect=err):
            is_open, is_unlocked = mgr.probe_zap(8090)
            assert is_open is True
            assert is_unlocked is False

    def test_probe_zap_other_service_200(self):
        mgr = ZAPManager()
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"<html>Welcome to Nginx</html>"

        with patch("urllib.request.OpenerDirector.open", return_value=mock_resp):
            is_open, is_unlocked = mgr.probe_zap(8090)
            assert is_open is True
            assert is_unlocked is False

    def test_probe_zap_connection_refused(self):
        mgr = ZAPManager()
        err = urllib.error.URLError(reason=ConnectionRefusedError(10061, "Connection refused"))
        with patch("urllib.request.OpenerDirector.open", side_effect=err):
            is_open, is_unlocked = mgr.probe_zap(8090)
            assert is_open is False
            assert is_unlocked is False


class TestZAPDaemonLifecycleAndBurpChaining:
    """Test start_daemon, port selection, Burp upstream chaining, and shutdown."""

    def test_reuse_existing_unlocked_daemon_8090(self):
        mgr = ZAPManager()
        with patch.object(mgr, "probe_zap", return_value=(True, True)):
            with patch.object(mgr, "_check_and_setup_burp_chaining", return_value=False):
                ok = mgr.start_daemon(port=8090)
                assert ok is True
                assert mgr.port == 8090
                assert mgr.owns_daemon is False

    def test_port_selection_fallback_to_8091(self):
        mgr = ZAPManager()

        def mock_probe(p):
            if p == 8090:
                # Locked on 8090
                return True, False
            if p == 8091:
                # Unlocked on 8091
                return True, True
            return False, False

        with patch.object(mgr, "probe_zap", side_effect=mock_probe):
            with patch.object(mgr, "_check_and_setup_burp_chaining", return_value=False):
                ok = mgr.start_daemon(port=8090)
                assert ok is True
                assert mgr.port == 8091
                assert mgr.owns_daemon is False

    def test_port_selection_both_locked_raises(self):
        mgr = ZAPManager()

        def mock_probe(p):
            return True, False  # both 8090 and 8091 locked

        with patch.object(mgr, "probe_zap", side_effect=mock_probe):
            with pytest.raises(RuntimeError, match="both occupied"):
                mgr.start_daemon(port=8090)

    def test_spawn_daemon_flags_and_burp_chaining(self, monkeypatch, capsys):
        mgr = ZAPManager()
        # Initial probe: port is free
        probe_calls = [(False, False), (True, True)]

        def mock_probe(p):
            if probe_calls:
                return probe_calls.pop(0)
            return True, True

        monkeypatch.setattr(mgr, "probe_zap", mock_probe)
        monkeypatch.setattr(mgr, "find_zap_binary", lambda: "mock_zap.bat")

        # Burp proxy is active on 8080
        mock_burp = MagicMock()
        mock_burp.is_proxy_running.return_value = True
        monkeypatch.setattr("app.tools.burp.BurpManager", lambda: mock_burp)

        captured_cmd = []
        captured_env = {}

        class MockProcess:
            returncode = 0
            def poll(self):
                return None
            def wait(self, timeout=None):
                return 0

        def mock_popen(cmd, env=None, **kwargs):
            nonlocal captured_cmd, captured_env
            captured_cmd = cmd
            captured_env = env
            return MockProcess()

        monkeypatch.setattr(subprocess, "Popen", mock_popen)

        ok = mgr.start_daemon(port=8090, timeout=5.0)
        assert ok is True
        assert mgr.owns_daemon is True
        assert mgr.burp_chaining is True

        # Check command arguments
        assert "mock_zap.bat" in captured_cmd
        assert "-Xmx512m" in captured_cmd
        assert "-daemon" in captured_cmd
        assert "-host" in captured_cmd
        assert "127.0.0.1" in captured_cmd
        assert "-port" in captured_cmd
        assert "8090" in captured_cmd
        assert "-config" in captured_cmd
        assert "api.disablekey=true" in captured_cmd

        # Check Burp chaining config flags
        assert "connection.proxyChain.enabled=true" in captured_cmd
        assert "connection.proxyChain.hostName=127.0.0.1" in captured_cmd
        assert "connection.proxyChain.port=8080" in captured_cmd
        assert "network.connection.httpProxy.enabled=true" in captured_cmd
        assert "network.connection.httpProxy.host=127.0.0.1" in captured_cmd
        assert "network.connection.httpProxy.port=8080" in captured_cmd

        # Check Java memory options
        assert captured_env.get("JAVA_OPTS") == "-Xmx512m"
        assert captured_env.get("_JAVA_OPTIONS") == "-Xmx512m"
        assert captured_env.get("jvmopts") == "-Xmx512m"

        # Check logged stdout
        out, _ = capsys.readouterr()
        assert "[ZAP] Active Burp Suite proxy detected on 127.0.0.1:8080 — chaining ZAP upstream -> Burp." in out
        assert "[ZAP] Note: WebRipper crawl traffic will appear in your Burp HTTP history." in out

    def test_spawn_daemon_jar_binary_uses_java_invocation(self, monkeypatch):
        mgr = ZAPManager()
        probe_calls = [(False, False), (True, True)]
        monkeypatch.setattr(mgr, "probe_zap", lambda p: probe_calls.pop(0) if probe_calls else (True, True))
        monkeypatch.setattr(mgr, "_check_and_setup_burp_chaining", lambda: False)
        monkeypatch.setattr(mgr, "find_zap_binary", lambda: "/tools/zap/zap.jar")
        monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/java" if name == "java" else None)

        captured_cmd = None
        captured_env = None

        class MockProcess:
            def poll(self):
                return None
            def wait(self, timeout=None):
                return 0

        def mock_popen(cmd, env=None, **kwargs):
            nonlocal captured_cmd, captured_env
            captured_cmd = cmd
            captured_env = env
            return MockProcess()

        monkeypatch.setattr(subprocess, "Popen", mock_popen)

        ok = mgr.start_daemon(port=8090, timeout=5.0)
        assert ok is True
        assert captured_cmd[0] == "/usr/bin/java"
        assert captured_cmd[1] == "-Xmx512m"
        assert captured_cmd[2] == "-jar"
        assert captured_cmd[3] == "/tools/zap/zap.jar"
        assert "-daemon" in captured_cmd
        assert captured_env.get("JAVA_OPTS") == "-Xmx512m"
        assert captured_env.get("_JAVA_OPTIONS") == "-Xmx512m"
        assert captured_env.get("jvmopts") == "-Xmx512m"

    def test_stop_daemon_owned(self):
        mgr = ZAPManager()
        mgr._owns_daemon = True
        mock_proc = MagicMock()
        mgr._process = mock_proc

        with patch.object(mgr, "_call_api") as mock_api:
            mgr.stop_daemon()
            mock_api.assert_called_with("/JSON/core/action/shutdown/", timeout=3.0)
            mock_proc.wait.assert_called_with(timeout=8.0)
            assert mgr.owns_daemon is False

    def test_stop_daemon_not_owned(self):
        mgr = ZAPManager()
        mgr._owns_daemon = False
        mgr._process = None

        with patch.object(mgr, "_call_api") as mock_api:
            mgr.stop_daemon()
            mock_api.assert_not_called()


class TestZAPCertAndProxies:
    """Test dynamic live root CA certificate retrieval and environment proxy configuration."""

    def test_fetch_ca_certificate_pem(self, tmp_path):
        mgr = ZAPManager()
        mgr.tools_dir = tmp_path
        mgr.ca_cert_path = tmp_path / "zap_cacert.pem"

        fake_pem = b"-----BEGIN CERTIFICATE-----\nMIIC...FAKE...\n-----END CERTIFICATE-----\n"
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.read.return_value = fake_pem

        with patch("urllib.request.OpenerDirector.open", return_value=mock_resp):
            ok, cert_path = mgr.fetch_ca_certificate()
            assert ok is True
            assert Path(cert_path).is_file()
            assert Path(cert_path).read_text(encoding="utf-8").strip() == fake_pem.decode("utf-8").strip()

    def test_fetch_ca_certificate_der_converted(self, tmp_path):
        mgr = ZAPManager()
        mgr.tools_dir = tmp_path
        mgr.ca_cert_path = tmp_path / "zap_cacert.pem"

        # Starts with DER header \x30\x82
        fake_der = b"\x30\x82\x01\x00" + b"\x00" * 100
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.read.return_value = fake_der

        with patch("urllib.request.OpenerDirector.open", return_value=mock_resp):
            with patch("ssl.DER_cert_to_PEM_cert", return_value="-----BEGIN CERTIFICATE-----\nDER_PEM\n-----END CERTIFICATE-----\n"):
                ok, cert_path = mgr.fetch_ca_certificate()
                assert ok is True
                content = Path(cert_path).read_text(encoding="utf-8")
                assert "BEGIN CERTIFICATE" in content

    def test_environment_proxies_set_and_unset(self, tmp_path):
        mgr = ZAPManager(port=8090)
        mgr.tools_dir = tmp_path
        mgr.ca_cert_path = tmp_path / "zap_cacert.pem"
        mgr.ca_cert_path.write_text("CERT", encoding="utf-8")

        orig_http = os.environ.get("HTTP_PROXY")
        try:
            mgr.set_environment_proxies(set_ca=True)
            assert os.environ.get("HTTP_PROXY") == "http://127.0.0.1:8090"
            assert os.environ.get("NO_PROXY") == "localhost,127.0.0.1,::1"
            assert os.environ.get("REQUESTS_CA_BUNDLE") == str(mgr.ca_cert_path)

            mgr.unset_environment_proxies()
            assert os.environ.get("HTTP_PROXY") == orig_http
            assert "REQUESTS_CA_BUNDLE" not in os.environ or os.environ.get("REQUESTS_CA_BUNDLE") != str(mgr.ca_cert_path)
        finally:
            mgr.unset_environment_proxies()


class TestZAPSessionAndDrain:
    """Test session hygiene and passive scan queue drain."""

    def test_new_session_calls(self):
        mgr = ZAPManager()
        calls = []

        def mock_call(endpoint, params=None, **kwargs):
            calls.append((endpoint, params))
            return {}

        with patch.object(mgr, "_call_api", side_effect=mock_call):
            ok = mgr.new_session("https://target.example.com/api")
            assert ok is True

            # 1. newSession
            assert calls[0][0] == "/JSON/core/action/newSession/"
            assert calls[0][1]["name"] == "webripper_session"
            assert calls[0][1]["overwrite"] == "true"

            # 2. disableScanners
            assert calls[1][0] == "/JSON/pscan/action/disableScanners/"
            assert calls[1][1]["ids"] == "10096,10027"

            # 3. includeInContext
            assert calls[2][0] == "/JSON/context/action/includeInContext/"
            assert calls[2][1]["contextName"] == "Default Context"
            assert "target\\.example\\.com" in calls[2][1]["regex"]

            # 4. setScanOnlyInScope
            assert calls[3][0] == "/JSON/pscan/action/setScanOnlyInScope/"
            assert calls[3][1]["onlyInScope"] == "true"

    def test_drain_passive_scan_success(self):
        mgr = ZAPManager()
        # Returns [5, 0, 0] -> two consecutive zeros
        responses = [
            {"recordsToScan": "5"},
            {"recordsToScan": "0"},
            {"recordsToScan": "0"},
        ]

        def mock_call(endpoint, params=None, **kwargs):
            if responses:
                return responses.pop(0)
            return {"recordsToScan": "0"}

        with patch.object(mgr, "_call_api", side_effect=mock_call):
            with patch("time.sleep", return_value=None):
                drained = mgr.drain_passive_scan(timeout=5.0, settle_delay=0.01)
                assert drained is True

    def test_drain_passive_scan_timeout(self):
        mgr = ZAPManager()

        def mock_call(endpoint, params=None, **kwargs):
            return {"recordsToScan": "10"}

        with patch.object(mgr, "_call_api", side_effect=mock_call):
            # Short timeout, settle_delay
            drained = mgr.drain_passive_scan(timeout=0.05, settle_delay=0.02)
            assert drained is False


class TestZAPAlertsAndRiskMatrix:
    """Test alert harvesting, false positive filtering, and Risk x Confidence matrix."""

    def test_filter_false_positives(self):
        mgr = ZAPManager()
        sample_alerts = [
            {
                "id": "1",
                "alert": "FP Alert 1",
                "confidence": "False Positive",
                "risk": "High",
            },
            {
                "id": "2",
                "alert": "FP Alert 2",
                "confidence": "0",
                "risk": "Medium",
            },
            {
                "id": "3",
                "alert": "Real Alert",
                "confidence": "High",
                "risk": "Medium",
                "cweid": "79",
                "wascid": "8",
            },
        ]
        with patch.object(mgr, "_call_api", return_value={"alerts": sample_alerts}):
            findings = mgr.get_alerts("https://example.com")
            assert len(findings) == 1
            assert findings[0].title == "Real Alert"
            assert findings[0].cwe == "CWE-79"
            assert findings[0].wasc == "WASC-8"

    @pytest.mark.parametrize(
        "zap_risk,zap_conf,expected_sev,expected_conf",
        [
            ("High", "High", Severity.HIGH, "POSSIBLE"),
            ("High", "Medium", Severity.HIGH, "POSSIBLE"),
            ("High", "Low", Severity.MEDIUM, "POSSIBLE"),
            ("Medium", "High", Severity.MEDIUM, "POSSIBLE"),
            ("Medium", "Medium", Severity.MEDIUM, "POSSIBLE"),
            ("Medium", "Low", Severity.LOW, "POSSIBLE"),
            ("Low", "High", Severity.LOW, "POSSIBLE"),
            ("Low", "Low", Severity.LOW, "POSSIBLE"),
            ("Informational", "High", Severity.INFO, "INFO"),
            ("Informational", "Low", Severity.INFO, "INFO"),
        ],
    )
    def test_risk_confidence_matrix(self, zap_risk, zap_conf, expected_sev, expected_conf):
        mgr = ZAPManager()
        alert = {
            "id": "100",
            "pluginId": "40012",
            "alert": f"Test {zap_risk} {zap_conf}",
            "description": "Test description",
            "risk": zap_risk,
            "confidence": zap_conf,
            "url": "https://example.com/test",
            "evidence": "foo=bar",
            "param": "foo",
            "attack": "' OR '1'='1",
            "cweid": "89",
            "wascid": "19",
        }
        with patch.object(mgr, "_call_api", return_value={"alerts": [alert]}):
            findings = mgr.get_alerts("https://example.com")
            assert len(findings) == 1
            f = findings[0]
            assert f.severity == expected_sev
            assert f.confidence == expected_conf
            assert f.confidence != "VERIFIED"
            assert "foo=bar" in f.evidence
            assert "Param: foo" in f.evidence
            assert "Attack: ' OR '1'='1" in f.evidence
            assert f.metadata["source"] == "zap"
            assert f.metadata["plugin_id"] == "40012"
            assert f.metadata["alert_id"] == "100"
            assert f.cwe == "CWE-89"
            assert f.wasc == "WASC-19"


class TestZAPSessionContextManager:
    """Test ZAPSessionContext execution flow and cleanup."""

    def test_context_manager_lifecycle(self):
        mgr = MagicMock(spec=ZAPManager)
        mgr.port = 8090
        mgr.start_daemon.return_value = True
        mgr.fetch_ca_certificate.return_value = (True, "/fake/cert.pem")

        progress_events = []

        def on_prog(msg, pct):
            progress_events.append((msg, pct))

        with ZAPSessionContext("https://example.com", port=8090, progress_cb=on_prog, zap_manager=mgr) as zap:
            assert zap == mgr
            mgr.start_daemon.assert_called_with(port=8090)
            mgr.fetch_ca_certificate.assert_called_once()
            mgr.set_environment_proxies.assert_called_with(set_ca=True)
            mgr.new_session.assert_called_with("https://example.com")

        mgr.stop_daemon.assert_called_once()
        assert len(progress_events) >= 4

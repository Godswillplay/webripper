"""
Unit tests for WebRipper Recon AI Agent, Ollama client, Tool Installer, and Burp Suite Manager.
"""

import json
import os
import tempfile
import zipfile
import pytest
from pathlib import Path

from app.tools.burp import BurpManager, BURP_COMMUNITY_JAR_URL
from app.tools.installer import (
    ToolInstaller,
    _safe_extract_zip,
    _safe_extract_tar,
    _get_github_asset_pattern,
    get_linux_package_manager,
)
from app.tools.detector import _find_tool, detect_all_tools, install_tool, install_all_missing
from app.tools.runner import run_nmap, ensure_nuclei_templates, _has_nuclei_templates
from app.ai.client import OllamaClient
from app.ai.setup import AISetupManager, RECOMMENDED_MODELS
from app.ai.tools import AgentToolbox
from app.ai.agent import AIAgent
from app.models import Finding, Severity, ScanResult, AttackChain, AttackChainStep, ReconReport


class TestBurpManager:
    """Test Burp Suite detection and CA certificate retrieval."""

    def test_detect_burp_structure(self):
        mgr = BurpManager()
        info = mgr.detect_burp()
        assert "installed" in info
        assert "edition" in info
        assert "path" in info

    def test_is_proxy_running_offline(self):
        # Unused local port should return False without crashing
        mgr = BurpManager(proxy_url="http://127.0.0.1:59999")
        assert mgr.is_proxy_running(timeout=0.2) is False

    def test_ca_certificate_der_to_pem(self, tmp_path):
        mgr = BurpManager()
        mgr.tools_dir = tmp_path
        mgr.ca_cert_path = tmp_path / "test_cacert.pem"

        # Simulate fetch failure when proxy is offline
        ok, msg = mgr.fetch_ca_certificate(timeout=0.2)
        assert ok is False
        assert "Could not fetch certificate" in msg


class TestToolInstallerAndZipSlip:
    """Test safe extraction and tool detection."""

    def test_safe_extract_zip_normal(self, tmp_path):
        target_dir = tmp_path / "extract_dest"
        target_dir.mkdir()
        zip_file = tmp_path / "normal.zip"

        with zipfile.ZipFile(zip_file, "w") as zf:
            zf.writestr("test.txt", "hello world")
            zf.writestr("sub/subtest.txt", "hello sub")

        with zipfile.ZipFile(zip_file, "r") as zf:
            _safe_extract_zip(zf, str(target_dir))

        assert (target_dir / "test.txt").exists()
        assert (target_dir / "sub" / "subtest.txt").exists()

    def test_zip_slip_prevention(self, tmp_path):
        target_dir = tmp_path / "safe_dir"
        target_dir.mkdir()
        bad_zip = tmp_path / "malicious.zip"

        with zipfile.ZipFile(bad_zip, "w") as zf:
            zf.writestr("../../evil.txt", "exploit")

        with pytest.raises(RuntimeError, match="Zip Slip attempt detected"):
            with zipfile.ZipFile(bad_zip, "r") as zf:
                _safe_extract_zip(zf, str(target_dir))

    def test_safe_extract_tar_normal(self, tmp_path):
        import tarfile
        import io
        target_dir = tmp_path / "tar_dest"
        target_dir.mkdir()
        tar_file = tmp_path / "normal.tar.gz"

        with tarfile.open(tar_file, "w:gz") as tf:
            data = b"hello linux tar"
            ti = tarfile.TarInfo(name="test.txt")
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))

        with tarfile.open(tar_file, "r:gz") as tf:
            _safe_extract_tar(tf, str(target_dir))

        assert (target_dir / "test.txt").exists()
        assert (target_dir / "test.txt").read_text(encoding="utf-8") == "hello linux tar"

    def test_tar_slip_prevention(self, tmp_path):
        import tarfile
        import io
        target_dir = tmp_path / "safe_tar_dir"
        target_dir.mkdir()
        bad_tar = tmp_path / "malicious.tar.gz"

        with tarfile.open(bad_tar, "w:gz") as tf:
            data = b"exploit"
            ti = tarfile.TarInfo(name="../../evil.txt")
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))

        with pytest.raises(RuntimeError, match="Tar Slip attempt detected"):
            with tarfile.open(bad_tar, "r:gz") as tf:
                _safe_extract_tar(tf, str(target_dir))

    def test_tar_slip_symlink_prevention(self, tmp_path):
        import tarfile
        target_dir = tmp_path / "safe_tar_symlink_dir"
        target_dir.mkdir()
        bad_tar = tmp_path / "symlink_evil.tar.gz"

        with tarfile.open(bad_tar, "w:gz") as tf:
            ti = tarfile.TarInfo(name="evil_link")
            ti.type = tarfile.SYMTYPE
            ti.linkname = "../../etc/shadow"
            tf.addfile(ti)

        with pytest.raises(RuntimeError, match="Tar Slip symlink attempt detected"):
            with tarfile.open(bad_tar, "r:gz") as tf:
                _safe_extract_tar(tf, str(target_dir))

    def test_get_installable_tools_returns_all(self):
        installer = ToolInstaller()
        tools = installer.get_installable_tools()
        assert "burpsuite" in tools
        assert "nmap" in tools
        assert "nuclei" in tools
        assert "sqlmap" in tools
        assert "gobuster" in tools


class TestAISetupAndClient:
    """Test AI setup recommendations and client initialization."""

    def test_recommended_models_list(self):
        mgr = AISetupManager()
        status = mgr.get_status()
        assert "server_running" in status
        assert len(status["recommended"]) >= 4
        assert status["recommended"][0]["name"] == "dolphin3-cyber:8b"
        assert any(r["name"] == "qwen2.5-coder:7b" for r in status["recommended"])
        assert any("llama3-abliterated" in r["name"] for r in status["recommended"])

    def test_client_offline_detection(self):
        client = OllamaClient(base_url="http://127.0.0.1:59998")
        assert client.is_server_running(timeout=0.2) is False
        assert client.list_models(timeout=0.2) == []


class TestAgentToolboxAndAgent:
    """Test AI agent tool execution and ReAct loop."""

    def test_toolbox_read_file(self, tmp_path):
        app_js = tmp_path / "app.js"
        app_js.write_text("console.log('secret_token = 12345');\nvar api = '/api/v1';", encoding="utf-8")

        toolbox = AgentToolbox(output_dir=str(tmp_path))
        content = toolbox.execute_tool("read_file", {"path": "app.js", "max_lines": 5})
        assert "secret_token" in content
        assert "app.js" in content

    def test_toolbox_search_code(self, tmp_path):
        (tmp_path / "main.js").write_text("fetch('/api/v2/auth/login');", encoding="utf-8")
        toolbox = AgentToolbox(output_dir=str(tmp_path))
        results = toolbox.execute_tool("search_code", {"query": "auth/login"})
        assert "main.js" in results
        assert "/api/v2/auth/login" in results

    def test_toolbox_get_scan_findings(self, tmp_path):
        recon = ReconReport(url="https://target.com")
        f = Finding(
            severity=Severity.HIGH,
            category="cors",
            title="CORS allows null Origin",
            description="Sandbox iframe can steal tokens.",
        )
        recon.scan_results.append(ScanResult(scanner_name="cors", findings=[f]))
        recon.attack_chains.append(AttackChain(
            name="CORS Data Theft",
            severity=Severity.HIGH,
            steps=[AttackChainStep(description="Trigger CORS", finding=f)],
        ))

        toolbox = AgentToolbox(output_dir=str(tmp_path), recon_report=recon)
        summary = toolbox.execute_tool("get_scan_findings", {})
        assert "Total Findings: 1" in summary
        assert "CORS allows null Origin" in summary
        assert "CORS Data Theft" in summary

    def test_lookup_vulnerability_intelligence_tool(self, tmp_path):
        toolbox = AgentToolbox(output_dir=str(tmp_path))
        
        # Test search by query
        res1 = toolbox.execute_tool("lookup_vulnerability_intelligence", {"query": "Next.js"})
        assert "Bug Bounty Intelligence" in res1
        assert "Next.js" in res1 or "nextjs" in res1.lower()

        # Test search by tech_stack
        res2 = toolbox.execute_tool("lookup_vulnerability_intelligence", {"tech_stack": "supabase"})
        assert "Bug Bounty Intelligence" in res2
        assert "H1-SUPABASE-001" in res2 or "Supabase" in res2

        # Test combined query and tech_stack
        res3 = toolbox.execute_tool("lookup_vulnerability_intelligence", {"query": "GraphQL", "tech_stack": "graphql"})
        assert "Bug Bounty Intelligence" in res3

        # Test empty input error
        res_empty = toolbox.execute_tool("lookup_vulnerability_intelligence", {})
        assert "Error: Either 'query' or 'tech_stack'" in res_empty

    def test_agent_react_execution(self, tmp_path):
        # Create a mock client that answers via ReAct action then final answer
        (tmp_path / "config.json").write_text('{"apiKey": "AIzaSySecret"}', encoding="utf-8")
        toolbox = AgentToolbox(output_dir=str(tmp_path))

        class MockOllamaClient:
            def __init__(self):
                self.calls = 0

            def chat(self, messages, system_prompt=None, temperature=0.1):
                self.calls += 1
                if self.calls == 1:
                    return (
                        "Thought: I should search for the API key in the codebase.\n"
                        'Action: {"tool": "search_code", "args": {"query": "apiKey"}}'
                    )
                else:
                    return "Final Answer: The API key was discovered in config.json as 'AIzaSySecret'."

        mock_client = MockOllamaClient()
        agent = AIAgent(toolbox=toolbox, client=mock_client)
        progress_events = []
        answer = agent.run_task("Find the leaked API key", progress_cb=lambda p, m: progress_events.append(p))

        assert "AIzaSySecret" in answer
        assert mock_client.calls == 2
        assert "tool_call" in progress_events
        assert "finish" in progress_events

    def test_extract_action_data_with_nested_braces_in_string(self):
        from app.ai.agent import _extract_action_data
        response = '''Thought: I will search for function with braces.
Action: {"tool": "search_code", "args": {"query": "function test() { return true; }"}}'''
        action, thought = _extract_action_data(response)
        assert action is not None
        assert action["tool"] == "search_code"
        assert action["args"]["query"] == "function test() { return true; }"
        assert "function with braces" in thought

    def test_burp_env_proxy_includes_no_proxy(self):
        from app.tools.burp import BurpManager
        import os

        saved_snapshot = {
            var: os.environ.get(var)
            for var in BurpManager.ENV_PROXY_VARS
        }

        try:
            # Set up explicit initial state: pre-existing NO_PROXY and ALL_PROXY, absent HTTP_PROXY
            os.environ["NO_PROXY"] = "preexisting.internal"
            os.environ["ALL_PROXY"] = "socks5://127.0.0.1:9050"
            os.environ.pop("HTTP_PROXY", None)
            os.environ.pop("HTTPS_PROXY", None)

            bm = BurpManager(proxy_url="http://127.0.0.1:8080")
            bm.set_environment_proxies(set_ca=False)

            # While active, proxies are set and NO_PROXY includes local loopbacks
            assert os.environ.get("NO_PROXY") == "localhost,127.0.0.1,::1"
            assert os.environ.get("HTTP_PROXY") == "http://127.0.0.1:8080"
            assert os.environ.get("ALL_PROXY") == "http://127.0.0.1:8080"

            bm.unset_environment_proxies()

            # After unset, original environment must be restored
            assert os.environ.get("NO_PROXY") == "preexisting.internal"
            assert os.environ.get("ALL_PROXY") == "socks5://127.0.0.1:9050"
            assert "HTTP_PROXY" not in os.environ
            assert "HTTPS_PROXY" not in os.environ
        finally:
            for var, val in saved_snapshot.items():
                if val is not None:
                    os.environ[var] = val
                else:
                    os.environ.pop(var, None)


class TestLinuxToolsParity:
    """Test Linux platform parity for tools subsystem: detection, install patterns, Burp JAR, Nmap fallback, Nuclei templates."""

    def test_linux_asset_patterns_x86_64(self, monkeypatch):
        import platform
        monkeypatch.setattr(platform, "system", lambda: "Linux")
        monkeypatch.setattr(platform, "machine", lambda: "x86_64")

        nuclei_pattern = _get_github_asset_pattern("nuclei")
        assert "linux" in nuclei_pattern.lower()
        assert "amd64" in nuclei_pattern.lower()
        assert nuclei_pattern.endswith(".zip")

        gobuster_pattern = _get_github_asset_pattern("gobuster")
        assert "linux" in gobuster_pattern.lower()
        assert "x86_64" in gobuster_pattern.lower()
        assert gobuster_pattern.endswith(".tar.gz")

        httpx_pattern = _get_github_asset_pattern("httpx")
        assert "linux" in httpx_pattern.lower()
        assert "amd64" in httpx_pattern.lower()

        subfinder_pattern = _get_github_asset_pattern("subfinder")
        assert "linux" in subfinder_pattern.lower()
        assert "amd64" in subfinder_pattern.lower()

    def test_linux_asset_patterns_arm64(self, monkeypatch):
        import platform
        monkeypatch.setattr(platform, "system", lambda: "Linux")
        monkeypatch.setattr(platform, "machine", lambda: "aarch64")

        nuclei_pattern = _get_github_asset_pattern("nuclei")
        assert "arm64" in nuclei_pattern.lower()
        assert nuclei_pattern.endswith(".zip")

        gobuster_pattern = _get_github_asset_pattern("gobuster")
        assert "arm64" in gobuster_pattern.lower()
        assert gobuster_pattern.endswith(".tar.gz")

    def test_linux_package_manager_detection(self, monkeypatch):
        import shutil

        # Test Debian/Ubuntu/Kali
        monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/apt-get" if cmd == "apt-get" else None)
        pkg = get_linux_package_manager()
        assert pkg is not None
        assert pkg[0] == "apt-get"
        assert "sudo apt-get install -y" in pkg[1]

        # Test Arch
        monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/pacman" if cmd == "pacman" else None)
        pkg = get_linux_package_manager()
        assert pkg is not None
        assert pkg[0] == "pacman"
        assert "sudo pacman -S --noconfirm" in pkg[1]

        # Test Fedora
        monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/dnf" if cmd == "dnf" else None)
        pkg = get_linux_package_manager()
        assert pkg is not None
        assert pkg[0] == "dnf"
        assert "sudo dnf install -y" in pkg[1]

    def test_nmap_install_instructions_on_linux(self, monkeypatch):
        import platform
        monkeypatch.setattr(platform, "system", lambda: "Linux")
        monkeypatch.setattr("app.tools.installer.get_linux_package_manager", lambda: ("apt-get", "sudo apt-get install -y"))

        messages = []
        installer = ToolInstaller(progress_cb=lambda msg: messages.append(msg))
        ok = installer.install_tool("nmap")
        assert ok is False
        assert any("sudo apt-get install -y nmap" in m for m in messages)

    def test_burp_download_and_launch_jar_on_linux(self, monkeypatch, tmp_path):
        import platform
        import subprocess
        monkeypatch.setattr(platform, "system", lambda: "Linux")

        mgr = BurpManager()
        mgr.tools_dir = tmp_path

        # Test download creates .jar
        def mock_urlopen(req, timeout=60):
            class MockResp:
                def __init__(self):
                    self.headers = {"Content-Length": "12"}
                def read(self, chunk_size=None):
                    if not hasattr(self, "_read"):
                        self._read = True
                        return b"PK\x03\x04mockjar"
                    return b""
                def __enter__(self):
                    return self
                def __exit__(self, *args):
                    pass
            return MockResp()

        monkeypatch.setattr("app.tools.burp.urlopen", mock_urlopen)
        ok, dest = mgr.download_installer()
        assert ok is True
        assert dest.endswith(".jar")
        assert os.path.exists(dest)

        # Test launch executes java -jar
        executed_cmds = []
        monkeypatch.setattr(subprocess, "Popen", lambda cmd, **kwargs: executed_cmds.append(cmd))
        monkeypatch.setattr("shutil.which", lambda prog: "/usr/bin/java" if prog == "java" else None)

        launched = mgr.launch_installer(dest)
        assert launched is True
        assert len(executed_cmds) == 1
        assert executed_cmds[0] == ["/usr/bin/java", "-jar", dest]

    def test_burp_jar_detection_and_detector_alignment(self, tmp_path, monkeypatch):
        jar_path = tmp_path / "burpsuite_community.jar"
        jar_path.write_bytes(b"PK\x03\x04fakejar")

        mgr = BurpManager()
        mgr.tools_dir = tmp_path

        # BurpManager detects it
        info = mgr.detect_burp()
        assert info["installed"] is True
        assert info["edition"] == "Community (Portable JAR)"
        assert info["path"] == str(jar_path)

        # detector._find_tool and detect_all_tools detect it
        monkeypatch.setattr("app.tools.burp.BurpManager", lambda: mgr)
        monkeypatch.setattr("app.tools.detector.get_tools_dir", lambda: tmp_path)
        found_path = _find_tool("burpsuite")
        assert found_path == str(jar_path)

        all_tools = detect_all_tools()
        burp_status = next((t for t in all_tools if t.name == "Burp Suite"), None)
        assert burp_status is not None
        assert burp_status.installed is True
        assert burp_status.version == "Community (Portable JAR)"
        assert burp_status.path == str(jar_path)

    def test_nmap_cap_net_raw_fallback(self, tmp_path, monkeypatch):
        import subprocess

        calls = []

        class MockCompletedProcess:
            def __init__(self, returncode, stdout, stderr):
                self.returncode = returncode
                self.stdout = stdout
                self.stderr = stderr

        def mock_run(cmd, **kwargs):
            calls.append(list(cmd))
            if len(calls) == 1:
                # First run fails with raw socket error
                return MockCompletedProcess(
                    returncode=1,
                    stdout="",
                    stderr="Couldn't open a raw socket. Error: Operation not permitted (1)",
                )
            else:
                # Second run (unprivileged fallback) succeeds and writes mock XML
                xml_out = tmp_path / "nmap_output.xml"
                xml_out.write_text("""<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24"/>
      </port>
    </ports>
  </host>
</nmaprun>""", encoding="utf-8")
                return MockCompletedProcess(returncode=0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", mock_run)
        monkeypatch.setattr("app.tools.runner._find", lambda name: "/usr/bin/nmap")

        log_messages = []
        findings = run_nmap("127.0.0.1", str(tmp_path), progress_cb=lambda m: log_messages.append(m))

        assert len(calls) == 2
        # First call did not have -sT --unprivileged
        assert "-sT" not in calls[0]
        # Fallback call has -sT and --unprivileged
        assert "-sT" in calls[1]
        assert "--unprivileged" in calls[1]
        assert any("container/CAP_NET_RAW" in m for m in log_messages)
        assert len(findings) == 1
        assert "nginx" in findings[0].title

    def test_nuclei_templates_check_and_update(self, tmp_path, monkeypatch):
        import subprocess
        from app.tools import runner

        # Mock template check to return False
        monkeypatch.setattr(runner, "_has_nuclei_templates", lambda: False)

        calls = []
        class MockProc:
            returncode = 0
            stderr = ""

        monkeypatch.setattr(subprocess, "run", lambda cmd, **kwargs: calls.append(cmd) or MockProc())

        messages = []
        ok = ensure_nuclei_templates("/usr/bin/nuclei", progress_cb=lambda m: messages.append(m))

        assert ok is True
        assert len(calls) == 1
        assert calls[0] == ["/usr/bin/nuclei", "-update-templates"]
        assert any("Nuclei templates not found" in m for m in messages)
        assert any("updated successfully" in m for m in messages)

    def test_detector_delegates_to_tool_installer(self, monkeypatch):
        installed_tools = []
        missing_installed = []

        class MockToolInstaller:
            def __init__(self, progress_cb=None):
                self.progress_cb = progress_cb
            def install_tool(self, name):
                installed_tools.append(name)
                return True
            def install_all_missing(self):
                missing_installed.append(True)
                return {"nuclei": True}

        monkeypatch.setattr("app.tools.installer.ToolInstaller", MockToolInstaller)

        res1 = install_tool("nuclei")
        assert res1 is True
        assert installed_tools == ["nuclei"]

        res2 = install_all_missing()
        assert res2 == {"nuclei": True}
        assert missing_installed == [True]


class TestZAPToolRegistryIntegration:
    """Test OWASP ZAP integration in detector, installer, and runner."""

    def test_zap_in_tool_defs(self):
        from app.tools.detector import _TOOL_DEFS
        assert "zaproxy" in _TOOL_DEFS
        zap_def = _TOOL_DEFS["zaproxy"]
        assert zap_def["display"] == "OWASP ZAP"
        assert zap_def["check_args"] == ["-version"]
        assert zap_def["installable"] is False
        assert zap_def["size"] == "~200MB"
        assert zap_def["url"] == "https://www.zaproxy.org/download/"
        assert "Java 11+" in zap_def["note"]

    def test_detector_find_tool_delegates_to_zap_manager(self, monkeypatch):
        from app.tools.detector import _find_tool

        class MockZAPManager:
            def detect_zap(self):
                return {"installed": True, "path": "/opt/zaproxy/zap.sh", "version": "2.15.0"}

        monkeypatch.setattr("app.tools.zap.ZAPManager", MockZAPManager)

        assert _find_tool("zaproxy") == "/opt/zaproxy/zap.sh"
        assert _find_tool("zap") == "/opt/zaproxy/zap.sh"

    def test_detector_get_version_zap(self, monkeypatch):
        from app.tools.detector import _get_version

        class MockZAPManager:
            def detect_zap(self):
                return {"installed": True, "path": "/opt/zaproxy/zap.sh", "version": "2.15.0"}

        monkeypatch.setattr("app.tools.zap.ZAPManager", MockZAPManager)

        ver = _get_version("/opt/zaproxy/zap.sh", ["-version"])
        assert ver == "2.15.0"

    def test_installer_get_installable_tools_has_zaproxy(self, monkeypatch):
        from app.tools.installer import ToolInstaller

        class MockZAPManager:
            def detect_zap(self):
                return {"installed": True, "path": "C:\\Program Files\\OWASP\\Zed Attack Proxy\\zap.bat", "version": "2.15.0"}
            def is_proxy_running(self):
                return True

        monkeypatch.setattr("app.tools.installer.ZAPManager", MockZAPManager)

        installer = ToolInstaller()
        installer.zap_manager = MockZAPManager()
        tools = installer.get_installable_tools()

        assert "zaproxy" in tools
        z = tools["zaproxy"]
        assert z["type"] == "gui_proxy"
        assert z["installed"] is True
        assert z["path"] == "C:\\Program Files\\OWASP\\Zed Attack Proxy\\zap.bat"
        assert z["source"] == "zaproxy.org"
        assert z["proxy_active"] is True
        assert z["can_auto_install"] is False

    def test_installer_install_zap_hints(self, monkeypatch):
        import platform
        from app.tools.installer import ToolInstaller

        messages = []
        installer = ToolInstaller(progress_cb=lambda m: messages.append(m))

        # Test Windows hint
        monkeypatch.setattr(platform, "system", lambda: "Windows")
        res_win = installer.install_tool("zaproxy")
        assert res_win is False
        assert any("https://www.zaproxy.org/download/" in m for m in messages)

        # Test Linux hint with package manager
        messages.clear()
        monkeypatch.setattr(platform, "system", lambda: "Linux")
        monkeypatch.setattr(
            "app.tools.installer.get_linux_package_manager",
            lambda: ("apt-get", "sudo apt-get install -y"),
        )
        res_linux = installer.install_tool("zap")
        assert res_linux is False
        assert any("sudo apt-get install -y zaproxy" in m for m in messages)

    def test_runner_run_zap_contract(self, monkeypatch):
        from app.tools.runner import run_zap, zap_command
        from app.models import Finding, Severity, Confidence

        # Check command
        cmd = zap_command("https://example.com")
        assert "zaproxy" in cmd

        class MockZAPManager:
            def detect_zap(self):
                return {"installed": True, "path": "/usr/bin/zaproxy", "version": "2.15.0"}
            def is_proxy_running(self):
                return True
            def drain_passive_scan(self, timeout=20.0, settle_delay=1.0):
                return True
            def get_alerts(self, base_url=""):
                return [
                    Finding(
                        severity=Severity.HIGH,
                        category="zap",
                        title="SQL Injection",
                        description="Potential SQL injection detected",
                        confidence="VERIFIED",  # Should be downgraded to POSSIBLE!
                    ),
                    Finding(
                        severity=Severity.MEDIUM,
                        category="zap",
                        title="X-Frame-Options Missing",
                        description="Clickjacking possible",
                        confidence="LIKELY",  # Should be downgraded to POSSIBLE!
                    ),
                    Finding(
                        severity=Severity.INFO,
                        category="zap",
                        title="Timestamp Disclosure",
                        description="Info header found",
                        confidence="INFO",
                    ),
                ]

        monkeypatch.setattr("app.tools.zap.ZAPManager", MockZAPManager)

        findings = run_zap("https://example.com")
        assert len(findings) == 3

        # Critical invariant check: No ZAP finding can ever be VERIFIED!
        for f in findings:
            conf = f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence)
            assert conf != "VERIFIED"
            assert conf in ("POSSIBLE", "INFO")

        assert findings[0].confidence == "POSSIBLE"
        assert findings[1].confidence == "POSSIBLE"
        assert findings[2].confidence == "INFO"

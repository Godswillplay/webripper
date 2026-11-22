"""
Unit tests for WebRipper Recon AI Agent, Ollama client, Tool Installer, and Burp Suite Manager.
"""

import json
import os
import tempfile
import zipfile
import pytest
from pathlib import Path

from app.tools.burp import BurpManager
from app.tools.installer import ToolInstaller, _safe_extract_zip
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

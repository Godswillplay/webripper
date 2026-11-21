"""
Unit tests for WebRipper Recon 5.0 CLI, Interactive Wizard, and Headless Agent Interface.

Validates:
- CLI argument parsing for --wizard, --interactive, --scanners, --delay, --open, --intel-query
- Interactive wizard execution flow with simulated prompt inputs
- Semantic exit codes (0=clean, 1=error, 2=critical/high, 3=WAF block, 4=rate-limited)
- AI agent cancellation and ping
- AI toolbox vulnerability intelligence lookup
"""

import os
from unittest.mock import patch, MagicMock
import pytest

from app.cli import build_parser, run_wizard, run_cli, _scan_target
from app.models import RipperSettings, ReconReport, RipReport, ScanResult, Finding, Severity
from app.ai.agent import AIAgent
from app.ai.client import OllamaClient
from app.ai.tools import AgentToolbox


def test_cli_parser_flags():
    """Verify that all new CLI flags are properly defined and parsed."""
    parser = build_parser()
    args = parser.parse_args([
        "https://example.com",
        "--wizard",
        "--profile", "aggressive",
        "--depth", "3",
        "--delay", "1.5",
        "--scanners", "secrets,headers,scenarios",
        "--no-scenarios",
        "--open",
        "--intel-query", "nextjs",
    ])
    assert args.target == "https://example.com"
    assert args.wizard is True
    assert args.profile == "aggressive"
    assert args.depth == 3
    assert args.delay == 1.5
    assert args.scanners == "secrets,headers,scenarios"
    assert args.no_scenarios is True
    assert args.open is True
    assert args.intel_query == "nextjs"


def test_cli_interactive_wizard_flow():
    """Verify that run_wizard() prompts operator and synthesizes correct arguments."""
    simulated_inputs = [
        "target.local",  # URL
        "2",             # standard profile
        "2",             # depth
        "y",             # bug bounty scenario probes
        "n",             # skip external tools
        "test_cookie=1", # session cookie
        "out_report.html", # output path
        "n",             # auto-open
    ]

    with patch("sys.stdin.isatty", return_value=True):
        with patch("builtins.input", side_effect=simulated_inputs):
            with patch("app.cli.run_cli", return_value=0) as mock_run_cli:
                exit_code = run_wizard()
                assert exit_code == 0
                mock_run_cli.assert_called_once()
                called_args = mock_run_cli.call_args[0][0]
                assert "https://target.local" in called_args
                assert "--profile" in called_args
                assert "standard" in called_args
                assert "--no-tools" in called_args
                assert "--cookie" in called_args
                assert "test_cookie=1" in called_args
                assert "-o" in called_args
                assert "out_report.html" in called_args


def test_cli_intel_query_direct():
    """Verify --intel-query option searches bug bounty intelligence database."""
    with patch("sys.stdout"):
        exit_code = run_cli(["--intel-query", "supabase"])
        assert exit_code == 0


def test_cli_semantic_exit_code_clean(tmp_path):
    """Verify exit code 0 when no critical or high severity findings are found."""
    mock_report = ReconReport(
        url="https://example.com",
        start_time="2026-01-01T00:00:00",
        end_time="2026-01-01T00:01:00",
        rip_report=RipReport(url="https://example.com"),
        scan_results=[
            ScanResult(
                scanner_name="headers",
                findings=[
                    Finding(
                        severity=Severity.LOW,
                        category="headers",
                        title="Missing X-Frame-Options",
                        description="Header not set",
                    )
                ]
            )
        ]
    )

    def mock_run(self):
        self.report = mock_report

    with patch("app.worker.RipperWorker.run", mock_run):
        opts = build_parser().parse_args(["https://example.com", "-o", str(tmp_path / "rep.html")])
        code = _scan_target("https://example.com", opts)
        assert code == 0


def test_cli_semantic_exit_code_critical_findings(tmp_path):
    """Verify exit code 2 when CRITICAL or HIGH severity findings are found."""
    mock_report = ReconReport(
        url="https://example.com",
        start_time="2026-01-01T00:00:00",
        end_time="2026-01-01T00:01:00",
        rip_report=RipReport(url="https://example.com"),
        scan_results=[
            ScanResult(
                scanner_name="secrets",
                findings=[
                    Finding(
                        severity=Severity.CRITICAL,
                        category="secrets",
                        title="Exposed AWS Secret Access Key",
                        description="Hardcoded AWS secret credentials exposed in client JavaScript.",
                    )
                ]
            )
        ]
    )

    def mock_run(self):
        self.report = mock_report

    with patch("app.worker.RipperWorker.run", mock_run):
        opts = build_parser().parse_args(["https://example.com", "-o", str(tmp_path / "rep.html")])
        code = _scan_target("https://example.com", opts)
        assert code == 2


def test_cli_semantic_exit_code_waf_blocked(tmp_path):
    """Verify exit code 3 when target is protected by a WAF or Gateway block."""
    mock_report = ReconReport(
        url="https://example.com",
        start_time="2026-01-01T00:00:00",
        end_time="2026-01-01T00:01:00",
        rip_report=RipReport(url="https://example.com"),
        scan_results=[
            ScanResult(
                scanner_name="waf",
                findings=[
                    Finding(
                        severity=Severity.INFO,
                        category="WAF",
                        title="Cloudflare WAF Challenge Enforced",
                        description="Access restricted by Cloudflare firewall.",
                    )
                ]
            )
        ]
    )

    def mock_run(self):
        self.report = mock_report

    with patch("app.worker.RipperWorker.run", mock_run):
        opts = build_parser().parse_args(["https://example.com", "-o", str(tmp_path / "rep.html")])
        code = _scan_target("https://example.com", opts)
        assert code == 3


def test_cli_semantic_exit_code_rate_limited(tmp_path):
    """Verify exit code 4 when target enforces HTTP 429 rate limiting."""
    mock_report = ReconReport(
        url="https://example.com",
        start_time="2026-01-01T00:00:00",
        end_time="2026-01-01T00:01:00",
        rip_report=RipReport(url="https://example.com"),
        scan_results=[
            ScanResult(
                scanner_name="crawl",
                findings=[
                    Finding(
                        severity=Severity.MEDIUM,
                        category="network",
                        title="HTTP 429 Rate Limit Encountered",
                        description="Target returned HTTP 429 Too Many Requests.",
                    )
                ]
            )
        ]
    )

    def mock_run(self):
        self.report = mock_report

    with patch("app.worker.RipperWorker.run", mock_run):
        opts = build_parser().parse_args(["https://example.com", "-o", str(tmp_path / "rep.html")])
        code = _scan_target("https://example.com", opts)
        assert code == 4


def test_agent_abort_cancellation():
    """Verify calling abort() flags agent and halts run_task cleanly."""
    toolbox = AgentToolbox(output_dir=".")
    client = OllamaClient()
    agent = AIAgent(toolbox=toolbox, client=client)

    assert not agent.is_aborted()
    agent.abort()
    assert agent.is_aborted()

    events = []
    result = agent.run_task("Investigate everything", progress_cb=lambda p, m: events.append((p, m)))
    assert "[MISSION TERMINATED // ABORTED BY OPERATOR]" in result
    assert any(p == "abort" for p, m in events)


def test_ollama_client_ping():
    """Verify ping returns a 3-tuple (bool, float, str)."""
    client = OllamaClient(base_url="http://127.0.0.1:9999")
    online, latency, msg = client.ping(timeout=0.5)
    assert online is False
    assert isinstance(latency, float)
    assert isinstance(msg, str)
    assert len(msg) > 0


def test_ai_toolbox_intel_lookup():
    """Verify AI AgentToolbox executes lookup_vulnerability_intelligence tool."""
    toolbox = AgentToolbox(output_dir=".")
    res = toolbox.execute_tool("lookup_vulnerability_intelligence", {"query": "Next.js"})
    assert "Bug Bounty Intelligence" in res
    assert "Scenario" in res

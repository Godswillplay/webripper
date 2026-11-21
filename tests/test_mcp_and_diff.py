"""
Unit tests for Native MCP Server, CLI Baseline Diffing, Telemetry Streaming,
Favicon Fingerprinting, and Modern Attack Chains 10-15.
"""

import os
import json
import tempfile
import hashlib
from unittest.mock import MagicMock, patch

from app.models import Finding, Severity, FileResult, RipReport, ReconReport, ScanResult
from app.cli import _handle_diff, build_parser, _scan_target
from app.correlator import correlate
from app.mcp.server import WebRipperMCPServer
from app.scanners.tech import TechScanner
from app.models import RipperSettings


# =====================================================================
# 1. Baseline Diffing Tests
# =====================================================================

def test_handle_diff_identifies_new_resolved_persisting():
    with tempfile.TemporaryDirectory() as tmpdir:
        baseline_file = os.path.join(tmpdir, "baseline_report.json")
        baseline_data = {
            "target": "https://example.com",
            "findings": [
                {
                    "severity": "CRITICAL",
                    "category": "vulns",
                    "title": "SQL Injection in /api/search",
                    "description": "SQLi vulnerability",
                },
                {
                    "severity": "HIGH",
                    "category": "headers",
                    "title": "Missing Content-Security-Policy",
                    "description": "CSP header missing",
                },
            ]
        }
        with open(baseline_file, "w", encoding="utf-8") as f:
            json.dump(baseline_data, f)

        # Current findings: CSP missing (persisting) + Git exposed (new). SQLi resolved!
        current_findings = [
            Finding(
                severity=Severity.HIGH,
                category="headers",
                title="Missing Content-Security-Policy",
                description="CSP header missing",
            ),
            Finding(
                severity=Severity.CRITICAL,
                category="paths",
                title="Git Repository Exposed via .git/HEAD",
                description="Git metadata found",
            ),
        ]

        emitted = []
        diff_res = _handle_diff(
            current_findings=current_findings,
            baseline_path=baseline_file,
            asset_dir=tmpdir,
            quiet=True,
            emit_fn=lambda ev: emitted.append(ev),
        )

        assert diff_res["summary"]["new"] == 1
        assert diff_res["summary"]["resolved"] == 1
        assert diff_res["summary"]["persisting"] == 1

        assert diff_res["new_findings"][0]["title"] == "Git Repository Exposed via .git/HEAD"
        assert diff_res["resolved_findings"][0]["title"] == "SQL Injection in /api/search"
        assert diff_res["persisting_findings"][0]["title"] == "Missing Content-Security-Policy"

        # Check recon_diff.json written to disk
        diff_file = os.path.join(tmpdir, "recon_diff.json")
        assert os.path.exists(diff_file)
        with open(diff_file, "r", encoding="utf-8") as f:
            saved_diff = json.load(f)
        assert saved_diff["summary"]["new"] == 1
        assert len(emitted) == 1
        assert emitted[0]["event"] == "diff_completed"


def test_handle_diff_missing_baseline_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        res = _handle_diff(
            current_findings=[],
            baseline_path=os.path.join(tmpdir, "nonexistent.json"),
            asset_dir=tmpdir,
            quiet=True,
        )
        assert res["summary"]["new"] == 0
        assert res["summary"]["resolved"] == 0


# =====================================================================
# 2. CLI Stream & Parser Flags
# =====================================================================

def test_cli_parser_telemetry_flags():
    parser = build_parser()
    opts = parser.parse_args([
        "https://test.com",
        "--json-stream",
        "--stream-file", "telemetry.ndjson",
        "--diff", "prev.json",
    ])
    assert opts.json_stream is True
    assert opts.stream_file == "telemetry.ndjson"
    assert opts.diff == "prev.json"


def test_cli_scan_target_telemetry_stream():
    with tempfile.TemporaryDirectory() as tmpdir:
        stream_path = os.path.join(tmpdir, "stream.ndjson")
        parser = build_parser()
        opts = parser.parse_args([
            "https://test.com",
            "--stream-file", stream_path,
            "--quiet",
            "--out-dir", tmpdir,
        ])

        with patch("app.worker.RipperWorker") as mock_worker_cls:
            mock_worker = MagicMock()
            mock_rep = MagicMock()
            mock_rep.scan_results = []
            mock_rep.rip_report = None
            mock_worker.report = mock_rep
            mock_worker_cls.return_value = mock_worker

            exit_code = _scan_target("https://test.com", opts)
            assert exit_code == 0

        assert os.path.exists(stream_path)
        with open(stream_path, "r", encoding="utf-8") as f:
            lines = [json.loads(line) for line in f if line.strip()]

        event_names = [e["event"] for e in lines]
        assert "scan_started" in event_names
        assert "scan_completed" in event_names
        assert any(e["target"] == "https://test.com" for e in lines)


# =====================================================================
# 3. Native MCP Server Tests
# =====================================================================

def test_mcp_server_initialize():
    server = WebRipperMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1.0"},
        },
    }
    resp = server.handle_request(req)
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == 1
    result = resp["result"]
    assert result["protocolVersion"] == "2024-11-05"
    assert "webripper" in result["serverInfo"]["name"]
    assert "tools" in result["capabilities"]


def test_mcp_server_tools_list():
    server = WebRipperMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {},
    }
    resp = server.handle_request(req)
    tools = resp["result"]["tools"]
    tool_names = [t["name"] for t in tools]
    assert "webripper_scan" in tool_names
    assert "lookup_vulnerability_intelligence" in tool_names
    assert "run_canary_probe" in tool_names
    assert "get_attack_chains" in tool_names
    assert "list_scans" in tool_names


def test_mcp_server_lookup_vulnerability_intelligence():
    server = WebRipperMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "lookup_vulnerability_intelligence",
            "arguments": {"query": "spring", "limit": 3},
        },
    }
    resp = server.handle_request(req)
    assert resp["id"] == 3
    content = resp["result"]["content"]
    assert len(content) > 0
    text = content[0]["text"]
    assert "Security & Bug Bounty Intelligence" in text
    assert "Spring" in text or "spring" in text


def test_mcp_server_get_attack_chains_empty():
    server = WebRipperMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "get_attack_chains",
            "arguments": {"domain": "nonexistent.example.com"},
        },
    }
    resp = server.handle_request(req)
    assert resp["id"] == 4
    content = resp["result"]["content"]
    assert "No previous reconnaissance scan history found" in content[0]["text"]


def test_mcp_server_get_attack_chains_with_history():
    from app.history import ScanRecord
    server = WebRipperMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 41,
        "method": "tools/call",
        "params": {
            "name": "get_attack_chains",
            "arguments": {"domain": "target.local"},
        },
    }

    mock_record = ScanRecord(
        path="dummy.json",
        domain="target.local",
        timestamp="2026-11-21T00:00:00",
        finding_count=2,
        critical_count=1,
        high_count=1,
        medium_count=0,
    )
    mock_findings = [
        {"severity": "CRITICAL", "title": "SQL Injection in /api/users", "category": "vulns"},
        {"severity": "HIGH", "title": "Missing HSTS Header", "category": "headers"},
    ]

    with patch("app.history.list_scans", return_value=[mock_record]):
        with patch("app.history.search_history", return_value=mock_findings) as mock_search:
            resp = server.handle_request(req)
            mock_search.assert_called_once_with(domain="target.local", limit=50)

    assert resp["id"] == 41
    text = resp["result"]["content"][0]["text"]
    assert "Attack Chains for Domain: target.local" in text
    assert "SQL Injection in /api/users" in text


def test_mcp_server_unknown_method():
    server = WebRipperMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 99,
        "method": "unknown/method",
        "params": {},
    }
    resp = server.handle_request(req)
    assert "error" in resp
    assert resp["error"]["code"] == -32601


# =====================================================================
# 4. Attack Chains 10 - 15 Tests
# =====================================================================

def test_correlator_chain_10_nextjs_server_actions():
    findings = [
        Finding(
            severity=Severity.MEDIUM,
            category="paths",
            title="Next.js Source Map Exposed via /_next/static/chunks/main.js.map",
            description="Source map disclosed",
        ),
        Finding(
            severity=Severity.LOW,
            category="endpoints",
            title="POST /api/mutate-record",
            url="/api/mutate-record",
            description="API Endpoint",
        ),
    ]
    chains = correlate(findings)
    assert any("Next.js" in c.name for c in chains)


def test_correlator_chain_11_spring_actuator_ssrf():
    findings = [
        Finding(
            severity=Severity.HIGH,
            category="paths",
            title="Spring Boot Actuator Exposed at /actuator/env",
            description="Actuator env endpoint reachable",
        ),
        Finding(
            severity=Severity.HIGH,
            category="vulns",
            title="SSRF to AWS Cloud Metadata Service",
            description="Metadata reachable",
        ),
    ]
    chains = correlate(findings)
    assert any("Spring Boot Actuator" in c.name for c in chains)


def test_correlator_chain_12_subdomain_takeover_oauth():
    findings = [
        Finding(
            severity=Severity.HIGH,
            category="subdomains",
            title="Dangling CNAME Subdomain Takeover Candidate on GitHub Pages",
            description="Unclaimed service",
        ),
        Finding(
            severity=Severity.MEDIUM,
            category="paths",
            title="OAuth 2.0 Authorization Endpoint with Wildcard Callback",
            description="OAuth callback flaw",
        ),
    ]
    chains = correlate(findings)
    assert any("Subdomain Takeover + OAuth" in c.name for c in chains)


def test_correlator_chain_13_cors_reflection_sensitive_endpoint():
    findings = [
        Finding(
            severity=Severity.HIGH,
            category="cors",
            title="CORS Arbitrary Origin Reflection with Access-Control-Allow-Credentials",
            description="CORS misconfiguration",
        ),
        Finding(
            severity=Severity.MEDIUM,
            category="endpoints",
            title="GET /api/user/profile",
            url="/api/user/profile",
            description="Sensitive user data",
        ),
    ]
    chains = correlate(findings)
    assert any("CORS Origin Reflection" in c.name for c in chains)


def test_correlator_chain_14_graphql_introspection():
    findings = [
        Finding(
            severity=Severity.MEDIUM,
            category="scenarios",
            title="Production GraphQL Introspection Enabled at /graphql",
            description="Schema introspection active",
        ),
    ]
    chains = correlate(findings)
    assert any("GraphQL Introspection" in c.name for c in chains)


def test_correlator_chain_15_request_smuggling():
    findings = [
        Finding(
            severity=Severity.CRITICAL,
            category="vulns",
            title="HTTP Request Smuggling CL.TE Vulnerability",
            description="Proxy desync detected",
        ),
    ]
    chains = correlate(findings)
    assert any("HTTP Request Smuggling" in c.name for c in chains)


# =====================================================================
# 5. Favicon Fingerprinting Tests
# =====================================================================

def test_tech_scanner_favicon_spring_boot_detection():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create dummy favicon file matching Spring Boot hash: 0488faca4c3c63faae1c2b999b304065
        fav_path = os.path.join(tmpdir, "favicon.ico")
        # We can find or craft bytes whose MD5 is Spring Boot, or mock hashlib.md5
        # Let's mock hashlib.md5 to return 0488faca4c3c63faae1c2b999b304065
        with open(fav_path, "wb") as f:
            f.write(b"dummy_spring_favicon")

        file_rec = FileResult(
            url="https://example.com/favicon.ico",
            local_path=fav_path,
            status=200,
        )
        rip_rep = RipReport(url="https://example.com", files=[file_rec])
        scanner = TechScanner(rip_rep, RipperSettings(url="https://example.com"))

        detected = {}
        with patch("hashlib.md5") as mock_md5:
            mock_hash = MagicMock()
            mock_hash.hexdigest.return_value = "0488faca4c3c63faae1c2b999b304065"
            mock_md5.return_value = mock_hash

            scanner._check_favicons(detected)

        assert "Spring Boot" in detected
        assert detected["Spring Boot"]["category"] == "Web Framework"
        assert len(scanner._findings) == 1
        assert scanner._findings[0].title == "Spring Boot"


# =====================================================================
# 6. MCP Resources & Scan Tool Execution Tests
# =====================================================================

def test_mcp_server_resources_list():
    server = WebRipperMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 10,
        "method": "resources/list",
        "params": {},
    }
    resp = server.handle_request(req)
    assert resp["id"] == 10
    resources = resp["result"]["resources"]
    uris = [r["uri"] for r in resources]
    assert "recon://intelligence/stats" in uris
    assert "recon://history/recent" in uris


def test_mcp_server_resources_read_intelligence_stats():
    server = WebRipperMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 11,
        "method": "resources/read",
        "params": {"uri": "recon://intelligence/stats"},
    }
    resp = server.handle_request(req)
    assert resp["id"] == 11
    contents = resp["result"]["contents"]
    assert len(contents) > 0
    assert contents[0]["uri"] == "recon://intelligence/stats"
    parsed = json.loads(contents[0]["text"])
    assert "total_scenarios" in parsed or "scenarios" in parsed or "version" in parsed


def test_mcp_server_resources_read_history_recent():
    server = WebRipperMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 14,
        "method": "resources/read",
        "params": {"uri": "recon://history/recent"},
    }
    resp = server.handle_request(req)
    assert resp["id"] == 14
    contents = resp["result"]["contents"]
    assert len(contents) > 0
    assert contents[0]["uri"] == "recon://history/recent"
    parsed = json.loads(contents[0]["text"])
    assert isinstance(parsed, list)


def test_mcp_server_resources_read_unknown_uri():
    server = WebRipperMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 12,
        "method": "resources/read",
        "params": {"uri": "recon://unknown/resource"},
    }
    resp = server.handle_request(req)
    assert "error" in resp
    assert resp["error"]["code"] == -32602


def test_mcp_server_notifications_ignored():
    server = WebRipperMCPServer()
    req = {
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {},
    }
    resp = server.handle_request(req)
    assert resp is None


def test_mcp_server_webripper_scan_tool():
    server = WebRipperMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 13,
        "method": "tools/call",
        "params": {
            "name": "webripper_scan",
            "arguments": {
                "target": "https://example.com",
                "profile": "quick",
            },
        },
    }

    dummy_report = ReconReport(
        url="https://example.com",
        rip_report=RipReport(url="https://example.com"),
        scan_results=[
            ScanResult(
                scanner_name="headers",
                findings=[
                    Finding(
                        severity=Severity.HIGH,
                        category="headers",
                        title="Missing HSTS Header",
                        description="HSTS missing",
                    )
                ]
            )
        ]
    )

    def mock_worker_run(worker_self):
        worker_self.report = dummy_report

    with patch("app.worker.RipperWorker.run", mock_worker_run):
        resp = server.handle_request(req)

    assert resp["id"] == 13
    assert "result" in resp
    content = resp["result"]["content"]
    assert len(content) > 0
    text = content[0]["text"]
    assert "Scan Summary" in text
    assert "Missing HSTS Header" in text


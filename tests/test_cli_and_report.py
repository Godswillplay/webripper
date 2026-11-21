"""
Unit tests for CLI parser, report escaping, and attack chain correlation.
"""

from app.cli import build_parser
from app.report import generate_html_report, _build_attack_graph
from app.correlator import correlate
from app.models import Finding, ReconReport, Severity, ScanResult


def test_cli_parser_positional_target():
    parser = build_parser()
    opts = parser.parse_args(["https://target.com", "--profile", "aggressive", "-o", "report.html"])
    assert opts.target == "https://target.com"
    assert opts.profile == "aggressive"
    assert opts.output == "report.html"


def test_cli_parser_headless_flag():
    parser = build_parser()
    opts = parser.parse_args(["--url", "https://target.com", "--headless"])
    assert opts.url == "https://target.com"
    assert opts.headless is True


def test_report_script_escaping_and_d3():
    findings = [
        Finding(
            severity=Severity.HIGH,
            category="javascript",
            title="Reflected Payload </script><script>alert(1)</script>",
            description="Malicious input reflected",
            evidence="alert(1)",
        )
    ]
    report = ReconReport(
        url="https://victim.com",
        start_time="2026-11-19T00:00:00",
        scan_results=[
            ScanResult(scanner_name="javascript", findings=findings)
        ],
    )
    html = generate_html_report(report)

    # HTML structure closing tags must be valid </script>
    assert "</script>\n</section>" in html
    # The JSON string literal inside script must escape the closing tags to prevent breakout
    assert r"<\/script>" in html
    assert "d3.v7.min.js\"></script>" in html


def test_correlator_sqli_chain_without_open_db_port():
    findings = [
        Finding(
            severity=Severity.CRITICAL,
            category="vulns",
            title="SQLi in user parameter",
            description="SQL Injection confirmed",
        )
    ]
    report = ReconReport(
        url="https://app.local",
        start_time="2026-11-19T00:00:00",
        scan_results=[
            ScanResult(scanner_name="vulns", findings=findings)
        ],
    )
    chains = correlate(report)
    assert any("SQL Injection" in c.name for c in chains)
    sqli_chain = next(c for c in chains if "SQL Injection" in c.name)
    assert sqli_chain.severity == Severity.CRITICAL
    assert len(sqli_chain.steps) >= 1


def test_severity_rich_comparison():
    assert Severity.CRITICAL > Severity.HIGH
    assert Severity.HIGH > Severity.MEDIUM
    assert Severity.MEDIUM > Severity.LOW
    assert Severity.LOW > Severity.INFO
    assert Severity.INFO < Severity.CRITICAL
    severities = [Severity.LOW, Severity.CRITICAL, Severity.INFO, Severity.HIGH]
    assert sorted(severities) == [Severity.INFO, Severity.LOW, Severity.HIGH, Severity.CRITICAL]


def test_recon_report_grade_f_on_critical_finding():
    report = ReconReport(
        url="https://target.com",
        scan_results=[
            ScanResult(
                scanner_name="secrets",
                findings=[
                    Finding(
                        severity=Severity.CRITICAL,
                        category="secrets",
                        title="AWS Root Key Leaked",
                        description="Exposed AWS secret key",
                    )
                ]
            )
        ]
    )
    assert report.risk_score == "F"


def test_cvss_zero_impact_clamp():
    from app.cvss import calculate_cvss31
    # Scope changed with no impact (C:N/I:N/A:N)
    base, impact, exploit = calculate_cvss31(s="C", c="N", i="N", a="N")
    assert base == 0.0
    assert impact == 0.0


def test_correlator_admin_panel_matching():
    report = ReconReport(
        url="https://app.local",
        scan_results=[
            ScanResult(
                scanner_name="endpoints",
                findings=[
                    Finding(
                        severity=Severity.HIGH,
                        category="endpoints",
                        title="/api/admin/users",
                        description="Admin endpoint exposed",
                    )
                ]
            ),
            ScanResult(
                scanner_name="secrets",
                findings=[
                    Finding(
                        severity=Severity.HIGH,
                        category="secrets",
                        title="Default Admin Password Found",
                        description="admin / admin123",
                    )
                ]
            ),
        ]
    )
    chains = correlate(report)
    assert any("Admin" in c.name for c in chains)
    admin_chain = next(c for c in chains if "Admin" in c.name)
    assert len(admin_chain.steps) >= 2


def test_confidence_coerced_to_str_at_model_boundary():
    """Ensure Confidence enum is coerced to string on Finding, AttackChain, and AttackChainStep."""
    from app.models import Confidence, AttackChain, AttackChainStep

    # Test initialization with Enum
    f1 = Finding(
        severity=Severity.HIGH,
        category="sqli",
        title="SQL Injection",
        description="Planted SQLi",
        confidence=Confidence.VERIFIED,
    )
    assert isinstance(f1.confidence, str)
    assert f1.confidence == "VERIFIED"
    assert f1.confidence == Confidence.VERIFIED

    # Test dynamic assignment of Enum
    f2 = Finding(
        severity=Severity.HIGH,
        category="xss",
        title="XSS",
        description="Planted XSS",
    )
    f2.confidence = Confidence.LIKELY
    assert isinstance(f2.confidence, str)
    assert f2.confidence == "LIKELY"
    assert f2.confidence == Confidence.LIKELY

    # Test AttackChainStep
    step = AttackChainStep(description="Exploit step", confidence=Confidence.VERIFIED)
    assert isinstance(step.confidence, str)
    assert step.confidence == "VERIFIED"
    step.confidence = Confidence.INFO
    assert isinstance(step.confidence, str)
    assert step.confidence == "INFO"

    # Test AttackChain
    chain = AttackChain(name="Chain", severity=Severity.HIGH, confidence=Confidence.VERIFIED)
    assert isinstance(chain.confidence, str)
    assert chain.confidence == "VERIFIED"
    chain.confidence = Confidence.POSSIBLE
    assert isinstance(chain.confidence, str)
    assert chain.confidence == "POSSIBLE"


def test_confidence_findings_serialize_in_report_history_and_ndjson(tmp_path):
    """Ensure findings with Confidence enums and proof metadata serialize properly."""
    import json
    from app import history
    from app.models import Confidence, AttackChain, AttackChainStep

    findings = [
        Finding(
            severity=Severity.CRITICAL,
            category="sqli",
            title="SQLi Critical",
            description="Exploitable SQLi",
            confidence=Confidence.VERIFIED,
            metadata={
                "proof": {
                    "validator": "SQLiValidator",
                    "observed_delta": "MySQL syntax error",
                    "request": {"method": "GET", "url": "http://127.0.0.1/sqli"},
                    "response": {"status": 500},
                },
                "proof_attached": True,
            },
        ),
        Finding(
            severity=Severity.HIGH,
            category="cors",
            title="CORS Misconfig",
            description="Wildcard CORS",
            confidence=Confidence.LIKELY,
        ),
        Finding(
            severity=Severity.MEDIUM,
            category="headers",
            title="Missing HSTS",
            description="HSTS header missing",
            confidence=Confidence.POSSIBLE,
        ),
        Finding(
            severity=Severity.INFO,
            category="tech",
            title="Nginx Detected",
            description="Server header Nginx",
            confidence=Confidence.INFO,
        ),
    ]

    report = ReconReport(
        url="http://127.0.0.1:8080",
        start_time="2026-11-21T00:00:00",
        scan_results=[ScanResult(scanner_name="audit", findings=findings)],
        attack_chains=[
            AttackChain(
                name="SQLi to Data Leak",
                severity=Severity.CRITICAL,
                confidence=Confidence.VERIFIED,
                steps=[AttackChainStep(description="Step 1", confidence=Confidence.VERIFIED)],
            )
        ],
    )

    # 1. Report to_json serialization
    rep_json = report.to_json()
    parsed_rep = json.loads(rep_json)
    assert parsed_rep["risk_score"] == "F"
    assert len(parsed_rep["scans"][0]["findings"]) == 4
    for item in parsed_rep["scans"][0]["findings"]:
        assert isinstance(item["confidence"], str)

    # 2. History save_scan serialization
    import os
    os.environ["APPDATA"] = str(tmp_path)
    os.environ["HOME"] = str(tmp_path)
    save_path = history.save_scan(findings, "http://127.0.0.1:8080", attack_chains=report.attack_chains)
    assert os.path.exists(save_path)
    with open(save_path, "r", encoding="utf-8") as fh:
        saved_data = json.load(fh)
    assert len(saved_data["findings"]) == 4
    for f_item in saved_data["findings"]:
        assert isinstance(f_item["confidence"], str)

    # 3. NDJSON streaming serialization
    streamed_lines = []
    def mock_emit(d):
        streamed_lines.append(json.dumps(d, default=str))

    for f in findings:
        mock_emit({
            "event": "finding_discovered",
            "severity": f.severity.value,
            "category": f.category,
            "title": f.title,
            "confidence": f.confidence,
        })
    assert len(streamed_lines) == 4
    for line in streamed_lines:
        line_data = json.loads(line)
        assert isinstance(line_data["confidence"], str)


def test_cli_acceptance_scan_exit_codes_and_json_report(tmp_path, monkeypatch):
    """
    Acceptance test for Fix 1:
    - Target with Critical/High findings exits 2, produces valid parseable JSON with string confidence, no scan error.
    - Clean target exits 0.
    - Unreachable target exits 3.
    """
    import json
    import io
    import sys
    from unittest.mock import MagicMock
    from app.cli import run_cli
    from app.models import Confidence

    out_json = str(tmp_path / "test_out.json")

    # Mock RipperWorker to return findings with Confidence enums and proof
    mock_findings = [
        Finding(
            severity=Severity.HIGH,
            category="sqli",
            title="Verified SQLi",
            description="SQL syntax error",
            confidence=Confidence.VERIFIED,
            metadata={"proof": "error returned", "method": "GET"},
        )
    ]
    mock_report = ReconReport(
        url="http://127.0.0.1:8080",
        start_time="2026-11-21T00:00:00",
        scan_results=[ScanResult(scanner_name="sqli", findings=mock_findings)],
    )

    mock_worker = MagicMock()
    mock_worker.report = mock_report

    monkeypatch.setattr("app.worker.RipperWorker", lambda settings: mock_worker)

    err_buf = io.StringIO()
    monkeypatch.setattr(sys, "stderr", err_buf)

    # Run scan with High finding: must exit 2
    exit_code = run_cli(["http://127.0.0.1:8080", "--json", out_json, "-q"])
    assert exit_code == 2
    assert "Scan error" not in err_buf.getvalue()

    with open(out_json, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["target"] == "http://127.0.0.1:8080"
    assert data["finding_count"] == 1
    assert data["findings"][0]["confidence"] == "VERIFIED"
    assert isinstance(data["findings"][0]["confidence"], str)

    # Clean target: must exit 0
    clean_report = ReconReport(
        url="http://127.0.0.1:8080",
        start_time="2026-11-21T00:00:00",
        scan_results=[ScanResult(scanner_name="audit", findings=[])],
    )
    mock_worker.report = clean_report
    clean_out_json = str(tmp_path / "clean_out.json")
    clean_code = run_cli(["http://127.0.0.1:8080", "--json", clean_out_json, "-q"])
    assert clean_code == 0

    # Unreachable target: must exit 3
    from app.models import RipReport
    unreach_report = ReconReport(
        url="http://127.0.0.1:8080",
        start_time="2026-11-21T00:00:00",
        scan_results=[],
        rip_report=RipReport(url="http://127.0.0.1:8080", unreachable=True),
    )
    unreach_report.unreachable = True
    mock_worker.report = unreach_report
    unreach_code = run_cli(["http://127.0.0.1:8080", "-q"])
    assert unreach_code == 3


def test_cli_live_fixture_server_scan_acceptance(tmp_path):
    """
    Live target acceptance test for Fix 1:
    - Scan local fixture target using --json out.json -q:
      process exits 2, out.json parses with json.load, findings in it carry
      confidence as a string, and no 'Scan error' appears in stderr.
    """
    import http.server
    import threading
    import json
    import io
    import sys
    from app.cli import run_cli

    class LiveVulnHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Dashboard</h1><p>Test Application</p></body></html>")

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), LiveVulnHandler)
    host, port = server.server_address[0], server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    out_json = str(tmp_path / "live_out.json")
    target_url = f"http://{host}:{port}/"

    try:
        err_buf = io.StringIO()
        old_stderr = sys.stderr
        sys.stderr = err_buf
        try:
            exit_code = run_cli([target_url, "--json", out_json, "-q", "--profile", "quick"])
        finally:
            sys.stderr = old_stderr

        assert exit_code == 2, f"Expected 2 on HTTP target with missing headers, got {exit_code}"
        assert "Scan error" not in err_buf.getvalue()

        with open(out_json, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert data["target"] == target_url
        assert data["finding_count"] > 0
        for f in data["findings"]:
            assert isinstance(f["confidence"], str)
            assert f["confidence"] in ("VERIFIED", "LIKELY", "POSSIBLE", "INFO")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)




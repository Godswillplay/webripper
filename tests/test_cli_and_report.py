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


"""
Tests for deep audit fixes in app.cli, app.main, and app.worker:
1. Thread safety & cancellation race conditions in CallbackSignal and RipperWorker.
2. Multi-target state leakage, RipReport merging, and output path uniqueness.
3. Exit code priority (2 > 3 > 4 > 1 > 0).
4. Argparse exit code 1 on parse error instead of 2.
5. Clean scan with 'No WAF Detected' returns code 0 (not 3).
"""

import sys
import pytest
from unittest.mock import MagicMock, patch

from app.worker import CallbackSignal, RipperWorker
from app.cli import build_parser, run_cli, _scan_target
from app.models import RipperSettings, ReconReport, RipReport, ScanResult, Finding, Severity


def test_callback_signal_callable_check():
    """Verify that CallbackSignal rejects non-callable slots."""
    sig = CallbackSignal()
    with pytest.raises(TypeError, match="callable"):
        sig.connect("not_a_callable")  # type: ignore


def test_callback_signal_thread_safety_and_emit():
    """Verify thread-safe emission and disconnect."""
    sig = CallbackSignal()
    received = []

    def handler(val):
        received.append(val)

    sig.connect(handler)
    sig.emit("event1")
    assert received == ["event1"]

    sig.disconnect(handler)
    sig.emit("event2")
    assert received == ["event1"]


def test_ripper_worker_immediate_cancel():
    """Verify worker halts cleanly when cancelled before execution starts."""
    settings = RipperSettings(url="https://example.com")
    worker = RipperWorker(settings)
    worker.cancel()

    events = []
    worker.progress.connect(lambda e: events.append(e))
    worker.run()

    assert any(e.phase == "Aborted" for e in events)
    assert worker.report is None


def test_ripper_worker_multi_target_merging_no_attribute_error():
    """Verify multi-target crawl merging does not fail with AttributeError."""
    settings = RipperSettings(
        url="https://target1.com",
        multi_targets=["https://target2.com"],
        scan_secrets=False,
        scan_headers=False,
        scan_tech=False,
        scan_endpoints=False,
        scan_paths=False,
        scan_cors=False,
        scan_javascript=False,
        scan_forms=False,
        scan_tls=False,
        scan_cookies=False,
        scan_subdomains=False,
        scan_ports=False,
        scan_waf=False,
        scan_dns=False,
        scan_emails=False,
        scan_screenshots=False,
        scan_github_dork=False,
        scan_vulns=False,
        scan_cves=False,
        scan_scenarios=False,
        use_external_tools=False,
    )
    worker = RipperWorker(settings)

    # Mock WebRipper.run to return dummy RipReport
    dummy_rip = RipReport(url="https://mock.com", pages_crawled=1, total_downloaded=2)
    with patch("app.ripper.WebRipper.run", return_value=dummy_rip):
        worker.run()

    assert worker.report is not None
    assert worker.report.rip_report is not None
    assert worker.report.rip_report.pages_crawled == 2
    assert worker.report.rip_report.total_downloaded == 4


def test_clean_scan_with_no_waf_detected_exits_zero(tmp_path):
    """Verify that a scan producing 'No WAF Detected' exits with code 0 (not 3)."""
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
                        severity=Severity.LOW,
                        category="waf",
                        title="No WAF Detected",
                        description="No Web Application Firewall was detected protecting this target.",
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
        assert code == 0, f"Expected 0 (clean scan) but got {code}"


def test_multi_target_exit_code_priority(tmp_path):
    """Verify that exit code 2 (Critical) takes precedence over exit code 4 (Rate Limited)."""
    # Target 1: Critical finding (exit code 2)
    # Target 2: Rate limited (exit code 4)
    rep_crit = ReconReport(
        url="https://target1.com",
        rip_report=RipReport(url="https://target1.com"),
        scan_results=[
            ScanResult(
                scanner_name="vulns",
                findings=[Finding(severity=Severity.CRITICAL, category="sqli", title="SQL Injection", description="desc")]
            )
        ]
    )
    rep_ratelimit = ReconReport(
        url="https://target2.com",
        rip_report=RipReport(url="https://target2.com"),
        scan_results=[
            ScanResult(
                scanner_name="crawl",
                findings=[Finding(severity=Severity.MEDIUM, category="network", title="HTTP 429 Rate Limit Encountered", description="desc")]
            )
        ]
    )

    call_count = 0
    def mock_run(self):
        nonlocal call_count
        call_count += 1
        self.report = rep_crit if call_count == 1 else rep_ratelimit

    with patch("app.worker.RipperWorker.run", mock_run):
        url_file = tmp_path / "urls.txt"
        url_file.write_text("https://target1.com\nhttps://target2.com\n", encoding="utf-8")
        exit_code = run_cli(["--urls", str(url_file), "-q"])
        assert exit_code == 2, f"Expected code 2 (Critical priority) but got {exit_code}"


def test_parser_exits_with_code_1_on_syntax_error():
    """Verify that parser exits with code 1 instead of 2 on argument error."""
    parser = build_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["--profile", "nonexistent_profile"])
    assert exc_info.value.code == 1, f"Expected exit code 1 for CLI syntax error, got {exc_info.value.code}"


def test_empty_urls_file_returns_error_code_1(tmp_path):
    """Verify that an empty --urls file returns exit code 1 instead of 0."""
    url_file = tmp_path / "empty_urls.txt"
    url_file.write_text("# only comments\n   \n", encoding="utf-8")
    exit_code = run_cli(["--urls", str(url_file)])
    assert exit_code == 1


def test_wizard_requires_tty():
    """Verify that run_wizard() fails with code 1 when not running in an interactive TTY."""
    from app.cli import run_wizard
    with patch("sys.stdin.isatty", return_value=False):
        code = run_wizard()
        assert code == 1


def test_source_map_path_traversal_prevention(tmp_path):
    """Verify that malicious relative paths in source maps cannot write outside the output directory."""
    from app.ripper import WebRipper
    import asyncio
    import json

    output_dir = tmp_path / "recon_out"
    output_dir.mkdir()
    settings = RipperSettings(url="https://example.com", output_dir=str(output_dir))
    ripper = WebRipper(settings, progress_callback=lambda p: None)

    # Malicious source map with traversal
    payload = {
        "version": 3,
        "sources": ["../../../../evil_escape.js", "normal.js"],
        "sourcesContent": ["malicious_content()", "normal_content()"],
    }
    asyncio.run(ripper._handle_source_map(json.dumps(payload), "https://example.com/assets/app.js.map"))

    # The evil escape file should NOT exist outside output_dir
    escaped_file = tmp_path / "evil_escape.js"
    assert not escaped_file.exists(), "Path traversal vulnerability: file written outside output directory!"

    # Normal file should be extracted inside output_dir
    extracted_normal = list(output_dir.glob("**/normal.js"))
    assert len(extracted_normal) >= 1, "Normal source file should have been extracted"


def test_version_comparison_padding():
    """Verify that version comparisons correctly pad zeroes so 3.5 is not < 3.5.0."""
    from app.scanners.cves import _version_match

    # 3.5 is identical to 3.5.0
    assert not _version_match("3.5", "<3.5.0")
    assert _version_match("3.5", "<=3.5.0")
    assert _version_match("3.4.9", "<3.5.0")
    assert not _version_match("3.5.1", "<3.5.0")


"""
Integration tests for OWASP ZAP passive scanning lifecycle in app.worker.
Verifies:
1. ZAP session startup before Phase 1 crawl and proxy routing injection.
2. Passive scan drain and finding harvesting after Phase 2 scanners.
3. Placement of ZAP findings in recon.scan_results before Phase 2.5 validation and Phase 2.7 dedup.
4. Graceful fail-open when ZAP is missing or fails to initialize.
5. Explicit disabling via settings (enable_zap=False or use_external_tools=False).
6. Resource cleanup on cancellation or unreachable target.
"""

from unittest.mock import MagicMock, patch
import pytest

from app.models import (
    RipperSettings,
    ReconReport,
    RipReport,
    Finding,
    Severity,
    Confidence,
    ScanResult,
)
from app.worker import RipperWorker


class TestZAPWorkerIntegration:
    """Test OWASP ZAP passive scanning lifecycle wired into RipperWorker."""

    def test_zap_passive_lifecycle_success(self):
        """Verify ZAP context enters before crawl, sets proxy, drains, harvests, and exits."""
        settings = RipperSettings(
            url="https://target.test",
            use_external_tools=True,
            enable_zap=True,
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
            scan_bola=False,
            scan_graphql=False,
            scan_llmapp=False,
            scan_mcptarget=False,
        )

        mock_rip = RipReport(url="https://target.test", pages_crawled=2, total_downloaded=5)
        captured_proxy = []

        async def fake_ripper_run(ripper_instance):
            captured_proxy.append(ripper_instance._settings.proxy)
            return mock_rip

        # Setup mock ZAP session
        mock_zap_session = MagicMock()
        mock_zap_session.is_proxy_running.return_value = True
        mock_zap_session.proxy_url = "http://127.0.0.1:8090"
        mock_zap_session.port = 8090

        sample_finding = Finding(
            severity=Severity.HIGH,
            category="zap",
            title="SQL Injection Alert",
            description="Passive ZAP inspection finding",
            confidence="POSSIBLE",
            metadata={"source": "zap", "plugin_id": "40018"},
        )
        mock_zap_session.get_alerts.return_value = [sample_finding]

        mock_zap_ctx = MagicMock()
        mock_zap_ctx.__enter__.return_value = mock_zap_session

        worker = RipperWorker(settings)
        events = []
        worker.progress.connect(lambda e: events.append(e))

        with patch("app.tools.zap.ZAPManager.detect_zap", return_value={"installed": True, "path": "/usr/bin/zaproxy"}), \
             patch("app.tools.zap.ZAPSessionContext", return_value=mock_zap_ctx), \
             patch("app.ripper.WebRipper.run", fake_ripper_run), \
             patch.object(worker, "_run_scanners") as mock_scanners, \
             patch.object(worker, "_run_external_tools") as mock_ext:

            worker.run()

        # 1. Verify proxy was injected into WebRipper settings
        assert len(captured_proxy) == 1
        assert captured_proxy[0] == "http://127.0.0.1:8090"

        # 2. Verify ZAP context entered and exited
        mock_zap_ctx.__enter__.assert_called_once()
        mock_zap_ctx.__exit__.assert_called_once()

        # 3. Verify drain and get_alerts called
        mock_zap_session.drain_passive_scan.assert_called_once_with(timeout=20.0, settle_delay=1.0)
        mock_zap_session.get_alerts.assert_called_once_with(base_url="https://target.test")

        # 4. Verify ZAP finding in report
        assert worker.report is not None
        zap_results = [r for r in worker.report.scan_results if r.scanner_name == "zap"]
        assert len(zap_results) == 1
        assert zap_results[0].findings[0].title == "SQL Injection Alert"

        # 5. Verify progress logs
        messages = [e.message for e in events]
        assert any("Draining ZAP passive scan queue..." in m for m in messages)
        assert any("1 candidate findings harvested" in m for m in messages)

    def test_zap_graceful_fail_open_when_not_installed(self):
        """Verify worker proceeds normally when ZAP is not installed."""
        settings = RipperSettings(
            url="https://clean.test",
            use_external_tools=True,
            enable_zap=True,
        )

        mock_rip = RipReport(url="https://clean.test", pages_crawled=1, total_downloaded=1)

        worker = RipperWorker(settings)
        events = []
        worker.progress.connect(lambda e: events.append(e))

        with patch("app.tools.zap.ZAPManager.detect_zap", return_value={"installed": False, "path": None}), \
             patch("app.tools.zap.ZAPManager.is_proxy_running", return_value=False), \
             patch("app.ripper.WebRipper.run", return_value=mock_rip), \
             patch.object(worker, "_run_scanners"), \
             patch.object(worker, "_run_external_tools"):

            worker.run()

        assert worker.report is not None
        messages = [e.message for e in events]
        assert any("not detected on system; skipping ZAP" in m for m in messages)

    def test_zap_graceful_fail_open_on_init_exception(self):
        """Verify worker continues unimpeded if ZAPSessionContext raises on enter."""
        settings = RipperSettings(
            url="https://error.test",
            use_external_tools=True,
            enable_zap=True,
        )

        mock_rip = RipReport(url="https://error.test", pages_crawled=1, total_downloaded=1)

        worker = RipperWorker(settings)
        events = []
        worker.progress.connect(lambda e: events.append(e))

        mock_zap_ctx = MagicMock()
        mock_zap_ctx.__enter__.side_effect = RuntimeError("Port 8090 bind failure")

        with patch("app.tools.zap.ZAPManager.detect_zap", return_value={"installed": True, "path": "zap.bat"}), \
             patch("app.tools.zap.ZAPSessionContext", return_value=mock_zap_ctx), \
             patch("app.ripper.WebRipper.run", return_value=mock_rip), \
             patch.object(worker, "_run_scanners"), \
             patch.object(worker, "_run_external_tools"):

            worker.run()

        assert worker.report is not None
        messages = [e.message for e in events]
        assert any("OWASP ZAP initialization notice" in m for m in messages)

    def test_zap_disabled_via_enable_zap_setting(self):
        """Verify ZAP context is not touched when enable_zap=False."""
        settings = RipperSettings(
            url="https://disabled.test",
            use_external_tools=True,
            enable_zap=False,
        )

        mock_rip = RipReport(url="https://disabled.test", pages_crawled=1, total_downloaded=1)
        worker = RipperWorker(settings)

        with patch("app.tools.zap.ZAPSessionContext") as mock_zap_cls, \
             patch("app.ripper.WebRipper.run", return_value=mock_rip), \
             patch.object(worker, "_run_scanners"), \
             patch.object(worker, "_run_external_tools"):

            worker.run()

        mock_zap_cls.assert_not_called()

    def test_zap_cleanup_on_unreachable_target(self):
        """Verify ZAP session context is closed if target is unreachable."""
        settings = RipperSettings(
            url="https://dead-target.test",
            use_external_tools=True,
            enable_zap=True,
        )

        # Unreachable report: 0 crawled, 0 downloaded, errors present
        mock_rip = RipReport(url="https://dead-target.test", pages_crawled=0, total_downloaded=0, errors=["Connection refused"])

        mock_zap_session = MagicMock()
        mock_zap_session.is_proxy_running.return_value = True
        mock_zap_session.proxy_url = "http://127.0.0.1:8090"
        mock_zap_ctx = MagicMock()
        mock_zap_ctx.__enter__.return_value = mock_zap_session

        worker = RipperWorker(settings)

        with patch("app.tools.zap.ZAPManager.detect_zap", return_value={"installed": True, "path": "zap.sh"}), \
             patch("app.tools.zap.ZAPSessionContext", return_value=mock_zap_ctx), \
             patch("app.ripper.WebRipper.run", return_value=mock_rip):

            worker.run()

        mock_zap_ctx.__exit__.assert_called_once()
        assert worker.report.unreachable is True

    def test_zap_findings_flow_through_validation_and_dedup(self):
        """Verify ZAP findings land in recon.scan_results before ValidationEngine and Dedup."""
        settings = RipperSettings(
            url="https://target.test",
            use_external_tools=True,
            enable_zap=True,
            enable_dedup=True,
        )

        mock_rip = RipReport(url="https://target.test", pages_crawled=1, total_downloaded=1)

        mock_zap_session = MagicMock()
        mock_zap_session.is_proxy_running.return_value = True
        mock_zap_session.proxy_url = "http://127.0.0.1:8090"

        sample_finding = Finding(
            severity=Severity.HIGH,
            category="zap",
            title="Cross-Site Scripting (Reflected)",
            description="Reflected XSS parameter vulnerability",
            url="https://target.test/search?q=test",
            confidence="POSSIBLE",
            metadata={"source": "zap", "plugin_id": "40012"},
        )
        mock_zap_session.get_alerts.return_value = [sample_finding]

        mock_zap_ctx = MagicMock()
        mock_zap_ctx.__enter__.return_value = mock_zap_session

        worker = RipperWorker(settings)

        validated_reports = []
        def fake_validate_report(self, report):
            validated_reports.append(report)

        with patch("app.tools.zap.ZAPManager.detect_zap", return_value={"installed": True, "path": "zap.sh"}), \
             patch("app.tools.zap.ZAPSessionContext", return_value=mock_zap_ctx), \
             patch("app.ripper.WebRipper.run", return_value=mock_rip), \
             patch.object(worker, "_run_scanners"), \
             patch.object(worker, "_run_external_tools"), \
             patch("app.validation.engine.ValidationEngine.validate_report", fake_validate_report):

            worker.run()

        # ValidationEngine.validate_report was called and received the ZAP findings
        assert len(validated_reports) == 1
        rep = validated_reports[0]
        zap_findings = [f for sr in rep.scan_results if sr.scanner_name == "zap" for f in sr.findings]
        assert len(zap_findings) == 1
        assert zap_findings[0].title == "Cross-Site Scripting (Reflected)"
        # Deduplication scored finding
        assert "duplicate_risk" in zap_findings[0].metadata


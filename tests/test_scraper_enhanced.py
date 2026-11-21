"""
Comprehensive unit tests for WebRipper's enhanced scraper engine:
- AutoThrottle dynamic pacing and backoff
- NetworkRecorder runtime API capture
- Stealth headers and device arguments
- Windows reserved device name path sanitization
- HTML parser enhancements (lazy attributes, JSON-LD, form actions, tracks)
- Ad and tracker domain filtering
- Scanner ingestion of runtime captured network endpoints
"""

import time
import pytest
from pathlib import Path
from app.models import RipperSettings, RipReport
from app.ripper import WebRipper, _sanitize_path
from app.stealth import (
    AutoThrottle,
    NetworkRecorder,
    parse_retry_after,
    is_ad_or_tracker,
    generate_browser_headers,
    STEALTH_CHROMIUM_ARGS,
    STEALTH_INIT_SCRIPT,
)
from app.scanners.endpoints import EndpointScanner
from app.scanners.vulns import VulnScanner
from app.scanners.cors import CORSScanner


class TestAutoThrottle:
    """Test dynamic pacing and rate-limit backoff."""

    def test_default_delay(self):
        throttle = AutoThrottle(target_concurrency=1.0, min_delay=0.1, max_delay=5.0)
        assert throttle.get_delay("example.com") == 0.1

    def test_latency_adaptation(self):
        throttle = AutoThrottle(target_concurrency=1.0, min_delay=0.05, max_delay=10.0)
        domain = "api.example.com"
        # Simulate a slow response of 2.0 seconds
        throttle.record_response(domain, latency=2.0, status_code=200)
        delay = throttle.get_delay(domain)
        # Delay should scale up with high latency
        assert delay > 0.05
        assert delay <= 10.0

    def test_exponential_backoff_on_429(self):
        throttle = AutoThrottle(target_concurrency=1.0, min_delay=0.1, max_delay=30.0)
        domain = "rate-limited.com"
        initial_delay = throttle.get_delay(domain)

        throttle.record_response(domain, latency=0.1, status_code=429)
        backoff_delay = throttle.get_delay(domain)
        assert backoff_delay >= initial_delay * 1.5

        # Second consecutive 429 should double again
        throttle.record_response(domain, latency=0.1, status_code=429)
        second_backoff = throttle.get_delay(domain)
        assert second_backoff >= backoff_delay * 1.5

    def test_retry_after_header_handling(self):
        throttle = AutoThrottle(target_concurrency=1.0, min_delay=0.1, max_delay=60.0)
        domain = "polite.com"
        headers = {"Retry-After": "12"}
        throttle.record_response(domain, latency=0.1, status_code=429, headers=headers)
        assert throttle.get_delay(domain) >= 12.0

    def test_parse_retry_after_seconds_and_date(self):
        assert parse_retry_after("30") == 30.0
        assert parse_retry_after("-5") is None
        assert parse_retry_after("invalid_header") is None

        # Test valid HTTP date in the future
        future_time = time.time() + 45
        import email.utils
        date_str = email.utils.formatdate(future_time, usegmt=True)
        parsed_sec = parse_retry_after(date_str)
        assert parsed_sec is not None
        assert 40.0 <= parsed_sec <= 50.0


class TestNetworkRecorder:
    """Test background XHR/Fetch/API network recording."""

    def test_record_json_api(self):
        recorder = NetworkRecorder(max_records=50)
        recorder.record(
            url="https://example.com/api/v1/users?page=1",
            method="GET",
            status=200,
            resource_type="fetch",
            headers={"content-type": "application/json"},
            post_data=None,
            response_body='{"users": [{"id": 1, "name": "Alice"}]}',
        )
        assert len(recorder.requests) == 1
        req = recorder.requests[0]
        assert req["url"] == "https://example.com/api/v1/users?page=1"
        assert req["method"] == "GET"
        assert req["status"] == 200
        assert req["resource_type"] == "fetch"
        assert "Alice" in req["response_body"]

    def test_filter_static_assets(self):
        recorder = NetworkRecorder()
        # Static media should not be recorded as internal API traffic
        recorder.record(
            url="https://example.com/images/hero.jpg",
            method="GET",
            status=200,
            resource_type="image",
        )
        assert len(recorder.requests) == 0

    def test_body_truncation(self):
        recorder = NetworkRecorder(max_body_bytes=100)
        large_body = "A" * 500
        recorder.record(
            url="https://example.com/api/data",
            method="POST",
            status=200,
            resource_type="xhr",
            response_body=large_body,
        )
        assert len(recorder.requests) == 1
        assert len(recorder.requests[0]["response_body"]) <= 130
        assert "[truncated]" in recorder.requests[0]["response_body"]


class TestStealthPrimitives:
    """Test stealth headers, arguments, and evasion scripts."""

    def test_stealth_chromium_args(self):
        args_str = " ".join(STEALTH_CHROMIUM_ARGS)
        assert "--disable-blink-features=AutomationControlled" in args_str
        assert "--no-sandbox" in args_str
        assert "--window-size=" in args_str

    def test_stealth_init_script_injections(self):
        assert "navigator.webdriver" in STEALTH_INIT_SCRIPT
        assert "window.chrome" in STEALTH_INIT_SCRIPT
        assert "__extract_shadow_dom_urls" in STEALTH_INIT_SCRIPT
        assert "WEBGL_debug_renderer_info" in STEALTH_INIT_SCRIPT

    def test_generate_browser_headers(self):
        headers = generate_browser_headers("https://target.com/page")
        assert "User-Agent" in headers
        assert "Sec-Ch-Ua" in headers
        assert "Sec-Fetch-Dest" in headers
        assert "Sec-Fetch-Mode" in headers


class TestEnhancedPathSanitize:
    """Test Windows reserved device name sanitization and collision resistance."""

    def test_windows_reserved_device_names(self):
        for name in ("con", "aux", "prn", "nul", "com1", "lpt1"):
            path = _sanitize_path(f"https://example.com/{name}.txt", "C:\\output")
            # Should be escaped, e.g. _con_.txt, never raw con.txt
            filename = Path(path).name
            assert not filename.lower().startswith(f"{name}.")

    def test_windows_reserved_folder_names(self):
        path = _sanitize_path("https://example.com/aux/service/prn/run.js", "C:\\output")
        assert "\\aux\\" not in path.lower()
        assert "/aux/" not in path.lower()
        assert "\\prn\\" not in path.lower()
        assert "/prn/" not in path.lower()


class TestHtmlExtractionModernWeb:
    """Test URL extraction for lazy loading, JSON-LD, forms, and inline styles."""

    def _make_ripper(self):
        settings = RipperSettings(url="https://example.com", output_dir="C:\\output")
        return WebRipper(settings=settings, progress_callback=lambda e: None)

    def test_data_lazy_attributes(self):
        ripper = self._make_ripper()
        html = """
        <img data-lazy-src="/images/photo-lazy.png" />
        <div data-original="/images/gallery-orig.jpg"></div>
        <a data-href="/secret-dashboard.html">Link</a>
        <div data-bg="/backgrounds/hero.webp"></div>
        """
        ripper._root_html = html
        ripper._parse_html()
        disc = ripper._discovered

        assert "https://example.com/images/photo-lazy.png" in disc
        assert "https://example.com/images/gallery-orig.jpg" in disc
        assert "https://example.com/secret-dashboard.html" in disc
        assert "https://example.com/backgrounds/hero.webp" in disc

    def test_json_ld_extraction(self):
        ripper = self._make_ripper()
        html = """
        <script type="application/ld+json">
        {
          "@context": "https://schema.org",
          "@type": "Product",
          "name": "Widget",
          "image": "https://example.com/images/product-widget.jpg",
          "url": "https://example.com/products/widget-item"
        }
        </script>
        """
        ripper._root_html = html
        ripper._parse_html()
        disc = ripper._discovered

        assert "https://example.com/images/product-widget.jpg" in disc
        assert "https://example.com/products/widget-item" in disc

    def test_track_input_form_action(self):
        ripper = self._make_ripper()
        html = """
        <video><track src="/captions/en.vtt" kind="subtitles"></video>
        <form action="/api/v1/auth/login" method="POST">
            <input type="image" src="/buttons/submit.png" />
        </form>
        <map name="workmap"><area href="/jobs/career.html" shape="rect" coords="34,44,270,350"></map>
        """
        ripper._root_html = html
        ripper._parse_html()
        disc = ripper._discovered

        assert "https://example.com/captions/en.vtt" in disc
        assert "https://example.com/api/v1/auth/login" in disc
        assert "https://example.com/buttons/submit.png" in disc
        assert "https://example.com/jobs/career.html" in disc


class TestAdAndTrackerFiltering:
    """Test that ad/telemetry domains are pruned unless explicitly included."""

    def test_is_ad_or_tracker(self):
        assert is_ad_or_tracker("https://www.google-analytics.com/analytics.js") is True
        assert is_ad_or_tracker("https://connect.facebook.net/en_US/fbevents.js") is True
        assert is_ad_or_tracker("https://static.hotjar.com/c/hotjar-123.js") is True
        assert is_ad_or_tracker("https://api.my-target-app.com/api/data") is False

    def test_filter_urls_excludes_trackers(self):
        settings = RipperSettings(
            url="https://example.com",
            output_dir="C:\\output",
            same_origin_only=False,
            include_external=False,
        )
        ripper = WebRipper(settings=settings, progress_callback=lambda e: None)
        ripper._origin = "https://example.com"
        ripper._discovered.add("https://example.com/app.js")
        ripper._discovered.add("https://www.google-analytics.com/analytics.js")
        ripper._discovered.add("https://stats.wp.com/e-2024.js")

        filtered = ripper._filter_urls()
        assert "https://example.com/app.js" in filtered
        assert "https://www.google-analytics.com/analytics.js" not in filtered
        assert "https://stats.wp.com/e-2024.js" not in filtered


class TestScannerIntegrationWithNetworkCapture:
    """Test that runtime network recordings feed into security scanners."""

    def test_endpoint_scanner_ingests_captured_requests(self):
        settings = RipperSettings(url="https://example.com", output_dir="C:\\output")
        rip_report = RipReport(url="https://example.com")
        rip_report.captured_requests = [
            {
                "url": "https://example.com/api/v2/user/billing",
                "method": "POST",
                "status": 200,
                "resource_type": "fetch",
            },
            {
                "url": "https://example.com/graphql",
                "method": "POST",
                "status": 200,
                "resource_type": "xhr",
            },
        ]

        scanner = EndpointScanner(rip_report, settings)
        result = scanner.scan()

        titles = [f.title for f in result.findings]
        assert any("/api/v2/user/billing" in t for t in titles)
        assert any("/graphql" in t for t in titles)

    def test_vuln_scanner_ingests_captured_requests(self):
        settings = RipperSettings(url="https://example.com", output_dir="C:\\output")
        rip_report = RipReport(url="https://example.com")
        rip_report.captured_requests = [
            {
                "url": "https://example.com/api/search?q=test&limit=10",
                "method": "GET",
                "status": 200,
                "resource_type": "fetch",
            }
        ]

        scanner = VulnScanner(rip_report, settings)
        targets = scanner._collect_targets()

        # Should extract q and limit parameters from the captured request
        param_names = [t["param"] for t in targets]
        assert "q" in param_names
        assert "limit" in param_names

    def test_base_href_support(self):
        settings = RipperSettings(url="https://example.com/sub/", output_dir="C:\\output")
        ripper = WebRipper(settings=settings, progress_callback=lambda e: None)
        html = """
        <html>
        <head><base href="/assets/v2/"></head>
        <body>
            <script src="bundle.js"></script>
            <img src="logo.png" />
        </body>
        </html>
        """
        ripper._parse_html_content(html, "https://example.com/sub/")
        assert "https://example.com/assets/v2/bundle.js" in ripper._discovered
        assert "https://example.com/assets/v2/logo.png" in ripper._discovered

    def test_js_template_literals(self):
        settings = RipperSettings(url="https://example.com", output_dir="C:\\output")
        ripper = WebRipper(settings=settings, progress_callback=lambda e: None)
        js_code = """
        const mod = import(`/chunks/auth.js`);
        const res = fetch(`/api/v1/user`);
        const asset = `/static/images/hero.webp`;
        """
        ripper._scan_js(js_code, "https://example.com")
        assert "https://example.com/chunks/auth.js" in ripper._discovered
        assert "https://example.com/api/v1/user" in ripper._discovered
        assert "https://example.com/static/images/hero.webp" in ripper._discovered

    def test_robots_parser_allows_normal_pages(self):
        settings = RipperSettings(url="https://example.com", respect_robots=True, output_dir="C:\\output")
        ripper = WebRipper(settings=settings, progress_callback=lambda e: None)
        robots_txt = "User-agent: *\nDisallow: /admin\nDisallow: /private/\n"
        import urllib.robotparser
        rp = urllib.robotparser.RobotFileParser()
        rp.parse(robots_txt.splitlines())
        ripper._robot_parser = rp
        assert ripper._is_robot_allowed("https://example.com/index.html") is True
        assert ripper._is_robot_allowed("https://example.com/public/data.json") is True
        assert ripper._is_robot_allowed("https://example.com/admin/login") is False

    def test_stealth_script_features(self):
        assert "PluginArray" in STEALTH_INIT_SCRIPT
        assert "WebGL2RenderingContext" in STEALTH_INIT_SCRIPT
        assert "namedItem" in STEALTH_INIT_SCRIPT
        assert "__shadowRoots" in STEALTH_INIT_SCRIPT

    def test_oversized_csp_header_detected(self):
        from app.scanners.headers import HeaderScanner
        from app.models import FileResult
        # Generate an oversized CSP header (e.g. 10,000 bytes)
        domains = " ".join([f"https://sub{i}.deriv.com" for i in range(500)])
        huge_csp = f"default-src 'self' {domains};"
        assert len(huge_csp) > 8192

        file_res = FileResult(
            url="https://deriv.com",
            status=200,
            size=1000,
            content_type="text/html",
            response_headers={"Content-Security-Policy": huge_csp},
        )
        rip_report = RipReport(url="https://deriv.com", files=[file_res])
        settings = RipperSettings(url="https://deriv.com")
        scanner = HeaderScanner(rip_report, settings)
        result = scanner.scan()

        oversized = [f for f in result.findings if "Oversized Content-Security-Policy" in f.title]
        assert len(oversized) == 1
        assert "exceeding standard 8 KB HTTP buffer limits" in oversized[0].description
        assert oversized[0].category == "headers"

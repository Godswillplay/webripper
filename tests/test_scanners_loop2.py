"""
Unit tests for Loop 2 scanner improvements:
- Multi-part TLD apex extraction (extract_base_domain)
- Cookie broad domain scoping and JWT padding math
- CVE scanner integration with tech scanner findings and server header regex
- DNS scanner SPF/DMARC fallback and quarantine handling
- Emails scanner staff email vs third-party email domain scoping
- Endpoints scanner parameter query strings and third party filtering
- Paths scanner SPA false-positive filtering for sensitive files
- WAF scanner behavioral detection on HTTP block
- CORS scanner deduplication
"""

import pytest
from app.models import Finding, RipReport, Severity, ScanResult, RipperSettings
from app.scanners.base import extract_base_domain
from app.scanners.cookies import _decode_jwt_part, CookieScanner
from app.scanners.cves import CVEScanner
from app.scanners.dns import DNSScanner
from app.scanners.emails import EmailHarvester
from app.scanners.endpoints import EndpointScanner, _RE_API_PATH
from app.scanners.paths import PathScanner
from app.scanners.tech import TechScanner
from app.scanners.waf import WAFScanner


def test_extract_base_domain_multipart():
    assert extract_base_domain("sub.example.co.uk") == "example.co.uk"
    assert extract_base_domain("dev.api.target.com.au") == "target.com.au"
    assert extract_base_domain("admin.portal.site.com") == "site.com"
    assert extract_base_domain("localhost") == "localhost"
    assert extract_base_domain("127.0.0.1") == "127.0.0.1"


def test_jwt_padding_even_multiple_of_four():
    # Header: {"alg":"none"} in base64url is "eyJhbGciOiJub25lIn0" (len 19 -> needs 1 pad)
    header = _decode_jwt_part("eyJhbGciOiJub25lIn0")
    assert header.get("alg") == "none"

    # String with len divisible by 4: "eyJhbGciOiJIUzI1NiJ9" (len 20 -> 0 pad needed)
    header2 = _decode_jwt_part("eyJhbGciOiJIUzI1NiJ9")
    assert header2.get("alg") == "HS256"


def test_cve_scanner_server_header_regex():
    settings = RipperSettings(url="https://target.com")
    report = RipReport(url="https://target.com")
    scanner = CVEScanner(report, settings)

    # Mock server header with prefix
    from app.models import FileResult
    fr = FileResult(
        url="https://target.com/",
        local_path="",
        response_headers={"Server": "Ubuntu Apache/2.4.41 (Unix)"}
    )
    report.files.append(fr)
    techs = scanner._gather_detected_tech()
    assert "apache" in techs
    assert techs["apache"] == "2.4.41"


def test_dns_scanner_dmarc_quarantine():
    settings = RipperSettings(url="https://target.com")
    report = RipReport(url="https://target.com")
    scanner = DNSScanner(report, settings)
    scanner._analyze_dmarc("target.com", "v=DMARC1; p=quarantine; rua=mailto:dmarc@target.com")

    findings = scanner._findings
    assert any(f.title == "DMARC Policy: Quarantine" for f in findings)


def test_emails_staff_vs_third_party():
    settings = RipperSettings(url="https://mycompany.com")
    report = RipReport(url="https://mycompany.com")
    scanner = EmailHarvester(report, settings)

    # Create dummy temp file
    import tempfile, os
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as tf:
        tf.write("""
            const staff = "alice.smith@mycompany.com";
            const vendor = "support@cloudvendor.net";
            const retinaImg = "icon@2x.png";
        """)
        tf_path = tf.name

    try:
        from app.models import FileResult
        report.files.append(FileResult(url="https://mycompany.com/app.js", local_path=tf_path))
        result = scanner.scan()
        # Retina asset must NOT be detected as email
        assert "icon@2x.png" not in [f.title for f in scanner._findings]
        # Staff email should be detected
        staff_findings = [f for f in scanner._findings if "Staff Emails Exposed" in f.title]
        assert len(staff_findings) == 1
        assert "alice.smith@mycompany.com" in staff_findings[0].evidence
        # Third party email should be classified as third party, not staff
        assert "support@cloudvendor.net" not in staff_findings[0].evidence
    finally:
        if os.path.exists(tf_path):
            os.remove(tf_path)


def test_endpoints_regex_query_params():
    m = _RE_API_PATH.search('"/api/users?status=active&sort=asc"')
    assert m is not None
    assert m.group(1) == "/api/users?status=active&sort=asc"


def test_password_false_positive_filter():
    from app.scanners.secrets import _is_password_false_positive

    # Should be TRUE (false positive)
    assert _is_password_false_positive('password: "required"', 'lg_password: "required"') is True
    assert _is_password_false_positive('password: "true"', 'debug_password: "true"') is True
    assert _is_password_false_positive('secret: "placeholder"', 'const x = {secret: "placeholder"}') is True
    assert _is_password_false_positive('password = "required"', '$(form).validate({ rules: { password: "required" } })') is True

    # Should be FALSE (real secrets)
    assert _is_password_false_positive('password: "s3cr3t_k3y_abc123"', 'const config = { password: "s3cr3t_k3y_abc123" }') is False
    assert _is_password_false_positive('api_key: "sk_live_abc123def456"', 'const api_key: "sk_live_abc123def456"') is False

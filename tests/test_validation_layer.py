"""
Phase 1 Acceptance Tests — Proof-Based Validator Layer.

Verifies:
1. Planted vulnerabilities (SQLi, CORS, Open Redirect, Exposed Files, Canaries, Secrets)
   verify deterministically with confidence="VERIFIED" and proof artifacts attached.
2. XSS degrades gracefully when headless browser is not available.
3. Known false-positive bait (docs sample keys, wildcard CORS without credentials/reflection,
   soft-404 catch-all pages, canaries with no token delta) do NOT verify.
4. Clean pages yield zero VERIFIED findings.
5. Scanners only propose candidates (LIKELY/POSSIBLE); only validators set VERIFIED.
"""

from __future__ import annotations

import http.server
import json
import threading
import urllib.parse
import urllib.request
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlparse

import pytest

from app.models import Finding, ReconReport, RipperSettings, ScanResult, Severity
from app.validation import (
    CanaryValidator,
    CORSValidator,
    ExposedFilesValidator,
    OpenRedirectValidator,
    SecretsValidator,
    SQLiValidator,
    ValidationEngine,
    XSSValidator,
)


class FixtureTrapServer(http.server.BaseHTTPRequestHandler):
    """Local deterministic fixture server with planted vulns and false-positive bait."""

    def log_message(self, format, *args):
        pass  # Suppress console logging in tests

    def do_POST(self):
        self.do_GET()

    def do_OPTIONS(self):
        self.do_GET()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        # 1. Clean endpoint
        if path == "/clean":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Clean Safe Page</h1><p>No vulnerabilities here.</p></body></html>")
            return

        # 2. Planted SQLi
        if path == "/sqli":
            query_id = params.get("id", [""])[0]
            if "'" in query_id or "'" in parsed.query:
                self.send_response(500)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"Error: SQL syntax error: unexpected quote in MySQL query at line 1")
            else:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status": "ok", "user": "normal_record"}')
            return

        # 3. Planted CORS (vulnerable: reflects arbitrary origin + credentials true)
        if path == "/cors-vuln":
            origin = self.headers.get("Origin", "")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            self.wfile.write(b'{"secret_data": "authenticated_profile"}')
            return

        # 4. Safe CORS bait (wildcard * without credentials and without origin reflection)
        if path == "/cors-safe":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(b'{"public_data": "world_readable"}')
            return

        # 5. Planted Open Redirect
        if path == "/redirect":
            dest = params.get("url", [""])[0]
            if dest:
                self.send_response(302)
                self.send_header("Location", dest)
                self.end_headers()
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Missing url parameter")
            return

        # 6. Planted Exposed File (.git/HEAD)
        if path == "/exposed-git/.git/HEAD":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ref: refs/heads/main\n")
            return

        # 7. Soft-404 catch-all bait (all paths return 200 with HTML generic template)
        if path.startswith("/catch-all-fake-404"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<!DOCTYPE html><html><head><title>404</title></head><body><h1>Page not found generic template</h1></body></html>")
            return

        # 8. Planted Canary (confirms only on specific canary probe request)
        if path == "/canary-vuln":
            canary_hdr = (
                self.headers.get("X-Canary-Probe")
                or self.headers.get("X-Canary")
                or self.headers.get("X-Probe")
            )
            if canary_hdr:
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Status OK: canary-delta-revealed-9912 token present")
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Normal baseline response without token")
            return

        # 9. Fake Canary bait (returns 200 OK but NEVER reveals canary token)
        if path == "/canary-fake":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Status OK: Generic status 200 message with no matching token")
            return

        # 10. Reflected XSS
        if path == "/xss":
            q = params.get("q", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            resp = f"<html><body><script>var search = '{q}';</script></body></html>"
            self.wfile.write(resp.encode("utf-8"))
            return

        # Default 404
        self.send_response(404)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Not Found")


@pytest.fixture(scope="module")
def fixture_server():
    """Starts local fixture server on an ephemeral port."""
    server = http.server.HTTPServer(("127.0.0.1", 0), FixtureTrapServer)
    host, port = server.server_address[0], server.server_address[1]
    base_url = f"http://{host}:{port}"

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield base_url

    server.shutdown()
    server.server_close()
    thread.join(timeout=2.0)


# ---------------------------------------------------------------------------
# Planted Vulnerabilities Tests
# ---------------------------------------------------------------------------

def test_planted_sqli_verifies(fixture_server):
    """Planted SQLi produces meaningful differential delta and verifies."""
    validator = SQLiValidator(RipperSettings(url=fixture_server))
    finding = Finding(
        severity=Severity.HIGH,
        confidence="LIKELY",
        category="vulns",
        title="SQLi in id parameter",
        description="Candidate error-based SQL injection",
        url=f"{fixture_server}/sqli?id=1",
        metadata={
            "vuln_type": "SQL Injection",
            "parameter": "id",
            "payload": "'",
        },
    )

    assert validator.can_validate(finding)
    validated = validator.validate(finding)

    assert validated.confidence == "VERIFIED"
    assert "proof" in validated.metadata
    assert validated.metadata.get("proof_attached") is True
    assert "observed_delta" in validated.metadata["proof"]
    assert "syntax error" in str(validated.metadata["proof"]["observed_delta"]).lower()


def test_planted_cors_verifies(fixture_server):
    """Planted CORS with arbitrary reflection and credentials verifies."""
    validator = CORSValidator(RipperSettings(url=fixture_server))
    finding = Finding(
        severity=Severity.HIGH,
        confidence="LIKELY",
        category="cors",
        title="CORS Misconfiguration on /cors-vuln",
        description="Candidate CORS arbitrary origin reflection",
        url=f"{fixture_server}/cors-vuln",
    )

    assert validator.can_validate(finding)
    validated = validator.validate(finding)

    assert validated.confidence == "VERIFIED"
    assert "proof" in validated.metadata
    assert validated.metadata.get("proof_attached") is True
    assert "reflected in access-control-allow-origin" in str(validated.metadata["proof"]["observed_delta"]).lower()


def test_planted_redirect_verifies(fixture_server):
    """Planted Open Redirect verifies strictly on Location header delta."""
    validator = OpenRedirectValidator(RipperSettings(url=fixture_server))
    finding = Finding(
        severity=Severity.MEDIUM,
        confidence="LIKELY",
        category="vulns",
        title="Open Redirect on url parameter",
        description="Candidate open redirect vulnerability",
        url=f"{fixture_server}/redirect?url=https://evil.com",
        metadata={
            "vuln_type": "Open Redirect",
            "parameter": "url",
        },
    )

    assert validator.can_validate(finding)
    validated = validator.validate(finding)

    assert validated.confidence == "VERIFIED"
    assert "proof" in validated.metadata
    assert validated.metadata.get("proof_attached") is True
    assert "external redirection" in str(validated.metadata["proof"]["observed_delta"]).lower()


def test_planted_exposed_files_verifies(fixture_server):
    """Planted .git/HEAD verifies with authentic ref: signature."""
    validator = ExposedFilesValidator(RipperSettings(url=fixture_server))
    finding = Finding(
        severity=Severity.HIGH,
        confidence="LIKELY",
        category="paths",
        title="/exposed-git/.git/HEAD",
        description="Exposed Git HEAD file",
        url=f"{fixture_server}/exposed-git/.git/HEAD",
    )

    assert validator.can_validate(finding)
    validated = validator.validate(finding)

    assert validated.confidence == "VERIFIED"
    assert "proof" in validated.metadata
    assert validated.metadata.get("proof_attached") is True
    assert "ref: refs/" in str(validated.metadata["proof"]["observed_delta"])


def test_planted_canary_verifies(fixture_server):
    """Canary confirms on unique token delta, never on status code alone."""
    validator = CanaryValidator(RipperSettings(url=fixture_server))
    finding = Finding(
        severity=Severity.HIGH,
        confidence="LIKELY",
        category="scenarios",
        title="Scenario: Active Exploit Canary",
        description="Canary verification recipe",
        url=f"{fixture_server}/canary-vuln",
        metadata={
            "scenario_id": "TEST-CANARY-001",
            "match_regex": "canary-delta-revealed-9912",
            "probe_headers": {"X-Canary-Probe": "activate"},
        },
    )

    assert validator.can_validate(finding)
    validated = validator.validate(finding)

    assert validated.confidence == "VERIFIED"
    assert "proof" in validated.metadata
    assert validated.metadata.get("proof_attached") is True
    assert "canary-delta-revealed-9912" in str(validated.metadata["proof"]["observed_delta"])


def test_planted_secrets_verifies():
    """Real high-entropy secret token verifies."""
    validator = SecretsValidator(RipperSettings())
    test_token = "AK" + "IAJ6R7T8W9X0Y1Z2AB"
    finding = Finding(
        severity=Severity.CRITICAL,
        confidence="LIKELY",
        category="secrets",
        title="AWS Access Key Disclosed",
        description="Hardcoded AWS Access Key in source",
        evidence=test_token,
        metadata={
            "token": test_token,
            "pattern_name": "AWS Access Key",
        },
    )

    assert validator.can_validate(finding)
    validated = validator.validate(finding)

    assert validated.confidence == "VERIFIED"
    assert "proof" in validated.metadata
    assert validated.metadata.get("proof_attached") is True
    assert "entropy" in str(validated.metadata["proof"]["observed_delta"]).lower()


def test_xss_degrades_gracefully_when_browser_absent(fixture_server):
    """XSS candidate gracefully degrades to POSSIBLE when real browser execution is unavailable."""
    validator = XSSValidator(RipperSettings(url=fixture_server))
    finding = Finding(
        severity=Severity.HIGH,
        confidence="LIKELY",
        category="vulns",
        title="XSS on q parameter",
        description="Reflected XSS candidate",
        url=f"{fixture_server}/xss?q=canary_payload",
        metadata={
            "vuln_type": "Reflected XSS",
            "parameter": "q",
            "payload": "<script>alert(1)</script>",
        },
    )

    assert validator.can_validate(finding)
    validated = validator.validate(finding)
    # Since Playwright browser binary is not pre-installed in the offline environment,
    # the validator must degrade gracefully to POSSIBLE rather than falsely claiming VERIFIED.
    assert validated.confidence in ("POSSIBLE", "LIKELY")
    assert validated.confidence != "VERIFIED"


# ---------------------------------------------------------------------------
# False-Positive Bait Tests
# ---------------------------------------------------------------------------

def test_false_positive_bait_docs_secret_rejected():
    """Documentation sample keys (e.g. AKIAIOSFODNN7EXAMPLE) do NOT verify."""
    validator = SecretsValidator(RipperSettings())
    finding = Finding(
        severity=Severity.CRITICAL,
        confidence="LIKELY",
        category="secrets",
        title="AWS Access Key in Documentation",
        description="Sample key from AWS documentation",
        evidence="AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'",
        metadata={"token": "AKIAIOSFODNN7EXAMPLE"},
    )

    validated = validator.validate(finding)
    assert validated.confidence != "VERIFIED"
    assert validated.confidence == "POSSIBLE"
    assert "rejected" in validated.metadata.get("validation_note", "").lower()


def test_false_positive_bait_wildcard_cors_rejected(fixture_server):
    """Wildcard CORS without origin reflection and without credentials does NOT verify."""
    validator = CORSValidator(RipperSettings(url=fixture_server))
    finding = Finding(
        severity=Severity.LOW,
        confidence="LIKELY",
        category="cors",
        title="CORS Wildcard on /cors-safe",
        description="Wildcard CORS policy",
        url=f"{fixture_server}/cors-safe",
    )

    validated = validator.validate(finding)
    assert validated.confidence != "VERIFIED"
    assert validated.confidence == "POSSIBLE"


def test_false_positive_bait_soft_404_rejected(fixture_server):
    """Catch-all soft 404 pages returning generic HTML do NOT verify as exposed files."""
    validator = ExposedFilesValidator(RipperSettings(url=fixture_server))
    finding = Finding(
        severity=Severity.HIGH,
        confidence="LIKELY",
        category="paths",
        title="/catch-all-fake-404/.env",
        description="Candidate .env file",
        url=f"{fixture_server}/catch-all-fake-404/.env",
    )

    validated = validator.validate(finding)
    assert validated.confidence != "VERIFIED"
    assert validated.confidence == "POSSIBLE"


def test_false_positive_bait_canary_status_only_rejected(fixture_server):
    """Canary probe that only gets 200 without marker delta does NOT verify."""
    validator = CanaryValidator(RipperSettings(url=fixture_server))
    finding = Finding(
        severity=Severity.HIGH,
        confidence="LIKELY",
        category="scenarios",
        title="Scenario: Fake Canary",
        description="Canary probe with missing delta",
        url=f"{fixture_server}/canary-fake",
        metadata={
            "scenario_id": "TEST-FAKE-002",
            "match_regex": "unique_token_never_present_12345",
        },
    )

    validated = validator.validate(finding)
    assert validated.confidence != "VERIFIED"
    assert validated.confidence == "POSSIBLE"


def test_clean_page_yields_zero_verified(fixture_server):
    """A clean scan with only informational findings yields zero VERIFIED findings."""
    engine = ValidationEngine(RipperSettings(url=fixture_server))
    recon = ReconReport(
        url=f"{fixture_server}/clean",
        scan_results=[
            ScanResult(
                scanner_name="headers",
                findings=[
                    Finding(
                        severity=Severity.INFO,
                        category="headers",
                        title="Clean Server Header",
                        description="Normal server response header",
                        url=f"{fixture_server}/clean",
                    )
                ],
            )
        ],
    )

    validated_recon = engine.validate_report(recon)
    verified = [f for f in validated_recon.all_findings if f.confidence == "VERIFIED"]
    assert len(verified) == 0


def test_no_scanner_sets_verified_directly():
    """Verify that scanners produce candidates (LIKELY/POSSIBLE) and never claim VERIFIED directly."""
    from app.scanners.cves import CVEScanner
    from app.scanners.subdomains import SubdomainScanner
    from app.scanners.vulns import VulnScanner

    # Verify scanner source code has no direct assignment of confidence="VERIFIED"
    for scanner_cls in (VulnScanner, CVEScanner, SubdomainScanner):
        import inspect
        src = inspect.getsource(scanner_cls)
        assert 'confidence="VERIFIED"' not in src
        assert "confidence = 'VERIFIED'" not in src
        assert 'confidence = "VERIFIED"' not in src


def test_server_deterministic_ten_routes(fixture_server):
    """Verify that all 10 local server routes serve deterministic responses per spec."""
    base_url = fixture_server

    # 1. /xss: reflects user input q in <script> context
    with urllib.request.urlopen(f"{base_url}/xss?q=canary_eval_42") as resp:
        body = resp.read().decode("utf-8")
        assert resp.status == 200
        assert "<script>" in body
        assert "canary_eval_42" in body

    # 2. /sqli: if id has single quote, returns SQL syntax error, else normal row
    with urllib.request.urlopen(f"{base_url}/sqli?id=1") as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert data.get("status") == "ok"

    try:
        urllib.request.urlopen(f"{base_url}/sqli?id=1'")
        pytest.fail("Expected HTTP 500 on SQL single quote probe")
    except urllib.error.HTTPError as err:
        assert err.code == 500
        assert "SQL syntax error: unexpected quote in MySQL query" in err.read().decode("utf-8")

    # 3. /cors-vuln: reflects Origin header and sets Access-Control-Allow-Credentials: true
    req_cors = urllib.request.Request(f"{base_url}/cors-vuln", headers={"Origin": "https://attacker.example.com"})
    with urllib.request.urlopen(req_cors) as resp:
        assert resp.status == 200
        assert resp.headers.get("Access-Control-Allow-Origin") == "https://attacker.example.com"
        assert resp.headers.get("Access-Control-Allow-Credentials") == "true"

    # 4. /cors-safe: returns Access-Control-Allow-Origin: * without credentials and without origin reflection
    with urllib.request.urlopen(f"{base_url}/cors-safe") as resp:
        assert resp.status == 200
        assert resp.headers.get("Access-Control-Allow-Origin") == "*"
        assert resp.headers.get("Access-Control-Allow-Credentials") is None

    # 5. /redirect: if url parameter passed, responds with 302 and Location: {url}
    class _NoRedirectOpener(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    no_redir = urllib.request.build_opener(_NoRedirectOpener())
    try:
        no_redir.open(f"{base_url}/redirect?url=https://attacker.example.com/defense-proof")
    except urllib.error.HTTPError as err:
        assert err.code == 302
        assert err.headers.get("Location") == "https://attacker.example.com/defense-proof"

    # 6. /exposed-git/.git/HEAD: returns ref: refs/heads/main\n
    with urllib.request.urlopen(f"{base_url}/exposed-git/.git/HEAD") as resp:
        assert resp.status == 200
        assert resp.read().decode("utf-8") == "ref: refs/heads/main\n"

    # 7. /catch-all-fake-404/*: returns 200 with HTML 'Page not found generic template'
    with urllib.request.urlopen(f"{base_url}/catch-all-fake-404/nonexistent_file.json") as resp:
        assert resp.status == 200
        assert "Page not found generic template" in resp.read().decode("utf-8")

    # 8. /canary-vuln: returns token canary-delta-revealed-9912 only when canary probe header/body sent
    with urllib.request.urlopen(f"{base_url}/canary-vuln") as resp:
        assert "canary-delta-revealed-9912" not in resp.read().decode("utf-8")

    req_canary = urllib.request.Request(f"{base_url}/canary-vuln", headers={"X-Canary-Probe": "activate"})
    with urllib.request.urlopen(req_canary) as resp:
        assert "canary-delta-revealed-9912" in resp.read().decode("utf-8")

    # 9. /canary-fake: returns 200 with status code OK but no token delta
    req_fake = urllib.request.Request(f"{base_url}/canary-fake", headers={"X-Canary-Probe": "activate"})
    with urllib.request.urlopen(req_fake) as resp:
        assert resp.status == 200
        assert "canary-delta-revealed-9912" not in resp.read().decode("utf-8")

    # 10. /clean: clean HTML page with no vulnerabilities
    with urllib.request.urlopen(f"{base_url}/clean") as resp:
        assert resp.status == 200
        assert "Clean Safe Page" in resp.read().decode("utf-8")


def test_planted_xss_verifies_with_proof(fixture_server):
    """Planted XSS validates and marks VERIFIED with proof when DOM canary executes."""
    validator = XSSValidator(RipperSettings(url=fixture_server))
    finding = Finding(
        severity=Severity.HIGH,
        confidence="LIKELY",
        category="vulns",
        title="Reflected XSS on parameter q",
        description="Candidate reflected XSS in parameter q",
        url=f"{fixture_server}/xss?q=canary_payload",
        metadata={
            "vuln_type": "Reflected XSS",
            "parameter": "q",
            "payload": "<script>window.__wr_xss_proof=1337;</script>",
        },
    )

    with patch("playwright.sync_api.sync_playwright") as mock_pw:
        mock_browser = MagicMock()
        mock_pw.return_value.__enter__.return_value.chromium.launch.return_value = mock_browser
        mock_ctx = mock_browser.new_context.return_value
        mock_page = mock_ctx.new_page.return_value
        mock_page.evaluate.return_value = 1337

        validated = validator.validate(finding)

        assert validated.confidence == "VERIFIED"
        assert "proof" in validated.metadata
        assert validated.metadata.get("proof_attached") is True
        proof = validated.metadata["proof"]
        assert proof["validator"] == "xss"
        assert "request" in proof
        assert "response" in proof
        assert "observed_delta" in proof
        assert proof["response"]["dom_execution_confirmed"] is True


def test_non_validator_scanner_finding_cannot_be_verified(fixture_server):
    """A non-validator scanner finding (e.g. tech fingerprint, headers) cannot be VERIFIED."""
    engine = ValidationEngine(RipperSettings(url=fixture_server))
    tech_finding = Finding(
        severity=Severity.LOW,
        confidence="POSSIBLE",
        category="tech",
        title="Server Tech Disclosed: Nginx 1.24",
        description="Nginx version header observed",
        url=f"{fixture_server}/clean",
    )

    validated = engine.validate_finding(tech_finding)
    assert validated.confidence != "VERIFIED"
    assert validated.confidence == "POSSIBLE"
    assert "proof" not in validated.metadata


def test_validation_engine_batch_report_coordination(fixture_server):
    """
    Validates a mixed batch ReconReport.
    Asserts only authentic planted vulnerabilities become VERIFIED with proof.
    """
    base_url = fixture_server

    planted_findings = [
        Finding(
            severity=Severity.CRITICAL,
            confidence="LIKELY",
            category="vulns",
            title="SQLi in id parameter",
            description="SQL injection candidate",
            url=f"{base_url}/sqli?id=1",
            metadata={"parameter": "id", "vuln_type": "sqli"},
        ),
        Finding(
            severity=Severity.HIGH,
            confidence="LIKELY",
            category="cors",
            title="CORS Arbitrary Origin",
            description="CORS origin reflection candidate",
            url=f"{base_url}/cors-vuln",
        ),
        Finding(
            severity=Severity.MEDIUM,
            confidence="LIKELY",
            category="vulns",
            title="Open Redirect in url",
            description="Redirect candidate",
            url=f"{base_url}/redirect?url=/home",
            metadata={"parameter": "url", "vuln_type": "redirect"},
        ),
        Finding(
            severity=Severity.HIGH,
            confidence="LIKELY",
            category="paths",
            title="/exposed-git/.git/HEAD",
            description="Git HEAD candidate",
            url=f"{base_url}/exposed-git/.git/HEAD",
        ),
        Finding(
            severity=Severity.HIGH,
            confidence="LIKELY",
            category="scenarios",
            title="Scenario Canary",
            description="Canary candidate",
            url=f"{base_url}/canary-vuln",
            metadata={
                "match_regex": "canary-delta-revealed-9912",
                "probe_headers": {"X-Canary-Probe": "activate"},
            },
        ),
    ]

    bait_findings = [
        Finding(
            severity=Severity.CRITICAL,
            confidence="LIKELY",
            category="secrets",
            title="Documentation AWS Key",
            description="AWS key bait",
            evidence="AKIAIOSFODNN7EXAMPLE",
            metadata={"token": "AKIAIOSFODNN7EXAMPLE"},
        ),
        Finding(
            severity=Severity.LOW,
            confidence="LIKELY",
            category="cors",
            title="CORS Wildcard",
            description="Wildcard CORS bait",
            url=f"{base_url}/cors-safe",
        ),
        Finding(
            severity=Severity.HIGH,
            confidence="LIKELY",
            category="paths",
            title="Soft-404 Fake File",
            description="Soft-404 bait",
            url=f"{base_url}/catch-all-fake-404/.env",
        ),
        Finding(
            severity=Severity.HIGH,
            confidence="LIKELY",
            category="scenarios",
            title="Canary Fake Endpoint",
            description="Canary without delta",
            url=f"{base_url}/canary-fake",
            metadata={"match_regex": "token_that_does_not_exist_7788"},
        ),
    ]

    clean_findings = [
        Finding(
            severity=Severity.INFO,
            confidence="POSSIBLE",
            category="headers",
            title="Clean Server Header",
            description="Clean header",
            url=f"{base_url}/clean",
        )
    ]

    sr_planted = ScanResult(scanner_name="planted", findings=planted_findings)
    sr_bait = ScanResult(scanner_name="bait", findings=bait_findings)
    sr_clean = ScanResult(scanner_name="clean", findings=clean_findings)

    recon = ReconReport(
        url=base_url,
        scan_results=[sr_planted, sr_bait, sr_clean],
    )

    engine = ValidationEngine(RipperSettings(url=base_url))
    validated_report = engine.validate_report(recon)

    verified = [f for f in validated_report.all_findings if f.confidence == "VERIFIED"]
    not_verified = [f for f in validated_report.all_findings if f.confidence != "VERIFIED"]

    assert len(verified) == 5
    for pf in planted_findings:
        assert pf.confidence == "VERIFIED"
        assert "proof" in pf.metadata
        assert pf.metadata.get("proof_attached") is True

    assert len(not_verified) == 5
    for bf in bait_findings:
        assert bf.confidence != "VERIFIED"
        assert "proof" not in bf.metadata

    for cf in clean_findings:
        assert cf.confidence != "VERIFIED"
        assert "proof" not in cf.metadata

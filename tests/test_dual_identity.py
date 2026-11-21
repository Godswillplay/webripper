"""
Phase 3 Acceptance Tests — Dual-Identity Differential Engine (BOLA / IDOR & BFLA).

Tests run completely offline using an ephemeral-port local fixture server.
Verifies:
  a) Vulnerable endpoint /api/documents/{doc_id} readable by user B -> flags VERIFIED BOLA with proof.
  b) Protected endpoint /api/private/{user_id} where user B gets 403 Forbidden -> clean, no finding.
  c) Admin endpoint /api/admin/users accessible by user B without admin role -> flags VERIFIED BFLA with proof.
  d) Admin endpoint properly rejecting non-admin -> clean, no finding.
  e) Candidate extraction logic (numeric, UUID, hash, query, body).
  f) Non-destructive safe-method invariant.
  g) False-positive bait rejection (HTML login forms returning 200).
"""

from __future__ import annotations

import http.server
import json
import threading
from urllib.parse import parse_qs, urlparse

import pytest

from app.models import Finding, RipReport, RipperSettings, Severity
from app.scanners.bola import (
    BOLAScanner,
    extract_admin_route_candidates,
    extract_object_id_candidates,
    is_safe_method_or_dry_run,
    generate_poc_curl,
    compute_body_similarity,
)


# ---------------------------------------------------------------------------
# Deterministic Local Fixture Server
# ---------------------------------------------------------------------------

class DualIdentityFixtureServer(http.server.BaseHTTPRequestHandler):
    """Local offline fixture server implementing vulnerable and protected endpoints."""

    def log_message(self, format, *args):
        pass  # Suppress console logging during test runs

    def do_HEAD(self):
        self.do_GET()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, OPTIONS")
        self.end_headers()

    def do_POST(self):
        self.do_GET()

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()

    def _get_identity(self) -> str:
        """Extract identity context from Cookie or Authorization header."""
        cookie_header = self.headers.get("Cookie", "")
        auth_header = self.headers.get("Authorization", "")

        # Check for User A / Alice
        if "user_a" in cookie_header or "user_a" in auth_header or "alice" in cookie_header or "alice" in auth_header:
            return "user_a"

        # Check for User B / Bob
        if "user_b" in cookie_header or "user_b" in auth_header or "bob" in cookie_header or "bob" in auth_header:
            return "user_b"

        return "anonymous"

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        identity = self._get_identity()

        # -------------------------------------------------------------------
        # 1. Vulnerable BOLA Endpoint: /api/documents/{doc_id}
        # -------------------------------------------------------------------
        if path.startswith("/api/documents/"):
            doc_id = path.split("/api/documents/")[-1]
            if identity == "anonymous":
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error": "Authentication required"}')
                return

            # Both user_a and user_b get User A's private confidential document (BOLA flaw)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            payload = {
                "doc_id": doc_id,
                "owner": "user_a",
                "title": "Secret Financial Strategy 2026",
                "content": "Confidential Alice Tenant Document Details",
            }
            self.wfile.write(json.dumps(payload).encode("utf-8"))
            return

        # -------------------------------------------------------------------
        # 2. Protected Endpoint: /api/private/{user_id}
        # -------------------------------------------------------------------
        if path.startswith("/api/private/"):
            target_user = path.split("/api/private/")[-1]
            if identity == "anonymous":
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error": "Authentication required"}')
                return

            if identity == "user_a":
                # User A accessing their own resource: allowed
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                payload = {
                    "user_id": target_user,
                    "profile": "Alice Profile Data",
                    "owner": "user_a",
                }
                self.wfile.write(json.dumps(payload).encode("utf-8"))
                return
            else:
                # User B attempting cross-tenant access: properly rejected!
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error": "Access denied: cannot view another user private data"}')
                return

        # -------------------------------------------------------------------
        # 3. Vulnerable BFLA Admin Endpoint: /api/admin/users
        # -------------------------------------------------------------------
        if path == "/api/admin/users":
            if identity == "anonymous":
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error": "Authentication required"}')
                return

            # Flaw: Both user_a (Admin) and user_b (Standard User) can access admin data!
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            payload = {
                "admin_area": True,
                "users": [
                    {"id": 1, "username": "admin", "role": "admin"},
                    {"id": 2, "username": "alice", "role": "user"},
                    {"id": 3, "username": "bob", "role": "user"},
                ],
            }
            self.wfile.write(json.dumps(payload).encode("utf-8"))
            return

        # -------------------------------------------------------------------
        # 4. Protected Admin Endpoint: /api/admin/system
        # -------------------------------------------------------------------
        if path == "/api/admin/system":
            if identity == "anonymous":
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error": "Authentication required"}')
                return

            if identity == "user_a":
                # Admin allowed
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"system_status": "ok", "admin_panel": true}')
                return
            else:
                # Standard user B rejected with 403 Forbidden!
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error": "Forbidden: Administrator role required"}')
                return

        # -------------------------------------------------------------------
        # 5. Soft-404 / Login Redirect Bait: /api/bait/{item_id}
        # Returns 200 OK with HTML login page to non-owners
        # -------------------------------------------------------------------
        if path.startswith("/api/bait/"):
            if identity == "user_a":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"item_id": 999, "owner": "user_a", "data": "alice_data"}')
                return
            else:
                # Returns 200 OK with an HTML login page (false-positive bait)
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(
                    b"<html><body><h1>Please Log In</h1>"
                    b'<form action="/login"><input type="password" name="p"></form>'
                    b"</body></html>"
                )
                return

        # Default 404
        self.send_response(404)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Not Found")


# ---------------------------------------------------------------------------
# Pytest Fixture on Ephemeral Port
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def fixture_server():
    """Starts local fixture server on an ephemeral port (127.0.0.1:0)."""
    server = http.server.HTTPServer(("127.0.0.1", 0), DualIdentityFixtureServer)
    host, port = server.server_address[0], server.server_address[1]
    base_url = f"http://{host}:{port}"

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield base_url

    server.shutdown()
    server.server_close()
    thread.join(timeout=2.0)


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------

def test_vulnerable_documents_flags_verified_bola(fixture_server):
    """
    Vulnerable endpoint /api/documents/{doc_id} where user A's doc is readable
    by user B -> flags confidence="VERIFIED" BOLA with machine-checkable proof.
    """
    settings = RipperSettings(
        url=fixture_server,
        auth_cookie="session=user_a_token",
    )
    # Configure Identity B and Tenant Marker
    settings.identity_a_cookie = "session=user_a_token"
    settings.identity_b_cookie = "session=user_b_token"
    settings.identity_a_tenant_marker = "user_a"

    report = RipReport(
        url=fixture_server,
        captured_requests=[
            {
                "url": f"{fixture_server}/api/documents/doc_101",
                "method": "GET",
                "status": 200,
            }
        ],
    )

    scanner = BOLAScanner(report, settings)
    result = scanner.scan()

    bola_findings = [f for f in result.findings if f.category == "bola"]
    assert len(bola_findings) == 1

    finding = bola_findings[0]
    assert finding.confidence == "VERIFIED"
    assert finding.severity == Severity.CRITICAL
    assert "doc_101" in finding.title or "documents" in finding.title
    assert "user_a" in finding.evidence
    assert finding.metadata.get("proof_attached") is True

    # Validate attached proof artifact
    proof = finding.metadata.get("proof", {})
    assert proof.get("scanner") == "bola"
    assert proof.get("vulnerability_type") == "BOLA"
    assert proof.get("classification") == "BOLA_VERIFIED_WITH_MARKER"
    assert proof["baseline_response"]["status"] == 200
    assert proof["replay_response"]["status"] == 200
    assert proof["anonymous_response"]["status"] == 401
    assert proof["observed_delta"]["marker_leaked"] is True
    assert proof["observed_delta"]["tenant_marker"] == "user_a"
    assert "session=user_b_token" in proof.get("poc_curl", "")


def test_protected_private_clean_no_finding(fixture_server):
    """
    Protected endpoint /api/private/{user_id} where user B gets 403 Forbidden
    -> clean, no finding emitted.
    """
    settings = RipperSettings(
        url=fixture_server,
        auth_cookie="session=user_a_token",
    )
    settings.identity_a_cookie = "session=user_a_token"
    settings.identity_b_cookie = "session=user_b_token"
    settings.identity_a_tenant_marker = "user_a"

    report = RipReport(
        url=fixture_server,
        captured_requests=[
            {
                "url": f"{fixture_server}/api/private/user_a_42",
                "method": "GET",
                "status": 200,
            }
        ],
    )

    scanner = BOLAScanner(report, settings)
    result = scanner.scan()

    assert len(result.findings) == 0


def test_vulnerable_admin_users_flags_verified_bfla(fixture_server):
    """
    Admin endpoint /api/admin/users accessible by user B without admin role
    -> flags confidence="VERIFIED" BFLA with machine-checkable proof.
    """
    settings = RipperSettings(
        url=fixture_server,
        auth_cookie="session=user_a_admin",
    )
    settings.identity_a_cookie = "session=user_a_admin"
    settings.identity_b_cookie = "session=user_b_standard"

    report = RipReport(
        url=fixture_server,
        captured_requests=[
            {
                "url": f"{fixture_server}/api/admin/users",
                "method": "GET",
                "status": 200,
            }
        ],
    )

    scanner = BOLAScanner(report, settings)
    result = scanner.scan()

    bfla_findings = [f for f in result.findings if f.category == "bfla"]
    assert len(bfla_findings) == 1

    finding = bfla_findings[0]
    assert finding.confidence == "VERIFIED"
    assert finding.severity in (Severity.HIGH, Severity.CRITICAL)
    assert "admin/users" in finding.title
    assert finding.metadata.get("proof_attached") is True

    # Validate attached proof artifact
    proof = finding.metadata.get("proof", {})
    assert proof.get("scanner") == "bola"
    assert proof.get("vulnerability_type") == "BFLA"
    assert proof.get("classification") == "BFLA_ADMIN_ACCESS_BY_STANDARD_USER"
    assert proof["baseline_response"]["status"] == 200
    assert proof["replay_response"]["status"] == 200
    assert proof["anonymous_response"]["status"] == 401
    assert "session=user_b_standard" in proof.get("poc_curl", "")


def test_protected_admin_clean_no_finding(fixture_server):
    """
    Admin endpoint /api/admin/system properly rejecting non-admin with 403 Forbidden
    -> clean, no finding emitted.
    """
    settings = RipperSettings(
        url=fixture_server,
        auth_cookie="session=user_a_admin",
    )
    settings.identity_a_cookie = "session=user_a_admin"
    settings.identity_b_cookie = "session=user_b_standard"

    report = RipReport(
        url=fixture_server,
        captured_requests=[
            {
                "url": f"{fixture_server}/api/admin/system",
                "method": "GET",
                "status": 200,
            }
        ],
    )

    scanner = BOLAScanner(report, settings)
    result = scanner.scan()

    assert len(result.findings) == 0


def test_offline_full_suite_clean_and_vuln_mix(fixture_server):
    """
    End-to-end differential scan against all 4 endpoints simultaneously:
    - 2 vulnerable endpoints flag VERIFIED findings with proof attached.
    - 2 protected endpoints produce 0 findings.
    - Total verified findings == 2.
    """
    settings = RipperSettings(
        url=fixture_server,
        auth_cookie="session=user_a_token",
    )
    settings.identity_a_cookie = "session=user_a_token"
    settings.identity_b_cookie = "session=user_b_token"
    settings.identity_a_tenant_marker = "user_a"

    report = RipReport(
        url=fixture_server,
        captured_requests=[
            {"url": f"{fixture_server}/api/documents/doc_101", "method": "GET", "status": 200},
            {"url": f"{fixture_server}/api/private/user_a_42", "method": "GET", "status": 200},
            {"url": f"{fixture_server}/api/admin/users", "method": "GET", "status": 200},
            {"url": f"{fixture_server}/api/admin/system", "method": "GET", "status": 200},
        ],
    )

    scanner = BOLAScanner(report, settings)
    result = scanner.scan()

    assert len(result.findings) == 2
    for finding in result.findings:
        assert finding.confidence == "VERIFIED"
        assert finding.metadata.get("proof_attached") is True
        assert "proof" in finding.metadata
        assert "poc_curl" in finding.metadata

    categories = {f.category for f in result.findings}
    assert categories == {"bola", "bfla"}


def test_login_page_soft_404_rejection(fixture_server):
    """
    When Identity B receives HTTP 200 OK but the response body is an HTML login form,
    the scanner recognizes it as an auth bounce and does NOT flag BOLA.
    """
    settings = RipperSettings(url=fixture_server)
    settings.identity_a_cookie = "session=user_a_token"
    settings.identity_b_cookie = "session=user_b_token"
    settings.identity_a_tenant_marker = "user_a"

    report = RipReport(
        url=fixture_server,
        captured_requests=[
            {"url": f"{fixture_server}/api/bait/item_999", "method": "GET", "status": 200},
        ],
    )

    scanner = BOLAScanner(report, settings)
    result = scanner.scan()

    # The HTML login form should be rejected as a false positive
    assert len(result.findings) == 0


def test_candidate_extraction():
    """Verify object ID candidates and admin route candidate extractors."""
    sample_requests = [
        {"url": "https://api.test.com/api/users/1042/profile", "method": "GET"},
        {"url": "https://api.test.com/api/orders/e3b0c442-98fc-1c14-9afb-4c7600cd0000", "method": "GET"},
        {"url": "https://api.test.com/api/search?id=9912&sort=asc", "method": "GET"},
        {"url": "https://api.test.com/api/admin/dashboard", "method": "GET"},
        {"url": "https://api.test.com/api/settings/users/manage", "method": "GET"},
        {"url": "https://api.test.com/static/logo.png", "method": "GET"},
        {"url": "https://api.test.com/api/documents/101", "method": "DELETE"},  # Destructive method
    ]

    bola_candidates = extract_object_id_candidates(sample_requests)
    bfla_candidates = extract_admin_route_candidates(sample_requests)

    # DELETE /api/documents/101 must be excluded by non-destructive filter
    assert not any(c["method"] == "DELETE" for c in bola_candidates)

    # BOLA candidates must include numeric, UUID, and query param IDs
    bola_urls = [c["url"] for c in bola_candidates]
    assert "https://api.test.com/api/users/1042/profile" in bola_urls
    assert "https://api.test.com/api/orders/e3b0c442-98fc-1c14-9afb-4c7600cd0000" in bola_urls
    assert "https://api.test.com/api/search?id=9912&sort=asc" in bola_urls
    assert "https://api.test.com/static/logo.png" not in bola_urls

    # BFLA candidates must include admin routes
    bfla_urls = [c["url"] for c in bfla_candidates]
    assert "https://api.test.com/api/admin/dashboard" in bfla_urls
    assert "https://api.test.com/api/settings/users/manage" in bfla_urls


def test_non_destructive_safety_filter():
    """Verify that destructive HTTP methods are rejected unless explicitly safe/dry_run."""
    assert is_safe_method_or_dry_run("GET") is True
    assert is_safe_method_or_dry_run("HEAD") is True
    assert is_safe_method_or_dry_run("OPTIONS") is True
    assert is_safe_method_or_dry_run("DELETE") is False
    assert is_safe_method_or_dry_run("POST") is False
    assert is_safe_method_or_dry_run("POST", {"dry_run": True}) is True
    assert is_safe_method_or_dry_run("PUT", {"is_safe": True}) is True


def test_poc_curl_generation():
    """Verify reproduction curl generation formatting."""
    cmd = generate_poc_curl(
        "https://api.target.com/api/documents/101",
        method="GET",
        headers={"Cookie": "session=test_cookie", "Authorization": "Bearer test_token"},
    )
    assert cmd.startswith("curl -i -s -k -X GET")
    assert "-H 'Cookie: session=test_cookie'" in cmd
    assert "-H 'Authorization: Bearer test_token'" in cmd
    assert "'https://api.target.com/api/documents/101'" in cmd

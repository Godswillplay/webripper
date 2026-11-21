"""
HTML form security scanner for WebRipper Recon.

Analyzes downloaded HTML for CSRF vulnerabilities, insecure login forms,
hidden field exposure, file upload risks, and external form actions.
"""

from __future__ import annotations

import os
import re
import time
from typing import List, Optional
from urllib.parse import urljoin, urlparse

from .base import BaseScanner
from ..models import Finding, ScanResult, Severity

_RE_FORM = re.compile(r"<form\b[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL)
_RE_ACTION = re.compile(r"""action\s*=\s*(?:['"]([^'"]+)['"]|([^\s>]+))""", re.IGNORECASE)
_RE_METHOD = re.compile(r"""method\s*=\s*(?:['"]([^'"]+)['"]|([^\s>]+))""", re.IGNORECASE)
_RE_INPUT = re.compile(r"<input\b([^>]*)>", re.IGNORECASE)
_RE_TYPE = re.compile(r"""type\s*=\s*(?:['"]([^'"]+)['"]|([^\s>]+))""", re.IGNORECASE)
_RE_NAME = re.compile(r"""name\s*=\s*(?:['"]([^'"]+)['"]|([^\s>]+))""", re.IGNORECASE)
_RE_VALUE = re.compile(r"""value\s*=\s*(?:['"]([^'"]+)['"]|([^\s>]+))""", re.IGNORECASE)
_RE_AUTOCOMPLETE = re.compile(r"""autocomplete\s*=\s*(?:['"]([^'"]+)['"]|([^\s>]+))""", re.IGNORECASE)

_CSRF_NAMES = {"csrf", "csrftoken", "csrf_token", "_csrf", "xsrf", "xsrf_token",
               "_token", "authenticity_token", "nonce", "__requestverificationtoken",
               "anti-forgery", "antiforgery"}


class FormScanner(BaseScanner):
    """Analyzes HTML forms for CSRF, insecure submissions, and information leakage."""

    @property
    def name(self) -> str:
        return "forms"

    @property
    def description(self) -> str:
        return "Analyzes HTML forms for CSRF, insecure login, hidden fields, and file uploads"

    def scan(self) -> ScanResult:
        start = time.time()
        html_files = self._get_downloaded_files(extensions=(".html", ".htm", ".php", ".asp", ".aspx", ".jsp"))
        self._log(f"Scanning {len(html_files)} HTML files for form vulnerabilities...")

        for f in html_files:
            self._scan_file(f.local_path, f.url)

        self._log(f"Form scan complete: {len(self._findings)} findings")
        return self._build_result(start, files_scanned=len(html_files))

    def _scan_file(self, filepath: str, url: str) -> None:
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                html = f.read(500_000)
        except (OSError, IOError):
            return

        target_host = urlparse(self._settings.url).hostname or ""

        for form_match in _RE_FORM.finditer(html):
            form_html = form_match.group(0)
            form_body = form_match.group(1)

            action_m = _RE_ACTION.search(form_html)
            method_m = _RE_METHOD.search(form_html)
            action = ((action_m.group(1) or action_m.group(2)) if action_m else "") or ""
            method = ((method_m.group(1) or method_m.group(2)) if method_m else "GET").upper()

            inputs = _RE_INPUT.findall(form_body)
            has_password = False
            has_csrf = False
            has_file = False
            hidden_fields = []

            for inp_attrs in inputs:
                type_m = _RE_TYPE.search(inp_attrs)
                name_m = _RE_NAME.search(inp_attrs)
                value_m = _RE_VALUE.search(inp_attrs)
                inp_type = ((type_m.group(1) or type_m.group(2)) if type_m else "text").lower()
                inp_name = ((name_m.group(1) or name_m.group(2)) if name_m else "").lower()
                inp_value = (value_m.group(1) or value_m.group(2)) if value_m else ""

                if inp_type == "password":
                    has_password = True
                    ac = _RE_AUTOCOMPLETE.search(inp_attrs)
                    ac_val = (ac.group(1) or ac.group(2)).lower() if ac else ""
                    if not ac or ac_val not in ("off", "new-password", "current-password"):
                        self._add_finding(Finding(
                            severity=Severity.LOW,
                            category="forms",
                            title="Password field allows autocomplete",
                            description="Password field without autocomplete='off' may be cached by the browser.",
                            evidence=f"<input {inp_attrs[:150]}>",
                            file_path=filepath, url=url,
                            remediation="Add autocomplete='new-password' or autocomplete='off' to password fields.",
                            metadata={
                                "exploit": "On shared/public computers, browser autocomplete fills in saved passwords. An attacker who gains brief physical access can see autofilled credentials.",
                                "impact": "Credential exposure on shared devices",
                                "cwe": "CWE-524", "owasp": "A04:2021 Insecure Design",
                                "time_to_exploit": "~1 minute with physical access",
                            },
                        ))

                if inp_type == "file":
                    has_file = True

                if inp_type == "hidden":
                    if inp_name in _CSRF_NAMES:
                        has_csrf = True
                    elif inp_value and len(inp_value) > 3:
                        hidden_fields.append((inp_name, inp_value))

            # CSRF check (POST forms without CSRF token)
            if method == "POST" and not has_csrf:
                sev = Severity.HIGH if has_password else Severity.MEDIUM
                self._add_finding(Finding(
                    severity=sev,
                    category="forms",
                    title="Form missing CSRF token",
                    description=f"POST form at {action or 'current page'} has no anti-CSRF token.",
                    evidence=form_html[:300],
                    file_path=filepath, url=url,
                    remediation="Add a hidden CSRF token field that is validated server-side. Use framework-provided CSRF protection (e.g., Django {% csrf_token %}, Rails authenticity_token).",
                    metadata={
                        "exploit": "Attacker creates evil.com with a hidden auto-submitting form: <form action='TARGET/change-password' method='POST'><input name='password' value='hacked123'></form><script>document.forms[0].submit()</script>. When a logged-in victim visits evil.com, their password is changed without their knowledge.",
                        "impact": "Account takeover via CSRF — attacker performs actions as the victim (password change, email change, fund transfer)",
                        "cwe": "CWE-352", "owasp": "A01:2021 Broken Access Control",
                        "time_to_exploit": "~5 minutes",
                    },
                ))

            # Resolve full action URL
            full_action = urljoin(url, action) if action else url

            # Login over HTTP
            if has_password and urlparse(full_action).scheme == "http":
                self._add_finding(Finding(
                    severity=Severity.CRITICAL,
                    category="forms",
                    title="Login form submits over HTTP",
                    description=f"Login form action is unencrypted HTTP: {full_action}",
                    evidence=f"action=\"{action or ''}\"",
                    file_path=filepath, url=url,
                    remediation="Change form action to HTTPS. Enforce HTTPS across the entire site with HSTS.",
                    metadata={
                        "exploit": "Attacker on the same network (WiFi, corporate LAN) runs Wireshark or tcpdump. When victim submits login, their username and password appear in plaintext in the network capture. Tools like Bettercap automate this with ARP spoofing.",
                        "impact": "Credential theft via network sniffing — full account compromise",
                        "cwe": "CWE-319", "owasp": "A02:2021 Cryptographic Failures",
                        "time_to_exploit": "~2 minutes on shared network",
                    },
                ))

            # External form action
            if action and "://" in action:
                action_host = urlparse(action).hostname or ""
                if action_host and target_host and action_host.lower() != target_host.lower():
                    self._add_finding(Finding(
                        severity=Severity.MEDIUM,
                        category="forms",
                        title="Form posts to external domain",
                        description=f"Form submits data to external domain: {action_host}",
                        evidence=f"action=\"{action}\"",
                        file_path=filepath, url=url,
                        remediation="Verify the external endpoint is trusted. Consider proxying through your own server.",
                        metadata={
                            "exploit": "If the external domain is compromised or the action URL is manipulated via DOM XSS, form data (including credentials) is sent to the attacker.",
                            "impact": "Data exfiltration to third party",
                            "cwe": "CWE-201", "owasp": "A04:2021 Insecure Design",
                            "time_to_exploit": "Depends on external domain compromise",
                        },
                    ))

            # File upload
            if has_file:
                self._add_finding(Finding(
                    severity=Severity.MEDIUM,
                    category="forms",
                    title="File upload form detected",
                    description="File upload may allow malicious file types if server-side validation is weak.",
                    evidence=form_html[:200],
                    file_path=filepath, url=url,
                    remediation="Validate file type, size, and content server-side. Store uploads outside the web root. Rename uploaded files. Scan for malware.",
                    metadata={
                        "exploit": "Attacker uploads a PHP webshell disguised as image.php.jpg or uses double extensions. If the server executes it, attacker gets remote code execution: system('whoami'), file access, database dumps, reverse shells.",
                        "impact": "Remote code execution if upload validation is bypassed",
                        "cwe": "CWE-434", "owasp": "A04:2021 Insecure Design",
                        "time_to_exploit": "~10 minutes to test bypass techniques",
                    },
                ))

            # Sensitive hidden fields
            for hname, hvalue in hidden_fields:
                if re.search(r'(?:^|[_\-])(user_?id|account_?id|admin|role|price|discount|internal|privilege|is_admin|permission)(?:[_\-]|$)', hname):
                    self._add_finding(Finding(
                        severity=Severity.MEDIUM,
                        category="forms",
                        title=f"Sensitive hidden field: {hname}",
                        description=f"Hidden field '{hname}' contains value that may be tampered with.",
                        evidence=f"name=\"{hname}\" value=\"{hvalue}\"",
                        file_path=filepath, url=url,
                        remediation="Never trust hidden field values. Validate all form data server-side. Use server-side session storage for sensitive values.",
                        metadata={
                            "exploit": "Attacker opens browser DevTools, modifies the hidden field value (e.g., changes role='user' to role='admin' or price='100' to price='1'), and submits. If the server trusts the hidden field, the attacker escalates privileges or manipulates business logic.",
                            "impact": "Privilege escalation, price manipulation, or business logic bypass",
                            "cwe": "CWE-472", "owasp": "A04:2021 Insecure Design",
                            "time_to_exploit": "~1 minute with browser DevTools",
                        },
                    ))

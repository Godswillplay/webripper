"""
Email harvester scanner for WebRipper Recon 5.0.

Extracts and classifies email addresses from downloaded files.
Assesses social engineering risk per email type.
"""

from __future__ import annotations

import os
import re
import time
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse

from .base import BaseScanner, extract_base_domain
from ..models import Finding, ScanResult, Severity


# ---------------------------------------------------------------------------
# Email patterns and classification
# ---------------------------------------------------------------------------

_RE_EMAIL = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

_FP_DOMAINS = {
    "example.com", "example.org", "example.net", "test.com", "localhost",
    "placeholder.com", "email.com", "domain.com", "yoursite.com",
    "yourdomain.com", "sentry.io", "w3.org", "schema.org",
    "jquery.com", "google.com", "github.com", "wordpress.org",
    "wix.com", "squarespace.com", "mozilla.org",
}

_FP_PATTERNS = re.compile(
    r"(?:noreply|no-reply|mailer-daemon|postmaster|webmaster|root@localhost"
    r"|user@|test@|foo@|bar@|admin@example|name@domain)",
    re.IGNORECASE,
)

_GENERIC_PREFIXES = {
    "info", "support", "contact", "help", "sales", "admin",
    "hello", "team", "office", "hr", "press", "media",
    "marketing", "billing", "abuse", "security", "noc",
    "feedback", "careers", "jobs", "legal", "privacy",
}

_TEXT_EXTENSIONS = (
    ".html", ".htm", ".js", ".mjs", ".jsx", ".ts", ".tsx", ".css",
    ".json", ".xml", ".txt", ".md", ".php", ".py", ".rb",
    ".yaml", ".yml", ".env", ".config", ".cfg", ".ini",
    ".sql", ".vue", ".svelte", ".map",
)


class EmailHarvester(BaseScanner):
    """Harvests and classifies email addresses from downloaded files."""

    @property
    def name(self) -> str:
        return "emails"

    @property
    def description(self) -> str:
        return "Harvests email addresses and assesses social engineering risk"

    def scan(self) -> ScanResult:
        start = time.time()
        target_domain = urlparse(self._settings.url).hostname or ""
        base_domain = extract_base_domain(target_domain)

        self._log(f"Harvesting emails (target domain: {base_domain})...")

        all_emails: Dict[str, Dict] = {}  # email -> {sources, line_numbers}

        for f in self._report.files:
            if not f.local_path or f.error:
                continue
            if not os.path.isfile(f.local_path):
                continue
            lower = f.local_path.lower()
            if not any(lower.endswith(ext) for ext in _TEXT_EXTENSIONS):
                continue
            try:
                if os.path.getsize(f.local_path) > 2_000_000:
                    continue
            except (OSError, IOError):
                continue

            try:
                with open(f.local_path, "r", encoding="utf-8", errors="ignore") as fh:
                    for line_num, line in enumerate(fh, 1):
                        for match in _RE_EMAIL.finditer(line):
                            email = match.group(0).lower().strip(".")
                            domain = email.split("@")[1]

                            # Skip false positives
                            if domain in _FP_DOMAINS:
                                continue
                            if any(domain.endswith(ext) for ext in (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".avif", ".ico")):
                                continue
                            if _FP_PATTERNS.search(email):
                                continue
                            if len(email) > 100:
                                continue

                            if email not in all_emails:
                                all_emails[email] = {
                                    "sources": set(),
                                    "first_line": line_num,
                                    "first_file": os.path.basename(f.local_path),
                                    "url": f.url,
                                }
                            all_emails[email]["sources"].add(os.path.basename(f.local_path))
            except (OSError, IOError):
                continue

        # Classify and create findings
        same_domain: List[str] = []
        third_party: List[str] = []
        staff_emails: List[str] = []
        generic_emails: List[str] = []

        for email, info in all_emails.items():
            domain = email.split("@")[1]
            prefix = email.split("@")[0]

            is_same_domain = bool(base_domain and (domain == base_domain or domain.endswith("." + base_domain)))
            is_generic = prefix in _GENERIC_PREFIXES
            is_staff = is_same_domain and not is_generic and bool(re.match(r"^[a-z]+[.\-_]?[a-z0-9]+$", prefix))

            if is_same_domain:
                same_domain.append(email)
            else:
                third_party.append(email)

            if is_staff:
                staff_emails.append(email)
            elif is_generic:
                generic_emails.append(email)

        # Staff emails — high social engineering value
        if staff_emails:
            self._add_finding(Finding(
                severity=Severity.MEDIUM,
                category="emails",
                title=f"Staff Emails Exposed ({len(staff_emails)})",
                description=f"Personal staff email addresses found in client-side code: {', '.join(staff_emails[:10])}{'...' if len(staff_emails) > 10 else ''}",
                evidence="\n".join(staff_emails[:20]),
                remediation="Remove personal email addresses from client-side code. Use contact forms instead.",
                metadata={
                    "emails": staff_emails,
                    "count": len(staff_emails),
                    "exploit": "Staff emails enable: 1) Spear phishing with personalized content, 2) Credential stuffing (check breach databases like haveibeenpwned.com), 3) Password spray attacks against webmail/VPN, 4) Social engineering via LinkedIn correlation.",
                    "impact": "Targeted phishing, credential stuffing, social engineering",
                    "cwe": "CWE-200",
                    "owasp": "A01:2021 Broken Access Control",
                    "time_to_exploit": "~10 minutes to craft targeted phishing email",
                },
            ))

        # Generic emails
        if generic_emails:
            self._add_finding(Finding(
                severity=Severity.LOW,
                category="emails",
                title=f"Generic Emails Found ({len(generic_emails)})",
                description=f"Generic contact emails: {', '.join(generic_emails[:10])}",
                evidence="\n".join(generic_emails[:20]),
                metadata={
                    "emails": generic_emails,
                    "count": len(generic_emails),
                    "exploit": "Generic emails (info@, support@) are lower-value for targeted attacks but can be used for: social engineering via support channels, phishing internal staff who monitor these inboxes.",
                    "impact": "Social engineering via support channels",
                    "cwe": "CWE-200",
                    "owasp": "A01:2021 Broken Access Control",
                    "time_to_exploit": "~15 minutes",
                },
            ))

        # Third-party emails
        if third_party:
            self._add_finding(Finding(
                severity=Severity.INFO,
                category="emails",
                title=f"Third-Party Emails ({len(third_party)})",
                description=f"Emails from external domains found: {', '.join(third_party[:10])}",
                evidence="\n".join(third_party[:20]),
                metadata={
                    "emails": third_party,
                    "count": len(third_party),
                    "exploit": "Third-party emails reveal business relationships, vendors, and service providers. Attackers target the supply chain — compromise a vendor to pivot to the target.",
                    "impact": "Supply chain mapping, vendor relationship disclosure",
                    "cwe": "CWE-200",
                    "owasp": "A01:2021 Broken Access Control",
                    "time_to_exploit": "Varies",
                },
            ))

        # Summary
        total = len(all_emails)
        self._log(f"Email harvest complete: {total} emails ({len(staff_emails)} staff, {len(generic_emails)} generic, {len(third_party)} third-party)")
        return self._build_result(
            start,
            total_emails=total,
            staff_count=len(staff_emails),
            generic_count=len(generic_emails),
            third_party_count=len(third_party),
            same_domain_count=len(same_domain),
        )

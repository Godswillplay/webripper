"""
GitHub dorking scanner for WebRipper Recon 5.0.

Searches GitHub for leaked credentials, secrets, and code mentioning the target domain.
Uses the public GitHub search API (no API key needed for basic search).
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Dict, List, Tuple
from urllib.parse import quote, urlparse
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

from .base import BaseScanner, extract_base_domain
from ..models import Finding, ScanResult, Severity


# GitHub dork queries — (description, query_template, severity)
_DORK_QUERIES = [
    ("Passwords/Secrets", '"{domain}" password OR secret OR api_key OR apikey OR token', Severity.HIGH),
    ("Configuration Files", '"{domain}" filename:.env OR filename:.config OR filename:config.json', Severity.HIGH),
    ("AWS Keys", '"{domain}" AKIA OR aws_secret_access_key OR AWS_ACCESS_KEY', Severity.CRITICAL),
    ("Private Keys", '"{domain}" filename:id_rsa OR filename:id_dsa OR filename:.pem OR BEGIN RSA', Severity.CRITICAL),
    ("Database Credentials", '"{domain}" password OR passwd OR jdbc OR mysql OR postgres filename:.properties OR filename:.yml', Severity.HIGH),
    ("Internal URLs", '"{domain}" internal OR staging OR dev OR test filename:.json OR filename:.yml', Severity.MEDIUM),
    ("SQL Dumps", '"{domain}" filename:.sql OR filename:dump.sql OR CREATE TABLE', Severity.HIGH),
    ("Backup Files", '"{domain}" filename:.bak OR filename:.backup OR filename:.old OR filename:.swp', Severity.MEDIUM),
    ("JWT Secrets", '"{domain}" JWT_SECRET OR jwt_key OR jsonwebtoken', Severity.HIGH),
    ("OAuth/API Tokens", '"{domain}" client_secret OR oauth OR bearer OR access_token', Severity.MEDIUM),
]


class GitHubDorkScanner(BaseScanner):
    """Searches GitHub for leaked code, credentials, and secrets mentioning the target domain."""

    @property
    def name(self) -> str:
        return "github_dork"

    @property
    def description(self) -> str:
        return "Searches GitHub for leaked credentials, secrets, and code mentioning the target"

    def scan(self) -> ScanResult:
        start = time.time()
        domain = urlparse(self._settings.url).hostname or ""
        base_domain = extract_base_domain(domain)

        if not base_domain:
            self._log("Cannot extract domain for GitHub dorking")
            return self._build_result(start)

        self._log(f"GitHub dorking for {base_domain}...")

        total_results = 0
        leaks_found = 0
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
        rate_limited = False
        api_error = False

        if not token:
            self._log("  No GITHUB_TOKEN configured. GitHub Code Search API requires authentication.")
            dork_links = []
            for desc, query_tpl, _ in _DORK_QUERIES[:6]:
                q = query_tpl.replace("{domain}", base_domain)
                search_url = f"https://github.com/search?q={quote(q)}&type=code"
                dork_links.append(f"• {desc}: {search_url}")

            self._add_finding(Finding(
                severity=Severity.INFO,
                category="github_dork",
                title=f"GitHub Reconnaissance Queries ({base_domain})",
                description="GitHub Code Search API requires authentication (set GITHUB_TOKEN). Manual search links generated below.",
                evidence="\n".join(dork_links),
                remediation="Configure a GitHub Personal Access Token (GITHUB_TOKEN environment variable) for automated dorking.",
                metadata={
                    "exploit": "Manual code searches on GitHub often reveal exposed API keys, private keys, database passwords, and .env files.",
                    "impact": "Information disclosure / credential exposure",
                    "cwe": "CWE-200", "owasp": "A05:2021 Security Misconfiguration",
                    "time_to_exploit": "~5 minutes",
                },
            ))
            return self._build_result(start, leaks_found=0, total_results=0, note="manual_links_generated")

        delay = 1.0 if token else 2.0

        for desc, query_tpl, severity in _DORK_QUERIES:
            query = query_tpl.replace("{domain}", base_domain)
            try:
                count, items, rate_limited = self._search_github(query, token)
                if rate_limited:
                    self._log(f"  GitHub rate limit encountered on '{desc}'. Stopping remaining dorks.")
                    break

                if count > 0:
                    leaks_found += 1
                    total_results += count

                    # Build evidence from top results
                    evidence_lines = [f"Query: {query}", f"Total matches: {count}", ""]
                    for item in items[:5]:
                        repo = item.get("repository", {}).get("full_name", "unknown")
                        path = item.get("path", "unknown")
                        html_url = item.get("html_url", "")
                        evidence_lines.append(f"  • {repo}/{path}")
                        if html_url:
                            evidence_lines.append(f"    {html_url}")

                    self._add_finding(Finding(
                        severity=severity,
                        category="github_dork",
                        title=f"GitHub Leak: {desc} ({count} results)",
                        description=f"Found {count} GitHub results matching '{desc}' dork for {base_domain}. "
                                    f"This may indicate leaked credentials, configurations, or source code.",
                        evidence="\n".join(evidence_lines),
                        remediation="1. Review each GitHub result for sensitive data. "
                                    "2. Rotate any exposed credentials immediately. "
                                    "3. Contact repository owners to remove sensitive files. "
                                    "4. Use GitHub secret scanning and .gitignore properly.",
                        metadata={
                            "dork_type": desc,
                            "result_count": count,
                            "search_query": query,
                            "exploit": f"GitHub search reveals {desc.lower()} for {base_domain}. "
                                       f"Attacker extracts credentials from public repos and uses them for direct access. "
                                       f"Search URL: https://github.com/search?q={quote(query)}&type=code",
                            "impact": f"Leaked {desc.lower()} — potential credential compromise and unauthorized access",
                            "cwe": "CWE-798" if severity == Severity.CRITICAL else "CWE-200",
                            "owasp": "A02:2021 Cryptographic Failures" if severity in (Severity.CRITICAL, Severity.HIGH) else "A05:2021 Security Misconfiguration",
                            "time_to_exploit": "~5 minutes to extract and use leaked credentials",
                        },
                    ))

                time.sleep(delay)

            except Exception as e:
                api_error = True
                self._log(f"  GitHub search error ({desc}): {e}")

        if leaks_found == 0 and not rate_limited and not api_error:
            self._add_finding(Finding(
                severity=Severity.INFO,
                category="github_dork",
                title="No GitHub Leaks Found",
                description=f"No leaked credentials or sensitive code found on GitHub for {base_domain}.",
                metadata={
                    "exploit": "No public code leaks detected. This is a positive finding.",
                    "impact": "Low — no public code exposure detected",
                    "cwe": "", "owasp": "", "time_to_exploit": "N/A",
                },
            ))
        elif leaks_found == 0 and (rate_limited or api_error):
            self._add_finding(Finding(
                severity=Severity.LOW,
                category="github_dork",
                title="GitHub Search Incomplete (Rate Limited or Error)",
                description=f"GitHub code search could not complete for {base_domain} due to rate limits or API error.",
                evidence="GitHub search API returned error / rate limit.",
                metadata={"cwe": "", "owasp": "", "time_to_exploit": "N/A"},
            ))

        self._log(f"GitHub dorking complete: {leaks_found} dork types matched, {total_results} total results")
        return self._build_result(start, leaks_found=leaks_found, total_results=total_results)

    def _search_github(self, query: str, token: str = "") -> Tuple[int, List[Dict], bool]:
        """Search GitHub code search API. Returns (total_count, items, rate_limited)."""
        url = f"https://api.github.com/search/code?q={quote(query)}&per_page=5"
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "WebRipper-Recon/5.0",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"

        req = Request(url, headers=headers)

        try:
            with urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
                return data.get("total_count", 0), data.get("items", []), False
        except HTTPError as e:
            if e.code in (401, 403, 429):
                return 0, [], True
            elif e.code == 422:
                # Validation failed — query too complex
                return 0, [], False
            raise
        except URLError:
            return 0, [], False

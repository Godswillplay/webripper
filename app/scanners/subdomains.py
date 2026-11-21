"""
Subdomain discovery scanner for WebRipper Recon.

Passive extraction from downloaded files + active crt.sh CT log lookup.
Detects takeover candidates and classifies subdomain types.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

import aiohttp

from .base import BaseScanner, extract_base_domain
from ..models import Finding, ScanResult, Severity

_TAKEOVER_CNAMES = {
    "github.io", "herokuapp.com", "pantheonsite.io", "domains.tumblr.com",
    "wpengine.com", "ghost.io", "myshopify.com", "surge.sh",
    "bitbucket.io", "custom.intercom.help", "proxy.webflow.com",
    "landing.subscribepage.com", "endpoint.mykajabi.com",
    "s3.amazonaws.com", "cloudfront.net", "azurewebsites.net",
    "cloudapp.net", "trafficmanager.net", "blob.core.windows.net",
    "netlify.app", "vercel.app", "fly.dev", "render.onrender.com",
}

_SUBDOMAIN_TYPES: Dict[str, str] = {
    "staging": "Staging environment — may have debug mode, test credentials, weaker security",
    "stage": "Staging environment",
    "dev": "Development environment — often has debug enabled, test accounts, verbose errors",
    "develop": "Development environment",
    "test": "Test environment — may contain test data and weaker access controls",
    "qa": "QA environment",
    "uat": "User acceptance testing environment",
    "api": "API endpoint — check for authentication bypass, rate limiting, exposed documentation",
    "admin": "Admin panel — high-value target for brute-force and credential stuffing",
    "cms": "Content management system",
    "mail": "Mail server — check for open relay, SPF/DKIM/DMARC",
    "smtp": "SMTP server",
    "ftp": "FTP server — check for anonymous access",
    "vpn": "VPN endpoint — check for known VPN vulnerabilities",
    "internal": "Internal service — should not be publicly accessible",
    "intranet": "Intranet — should not be publicly accessible",
    "portal": "Portal — likely has login functionality",
    "dashboard": "Dashboard — administrative interface",
    "jenkins": "Jenkins CI/CD — check for unauthenticated access",
    "gitlab": "GitLab — check for public repositories and registration",
    "jira": "Jira — check for public projects and user enumeration",
    "grafana": "Grafana — check for default credentials and public dashboards",
    "kibana": "Kibana — check for unauthenticated access to logs",
    "elastic": "Elasticsearch — check for unauthenticated access",
    "mongo": "MongoDB — check for unauthenticated access",
    "redis": "Redis — check for unauthenticated access",
    "db": "Database — should never be publicly accessible",
    "backup": "Backup — may contain sensitive data",
    "old": "Old/legacy — likely unpatched and unmaintained",
    "legacy": "Legacy system — likely has known vulnerabilities",
    "debug": "Debug endpoint — should never be in production",
}

_RE_SUBDOMAIN = re.compile(r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}")


def _get_takeover_targets() -> Dict[str, str]:
    """Retrieve mapping of CNAME patterns to service provider names from intelligence DB."""
    targets = {c: c for c in _TAKEOVER_CNAMES}
    try:
        from ..intelligence import get_engine
        engine = get_engine()
        for to in engine.get_takeovers():
            service = to.get("service", "")
            for c in to.get("cnames", []):
                if c:
                    targets[c.lower().strip()] = service
    except Exception:
        pass
    return targets


class SubdomainScanner(BaseScanner):
    """Discovers subdomains via passive extraction and crt.sh CT log lookup."""

    @property
    def name(self) -> str:
        return "subdomains"

    @property
    def description(self) -> str:
        return "Discovers subdomains via passive extraction and Certificate Transparency logs"

    def scan(self) -> ScanResult:
        start = time.time()
        parsed = urlparse(self._settings.url)
        domain = parsed.netloc.split(":")[0]
        base_domain = extract_base_domain(domain)

        self._log(f"Discovering subdomains for {base_domain}")

        # Passive: extract from downloaded files
        passive_subs = self._passive_extract(base_domain)
        self._log(f"Passive extraction: {len(passive_subs)} subdomains")

        # Active: crt.sh lookup
        ct_subs: Set[str] = set()
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            ct_subs = loop.run_until_complete(self._crtsh_lookup(base_domain))
            loop.close()
            self._log(f"crt.sh: {len(ct_subs)} subdomains from Certificate Transparency")
        except Exception as exc:
            self._log(f"crt.sh lookup failed: {exc}")

        all_subs = passive_subs | ct_subs
        all_subs.discard(domain)
        all_subs.discard(f"www.{base_domain}")

        if all_subs:
            self._add_finding(Finding(
                severity=Severity.INFO,
                category="subdomains",
                title=f"Discovered {len(all_subs)} subdomains",
                description="Subdomains found via passive extraction and Certificate Transparency logs.",
                evidence="\n".join(sorted(all_subs)[:50]),
                url=self._settings.url,
                metadata={
                    "all_subdomains": sorted(all_subs),
                    "passive_count": len(passive_subs),
                    "ct_count": len(ct_subs),
                    "cwe": "", "owasp": "",
                },
            ))

        # Classify and flag interesting subdomains
        for sub in sorted(all_subs):
            self._classify_subdomain(sub, base_domain)

        self._log(f"Subdomain scan complete: {len(self._findings)} findings")
        return self._build_result(
            start, total_subdomains=len(all_subs),
            passive=len(passive_subs), ct_log=len(ct_subs),
        )

    def _passive_extract(self, base_domain: str) -> Set[str]:
        """Extract subdomains from downloaded files."""
        subs: Set[str] = set()
        suffix = base_domain.lower()

        for f in self._report.files:
            if not f.local_path:
                continue
            try:
                with open(f.local_path, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read(500_000)
                for match in _RE_SUBDOMAIN.finditer(content):
                    hostname = match.group(0).lower()
                    if hostname.endswith("." + suffix):
                        subs.add(hostname)
            except (OSError, IOError):
                pass

        return subs

    async def _crtsh_lookup(self, domain: str) -> Set[str]:
        """Query crt.sh Certificate Transparency logs using clean public headers."""
        subs: Set[str] = set()
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        timeout = aiohttp.ClientTimeout(total=15)

        try:
            clean_headers = {"User-Agent": self._settings.user_agent or "WebRipper", "Accept": "application/json"}
            async with aiohttp.ClientSession(
                timeout=timeout,
                headers=clean_headers,
                max_line_size=131072,
                max_field_size=131072,
            ) as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        for entry in data:
                            name = entry.get("name_value", "")
                            for line in name.split("\n"):
                                line = line.strip().lower()
                                if line and "*" not in line and line.endswith("." + domain):
                                    subs.add(line)
        except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError):
            pass

        return subs

    def _classify_subdomain(self, subdomain: str, base_domain: str) -> None:
        """Classify subdomain type and flag security-relevant ones."""
        prefix = subdomain.replace(f".{base_domain}", "").split(".")[0].lower()

        # Check for takeover candidates via CNAME resolution
        try:
            import socket
            dangling = False
            cname_host = ""
            try:
                cname_host = socket.gethostbyname_ex(subdomain)[0]
            except socket.gaierror:
                dangling = True

            matched_provider = None
            takeover_map = _get_takeover_targets()
            if cname_host:
                for cname_target, provider_name in takeover_map.items():
                    if cname_target in cname_host:
                        matched_provider = provider_name
                        break

            if matched_provider:
                sev = Severity.HIGH if dangling else Severity.LOW
                conf = "VERIFIED" if dangling else "POSSIBLE"
                desc = (
                    f"Subdomain {subdomain} points to unclaimed/dangling {matched_provider} host."
                    if dangling else
                    f"Subdomain {subdomain} points to {matched_provider} ({cname_host or 'CNAME'}). Verify asset ownership."
                )
                self._add_finding(Finding(
                    severity=sev,
                    confidence=conf,
                    category="subdomains",
                    title=f"Subdomain Takeover Target: {subdomain} ({matched_provider})" if dangling else f"Cloud Hosted Subdomain: {subdomain} ({matched_provider})",
                    description=desc,
                    evidence=f"Target: {subdomain} -> Host: {cname_host or 'Unresolved (NXDOMAIN/Dangling)'}\nProvider: {matched_provider}",
                    remediation=f"Verify {matched_provider} resource ownership or remove dangling DNS CNAME record.",
                    metadata={
                        "exploit": f"If unclaimed on {matched_provider}, attacker claims the resource and controls content on {subdomain}.",
                        "impact": "Subdomain takeover, phishing, session hijacking",
                        "cwe": "CWE-284", "owasp": "A05:2021 Security Misconfiguration",
                        "time_to_exploit": "~10 minutes",
                    },
                ))
                if dangling:
                    return
        except Exception:
            pass

        # Classify by prefix
        if prefix in _SUBDOMAIN_TYPES:
            classification = _SUBDOMAIN_TYPES[prefix]
            sev = Severity.MEDIUM if prefix in (
                "staging", "stage", "dev", "develop", "test", "internal",
                "intranet", "debug", "admin", "backup", "old", "legacy",
                "jenkins", "grafana", "kibana", "elastic", "mongo", "redis", "db",
            ) else Severity.LOW

            self._add_finding(Finding(
                severity=sev,
                category="subdomains",
                title=f"Interesting subdomain: {subdomain}",
                description=f"[{prefix}] {classification}",
                evidence=subdomain,
                remediation="Review if this subdomain should be publicly accessible. Apply same security standards as production. Remove unused subdomains.",
                metadata={
                    "exploit": f"Attacker targets {subdomain} because {classification.lower()}. Non-production environments often have: debug mode enabled, test credentials (admin/admin), verbose error messages revealing stack traces, and unpatched vulnerabilities.",
                    "impact": f"Depends on the service — potential for unauthorized access, data exposure, or pivot to production",
                    "cwe": "CWE-200", "owasp": "A05:2021 Security Misconfiguration",
                    "time_to_exploit": "~15 minutes to enumerate and test",
                    "subdomain_type": prefix,
                },
            ))

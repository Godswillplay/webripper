"""
DNS reconnaissance scanner for WebRipper Recon 5.0.

Enumerates DNS records (A, MX, NS, TXT, SOA), checks zone transfers,
and analyzes email security (SPF, DMARC, DKIM).
"""

from __future__ import annotations

import re
import socket
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .base import BaseScanner, extract_base_domain
from ..models import Finding, ScanResult, Severity


# ---------------------------------------------------------------------------
# Windows subprocess flags
# ---------------------------------------------------------------------------
_CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0


class DNSScanner(BaseScanner):
    """DNS reconnaissance: record enumeration, zone transfer, email security."""

    @property
    def name(self) -> str:
        return "dns"

    @property
    def description(self) -> str:
        return "DNS record enumeration, zone transfer attempts, and email security analysis"

    def scan(self) -> ScanResult:
        start = time.time()
        domain = urlparse(self._settings.url).hostname or ""
        if not domain:
            self._log("Cannot extract domain from URL")
            return self._build_result(start)

        self._log(f"DNS recon for {domain}...")

        # Collect records
        a_records = self._query("A", domain)
        aaaa_records = self._query("AAAA", domain)
        mx_records = self._query("MX", domain)
        ns_records = self._query("NS", domain)
        txt_records = self._query("TXT", domain)
        soa_records = self._query("SOA", domain)
        cname_records = self._query("CNAME", domain)

        # Report A records
        if a_records:
            self._add_finding(Finding(
                severity=Severity.INFO,
                category="dns",
                title=f"A Records: {domain}",
                description=f"IPv4 addresses: {', '.join(a_records)}",
                evidence="\n".join(a_records),
                metadata={
                    "record_type": "A", "records": a_records,
                    "exploit": "IP addresses reveal hosting provider. Attacker checks for other sites on the same IP (virtual hosting) and scans for services directly via IP to bypass WAF.",
                    "impact": "Infrastructure mapping, WAF bypass via direct IP access",
                    "cwe": "CWE-200", "owasp": "A05:2021 Security Misconfiguration",
                    "time_to_exploit": "~2 minutes",
                },
            ))

        # Report MX records
        if mx_records:
            self._add_finding(Finding(
                severity=Severity.INFO,
                category="dns",
                title=f"MX Records: {domain}",
                description=f"Mail servers: {', '.join(mx_records)}",
                evidence="\n".join(mx_records),
                metadata={
                    "record_type": "MX", "records": mx_records,
                    "exploit": "Mail server identification enables: targeted phishing with spoofed sender, SMTP enumeration (VRFY/EXPN), and relay testing.",
                    "impact": "Email infrastructure exposure, phishing vector identification",
                    "cwe": "CWE-200", "owasp": "A05:2021 Security Misconfiguration",
                    "time_to_exploit": "~10 minutes",
                },
            ))

        # Report NS records
        if ns_records:
            self._add_finding(Finding(
                severity=Severity.INFO,
                category="dns",
                title=f"NS Records: {domain}",
                description=f"Name servers: {', '.join(ns_records)}",
                evidence="\n".join(ns_records),
                metadata={
                    "record_type": "NS", "records": ns_records,
                    "exploit": "Name server identification allows: DNS cache poisoning attempts, checking for outdated DNS software, and zone transfer attempts.",
                    "impact": "DNS infrastructure mapping",
                    "cwe": "CWE-200", "owasp": "A05:2021 Security Misconfiguration",
                    "time_to_exploit": "~5 minutes",
                },
            ))

            # Zone transfer attempts
            for ns in ns_records:
                ns_clean = ns.strip().rstrip(".")
                if ns_clean:
                    self._try_zone_transfer(domain, ns_clean)

        # Analyze TXT records for SPF/DMARC
        base_domain = extract_base_domain(domain)
        spf_found = False
        all_txt = list(txt_records)
        if domain != base_domain:
            base_txt = self._query("TXT", base_domain)
            for bt in base_txt:
                if bt not in all_txt:
                    all_txt.append(bt)

        for txt in all_txt:
            if "v=spf1" in txt.lower():
                spf_found = True
                self._analyze_spf(domain, txt)
                break

        if not spf_found:
            self._add_finding(Finding(
                severity=Severity.MEDIUM,
                category="dns",
                title="Missing SPF Record",
                description=f"No SPF record found for {domain}. Attackers can send emails spoofing this domain.",
                remediation="Add a TXT record: v=spf1 include:_spf.google.com ~all (adjust for your mail provider).",
                metadata={
                    "exploit": "Without SPF, attacker sends phishing emails FROM your domain using any SMTP server. Recipients see the email as legitimately from your organization.",
                    "impact": "Email spoofing — phishing emails from your domain pass basic checks",
                    "cwe": "CWE-290", "owasp": "A05:2021 Security Misconfiguration",
                    "time_to_exploit": "~5 minutes with sendmail/swaks",
                },
            ))

        # Check DMARC (check subdomain and fallback to apex domain)
        dmarc_records = self._query("TXT", f"_dmarc.{domain}")
        if not dmarc_records and domain != base_domain:
            dmarc_records = self._query("TXT", f"_dmarc.{base_domain}")

        if dmarc_records:
            dmarc_txt = " ".join(dmarc_records)
            self._analyze_dmarc(domain, dmarc_txt)
        else:
            self._add_finding(Finding(
                severity=Severity.MEDIUM,
                category="dns",
                title="Missing DMARC Record",
                description=f"No DMARC record found for {domain}. Email authentication is incomplete.",
                remediation="Add TXT record at _dmarc.domain: v=DMARC1; p=reject; rua=mailto:dmarc@domain.com",
                metadata={
                    "exploit": "Without DMARC, even if SPF exists, receiving servers may not enforce it. Attacker spoofs emails from your domain with higher success rate.",
                    "impact": "Email spoofing protection is incomplete",
                    "cwe": "CWE-290", "owasp": "A05:2021 Security Misconfiguration",
                    "time_to_exploit": "~5 minutes",
                },
            ))

        # Check DNSSEC
        self._check_dnssec(domain)

        # Check DKIM
        self._check_dkim(domain)

        total_records = len(a_records) + len(aaaa_records) + len(mx_records) + len(ns_records) + len(txt_records)
        self._log(f"DNS scan complete: {total_records} records found, {len(self._findings)} findings")
        return self._build_result(start, total_records=total_records, domain=domain)

    def _query(self, record_type: str, domain: str) -> List[str]:
        """Query DNS using Python socket for A/AAAA, and nslookup for others."""
        if record_type in ("A", "AAAA"):
            try:
                import socket
                family = socket.AF_INET if record_type == "A" else socket.AF_INET6
                infos = socket.getaddrinfo(domain, None, family=family)
                res = list(set(info[4][0] for info in infos))
                if res:
                    return res
            except Exception:
                pass

        try:
            result = subprocess.run(
                ["nslookup", f"-type={record_type}", domain],
                capture_output=True, text=True, timeout=10,
                creationflags=_CREATE_NO_WINDOW,
            )
            output = result.stdout + result.stderr
            return self._parse_nslookup(output, record_type, domain)
        except Exception:
            return []

    def _parse_nslookup(self, output: str, record_type: str, domain: str) -> List[str]:
        """Parse nslookup output for record values."""
        records = []
        lines = output.split("\n")

        if record_type == "A":
            in_answer = False
            for line in lines:
                if "answer" in line.lower() or "name:" in line.lower():
                    in_answer = True
                if in_answer:
                    m = re.search(r"Address(?:es)?:\s*(\d+\.\d+\.\d+\.\d+)", line)
                    if m:
                        records.append(m.group(1))
            if not records:
                found = re.findall(r"Address(?:es)?:\s*(\d+\.\d+\.\d+\.\d+)", output)
                if len(found) > 1:
                    # Skip found[0] as that is usually the local resolver address
                    records.extend(found[1:])
        elif record_type == "AAAA":
            for line in lines:
                m = re.search(r"Address:\s*([0-9a-fA-F:]+)", line)
                if m and ":" in m.group(1):
                    records.append(m.group(1))
        elif record_type in ("MX", "NS", "CNAME", "SOA"):
            for line in lines:
                for pattern in [
                    r"mail exchanger\s*=\s*(.+)",
                    r"nameserver\s*=\s*(.+)",
                    r"canonical name\s*=\s*(.+)",
                    r"primary name server\s*=\s*(.+)",
                    r"MX preference.*exchange\s*=\s*(.+)",
                ]:
                    m = re.search(pattern, line, re.IGNORECASE)
                    if m:
                        records.append(m.group(1).strip())
        elif record_type == "TXT":
            for line in lines:
                m = re.search(r'text\s*=\s*"?(.+?)"?\s*$', line, re.IGNORECASE)
                if m:
                    records.append(m.group(1).strip().strip('"'))

        return list(set(records))

    def _try_zone_transfer(self, domain: str, nameserver: str) -> None:
        """Attempt DNS zone transfer against a nameserver."""
        try:
            result = subprocess.run(
                ["nslookup", "-type=AXFR", domain, nameserver],
                capture_output=True, text=True, timeout=15,
                creationflags=_CREATE_NO_WINDOW,
            )
            output = (result.stdout + result.stderr).lower()
            if "refused" in output or "failed" in output or "can't" in output or "timed out" in output or "server failure" in output:
                return  # Transfer denied — good
            has_zone_records = (
                ("soa" in output and ("in\ta" in output or "has soa record" in output or "serial =" in output)) or
                output.count("internet address =") > 3 or
                output.count("nameserver =") > 3
            )
            if has_zone_records and len(output) > 300:  # Got confirmed zone transfer records
                self._add_finding(Finding(
                    severity=Severity.CRITICAL,
                    category="dns",
                    title=f"Zone Transfer Possible: {nameserver}",
                    description=f"DNS zone transfer (AXFR) succeeded against {nameserver}. "
                                f"This exposes ALL DNS records including internal hosts.",
                    evidence=output[:500],
                    remediation="Restrict zone transfers to authorized secondary DNS servers only.",
                    metadata={
                        "exploit": f"Run: nslookup -type=AXFR {domain} {nameserver} — dumps every DNS record. Reveals all subdomains, internal hostnames, mail servers, and network topology.",
                        "impact": "Complete DNS zone exposure — all subdomains, internal hosts, network layout revealed",
                        "cwe": "CWE-200", "owasp": "A05:2021 Security Misconfiguration",
                        "time_to_exploit": "~1 minute",
                    },
                ))
        except Exception:
            pass

    def _analyze_spf(self, domain: str, spf_record: str) -> None:
        """Analyze SPF record strength."""
        spf_lower = spf_record.lower()

        if "+all" in spf_lower:
            self._add_finding(Finding(
                severity=Severity.HIGH,
                category="dns",
                title="SPF Record Allows All (+all)",
                description=f"SPF record uses +all which allows ANY server to send email as {domain}. This provides zero protection.",
                evidence=spf_record,
                remediation="Change +all to -all (hard fail) or ~all (soft fail).",
                metadata={
                    "exploit": "SPF +all means ANY mail server is authorized. Attacker sends emails from your domain with 100% delivery rate.",
                    "impact": "No email spoofing protection at all",
                    "cwe": "CWE-290", "owasp": "A05:2021 Security Misconfiguration",
                    "time_to_exploit": "~2 minutes",
                },
            ))
        elif "~all" in spf_lower:
            self._add_finding(Finding(
                severity=Severity.LOW,
                category="dns",
                title="SPF Soft Fail (~all)",
                description=f"SPF uses soft fail (~all). Some mail servers may still accept spoofed emails.",
                evidence=spf_record,
                remediation="Consider changing ~all to -all for strict enforcement.",
                metadata={
                    "exploit": "Soft fail means spoofed emails are flagged but may still be delivered to inbox, especially without DMARC.",
                    "impact": "Partial email spoofing protection — some spoofed emails may be delivered",
                    "cwe": "CWE-290", "owasp": "A05:2021 Security Misconfiguration",
                    "time_to_exploit": "~5 minutes",
                },
            ))

    def _analyze_dmarc(self, domain: str, dmarc_record: str) -> None:
        """Analyze DMARC record policy."""
        dmarc_lower = dmarc_record.lower()

        if "p=none" in dmarc_lower:
            self._add_finding(Finding(
                severity=Severity.MEDIUM,
                category="dns",
                title="DMARC Policy Set to None",
                description=f"DMARC policy is 'none' — no action taken on failed authentication. Only monitoring.",
                evidence=dmarc_record,
                remediation="Upgrade DMARC policy to p=quarantine or p=reject after monitoring period.",
                metadata={
                    "exploit": "DMARC p=none only monitors — it doesn't block spoofed emails. Attacker's spoofed emails are still delivered.",
                    "impact": "Email spoofing not actively blocked, only monitored",
                    "cwe": "CWE-290", "owasp": "A05:2021 Security Misconfiguration",
                    "time_to_exploit": "~5 minutes",
                },
            ))
        elif "p=quarantine" in dmarc_lower:
            self._add_finding(Finding(
                severity=Severity.LOW,
                category="dns",
                title="DMARC Policy: Quarantine",
                description="DMARC policy is 'quarantine' — unauthenticated emails are directed to spam folders.",
                evidence=dmarc_record,
                remediation="Consider upgrading DMARC policy to p=reject once mail sources are verified.",
                metadata={
                    "exploit": "Quarantine policy diverts spoofed emails to spam folder, but user may still inspect and open them.",
                    "impact": "Partial protection — unauthenticated emails not rejected outright",
                    "cwe": "CWE-290", "owasp": "A05:2021 Security Misconfiguration", "time_to_exploit": "N/A",
                },
            ))
        elif "p=reject" in dmarc_lower:
            self._add_finding(Finding(
                severity=Severity.INFO,
                category="dns",
                title="DMARC Policy: Reject (Strong)",
                description="DMARC is set to reject — spoofed emails will be blocked.",
                evidence=dmarc_record,
                metadata={
                    "exploit": "Strong DMARC policy is in place. Email spoofing for this domain is effectively blocked at receiving mail servers.",
                    "impact": "Low — email spoofing protection is properly configured",
                    "cwe": "", "owasp": "", "time_to_exploit": "N/A",
                },
            ))

    def _check_dnssec(self, domain: str) -> None:
        """Check if DNSSEC is enabled for the domain."""
        try:
            result = subprocess.run(
                ["nslookup", "-type=DNSKEY", domain],
                capture_output=True, text=True, timeout=10,
                creationflags=_CREATE_NO_WINDOW,
            )
            output = result.stdout + result.stderr
            has_dnskey = "DNSKEY" in output.upper() and "protocol" in output.lower()

            if has_dnskey:
                self._add_finding(Finding(
                    severity=Severity.INFO,
                    category="dns",
                    title="DNSSEC Enabled",
                    description=f"DNSSEC is configured for {domain}. DNS responses are cryptographically signed.",
                    evidence=output[:300],
                    metadata={
                        "exploit": "DNSSEC prevents DNS spoofing/cache poisoning. This is a positive security finding.",
                        "impact": "Low — DNS integrity protection is in place",
                        "cwe": "", "owasp": "", "time_to_exploit": "N/A",
                    },
                ))
            else:
                self._add_finding(Finding(
                    severity=Severity.LOW,
                    category="dns",
                    title="DNSSEC Not Enabled",
                    description=f"No DNSSEC (DNSKEY) records found for {domain}. DNS responses are not cryptographically signed.",
                    remediation="Enable DNSSEC at your DNS provider to prevent DNS spoofing and cache poisoning attacks.",
                    metadata={
                        "exploit": "Without DNSSEC, attacker can poison DNS cache to redirect users to malicious servers (Kaminsky attack). Requires network access to DNS resolver.",
                        "impact": "DNS cache poisoning possible — users can be redirected to attacker-controlled servers",
                        "cwe": "CWE-350", "owasp": "A05:2021 Security Misconfiguration",
                        "time_to_exploit": "~30 minutes with specialized tools",
                    },
                ))
        except Exception:
            pass

    def _check_dkim(self, domain: str) -> None:
        """Check common DKIM selectors."""
        selectors = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim"]
        found = []

        for sel in selectors:
            dkim_domain = f"{sel}._domainkey.{domain}"
            records = self._query("TXT", dkim_domain)
            if records:
                for r in records:
                    if "v=dkim1" in r.lower() or "p=" in r:
                        found.append(f"{sel}: {r[:80]}")

        if found:
            self._add_finding(Finding(
                severity=Severity.INFO,
                category="dns",
                title=f"DKIM Configured ({len(found)} selector{'s' if len(found) > 1 else ''})",
                description="DKIM email signing is configured, providing email authentication.",
                evidence="\n".join(found),
                metadata={
                    "exploit": "DKIM is properly configured. Email authenticity can be verified by receiving servers.",
                    "impact": "Positive — email authentication strengthened",
                    "cwe": "", "owasp": "", "time_to_exploit": "N/A",
                },
            ))

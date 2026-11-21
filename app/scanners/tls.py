"""
TLS/SSL certificate scanner for WebRipper Recon.

Analyzes the target's TLS configuration: certificate validity, TLS version,
cipher suites, mixed content, and certificate chain issues.
"""

from __future__ import annotations

import os
import re
import ssl
import socket
import tempfile
import time
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from .base import BaseScanner
from ..models import Finding, ScanResult, Severity


class TLSScanner(BaseScanner):
    """Analyzes TLS certificate and configuration of the target."""

    @property
    def name(self) -> str:
        return "tls"

    @property
    def description(self) -> str:
        return "Analyzes TLS certificate validity, version, ciphers, and mixed content"

    def scan(self) -> ScanResult:
        start = time.time()
        parsed = urlparse(self._settings.url)
        hostname = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if parsed.scheme != "https":
            self._add_finding(Finding(
                severity=Severity.HIGH,
                category="tls",
                title="Site uses HTTP (no encryption)",
                description="Target URL uses unencrypted HTTP. All data transmitted in plaintext.",
                evidence=self._settings.url,
                remediation="Enable HTTPS with a valid TLS certificate. Use Let's Encrypt for free certificates. Redirect all HTTP to HTTPS.",
                metadata={
                    "exploit": "Attacker on the same network runs Wireshark/tcpdump or uses ARP spoofing (Bettercap/Ettercap) to intercept ALL traffic: credentials, session cookies, personal data, API responses — everything is visible in plaintext.",
                    "impact": "Complete traffic interception — credentials, session tokens, personal data exposed to network attackers",
                    "cwe": "CWE-319", "owasp": "A02:2021 Cryptographic Failures",
                    "time_to_exploit": "~2 minutes on shared network",
                },
            ))
            self._check_mixed_content()
            return self._build_result(start, scheme="http")

        self._log(f"Analyzing TLS for {hostname}:{port}")

        # Connect and get certificate info
        self._check_certificate(hostname, port)
        self._check_mixed_content()

        self._log(f"TLS scan complete: {len(self._findings)} findings")
        return self._build_result(start, hostname=hostname, port=port)

    def _check_certificate(self, hostname: str, port: int) -> None:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cipher = ssock.cipher()
                    version = ssock.version()
                    der_cert = ssock.getpeercert(binary_form=True)

            if not cert:
                # Try verifying with trusted context
                ctx2 = ssl.create_default_context()
                try:
                    with socket.create_connection((hostname, port), timeout=10) as sock2:
                        with ctx2.wrap_socket(sock2, server_hostname=hostname) as ssock2:
                            cert = ssock2.getpeercert()
                except ssl.SSLCertVerificationError as e:
                    self._add_finding(Finding(
                        severity=Severity.HIGH,
                        category="tls",
                        title="Certificate verification failed",
                        description=str(e),
                        evidence=str(e),
                        remediation="Fix the certificate issue: obtain a valid certificate from a trusted CA.",
                        metadata={
                            "exploit": "Invalid certificates trigger browser warnings. Users who click 'proceed anyway' are vulnerable to MITM attacks. Automated tools and APIs that skip verification are directly exploitable.",
                            "impact": "Man-in-the-middle attacks — attacker intercepts and modifies all HTTPS traffic",
                            "cwe": "CWE-295", "owasp": "A02:2021 Cryptographic Failures",
                            "time_to_exploit": "~5 minutes with MITM proxy",
                        },
                    ))
                except Exception:
                    pass

                # If cert is still empty but we have der_cert, decode it directly
                if not cert and der_cert:
                    try:
                        pem = ssl.DER_cert_to_PEM_cert(der_cert)
                        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".pem") as tf:
                            tf.write(pem)
                            tf_path = tf.name
                        try:
                            if hasattr(ssl, "_ssl") and hasattr(ssl._ssl, "_test_decode_cert"):
                                cert = ssl._ssl._test_decode_cert(tf_path)
                        finally:
                            try:
                                os.unlink(tf_path)
                            except OSError:
                                pass
                    except Exception as dec_err:
                        self._log(f"Could not decode DER certificate: {dec_err}")

            # TLS version
            if version:
                if "TLSv1.0" in version or "SSLv" in version:
                    self._add_finding(Finding(
                        severity=Severity.HIGH,
                        category="tls",
                        title=f"Weak TLS version: {version}",
                        description=f"Server uses {version}, which has known vulnerabilities (BEAST, POODLE).",
                        evidence=f"Negotiated: {version}",
                        remediation="Disable TLS 1.0 and 1.1. Configure server to use TLS 1.2+ only.",
                        metadata={
                            "exploit": f"Attacker performs protocol downgrade attack using tools like tlsattacker. {version} is vulnerable to BEAST (CBC cipher attacks) and POODLE (padding oracle). Attacker on the network can decrypt session cookies byte-by-byte.",
                            "impact": "Session cookie decryption — account hijacking via network attack",
                            "cwe": "CWE-326", "owasp": "A02:2021 Cryptographic Failures",
                            "time_to_exploit": "~30 minutes for BEAST, ~15 minutes for POODLE",
                        },
                    ))
                elif "TLSv1.1" in version:
                    self._add_finding(Finding(
                        severity=Severity.MEDIUM,
                        category="tls",
                        title=f"Deprecated TLS version: {version}",
                        description="TLS 1.1 is deprecated by all major browsers since 2020.",
                        evidence=f"Negotiated: {version}",
                        remediation="Disable TLS 1.1. Use TLS 1.2 or 1.3 only.",
                        metadata={
                            "exploit": "While no practical attacks exist for TLS 1.1 specifically, it uses older cipher suites and is rejected by modern browsers, breaking compatibility.",
                            "impact": "Reduced security posture, potential for future vulnerabilities",
                            "cwe": "CWE-326", "owasp": "A02:2021 Cryptographic Failures",
                            "time_to_exploit": "N/A currently",
                        },
                    ))
                else:
                    self._add_finding(Finding(
                        severity=Severity.INFO,
                        category="tls",
                        title=f"TLS version: {version}",
                        description=f"Server negotiated {version}.",
                        evidence=f"Version: {version}",
                        metadata={"cwe": "", "owasp": ""},
                    ))

            # Cipher suite
            if cipher:
                cipher_name, proto, bits = cipher
                if bits and bits < 128:
                    self._add_finding(Finding(
                        severity=Severity.HIGH,
                        category="tls",
                        title=f"Weak cipher: {cipher_name} ({bits}-bit)",
                        description=f"Cipher {cipher_name} uses only {bits}-bit encryption.",
                        evidence=f"Cipher: {cipher_name}, Protocol: {proto}, Bits: {bits}",
                        remediation="Disable weak ciphers. Use AES-256-GCM or ChaCha20-Poly1305.",
                        metadata={
                            "exploit": f"A {bits}-bit cipher can be brute-forced with moderate computing resources. Attacker captures encrypted traffic and decrypts offline.",
                            "impact": "Traffic decryption — all HTTPS data exposed",
                            "cwe": "CWE-326", "owasp": "A02:2021 Cryptographic Failures",
                            "time_to_exploit": "Hours to days depending on cipher strength",
                        },
                    ))
                if "RC4" in cipher_name or "DES" in cipher_name or "NULL" in cipher_name:
                    self._add_finding(Finding(
                        severity=Severity.HIGH,
                        category="tls",
                        title=f"Insecure cipher: {cipher_name}",
                        description=f"Cipher {cipher_name} is known to be broken.",
                        evidence=f"Cipher: {cipher_name}",
                        remediation=f"Disable {cipher_name}. Use modern AEAD ciphers.",
                        metadata={
                            "exploit": f"{cipher_name} has known cryptographic weaknesses. Attacker can decrypt traffic using known attacks specific to this cipher.",
                            "impact": "Traffic decryption",
                            "cwe": "CWE-327", "owasp": "A02:2021 Cryptographic Failures",
                            "time_to_exploit": "~1 hour",
                        },
                    ))

            # Certificate details
            if cert:
                # Expiry
                not_after = cert.get("notAfter", "")
                if not_after:
                    try:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        now = datetime.now(timezone.utc)
                        days_left = (expiry - now).days
                        if days_left < 0:
                            self._add_finding(Finding(
                                severity=Severity.CRITICAL,
                                category="tls",
                                title="Certificate EXPIRED",
                                description=f"Certificate expired {abs(days_left)} days ago on {not_after}.",
                                evidence=f"Expired: {not_after}",
                                remediation="Renew the certificate immediately. Use Let's Encrypt with auto-renewal.",
                                metadata={
                                    "exploit": "Expired certificates cause browser warnings. Users who proceed are vulnerable to MITM. Automated systems may fail or skip verification.",
                                    "impact": "MITM attacks, browser warnings reducing user trust, broken API integrations",
                                    "cwe": "CWE-298", "owasp": "A02:2021 Cryptographic Failures",
                                    "time_to_exploit": "~5 minutes for MITM",
                                },
                            ))
                        elif days_left < 30:
                            self._add_finding(Finding(
                                severity=Severity.MEDIUM,
                                category="tls",
                                title=f"Certificate expires in {days_left} days",
                                description=f"Certificate expires on {not_after}. Renew soon to avoid outages.",
                                evidence=f"Expires: {not_after} ({days_left} days)",
                                remediation="Renew the certificate. Set up auto-renewal with certbot or your CA.",
                                metadata={
                                    "exploit": "No direct exploit, but expiry causes service disruption and may force emergency changes that introduce vulnerabilities.",
                                    "impact": "Service disruption, potential security bypass during emergency renewal",
                                    "cwe": "CWE-298", "owasp": "A02:2021 Cryptographic Failures",
                                    "time_to_exploit": "N/A",
                                },
                            ))

                    except (ValueError, TypeError):
                        pass

                # Subject / SAN
                subject = dict(x[0] for x in cert.get("subject", ()) if x)
                cn = subject.get("commonName", "")
                if cn:
                    self._add_finding(Finding(
                        severity=Severity.INFO,
                        category="tls",
                        title=f"Certificate CN: {cn}",
                        description=f"Certificate issued to {cn}",
                        evidence=f"CN={cn}, Issuer: {dict(x[0] for x in cert.get('issuer', ()) if x).get('organizationName', 'Unknown')}",
                        metadata={"cwe": "", "owasp": ""},
                    ))

        except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
            self._log(f"Could not connect to {hostname}:{port} — {e}")
        except Exception as e:
            self._log(f"TLS scan error: {e}")

    def _check_mixed_content(self) -> None:
        """Check for HTTP resources loaded on HTTPS pages."""
        if not self._settings.url.startswith("https://"):
            return

        html_files = self._get_downloaded_files(extensions=(".html", ".htm"))
        # Focus on active subresources and form actions loaded over HTTP (not benign outbound anchor hrefs)
        re_http = re.compile(r"""(?:src|action)\s*=\s*['"]http://[^'"]+['"]""", re.IGNORECASE)

        for f in html_files:
            try:
                found_in_file = False
                with open(f.local_path, "r", encoding="utf-8", errors="ignore") as fh:
                    for ln, line in enumerate(fh, 1):
                        for m in re_http.finditer(line):
                            self._add_finding(Finding(
                                severity=Severity.MEDIUM,
                                category="tls",
                                title="Mixed content: HTTP resource on HTTPS page",
                                description="HTTPS page loads an active resource or submits forms over unencrypted HTTP.",
                                evidence=m.group(0)[:150],
                                file_path=f.local_path,
                                line_number=ln,
                                url=f.url,
                                remediation="Change all resource URLs to HTTPS or use protocol-relative URLs (//).",
                                metadata={
                                    "exploit": "Attacker on the network intercepts the HTTP resource and replaces it with malicious content (JS injection, image replacement, CSS keylogger). The HTTPS page becomes compromised through the insecure resource.",
                                    "impact": "Content injection via network MITM — can escalate to full XSS on the HTTPS page",
                                    "cwe": "CWE-311", "owasp": "A02:2021 Cryptographic Failures",
                                    "time_to_exploit": "~5 minutes with MITM proxy",
                                },
                            ))
                            found_in_file = True
                            break
                        if found_in_file:
                            break
            except (OSError, IOError):
                pass

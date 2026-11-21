"""
TCP port scanner for WebRipper Recon.

Async TCP connect scan on top 100 ports with service banner grabbing.
Used as fallback when nmap is not installed.
"""

from __future__ import annotations

import asyncio
import re
import socket
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .base import BaseScanner
from ..models import Finding, ScanResult, Severity

# Top 100 most common ports
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 161, 389, 443, 445, 465, 514, 587, 636, 993,
    995, 1025, 1080, 1433, 1434, 1521, 1723, 2049, 2082, 2083,
    2086, 2087, 2096, 2181, 3000, 3128, 3306, 3389, 4443, 4444,
    4567, 4848, 5000, 5432, 5555, 5601, 5672, 5900, 5984, 6379,
    6443, 7001, 7002, 7077, 7443, 8000, 8008, 8009, 8080, 8081,
    8082, 8083, 8088, 8089, 8090, 8161, 8443, 8444, 8500, 8834,
    8880, 8888, 8983, 9000, 9001, 9042, 9043, 9060, 9090, 9091,
    9200, 9300, 9443, 9999, 10000, 10250, 11211, 15672, 27017, 27018,
    28017, 50000, 50070, 50075, 61616, 2375, 2376, 4040, 6066, 8472,
]

# Service identification from banner patterns
_SERVICE_PATTERNS: List[Tuple[str, re.Pattern, str]] = [
    ("SSH", re.compile(r"SSH-\d", re.IGNORECASE), "SSH remote access"),
    ("HTTP", re.compile(r"HTTP/\d", re.IGNORECASE), "Web server"),
    ("FTP", re.compile(r"220.*FTP", re.IGNORECASE), "FTP file transfer"),
    ("SMTP", re.compile(r"220.*SMTP|220.*mail", re.IGNORECASE), "Mail server"),
    ("MySQL", re.compile(r"mysql|MariaDB", re.IGNORECASE), "MySQL database"),
    ("PostgreSQL", re.compile(r"PostgreSQL", re.IGNORECASE), "PostgreSQL database"),
    ("Redis", re.compile(r"REDIS|\+OK|\-ERR", re.IGNORECASE), "Redis cache/database"),
    ("MongoDB", re.compile(r"MongoDB|ismaster", re.IGNORECASE), "MongoDB database"),
    ("Elasticsearch", re.compile(r"elasticsearch|lucene", re.IGNORECASE), "Elasticsearch"),
    ("RDP", re.compile(r"\x03\x00", re.IGNORECASE), "Remote Desktop"),
    ("IMAP", re.compile(r"\* OK.*IMAP", re.IGNORECASE), "IMAP mail"),
    ("POP3", re.compile(r"\+OK.*POP3|^\+OK", re.IGNORECASE), "POP3 mail"),
]

# Known port-to-service mapping for when banner grabbing fails
_PORT_SERVICES: Dict[int, Tuple[str, str]] = {
    21: ("FTP", "File Transfer Protocol"),
    22: ("SSH", "Secure Shell"),
    23: ("Telnet", "Unencrypted remote access"),
    25: ("SMTP", "Mail server"),
    53: ("DNS", "Domain Name System"),
    80: ("HTTP", "Web server"),
    110: ("POP3", "Mail retrieval"),
    111: ("RPCbind", "RPC port mapper"),
    135: ("MSRPC", "Microsoft RPC"),
    139: ("NetBIOS", "Windows file sharing"),
    143: ("IMAP", "Mail access"),
    161: ("SNMP", "Network monitoring"),
    389: ("LDAP", "Directory service"),
    443: ("HTTPS", "Encrypted web server"),
    445: ("SMB", "Windows file sharing"),
    465: ("SMTPS", "Encrypted mail"),
    587: ("SMTP Submission", "Mail submission"),
    636: ("LDAPS", "Encrypted LDAP"),
    993: ("IMAPS", "Encrypted IMAP"),
    995: ("POP3S", "Encrypted POP3"),
    1433: ("MSSQL", "Microsoft SQL Server"),
    1521: ("Oracle", "Oracle database"),
    2375: ("Docker", "Docker API (unencrypted)"),
    2376: ("Docker TLS", "Docker API (encrypted)"),
    2181: ("ZooKeeper", "Apache ZooKeeper"),
    3000: ("Dev Server", "Node.js/Grafana/Gitea"),
    3306: ("MySQL", "MySQL database"),
    3389: ("RDP", "Remote Desktop Protocol"),
    4443: ("HTTPS Alt", "Alternative HTTPS"),
    5000: ("Dev Server", "Flask/Docker Registry"),
    5432: ("PostgreSQL", "PostgreSQL database"),
    5601: ("Kibana", "Elasticsearch dashboard"),
    5672: ("AMQP", "RabbitMQ messaging"),
    5900: ("VNC", "Virtual Network Computing"),
    5984: ("CouchDB", "CouchDB database"),
    6379: ("Redis", "Redis cache/database"),
    6443: ("Kubernetes API", "K8s API server"),
    7001: ("WebLogic", "Oracle WebLogic"),
    8080: ("HTTP Proxy", "HTTP proxy/alt web server"),
    8443: ("HTTPS Alt", "Alternative HTTPS"),
    8500: ("Consul", "HashiCorp Consul"),
    8834: ("Nessus", "Nessus vulnerability scanner"),
    8888: ("HTTP Alt", "Alternative HTTP"),
    8983: ("Solr", "Apache Solr"),
    9000: ("SonarQube", "SonarQube/PHP-FPM"),
    9090: ("Prometheus", "Prometheus monitoring"),
    9200: ("Elasticsearch", "Elasticsearch HTTP"),
    9300: ("Elasticsearch", "Elasticsearch transport"),
    9443: ("HTTPS Alt", "Alternative HTTPS"),
    10250: ("Kubelet", "Kubernetes kubelet"),
    11211: ("Memcached", "Memcached cache"),
    15672: ("RabbitMQ", "RabbitMQ management"),
    27017: ("MongoDB", "MongoDB database"),
    50000: ("Jenkins", "Jenkins build server"),
}

# Dangerous services that should NOT be internet-facing
_DANGEROUS_SERVICES = {
    "Redis": (Severity.CRITICAL, "Redis without authentication allows remote command execution. Attacker connects with redis-cli and runs CONFIG SET dir /var/www/html; CONFIG SET dbfilename shell.php; SET test '<?php system($_GET[\"cmd\"]);?>'; SAVE — creating a webshell for full server control."),
    "MongoDB": (Severity.CRITICAL, "MongoDB without auth allows full database access. Attacker connects with mongosh and runs show dbs; use admin; db.getUsers() to enumerate all data. Ransomware groups automate this to mass-wipe databases."),
    "Elasticsearch": (Severity.HIGH, "Elasticsearch without auth exposes all indexed data. Attacker hits GET /_cat/indices to list all indices, then GET /index/_search?size=10000 to dump data. Often contains logs with PII, credentials, and session tokens."),
    "Memcached": (Severity.HIGH, "Memcached without auth allows reading cached data including session tokens and user data. Also used for DDoS amplification attacks."),
    "Docker": (Severity.CRITICAL, "Exposed Docker API allows full container control. Attacker creates a privileged container mounting the host filesystem: docker -H target:2375 run -v /:/mnt --privileged -it alpine chroot /mnt — full host access."),
    "Kubelet": (Severity.CRITICAL, "Exposed kubelet API allows pod listing, exec into containers, and secrets extraction. Attacker can pivot across the entire Kubernetes cluster."),
    "CouchDB": (Severity.HIGH, "CouchDB without auth allows database enumeration and data theft. GET /_all_dbs lists all databases."),
    "Consul": (Severity.HIGH, "Exposed Consul allows service discovery enumeration, KV store access (may contain secrets), and service registration manipulation."),
    "Telnet": (Severity.HIGH, "Telnet sends credentials in plaintext. Any network observer captures login credentials. Often has default credentials on IoT/network devices."),
    "FTP": (Severity.MEDIUM, "FTP sends credentials in plaintext. Check for anonymous access: ftp target → login: anonymous → password: test@test.com. Anonymous FTP may expose sensitive files."),
    "VNC": (Severity.HIGH, "VNC provides direct graphical desktop access. Many VNC servers have weak or no authentication. Attacker gets full desktop control."),
    "SNMP": (Severity.MEDIUM, "SNMP with default community string 'public' reveals detailed system info: OS version, network interfaces, running processes, installed software."),
    "RDP": (Severity.MEDIUM, "RDP is targeted for brute-force attacks and has had critical vulnerabilities (BlueKeep CVE-2019-0708). Ensure NLA is enabled and use strong credentials."),
    "SMB": (Severity.HIGH, "SMB has had critical vulnerabilities (EternalBlue/MS17-010, PrintNightmare). Check for null sessions: smbclient -L target -N. May expose file shares."),
    "Jenkins": (Severity.HIGH, "Jenkins often has unauthenticated access to /script console allowing Groovy code execution = full server RCE."),
}


class PortScanner(BaseScanner):
    """Async TCP connect scan with service detection and banner grabbing."""

    @property
    def name(self) -> str:
        return "portscan"

    @property
    def description(self) -> str:
        return "TCP port scan with service detection and banner grabbing"

    def scan(self) -> ScanResult:
        start = time.time()
        parsed = urlparse(self._settings.url)
        hostname = parsed.hostname or ""

        if not hostname:
            self._log("No hostname to scan")
            return self._build_result(start)

        self._log(f"Scanning {len(TOP_PORTS)} ports on {hostname}...")

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            open_ports = loop.run_until_complete(self._scan_ports(hostname))
            loop.close()
        except Exception as exc:
            self._log(f"Port scan error: {exc}")
            open_ports = []

        self._log(f"Port scan complete: {len(open_ports)} open ports, {len(self._findings)} findings")
        return self._build_result(
            start, hostname=hostname,
            open_ports=[p for p, _, _ in open_ports],
            total_scanned=len(TOP_PORTS),
        )

    async def _scan_ports(self, hostname: str) -> List[Tuple[int, str, str]]:
        """Scan all ports concurrently and return (port, service, banner) for open ports."""
        sem = asyncio.Semaphore(20)
        open_ports: List[Tuple[int, str, str]] = []

        async def check_port(port: int) -> Optional[Tuple[int, str, str]]:
            async with sem:
                try:
                    fut = asyncio.open_connection(hostname, port)
                    reader, writer = await asyncio.wait_for(fut, timeout=2.0)

                    # Try to grab banner (probe web ports with HTTP request)
                    banner = ""
                    try:
                        if port in (80, 8080, 8000, 8888):
                            writer.write(b"HEAD / HTTP/1.0\r\nHost: " + hostname.encode() + b"\r\n\r\n")
                            await writer.drain()
                        data = await asyncio.wait_for(reader.read(1024), timeout=0.5)
                        banner = data.decode("utf-8", errors="replace").strip()[:200]
                    except (asyncio.TimeoutError, UnicodeDecodeError, OSError):
                        pass

                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

                    # Identify service
                    service = self._identify_service(port, banner)
                    return (port, service, banner)

                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    return None

        tasks = [check_port(port) for port in TOP_PORTS]
        results = await asyncio.gather(*tasks)

        for result in results:
            if result:
                open_ports.append(result)
                port, service, banner = result
                self._report_open_port(hostname, port, service, banner)

        return open_ports

    def _identify_service(self, port: int, banner: str) -> str:
        """Identify service from banner or port number."""
        if banner:
            for svc_name, pattern, _ in _SERVICE_PATTERNS:
                if pattern.search(banner):
                    return svc_name

        if port in _PORT_SERVICES:
            return _PORT_SERVICES[port][0]

        return "Unknown"

    def _report_open_port(self, hostname: str, port: int, service: str, banner: str) -> None:
        """Create a finding for an open port."""
        port_info = _PORT_SERVICES.get(port, ("Unknown", "Unknown service"))
        svc_desc = port_info[1] if port in _PORT_SERVICES else service

        # Check if this is a dangerous service
        if service in _DANGEROUS_SERVICES:
            sev, exploit = _DANGEROUS_SERVICES[service]
            self._add_finding(Finding(
                severity=sev,
                category="portscan",
                title=f"DANGEROUS: {service} on port {port}",
                description=f"{service} ({svc_desc}) is exposed to the internet on port {port}.",
                evidence=f"Port {port} OPEN — {service}" + (f"\nBanner: {banner}" if banner else ""),
                url=f"{hostname}:{port}",
                remediation=f"Restrict {service} access with firewall rules. Only allow connections from trusted IPs. Enable authentication if not already configured.",
                metadata={
                    "exploit": exploit,
                    "impact": f"Depends on {service} configuration — ranges from data theft to full server compromise",
                    "cwe": "CWE-284",
                    "owasp": "A05:2021 Security Misconfiguration",
                    "time_to_exploit": "~5 minutes for unauthenticated services",
                    "port": port, "service": service, "banner": banner,
                },
            ))
        else:
            sev = Severity.INFO
            if port in (23, 21) and service in ("Telnet", "FTP"):
                sev = Severity.MEDIUM

            self._add_finding(Finding(
                severity=sev,
                category="portscan",
                title=f"Open port: {port}/{service}",
                description=f"{service} ({svc_desc}) is running on port {port}.",
                evidence=f"Port {port} OPEN — {service}" + (f"\nBanner: {banner}" if banner else ""),
                url=f"{hostname}:{port}",
                metadata={
                    "port": port, "service": service, "banner": banner,
                    "cwe": "", "owasp": "",
                },
            ))

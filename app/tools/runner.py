"""
External tool runner — runs detected tools and parses their output.

Wraps nmap, nikto, nuclei, gobuster, sslscan, sqlmap into a unified
interface that returns Finding objects.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from ..models import Finding, ScanResult, Severity
from .base import get_tools_dir


def _flags() -> int:
    return subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0


def _find(name: str) -> Optional[str]:
    """Find a tool in tools_dir, system paths, or PATH."""
    from .detector import _find_tool
    return _find_tool(name)


# =====================================================================
# NMAP
# =====================================================================

def run_nmap(target: str, output_dir: str, timeout: int = 180,
             progress_cb: Optional[Callable[[str], None]] = None) -> List[Finding]:
    """Run nmap and parse XML output into findings."""
    cb = progress_cb or (lambda s: None)
    path = _find("nmap")
    if not path:
        return []

    xml_file = os.path.join(output_dir, "nmap_output.xml")
    
    # Handle URL and host:port targets correctly
    from urllib.parse import urlparse
    port_args = []
    clean_target = target
    if "://" in target:
        parsed = urlparse(target)
        clean_target = parsed.hostname or target
        if parsed.port:
            port_args = ["-p", str(parsed.port)]
    elif ":" in target and not target.startswith("["):
        host_part, _, port_part = target.partition(":")
        if port_part.isdigit():
            clean_target = host_part
            port_args = ["-p", port_part]

    cmd = [path, "-sV", "-sC", "-T4"]
    if port_args:
        cmd.extend(port_args)
    else:
        cmd.extend(["--top-ports", "1000"])
    cmd.extend(["-oX", xml_file, clean_target])

    cb(f"Running: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                       stdin=subprocess.DEVNULL, encoding="utf-8", errors="replace",
                       creationflags=_flags(), shell=False)
    except subprocess.TimeoutExpired:
        cb("nmap timed out")
    except Exception as exc:
        cb(f"nmap error: {exc}")
        return []

    if not os.path.exists(xml_file):
        return []

    return _parse_nmap_xml(xml_file, cb)


def _parse_nmap_xml(xml_file: str, cb: Callable) -> List[Finding]:
    findings: List[Finding] = []
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        for host in root.findall(".//host"):
            addr_el = host.find("address")
            addr = addr_el.get("addr", "") if addr_el is not None else ""

            for port_el in host.findall(".//port"):
                portid = port_el.get("portid", "")
                protocol = port_el.get("protocol", "tcp")
                state_el = port_el.find("state")
                state = state_el.get("state", "") if state_el is not None else ""

                if state != "open":
                    continue

                service_el = port_el.find("service")
                svc_name = service_el.get("name", "unknown") if service_el is not None else "unknown"
                svc_product = service_el.get("product", "") if service_el is not None else ""
                svc_version = service_el.get("version", "") if service_el is not None else ""

                banner = f"{svc_product} {svc_version}".strip()
                evidence = f"Port {portid}/{protocol} OPEN — {svc_name}"
                if banner:
                    evidence += f" ({banner})"

                # Collect NSE script output
                scripts = []
                for script_el in port_el.findall(".//script"):
                    sid = script_el.get("id", "")
                    sout = script_el.get("output", "")
                    if sid and sout:
                        scripts.append(f"{sid}: {sout[:200]}")

                if scripts:
                    evidence += "\n\nNSE Scripts:\n" + "\n".join(scripts)

                sev = Severity.INFO
                if svc_name in ("mysql", "postgresql", "mongodb", "redis", "memcached"):
                    sev = Severity.HIGH
                elif scripts:
                    sev = Severity.MEDIUM

                findings.append(Finding(
                    severity=sev,
                    category="nmap",
                    title=f"[nmap] {portid}/{protocol} — {svc_name}" + (f" {banner}" if banner else ""),
                    description=f"nmap detected {svc_name} service on port {portid}.",
                    evidence=evidence,
                    url=f"{addr}:{portid}",
                    metadata={
                        "port": int(portid), "protocol": protocol,
                        "service": svc_name, "product": svc_product,
                        "version": svc_version, "scripts": scripts,
                        "cwe": "", "owasp": "",
                        "source": "nmap",
                    },
                ))

        cb(f"nmap: parsed {len(findings)} open ports")

    except ET.ParseError as exc:
        cb(f"nmap XML parse error: {exc}")

    return findings


def nmap_command(target: str) -> str:
    return f"nmap -sV -sC -T4 --top-ports 1000 {target}"


# =====================================================================
# NIKTO
# =====================================================================

def run_nikto(target: str, output_dir: str, timeout: int = 120,
              progress_cb: Optional[Callable[[str], None]] = None) -> List[Finding]:
    cb = progress_cb or (lambda s: None)
    path = _find("nikto") or _find("nikto.pl")
    if not path:
        return []

    json_file = os.path.join(output_dir, "nikto_output.json")
    cmd = [path, "-h", target, "-Format", "json", "-output", json_file]

    # nikto might need perl
    if path.endswith(".pl"):
        perl = shutil.which("perl")
        if perl:
            cmd = [perl, path, "-h", target, "-Format", "json", "-output", json_file]

    cb(f"Running nikto...")
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                       stdin=subprocess.DEVNULL, encoding="utf-8", errors="replace",
                       creationflags=_flags(), shell=False)
    except subprocess.TimeoutExpired:
        cb("nikto timed out")
    except Exception as exc:
        cb(f"nikto error: {exc}")
        return []

    if not os.path.exists(json_file):
        return []

    findings: List[Finding] = []
    try:
        with open(json_file, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)

        vulns = data if isinstance(data, list) else data.get("vulnerabilities", [])
        for vuln in vulns:
            msg = vuln.get("msg", vuln.get("message", ""))
            osvdb = vuln.get("OSVDB", vuln.get("id", ""))
            method = vuln.get("method", "GET")
            uri = vuln.get("url", vuln.get("uri", ""))

            findings.append(Finding(
                severity=Severity.MEDIUM,
                category="nikto",
                title=f"[nikto] {msg[:80]}",
                description=msg,
                evidence=f"OSVDB-{osvdb}: {method} {uri}" if osvdb else msg,
                url=uri,
                remediation="Review nikto finding and apply recommended fix.",
                metadata={
                    "osvdb": str(osvdb), "method": method,
                    "cwe": "", "owasp": "A05:2021 Security Misconfiguration",
                    "source": "nikto",
                },
            ))

        cb(f"nikto: {len(findings)} findings")
    except (json.JSONDecodeError, Exception) as exc:
        cb(f"nikto parse error: {exc}")

    return findings


def nikto_command(target: str) -> str:
    return f"nikto -h {target}"


# =====================================================================
# NUCLEI
# =====================================================================

def run_nuclei(target: str, output_dir: str, timeout: int = 180,
               progress_cb: Optional[Callable[[str], None]] = None) -> List[Finding]:
    cb = progress_cb or (lambda s: None)
    path = _find("nuclei")
    if not path:
        return []

    json_file = os.path.join(output_dir, "nuclei_output.jsonl")
    cmd = [path, "-u", target, "-jsonl", "-o", json_file, "-silent", "-severity", "critical,high,medium", "-no-interactsh", "-timeout", "5"]

    cb("Running nuclei...")
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                       stdin=subprocess.DEVNULL, encoding="utf-8", errors="replace",
                       creationflags=_flags(), shell=False)
    except subprocess.TimeoutExpired:
        cb("nuclei timed out")
    except Exception as exc:
        cb(f"nuclei error: {exc}")
        return []

    if not os.path.exists(json_file):
        return []

    findings: List[Finding] = []
    _sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}

    try:
        with open(json_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                template_id = entry.get("template-id", entry.get("templateID", ""))
                info_dict = entry.get("info") or {}
                name = info_dict.get("name", template_id)
                severity_str = (info_dict.get("severity") or "info").lower()
                matched = entry.get("matched-at", entry.get("matched", ""))
                extracted = entry.get("extracted-results", [])
                classification = info_dict.get("classification") or {}
                cve_refs = classification.get("cve-id", [])
                if isinstance(cve_refs, str):
                    cve_refs = [cve_refs]

                findings.append(Finding(
                    severity=_sev_map.get(severity_str, Severity.INFO),
                    category="nuclei",
                    title=f"[nuclei] {name}",
                    description=entry.get("info", {}).get("description", name),
                    evidence=f"Template: {template_id}\nMatched: {matched}" +
                             (f"\nExtracted: {extracted}" if extracted else "") +
                             (f"\nCVE: {', '.join(cve_refs)}" if cve_refs else ""),
                    url=matched,
                    remediation=entry.get("info", {}).get("remediation", "See nuclei template for details."),
                    metadata={
                        "template_id": template_id,
                        "cve": ", ".join(cve_refs) if cve_refs else "",
                        "cwe": "", "owasp": "",
                        "source": "nuclei",
                    },
                ))

        cb(f"nuclei: {len(findings)} findings")
    except Exception as exc:
        cb(f"nuclei parse error: {exc}")

    return findings


def nuclei_command(target: str) -> str:
    return f"nuclei -u {target} -severity critical,high,medium"


# =====================================================================
# GOBUSTER
# =====================================================================

def run_gobuster(target: str, output_dir: str, wordlist: str = "",
                 timeout: int = 120,
                 progress_cb: Optional[Callable[[str], None]] = None) -> List[Finding]:
    cb = progress_cb or (lambda s: None)
    path = _find("gobuster")
    if not path:
        return []

    if "://" not in target:
        target = f"https://{target}"

    if not wordlist:
        # Try SecLists
        appdata = os.environ.get("APPDATA", os.path.expanduser("~"))
        sl = Path(appdata) / "WebRipper" / "SecLists" / "common.txt"
        if sl.is_file():
            wordlist = str(sl)
        else:
            try:
                from ..wordlists.paths import BUILTIN_PATHS
                temp_wl = Path(output_dir) / "_gobuster_builtin.txt"
                temp_wl.write_text("\n".join(p.lstrip("/") for p in BUILTIN_PATHS), encoding="utf-8")
                wordlist = str(temp_wl)
            except Exception:
                cb("gobuster: no wordlist available")
                return []

    out_file = os.path.join(output_dir, "gobuster_output.txt")
    cmd = [path, "dir", "-u", target, "-w", wordlist, "-o", out_file,
           "-q", "--no-color", "-t", "20"]

    cb("Running gobuster...")
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                       stdin=subprocess.DEVNULL, encoding="utf-8", errors="replace",
                       creationflags=_flags(), shell=False)
    except subprocess.TimeoutExpired:
        cb("gobuster timed out")
    except Exception as exc:
        cb(f"gobuster error: {exc}")
        return []

    if not os.path.exists(out_file):
        return []

    findings: List[Finding] = []
    try:
        with open(out_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # gobuster output: /path (Status: 200) [Size: 1234]
                m = re.match(r"(/\S+)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]", line)
                if m:
                    path_found, status, size = m.group(1), int(m.group(2)), int(m.group(3))
                    if status in (200, 201, 301, 302, 403):
                        sev = Severity.MEDIUM if status == 200 else Severity.LOW
                        findings.append(Finding(
                            severity=sev,
                            category="gobuster",
                            title=f"[gobuster] {path_found} ({status})",
                            description=f"Directory/file found: {path_found}",
                            evidence=f"Status: {status}, Size: {size}",
                            url=f"{target.rstrip('/')}{path_found}",
                            metadata={"status": status, "size": size,
                                      "cwe": "", "owasp": "", "source": "gobuster"},
                        ))
        cb(f"gobuster: {len(findings)} paths found")
    except Exception as exc:
        cb(f"gobuster parse error: {exc}")

    return findings


def gobuster_command(target: str) -> str:
    return f"gobuster dir -u {target} -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 30"


# =====================================================================
# SSLSCAN
# =====================================================================

def run_sslscan(target: str, output_dir: str, timeout: int = 60,
                progress_cb: Optional[Callable[[str], None]] = None) -> List[Finding]:
    cb = progress_cb or (lambda s: None)
    path = _find("sslscan")
    if not path:
        return []

    xml_file = os.path.join(output_dir, "sslscan_output.xml")
    cmd = [path, f"--xml={xml_file}", target]

    cb("Running sslscan...")
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                       stdin=subprocess.DEVNULL, encoding="utf-8", errors="replace",
                       creationflags=_flags(), shell=False)
    except subprocess.TimeoutExpired:
        cb("sslscan timed out")
    except Exception as exc:
        cb(f"sslscan error: {exc}")
        return []

    if not os.path.exists(xml_file):
        return []

    findings: List[Finding] = []
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        for cipher in root.findall(".//cipher"):
            status = cipher.get("status", "")
            sslversion = cipher.get("sslversion", "")
            name = cipher.get("cipher", "")
            bits = cipher.get("bits", "")

            if status == "accepted" and ("SSLv" in sslversion or "TLSv1.0" in sslversion or "TLSv1.1" in sslversion):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    category="sslscan",
                    title=f"[sslscan] Weak cipher: {name} ({sslversion})",
                    description=f"Cipher {name} accepted on deprecated {sslversion}.",
                    evidence=f"{sslversion}: {name} ({bits}-bit)",
                    remediation=f"Disable {sslversion} and this cipher suite.",
                    metadata={"cwe": "CWE-326", "owasp": "A02:2021 Cryptographic Failures",
                              "source": "sslscan"},
                ))

        cb(f"sslscan: {len(findings)} findings")
    except ET.ParseError as exc:
        cb(f"sslscan XML parse error: {exc}")

    return findings


def sslscan_command(target: str) -> str:
    return f"sslscan {target}"


# =====================================================================
# SQLMAP — Command generation only (does NOT auto-run)
# =====================================================================

def generate_sqlmap_commands(
    endpoints: List[str],
    forms: Optional[List[Dict]] = None,
) -> List[str]:
    """Generate sqlmap commands for discovered endpoints with parameters."""
    commands = []

    for endpoint in endpoints:
        if "?" in endpoint and "=" in endpoint:
            commands.append(
                f'sqlmap -u "{endpoint}" --batch --level=3 --risk=2 --threads=5'
            )

    if forms:
        for form in forms:
            action = form.get("action", "")
            method = form.get("method", "POST")
            params = form.get("params", "")
            if action and method.upper() == "POST" and params:
                commands.append(
                    f'sqlmap -u "{action}" --data="{params}" --batch --level=3 --risk=2'
                )

    return commands


# =====================================================================
# Runner — runs all available tools
# =====================================================================

def run_all_tools(
    target: str, output_dir: str,
    endpoints: Optional[List[str]] = None,
    timeout: int = 120,
    progress_cb: Optional[Callable[[str], None]] = None,
) -> Tuple[List[Finding], Dict[str, str]]:
    """Run all detected tools. Returns (findings, manual_commands)."""
    cb = progress_cb or (lambda s: None)
    all_findings: List[Finding] = []
    manual_commands: Dict[str, str] = {}

    # Always generate manual commands
    manual_commands["nmap"] = nmap_command(target)
    manual_commands["nikto"] = nikto_command(target)
    manual_commands["nuclei"] = nuclei_command(target)
    manual_commands["gobuster"] = gobuster_command(target)
    manual_commands["sslscan"] = sslscan_command(target)

    if endpoints:
        sqli_cmds = generate_sqlmap_commands(endpoints)
        if sqli_cmds:
            manual_commands["sqlmap"] = "\n".join(sqli_cmds)

    # Run installed tools
    tool_runners = [
        ("nmap", run_nmap, {"target": target, "output_dir": output_dir, "timeout": min(timeout, 180)}),
        ("nikto", run_nikto, {"target": target, "output_dir": output_dir, "timeout": min(timeout, 120)}),
        ("nuclei", run_nuclei, {"target": target, "output_dir": output_dir, "timeout": min(timeout, 180)}),
        ("sslscan", run_sslscan, {"target": target, "output_dir": output_dir, "timeout": min(timeout, 60)}),
    ]

    for name, runner, kwargs in tool_runners:
        if _find(name):
            cb(f"\n=== Running {name} ===")
            try:
                findings = runner(progress_cb=cb, **kwargs)
                all_findings.extend(findings)
                cb(f"{name}: {len(findings)} findings")
            except Exception as exc:
                cb(f"{name} failed: {exc}")
        else:
            cb(f"{name}: not installed (use manual command)")

    # Gobuster needs wordlist
    if _find("gobuster"):
        cb("\n=== Running gobuster ===")
        try:
            findings = run_gobuster(target, output_dir, timeout=min(timeout, 120), progress_cb=cb)
            all_findings.extend(findings)
        except Exception as exc:
            cb(f"gobuster failed: {exc}")

    return all_findings, manual_commands

"""
Recon report generator for WebRipper Recon.

Produces self-contained HTML and JSON reports summarizing all scan findings.
No redaction — all evidence shown in full for professional pentesting use.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from .models import Finding, ReconReport, ScanResult, Severity, _format_size
from .cvss import score_finding, CVSSScore

# ---------------------------------------------------------------------------
# Color scheme
# ---------------------------------------------------------------------------

_SEVERITY_COLORS = {
    "CRITICAL": "#ff2222",
    "HIGH": "#ff6600",
    "MEDIUM": "#ffaa00",
    "LOW": "#44aa44",
    "INFO": "#4488ff",
}

_GRADE_COLORS = {
    "A": "#44aa44", "B": "#88cc44", "C": "#ffaa00", "D": "#ff6600", "F": "#ff2222",
}


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

def generate_html_report(report: ReconReport) -> str:
    """Generate a complete, self-contained HTML recon report with full detail."""
    findings = report.all_findings
    severity_counts = _count_severities(findings)

    scans: Dict[str, ScanResult] = {}
    for sr in report.scan_results:
        if sr.scanner_name not in scans:
            scans[sr.scanner_name] = ScanResult(
                scanner_name=sr.scanner_name,
                description=sr.description,
                scan_time=sr.scan_time,
                findings=list(sr.findings),
                metadata=dict(sr.metadata),
            )
        else:
            scans[sr.scanner_name].findings.extend(sr.findings)
            scans[sr.scanner_name].scan_time += sr.scan_time

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WebRipper Recon Report — {_esc(report.url)}</title>
<style>
{_CSS}
</style>
</head>
<body>
<nav class="sidebar">
  <div class="nav-title">SECTIONS</div>
  <a href="#summary">Executive Summary</a>
  {"<a href='#chains'>⚡ Attack Chains</a>" if report.attack_chains else ""}
  {"<a href='#headers'>Security Headers</a>" if "headers" in scans else ""}
  {"<a href='#tech'>Tech Stack</a>" if "tech" in scans else ""}
  {"<a href='#secrets'>Secrets</a>" if "secrets" in scans else ""}
  {"<a href='#paths'>Exposed Paths</a>" if "paths" in scans else ""}
  {"<a href='#endpoints'>API Endpoints</a>" if "endpoints" in scans else ""}
  {"<a href='#cors'>CORS</a>" if "cors" in scans else ""}
  {"<a href='#javascript'>JavaScript</a>" if "javascript" in scans else ""}
  {"<a href='#forms'>Forms</a>" if "forms" in scans else ""}
  {"<a href='#tls'>TLS/SSL</a>" if "tls" in scans else ""}
  {"<a href='#cookies'>Cookies</a>" if "cookies" in scans else ""}
  {"<a href='#subdomains'>Subdomains</a>" if "subdomains" in scans else ""}
  {"<a href='#portscan'>Port Scan</a>" if "portscan" in scans else ""}
  {"<a href='#waf'>WAF</a>" if "waf" in scans else ""}
  {"<a href='#dns'>DNS</a>" if "dns" in scans else ""}
  {"<a href='#emails'>Emails</a>" if "emails" in scans else ""}
  {"<a href='#screenshots'>📸 Screenshots</a>" if "screenshots" in scans else ""}
  {"<a href='#github_dork'>🐙 GitHub</a>" if "github_dork" in scans else ""}
  {"<a href='#vulns' style='color:#dc2626'>⚡ Active Vulns</a>" if "vulns" in scans and scans["vulns"].findings else ""}
  {"<a href='#cves'>🔍 CVEs</a>" if "cves" in scans and scans["cves"].findings else ""}
  {"<a href='#scenarios' style='color:#a78bfa'>🎯 Scenario Intel</a>" if "scenarios" in scans and scans["scenarios"].findings else ""}
  {"<a href='#tools'>🔧 Tools</a>" if report.tool_status else ""}
  <a href="#compliance">📋 OWASP Compliance</a>
  <a href="#attack-graph">🕸️ Attack Graph</a>
  <a href="#assets">Asset Inventory</a>
</nav>
<main>

<!-- Header -->
<header>
<pre class="ascii-art">
 █     █░▓█████  ▄▄▄▄    ██▀███   ██▓ ██▓███   ██▓███  ▓█████  ██▀███
▓█░ █ ░█░▓█   ▀ ▓█████▄ ▓██ ▒ ██▒▓██▒▓██░  ██▒▓██░  ██▒▓█   ▀ ▓██ ▒ ██▒
▒█░ █ ░█ ▒███   ▒██▒ ▄██▓██ ░▄█ ▒▒██▒▓██░ ██▓▒▓██░ ██▓▒▒███   ▓██ ░▄█ ▒
░█░ █ ░█ ▒▓█  ▄ ▒██░█▀  ▒██▀▀█▄  ░██░▒██▄█▓▒ ▒▒██▄█▓▒ ▒▒▓█  ▄ ▒██▀▀█▄
░░██▒██▓ ░▒████▒░▓█  ▀█▓░██▓ ▒██▒░██░▒██▒ ░  ░▒██▒ ░  ░░▒████▒░██▓ ▒██▒
░ ▓░▒ ▒  ░░ ▒░ ░░▒▓███▀▒░ ▒▓ ░▒▓░░▓  ▒▓▒░ ░  ░▒▓▒░ ░  ░░░ ▒░ ░░ ▒▓ ░▒▓░
  ▒ ░ ░   ░ ░  ░▒░▒   ░   ░▒ ░ ▒░ ▒ ░░▒ ░     ░▒ ░      ░ ░  ░  ░▒ ░ ▒░
            R   E   C   O   N
</pre>
<div class="header-info">
  <div class="target">Target: <span class="mono">{_esc(report.url)}</span></div>
  <div class="timestamp">Scan: {_esc(report.start_time)} → {_esc(report.end_time)}</div>
  <div class="grade" style="background: {_GRADE_COLORS.get(report.risk_score, '#666')}">
    {_esc(report.risk_score)}
  </div>
</div>
</header>

<!-- Executive Summary -->
<section id="summary">
<h2>Executive Summary</h2>
<div class="severity-badges">
  {_badge("CRITICAL", severity_counts.get("CRITICAL", 0))}
  {_badge("HIGH", severity_counts.get("HIGH", 0))}
  {_badge("MEDIUM", severity_counts.get("MEDIUM", 0))}
  {_badge("LOW", severity_counts.get("LOW", 0))}
  {_badge("INFO", severity_counts.get("INFO", 0))}
</div>
<div class="stats-grid">
  <div class="stat"><div class="stat-num">{report.rip_report.pages_crawled if report.rip_report else 0}</div><div class="stat-label">Pages Crawled</div></div>
  <div class="stat"><div class="stat-num">{report.rip_report.total_downloaded if report.rip_report else 0}</div><div class="stat-label">Files Downloaded</div></div>
  <div class="stat"><div class="stat-num">{_format_size(report.rip_report.total_size) if report.rip_report else "0 B"}</div><div class="stat-label">Total Size</div></div>
  <div class="stat"><div class="stat-num">{len(report.scan_results)}</div><div class="stat-label">Scans Run</div></div>
  <div class="stat"><div class="stat-num">{len(findings)}</div><div class="stat-label">Total Findings</div></div>
  <div class="stat"><div class="stat-num">{len(report.attack_chains)}</div><div class="stat-label">Attack Chains</div></div>
</div>
{f'''
<div class="ai-summary-card" style="margin-top: 1.5rem; padding: 1.2rem; background: rgba(0, 255, 170, 0.05); border-left: 4px solid #00ffaa; border-radius: 4px;">
  <h3 style="color: #00ffaa; margin-top: 0; display: flex; align-items: center; gap: 8px;">
    🤖 AI Security Analyst — Executive Narrative & Threat Assessment
  </h3>
  <div style="line-height: 1.6; font-size: 0.95rem; color: #ddd;">
    {_esc(report.ai_summary).replace(chr(10), "<br>")}
  </div>
</div>
''' if getattr(report, "ai_summary", "") else ""}
</section>
"""

    # Security Headers section
    if "headers" in scans:
        sr = scans["headers"]
        grade = sr.metadata.get("overall_grade", "N/A")
        grade_str = _esc(grade)
        html += f"""
<section id="headers">
<h2>Security Headers <span class="grade-inline" style="background:{_GRADE_COLORS.get(grade, '#666')}">{grade_str}</span></h2>
<table>
<thead><tr><th>Severity</th><th>Header / Issue</th><th>Details</th><th>Remediation</th></tr></thead>
<tbody>
"""
        for f in sorted(sr.findings, key=lambda x: x.severity.weight, reverse=True):
            evidence_html = f"<code>{_esc(f.evidence)}</code>" if f.evidence else ""
            html += f"<tr><td>{_sev_badge(f.severity)}</td><td><strong>{_esc(f.title)}</strong></td><td>{_esc(f.description)}{' — ' + evidence_html if evidence_html else ''}</td><td class='remediation'>{_esc(f.remediation)}</td></tr>\n"
        html += "</tbody></table></section>\n"

    # Tech Stack section
    if "tech" in scans:
        sr = scans["tech"]
        html += '<section id="tech"><h2>Technology Stack</h2><div class="tech-grid">\n'
        by_cat: Dict[str, List[Finding]] = {}
        for f in sr.findings:
            cat = f.metadata.get("category", "Other")
            by_cat.setdefault(cat, []).append(f)
        for cat in sorted(by_cat.keys()):
            html += f'<div class="tech-category"><h3>{_esc(cat)}</h3><ul>'
            for f in by_cat[cat]:
                icon = "⚠️ " if f.severity != Severity.INFO else ""
                evidence_text = f.evidence if f.evidence else ""
                html += f"<li>{icon}<strong>{_esc(f.title)}</strong><br><code class='evidence'>{_esc(evidence_text)}</code></li>"
            html += "</ul></div>"
        html += "</div></section>\n"

    # Secrets section — FULL DETAIL, NO REDACTION
    if "secrets" in scans:
        sr = scans["secrets"]
        html += f"""
<section id="secrets">
<h2>Secrets & Leaks ({len(sr.findings)})</h2>
<p class="section-note">⚠️ All evidence shown unredacted for pentesting use. Handle this report securely.</p>
<table class="wide-table">
<thead><tr><th>Severity</th><th>Type</th><th>File</th><th>Line</th><th>Evidence</th><th>Context</th><th>Remediation</th></tr></thead>
<tbody>
"""
        for f in sorted(sr.findings, key=lambda x: x.severity.weight, reverse=True):
            fname = os.path.basename(f.file_path) if f.file_path else ""
            full_path = f.file_path or ""
            context = f.metadata.get("context", "")
            html += (
                f"<tr>"
                f"<td>{_sev_badge(f.severity)}</td>"
                f"<td>{_esc(f.title)}</td>"
                f"<td class='mono' title='{_esc(full_path)}'>{_esc(fname)}</td>"
                f"<td>{f.line_number}</td>"
                f"<td><code class='evidence'>{_esc(f.evidence)}</code></td>"
                f"<td class='mono context-cell'>{_esc(context[:200])}</td>"
                f"<td class='remediation'>{_esc(f.remediation)}</td>"
                f"</tr>\n"
            )
        html += "</tbody></table></section>\n"

    # Exposed Paths section — FULL URLs, status, content-type, size, remediation
    if "paths" in scans:
        sr = scans["paths"]
        html += f"""
<section id="paths">
<h2>Exposed Paths ({len(sr.findings)})</h2>
<table class="wide-table">
<thead><tr><th>Severity</th><th>Path</th><th>Full URL</th><th>Status</th><th>Content-Type</th><th>Size</th><th>Description</th><th>Remediation</th></tr></thead>
<tbody>
"""
        for f in sorted(sr.findings, key=lambda x: x.severity.weight, reverse=True):
            status = f.metadata.get("status_code", "")
            ct = f.metadata.get("content_type", "")
            cl = f.metadata.get("content_length", 0)
            full_url = f.url or ""
            size_str = _format_size(cl) if cl else ""
            redir = f.metadata.get("response_url", "")
            desc = f.description
            if redir:
                desc += f" → Redirects to: {redir}"
            html += (
                f"<tr>"
                f"<td>{_sev_badge(f.severity)}</td>"
                f"<td class='mono'><strong>{_esc(f.title)}</strong></td>"
                f"<td class='mono'><a href='{_safe_href(full_url)}' target='_blank' rel='noopener noreferrer'>{_esc(full_url)}</a></td>"
                f"<td class='status-{_esc(status)}'>{_esc(status)}</td>"
                f"<td class='mono'>{_esc(ct)}</td>"
                f"<td>{size_str}</td>"
                f"<td>{_esc(desc)}</td>"
                f"<td class='remediation'>{_esc(f.remediation)}</td>"
                f"</tr>\n"
            )
        html += "</tbody></table></section>\n"

    # API Endpoints section — full detail
    if "endpoints" in scans:
        sr = scans["endpoints"]
        html += f"""
<section id="endpoints">
<h2>API Endpoints ({len(sr.findings)})</h2>
<table class="wide-table">
<thead><tr><th>Method</th><th>Path / URL</th><th>Source File(s)</th><th>Evidence</th></tr></thead>
<tbody>
"""
        for f in sr.findings:
            method = f.metadata.get("method", "UNKNOWN")
            sources = f.metadata.get("source_files", [])
            sources_str = ", ".join(os.path.basename(s) for s in sources[:5])
            if len(sources) > 5:
                sources_str += f" +{len(sources) - 5} more"
            method_class = f"method-{method.lower()}" if method in ("GET", "POST", "PUT", "DELETE", "PATCH") else ""
            evidence = f.evidence or ""
            html += (
                f"<tr>"
                f"<td><span class='method {method_class}'>{_esc(method)}</span></td>"
                f"<td class='mono'><strong>{_esc(f.title)}</strong></td>"
                f"<td class='mono'>{_esc(sources_str)}</td>"
                f"<td class='mono evidence-cell'><code>{_esc(evidence[:150])}</code></td>"
                f"</tr>\n"
            )
        html += "</tbody></table></section>\n"

    # Asset Inventory — show full file paths
    if report.rip_report and report.rip_report.files:
        by_type: Dict[str, List] = {}
        for f in report.rip_report.files:
            if f.error:
                continue
            ext = os.path.splitext(f.local_path or f.url)[1].lower() or ".other"
            by_type.setdefault(ext, []).append(f)

        html += """
<section id="assets">
<h2>Asset Inventory</h2>
"""
        for ext in sorted(by_type.keys()):
            files = by_type[ext]
            total = sum(f.size for f in files)
            html += f"""<details><summary>{_esc(ext)} — {len(files)} files ({_format_size(total)})</summary><table class="asset-table">
<thead><tr><th>File</th><th>URL</th><th>Size</th><th>Content-Type</th></tr></thead><tbody>"""
            for f in files[:100]:
                fname = os.path.basename(f.local_path or f.url)
                html += (
                    f"<tr>"
                    f"<td class='mono'>{_esc(fname)}</td>"
                    f"<td class='mono'><a href='{_safe_href(f.url)}' target='_blank' rel='noopener noreferrer'>{_esc(f.url[:80])}</a></td>"
                    f"<td>{_format_size(f.size)}</td>"
                    f"<td class='mono'>{_esc(f.content_type[:40])}</td>"
                    f"</tr>\n"
                )
            if len(files) > 100:
                html += f"<tr><td colspan='4' class='dim'>... and {len(files) - 100} more files</td></tr>"
            html += "</tbody></table></details>\n"
        html += "</section>\n"

    # Generic scanner sections for new v4.0 and v5.0 scanners
    for scanner_name, section_id, section_title in [
        ("cors", "cors", "CORS Misconfiguration"),
        ("javascript", "javascript", "JavaScript Security"),
        ("forms", "forms", "Form Vulnerabilities"),
        ("tls", "tls", "TLS/SSL Analysis"),
        ("cookies", "cookies", "Cookie Security"),
        ("subdomains", "subdomains", "Subdomain Discovery"),
        ("portscan", "portscan", "Port Scan"),
        ("waf", "waf", "Web Application Firewall (WAF)"),
        ("dns", "dns", "DNS & Domain Intelligence"),
        ("emails", "emails", "Harvested Email Addresses"),
        ("screenshots", "screenshots", "Captured Screenshots"),
        ("github_dork", "github_dork", "GitHub Recon & Leaks"),
        ("nmap", "nmap", "nmap Results"),
        ("nikto", "nikto", "nikto Results"),
        ("nuclei", "nuclei", "nuclei Results"),
        ("gobuster", "gobuster", "gobuster Results"),
        ("sslscan", "sslscan", "sslscan Results"),
        ("external_tools", "ext-tools", "External Tool Findings"),
    ]:
        if scanner_name in scans:
            sr = scans[scanner_name]
            if not sr.findings:
                continue
            html += f'<section id="{section_id}"><h2>{_esc(section_title)} ({len(sr.findings)})</h2>\n'
            html += '<table class="wide-table"><thead><tr><th>Severity</th><th>Finding</th><th>Evidence</th><th>How an Attacker Exploits This</th><th>Impact</th><th>Remediation</th><th>Ref</th></tr></thead><tbody>\n'
            for f in sorted(sr.findings, key=lambda x: x.severity.weight, reverse=True):
                exploit_text = f.metadata.get("exploit", "")
                impact_text = f.metadata.get("impact", "")
                cwe = f.metadata.get("cwe", "")
                owasp = f.metadata.get("owasp", "")
                ref_parts = []
                if cwe:
                    ref_parts.append(_esc(cwe))
                if owasp:
                    ref_parts.append(_esc(owasp))
                ref_str = "<br>".join(ref_parts)
                html += (
                    f"<tr>"
                    f"<td>{_sev_badge(f.severity)}</td>"
                    f"<td><strong>{_esc(f.title)}</strong><br><span class='dim'>{_esc(f.description[:200])}</span></td>"
                    f"<td><code class='evidence'>{_esc(f.evidence[:300])}</code></td>"
                    f"<td class='exploit-cell'>{_esc(exploit_text[:400])}</td>"
                    f"<td class='impact-cell'>{_esc(impact_text[:200])}</td>"
                    f"<td class='remediation'>{_esc(f.remediation)}</td>"
                    f"<td class='dim mono' style='font-size:10px'>{ref_str}</td>"
                    f"</tr>\n"
                )
            html += '</tbody></table></section>\n'

    # Verified Vulnerabilities — special highlighted section
    if "vulns" in scans and scans["vulns"].findings:
        sr = scans["vulns"]
        verified_count = sum(1 for f in sr.findings if getattr(f, 'confidence', '') == 'VERIFIED')
        likely_count = sum(1 for f in sr.findings if getattr(f, 'confidence', '') == 'LIKELY')
        html += f"""
<section id="vulns" style="border:2px solid #dc2626;border-radius:8px;padding:16px;margin:20px 0">
<h2 style="color:#dc2626">⚡ Active Vulnerability Testing ({len(sr.findings)} found: {verified_count} verified, {likely_count} likely)</h2>
<p style="color:#9ca3af">These findings were confirmed by sending actual payloads and analyzing the server's response.</p>
<table class="wide-table">
<thead><tr><th>Severity</th><th>Confidence</th><th>CVSS</th><th>Vulnerability</th><th>Parameter</th><th>Evidence</th><th>Exploit Steps</th><th>Remediation</th></tr></thead>
<tbody>
"""
        for f in sorted(sr.findings, key=lambda x: x.severity.weight, reverse=True):
            param = f.metadata.get("parameter", "")
            exploit_text = f.metadata.get("exploit", "")
            html += (
                f"<tr>"
                f"<td>{_sev_badge(f.severity)}</td>"
                f"<td>{_conf_badge(f)}</td>"
                f"<td>{_cvss_badge(f)}</td>"
                f"<td><strong>{_esc(f.title)}</strong><br><span class='dim'>{_esc(f.description[:200])}</span></td>"
                f"<td class='mono'>{_esc(param)}</td>"
                f"<td><code class='evidence'>{_esc(f.evidence[:300])}</code></td>"
                f"<td class='exploit-cell'>{_esc(exploit_text[:400])}</td>"
                f"<td class='remediation'>{_esc(f.remediation)}</td>"
                f"</tr>\n"
            )
        html += '</tbody></table></section>\n'

    # Known CVEs section
    if "cves" in scans and scans["cves"].findings:
        sr = scans["cves"]
        html += f"""
<section id="cves">
<h2>🔍 Known CVEs ({len(sr.findings)})</h2>
<p style="color:#9ca3af">Libraries with known vulnerabilities detected in the target's codebase.</p>
<table class="wide-table">
<thead><tr><th>Severity</th><th>CVSS</th><th>CVE ID</th><th>Library</th><th>Description</th><th>Fix</th></tr></thead>
<tbody>
"""
        for f in sorted(sr.findings, key=lambda x: x.severity.weight, reverse=True):
            cvss_score = f.metadata.get("cvss_score", 0)
            fix_ver = f.metadata.get("fix_version", "")
            lib = f.metadata.get("library", "")
            det_ver = f.metadata.get("detected_version", "")
            cve_id = f.title.split(":")[0] if ":" in f.title else f.title
            html += (
                f"<tr>"
                f"<td>{_sev_badge(f.severity)}</td>"
                f"<td>{_cvss_badge(f)}</td>"
                f"<td class='mono'><a href='https://nvd.nist.gov/vuln/detail/{_esc(cve_id)}' target='_blank'>{_esc(cve_id)}</a></td>"
                f"<td class='mono'>{_esc(lib)} {_esc(det_ver)}</td>"
                f"<td>{_esc(f.description[:200])}</td>"
                f"<td class='mono' style='color:#22c55e'>→ {_esc(fix_ver)}</td>"
                f"</tr>\n"
            )
        html += '</tbody></table></section>\n'

    # Scenario Intelligence section (Scanner #21)
    if "scenarios" in scans and scans["scenarios"].findings:
        sr = scans["scenarios"]
        html += f"""
<section id="scenarios" style="border:2px solid #8b5cf6;border-radius:8px;padding:16px;margin:20px 0;background:#0f172a">
<h2 style="color:#a78bfa">🎯 Scenario Intelligence & Real-World Precedents ({len(sr.findings)})</h2>
<p style="color:#94a3b8">Targeted verification probes matching detected technology fingerprints, cross-referenced with 30,000+ HackerOne disclosures and CISA KEV active exploits.</p>
<table class="wide-table">
<thead><tr><th>Severity</th><th>CVSS</th><th>Scenario / ID</th><th>Precedent & Payout</th><th>Target Probe</th><th>Author Insight</th><th>Remediation</th><th>PoC cURL</th></tr></thead>
<tbody>
"""
        for f in sorted(sr.findings, key=lambda x: x.severity.weight, reverse=True):
            bounty_ref = f.metadata.get("bounty_reference", "")
            sc_id = f.metadata.get("scenario_id", "")
            insight = f.metadata.get("author_insight", f.description[:200])
            poc_curl = f.poc_curl
            curl_cell = f"<details><summary style='cursor:pointer;color:#a78bfa'>PoC Command</summary><pre class='cmd-block' style='font-size:11px;margin-top:4px'>{_esc(poc_curl)}</pre></details>" if poc_curl else ""
            sc_badge = f"<br><span class='dim mono' style='font-size:10px'>{_esc(sc_id)}</span>" if sc_id else ""
            html += (
                f"<tr>"
                f"<td>{_sev_badge(f.severity)}</td>"
                f"<td>{_cvss_badge(f)}</td>"
                f"<td><strong>{_esc(f.title)}</strong>{sc_badge}</td>"
                f"<td><span style='color:#38bdf8'>{_esc(bounty_ref)}</span></td>"
                f"<td class='mono'><a href='{_safe_href(f.url)}' target='_blank' rel='noopener noreferrer'>{_esc(f.url)}</a></td>"
                f"<td class='exploit-cell'>{_esc(insight[:300])}</td>"
                f"<td class='remediation'>{_esc(f.remediation)}</td>"
                f"<td>{curl_cell}</td>"
                f"</tr>\n"
            )
        html += '</tbody></table></section>\n'

    # Attack Chains section
    if report.attack_chains:
        html += '<section id="chains"><h2>⚡ Attack Chains</h2>\n'
        html += '<p class="section-note">These are multi-step attack paths detected by correlating findings across all scanners. Each chain shows how individual vulnerabilities combine into a more dangerous attack.</p>\n'
        for i, chain in enumerate(report.attack_chains, 1):
            html += f'<div class="chain-card"><div class="chain-header"><span class="chain-num">CHAIN #{i}</span> {_sev_badge(chain.severity)} <strong>{_esc(chain.name)}</strong></div>\n'
            html += '<div class="chain-steps">\n'
            for j, step in enumerate(chain.steps, 1):
                source_tag = f" <span class='dim'>[{_esc(step.source)}]</span>" if step.source else ""
                html += f'<div class="chain-step"><span class="step-num">{j}</span> {_esc(step.description)}{source_tag}</div>\n'
                if step.command:
                    html += f'<div class="chain-cmd"><code>{_esc(step.command)}</code></div>\n'
            html += '</div>\n'
            html += f'<div class="chain-meta"><strong>Impact:</strong> {_esc(chain.impact)}</div>\n'
            html += f'<div class="chain-meta"><strong>Time to exploit:</strong> {_esc(chain.time_to_exploit)}</div>\n'
            html += f'<div class="chain-meta"><strong>Fix:</strong> {_esc(chain.remediation)}</div>\n'
            html += '</div>\n'
        html += '</section>\n'

    # Tool Status & Commands section
    if report.tool_status:
        html += '<section id="tools"><h2>🔧 External Tools</h2>\n'
        html += '<table><thead><tr><th>Tool</th><th>Status</th><th>Version</th><th>Path</th></tr></thead><tbody>\n'
        for t in report.tool_status:
            status_str = f"<span style='color:#44aa44'>● INSTALLED</span>" if t.installed else f"<span style='color:#ff6600'>○ Not installed</span>{' (downloadable)' if t.installable else ''}"
            html += f"<tr><td><strong>{_esc(t.name)}</strong></td><td>{status_str}</td><td class='mono'>{_esc(t.version)}</td><td class='mono dim'>{_esc(t.path[:80])}</td></tr>\n"
        html += '</tbody></table>\n'

        if report.tool_commands:
            html += '<h3 style="margin-top:20px">Manual Commands (copy & paste)</h3>\n'
            html += '<p class="dim">These commands are auto-generated based on scan findings. Run them manually for deeper analysis.</p>\n'
            for tool_name, cmd in report.tool_commands.items():
                html += f'<details><summary>{_esc(tool_name)}</summary><pre class="cmd-block">{_esc(cmd)}</pre></details>\n'
        html += '</section>\n'

    # OWASP Top 10 Compliance Dashboard
    html += _build_owasp_compliance(findings)

    # D3.js Interactive Attack Graph
    html += _build_attack_graph(findings, report.attack_chains)

    html += """
<!-- PDF Export Button -->
<button id="pdf-btn" onclick="window.print()" title="Export as PDF">
  📄 Export PDF
</button>

<footer>
  <p>Generated by WebRipper Recon 5.0 — Active/passive reconnaissance & attack surface analysis</p>
  <p class="dim">⚠️ This report contains unredacted security findings. Handle with appropriate care.</p>
</footer>
</main>
</body>
</html>"""

    return html


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------

def generate_json_report(report: ReconReport) -> str:
    """Generate JSON report."""
    return report.to_json(indent=2)


# ---------------------------------------------------------------------------
# Save reports
# ---------------------------------------------------------------------------

def save_report(report: ReconReport, output_dir: str) -> Tuple[str, str]:
    """Save HTML and JSON reports to the output directory."""
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        html_path = os.path.join(output_dir, "recon_report.html")
        json_path = os.path.join(output_dir, "recon_report.json")
    else:
        html_path = "recon_report.html"
        json_path = "recon_report.json"

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(generate_html_report(report))

    with open(json_path, "w", encoding="utf-8") as f:
        f.write(generate_json_report(report))

    return html_path, json_path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

import html


def _esc(text: Any) -> str:
    """HTML-escape a string, escaping quotes for attribute safety."""
    if text is None:
        return ""
    return html.escape(str(text), quote=True)


def _safe_href(url: Optional[str]) -> str:
    """Ensure URL uses http/https scheme before placing in an href attribute."""
    if not url:
        return "#"
    clean = str(url).strip()
    if clean.lower().startswith(("http://", "https://")):
        return _esc(clean)
    return "#"


def _count_severities(findings: List[Finding]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    return counts


def _badge(severity: str, count: int) -> str:
    color = _SEVERITY_COLORS.get(severity, "#666")
    return f'<span class="badge" style="background:{color}">{severity}: {count}</span>'


def _sev_badge(severity: Severity) -> str:
    sev_val = severity.value if hasattr(severity, "value") else str(severity)
    color = _SEVERITY_COLORS.get(sev_val, "#666")
    return f'<span class="sev-tag" style="background:{color}">{_esc(sev_val)}</span>'


def _cvss_badge(finding: Finding) -> str:
    """Generate a CVSS score badge for a finding."""
    cs = score_finding(finding)
    if cs.score >= 9.0:
        cls = "cvss-critical"
    elif cs.score >= 7.0:
        cls = "cvss-high"
    elif cs.score >= 4.0:
        cls = "cvss-medium"
    elif cs.score > 0:
        cls = "cvss-low"
    else:
        return ""
    return f'<span class="cvss-badge {cls}">{cs.score}</span>'


def _conf_badge(finding: Finding) -> str:
    """Generate a confidence badge (VERIFIED/LIKELY/POSSIBLE)."""
    conf = getattr(finding, 'confidence', 'POSSIBLE') or 'POSSIBLE'
    colors = {
        "VERIFIED": "#22c55e",   # green
        "LIKELY": "#f59e0b",     # amber
        "POSSIBLE": "#6b7280",   # gray
        "INFO": "#3b82f6",       # blue
    }
    color = colors.get(str(conf).upper(), "#6b7280")
    return f'<span class="conf-badge" style="background:{color};color:#fff;padding:2px 6px;border-radius:3px;font-size:0.7em;font-weight:bold">{_esc(conf)}</span>'


def _build_owasp_compliance(findings: List[Finding]) -> str:
    """Build OWASP Top 10 (2021) compliance dashboard section."""
    owasp_map = {
        "A01:2021": {"name": "Broken Access Control", "findings": [], "rec": "Enforce least privilege, implement proper access controls, deny by default"},
        "A02:2021": {"name": "Cryptographic Failures", "findings": [], "rec": "Use strong encryption, enforce HTTPS, secure key management"},
        "A03:2021": {"name": "Injection", "findings": [], "rec": "Use parameterized queries, validate/sanitize all input, escape output"},
        "A04:2021": {"name": "Insecure Design", "findings": [], "rec": "Use threat modeling, secure design patterns, reference architecture"},
        "A05:2021": {"name": "Security Misconfiguration", "findings": [], "rec": "Harden configs, remove defaults, automate security configuration"},
        "A06:2021": {"name": "Vulnerable Components", "findings": [], "rec": "Inventory components, monitor CVEs, update regularly"},
        "A07:2021": {"name": "Auth Failures", "findings": [], "rec": "Implement MFA, rate limiting, credential stuffing protection"},
        "A08:2021": {"name": "Software Integrity", "findings": [], "rec": "Use digital signatures, verify integrity, secure CI/CD pipeline"},
        "A09:2021": {"name": "Logging & Monitoring", "findings": [], "rec": "Log security events, implement alerting, establish incident response"},
        "A10:2021": {"name": "SSRF", "findings": [], "rec": "Validate URLs server-side, use allowlists, segment network access"},
    }
    for f in findings:
        owasp = (f.metadata or {}).get("owasp", "")
        for code in owasp_map:
            if code in str(owasp):
                owasp_map[code]["findings"].append(f)

    html = '<section id="compliance">\n<h2>OWASP Top 10 Compliance</h2>\n'
    html += '<table class="compliance-table">\n'
    html += '<tr><th>Category</th><th>Status</th><th>Findings</th><th>Worst</th><th>Recommendation</th></tr>\n'
    pass_count = 0
    for code, info in owasp_map.items():
        count = len(info["findings"])
        if count == 0:
            status = '<span class="compliance-status status-pass">PASS</span>'
            worst = "-"
            pass_count += 1
        else:
            worst_sev = max(info["findings"], key=lambda x: x.severity.weight).severity.value
            if worst_sev in ("CRITICAL", "HIGH"):
                status = '<span class="compliance-status status-fail">FAIL</span>'
            else:
                status = '<span class="compliance-status status-warn">WARN</span>'
            worst = f'<span class="sev-tag" style="background:{_SEVERITY_COLORS.get(worst_sev, "#666")};font-size:11px">{_esc(worst_sev)}</span>'
        html += f'<tr><td><strong>{_esc(code)}</strong> {_esc(info["name"])}</td><td>{status}</td>'
        html += f'<td>{count}</td><td>{worst}</td><td class="dim">{_esc(info["rec"])}</td></tr>\n'
    total = len(owasp_map)
    pct = int(pass_count / total * 100)
    color = "#44aa44" if pct >= 70 else ("#ffaa00" if pct >= 40 else "#ff4444")
    html += f'</table>\n<div style="text-align:center;margin:16px 0;font-size:18px;font-weight:700">'
    html += f'OWASP Score: <span style="color:{color}">{pct}%</span> ({pass_count}/{total} passing)</div>\n'

    # PCI DSS 4.0 compliance
    pci_map = {
        "1": {"name": "Network Security Controls", "cats": ["portscan", "waf", "subdomains"], "rec": "Install and maintain network security controls (firewalls, WAF)"},
        "2": {"name": "Secure Configurations", "cats": ["headers", "paths", "tls"], "rec": "Apply secure configurations to all system components"},
        "3": {"name": "Protect Stored Data", "cats": ["secrets"], "rec": "Protect stored account data with encryption"},
        "4": {"name": "Encrypt Transmissions", "cats": ["tls", "cookies"], "rec": "Protect cardholder data with strong cryptography during transmission"},
        "5": {"name": "Malware Protection", "cats": ["tech"], "rec": "Protect systems from malware with regularly updated anti-malware"},
        "6": {"name": "Secure Development", "cats": ["forms", "endpoints", "javascript", "cors"], "rec": "Develop and maintain secure systems and software"},
        "7": {"name": "Restrict Access", "cats": ["paths", "endpoints"], "rec": "Restrict access to cardholder data by business need-to-know"},
        "8": {"name": "Identify & Auth Users", "cats": ["secrets", "cookies"], "rec": "Identify users and authenticate access to system components"},
    }
    html += '<h3 style="margin-top:24px">PCI DSS 4.0 Compliance</h3>\n'
    html += '<table class="compliance-table">\n'
    html += '<tr><th>Req</th><th>Status</th><th>Findings</th><th>Worst</th><th>Recommendation</th></tr>\n'
    pci_pass = 0
    for req, info in pci_map.items():
        matched = [f for f in findings if f.category in info["cats"]]
        count = len(matched)
        if count == 0:
            status = '<span class="compliance-status status-pass">PASS</span>'
            worst = "-"
            pci_pass += 1
        else:
            ws = max(matched, key=lambda x: x.severity.weight).severity.value
            status = '<span class="compliance-status status-fail">FAIL</span>' if ws in ("CRITICAL","HIGH") else '<span class="compliance-status status-warn">WARN</span>'
            worst = f'<span class="sev-tag" style="background:{_SEVERITY_COLORS.get(ws,"#666")};font-size:11px">{_esc(ws)}</span>'
        html += f'<tr><td><strong>Req {req}</strong> {_esc(info["name"])}</td><td>{status}</td>'
        html += f'<td>{count}</td><td>{worst}</td><td class="dim">{_esc(info["rec"])}</td></tr>\n'
    pci_total = len(pci_map)
    pci_pct = int(pci_pass / pci_total * 100)
    pci_color = "#44aa44" if pci_pct >= 70 else ("#ffaa00" if pci_pct >= 40 else "#ff4444")
    html += f'</table>\n<div style="text-align:center;margin:16px 0;font-size:18px;font-weight:700">'
    html += f'PCI DSS Score: <span style="color:{pci_color}">{pci_pct}%</span> ({pci_pass}/{pci_total} passing)</div>\n'
    html += '</section>\n'
    return html


def _build_attack_graph(findings: List[Finding], attack_chains: list) -> str:
    """Build D3.js interactive attack graph section with identity mapping and referential integrity."""
    import json as _json
    import re as _re

    sev_colors = {"CRITICAL": "#ff2222", "HIGH": "#ff6600", "MEDIUM": "#ffaa00", "LOW": "#44aa44", "INFO": "#4488ff"}
    nodes = []
    node_ids = set()
    node_map = {}

    for i, f in enumerate(findings):
        clean_cat = _re.sub(r'[^a-zA-Z0-9_]', '_', str(f.category or 'finding'))
        nid = f"n_{i}_{clean_cat}"
        node_map[id(f)] = nid
        node_ids.add(nid)
        nodes.append({
            "id": nid,
            "label": f.title[:40],
            "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            "color": sev_colors.get(f.severity.value if hasattr(f.severity, "value") else str(f.severity), "#666"),
            "size": f.severity.weight if hasattr(f.severity, "weight") else 10,
            "title": f.title,
            "category": f.category
        })

    links = []
    seen_links = set()
    if attack_chains:
        for chain in attack_chains:
            cf = [step.finding for step in getattr(chain, "steps", []) if getattr(step, "finding", None) is not None]
            for j in range(len(cf) - 1):
                f1, f2 = cf[j], cf[j + 1]
                src_id = node_map.get(id(f1))
                tgt_id = node_map.get(id(f2))
                if src_id and tgt_id and src_id != tgt_id and (src_id, tgt_id) not in seen_links:
                    seen_links.add((src_id, tgt_id))
                    links.append({"source": src_id, "target": tgt_id})

    # Preserve attack chain participants when truncating large node sets (>100)
    chain_node_ids = {l["source"] for l in links} | {l["target"] for l in links}
    if len(nodes) > 100:
        so = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        chain_nodes = [n for n in nodes if n["id"] in chain_node_ids]
        other_nodes = [n for n in nodes if n["id"] not in chain_node_ids]
        other_nodes.sort(key=lambda n: so.get(n["severity"], 5))
        remaining_slots = max(0, 100 - len(chain_nodes))
        nodes = chain_nodes + other_nodes[:remaining_slots]

    # Always enforce strict referential integrity
    valid_ids = {n["id"] for n in nodes}
    links = [l for l in links if l["source"] in valid_ids and l["target"] in valid_ids and l["source"] != l["target"]]

    gd = _json.dumps({"nodes": nodes, "links": links})
    # Safe JSON-in-script escaping: escape </ to <\/ (prevents HTML tag closing), and line/paragraph separators
    gd_safe = (
        gd.replace("</", "<\\/")
          .replace("\u2028", "\\u2028")
          .replace("\u2029", "\\u2029")
    )

    return f'''<section id="attack-graph">
<h2>Attack Graph</h2>
<p class="dim">Interactive visualization — nodes colored by severity, connected by attack chains. Drag to rearrange, hover for details.</p>
<div id="attack-graph-canvas"></div>
<script src="https://d3js.org/d3.v7.min.js"></script>
<script>
(function(){{
  function escHtml(str){{
    if(!str) return '';
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  }}
  function sanitizeColor(c){{
    return (/^#[0-9a-fA-F]{{3,8}}$/.test(c)) ? c : '#666';
  }}
  const d={gd_safe};
  if(!d.nodes.length)return;
  const c=document.getElementById('attack-graph-canvas'),w=c.clientWidth||900,h=500;
  const s=d3.select('#attack-graph-canvas').append('svg').attr('width',w).attr('height',h).style('background','#0d1117');
  const sim=d3.forceSimulation(d.nodes).force('link',d3.forceLink(d.links).id(n=>n.id).distance(80)).force('charge',d3.forceManyBody().strength(-200)).force('center',d3.forceCenter(w/2,h/2)).force('collision',d3.forceCollide().radius(n=>Math.max(8,n.size/2+5)));
  const lnk=s.append('g').selectAll('line').data(d.links).join('line').attr('stroke','#333').attr('stroke-width',1.5);
  const nd=s.append('g').selectAll('circle').data(d.nodes).join('circle').attr('r',n=>Math.max(6,n.size/3)).attr('fill',n=>n.color).attr('stroke','#fff').attr('stroke-width',1).style('cursor','pointer').call(d3.drag().on('start',(e)=>{{if(!e.active)sim.alphaTarget(.3).restart();e.subject.fx=e.subject.x;e.subject.fy=e.subject.y}}).on('drag',(e)=>{{e.subject.fx=e.x;e.subject.fy=e.y}}).on('end',(e)=>{{if(!e.active)sim.alphaTarget(0);e.subject.fx=null;e.subject.fy=null}}));
  const lb=s.append('g').selectAll('text').data(d.nodes).join('text').text(n=>n.label.length>20?n.label.substring(0,20)+'...':n.label).attr('font-size','9px').attr('fill','#888').attr('dx',12).attr('dy',4);
  const tt=d3.select('body').append('div').attr('class','graph-tooltip').style('opacity',0);
  nd.on('mouseover',function(e,n){{
    tt.transition().duration(200).style('opacity',1);
    tt.html('<strong style="color:'+sanitizeColor(n.color)+'">'+escHtml(n.severity)+'</strong> '+escHtml(n.title)+'<br><span style="color:#888">'+escHtml(n.category)+'</span>').style('left',(e.pageX+10)+'px').style('top',(e.pageY-10)+'px');
  }}).on('mouseout',function(){{
    tt.transition().duration(300).style('opacity',0);
  }});
  sim.on('tick',()=>{{lnk.attr('x1',d=>d.source.x).attr('y1',d=>d.source.y).attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);nd.attr('cx',d=>d.x=Math.max(10,Math.min(w-10,d.x))).attr('cy',d=>d.y=Math.max(10,Math.min(h-10,d.y)));lb.attr('x',d=>d.x).attr('y',d=>d.y)}});
}})();
</script>
</section>
'''


# ---------------------------------------------------------------------------
# Embedded CSS
# ---------------------------------------------------------------------------

_CSS = """
:root {
  --bg: #0a0a0a;
  --bg2: #111;
  --bg3: #1a1a1a;
  --fg: #e0e0e0;
  --fg2: #999;
  --border: #2a2a2a;
  --accent: #4488ff;
}

* { margin:0; padding:0; box-sizing:border-box; }

body {
  background: var(--bg);
  color: var(--fg);
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  font-size: 14px;
  line-height: 1.6;
  display: flex;
}

.sidebar {
  position: fixed;
  top: 0; left: 0;
  width: 200px;
  height: 100vh;
  background: var(--bg2);
  border-right: 1px solid var(--border);
  padding: 20px 0;
  overflow-y: auto;
  z-index: 10;
}

.nav-title {
  padding: 8px 16px;
  font-size: 11px;
  letter-spacing: 2px;
  color: var(--fg2);
  text-transform: uppercase;
}

.sidebar a {
  display: block;
  padding: 8px 16px;
  color: var(--fg);
  text-decoration: none;
  border-left: 3px solid transparent;
  transition: all 0.2s;
}

.sidebar a:hover {
  background: var(--bg3);
  border-left-color: var(--accent);
  color: white;
}

main {
  margin-left: 200px;
  padding: 40px;
  max-width: 1400px;
  width: 100%;
}

header { margin-bottom: 40px; }

.ascii-art {
  color: var(--accent);
  font-size: 8px;
  line-height: 1.1;
  margin-bottom: 20px;
  overflow-x: auto;
}

.header-info {
  display: flex;
  align-items: center;
  gap: 20px;
  flex-wrap: wrap;
}

.target { font-size: 18px; font-weight: 600; }
.timestamp { color: var(--fg2); font-size: 13px; }

.grade {
  font-size: 36px;
  font-weight: 800;
  width: 60px;
  height: 60px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 12px;
  color: #fff;
  margin-left: auto;
}

.grade-inline {
  font-size: 14px;
  font-weight: 700;
  padding: 2px 8px;
  border-radius: 4px;
  color: #fff;
  vertical-align: middle;
}

section {
  margin-bottom: 40px;
  padding-bottom: 20px;
  border-bottom: 1px solid var(--border);
}

.section-note {
  color: #ff6600;
  font-size: 12px;
  margin-bottom: 12px;
  padding: 6px 10px;
  background: rgba(255, 102, 0, 0.1);
  border-left: 3px solid #ff6600;
  border-radius: 2px;
}

h2 {
  font-size: 20px;
  font-weight: 600;
  margin-bottom: 16px;
  color: white;
}

h3 {
  font-size: 14px;
  font-weight: 600;
  margin-bottom: 8px;
  color: var(--accent);
  text-transform: uppercase;
  letter-spacing: 1px;
}

.severity-badges {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  margin-bottom: 20px;
}

.badge {
  padding: 6px 14px;
  border-radius: 6px;
  font-weight: 700;
  font-size: 13px;
  color: #fff;
}

.sev-tag {
  padding: 2px 8px;
  border-radius: 3px;
  font-size: 11px;
  font-weight: 700;
  color: #fff;
  white-space: nowrap;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 16px;
  margin-top: 16px;
}

.stat {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px;
  text-align: center;
}

.stat-num { font-size: 28px; font-weight: 700; color: white; }
.stat-label { font-size: 12px; color: var(--fg2); margin-top: 4px; }

table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}

.wide-table {
  display: block;
  overflow-x: auto;
  white-space: nowrap;
}

thead th {
  text-align: left;
  padding: 10px;
  background: var(--bg2);
  border-bottom: 2px solid var(--border);
  font-weight: 600;
  color: var(--fg2);
  text-transform: uppercase;
  font-size: 11px;
  letter-spacing: 1px;
  position: sticky;
  top: 0;
}

tbody td {
  padding: 8px 10px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
  max-width: 400px;
  white-space: normal;
  word-break: break-all;
}

tbody tr:hover { background: var(--bg3); }

.mono { font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace; font-size: 12px; }
.dim { color: var(--fg2); }

code.evidence {
  background: var(--bg3);
  padding: 2px 6px;
  border-radius: 3px;
  color: #ff6600;
  font-size: 12px;
  word-break: break-all;
  white-space: pre-wrap;
}

.context-cell {
  max-width: 300px;
  overflow: hidden;
  text-overflow: ellipsis;
  font-size: 11px;
  color: var(--fg2);
}

.evidence-cell {
  max-width: 250px;
}

.remediation {
  font-size: 12px;
  color: var(--fg2);
  max-width: 250px;
}

.status-200 { color: #44aa44; font-weight: 700; }
.status-301, .status-302, .status-307, .status-308 { color: #ffaa00; }
.status-403 { color: #ff6600; }
.status-404 { color: var(--fg2); }

a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

.method {
  padding: 2px 6px;
  border-radius: 3px;
  font-weight: 700;
  font-size: 11px;
  background: var(--bg2);
  border: 1px solid var(--border);
}

.method-get { color: #44aa44; border-color: #44aa44; }
.method-post { color: #4488ff; border-color: #4488ff; }
.method-put { color: #ffaa00; border-color: #ffaa00; }
.method-delete { color: #ff2222; border-color: #ff2222; }
.method-patch { color: #aa44ff; border-color: #aa44ff; }

.tech-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 16px;
}

.tech-category {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px;
}

.tech-category ul { list-style: none; }
.tech-category li { padding: 4px 0; }
.tech-category small { color: var(--fg2); }

details {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 8px;
  margin-bottom: 8px;
}

summary {
  padding: 10px 16px;
  cursor: pointer;
  font-weight: 600;
  color: white;
}

summary:hover { background: var(--bg3); }

.asset-table {
  font-size: 12px;
  margin: 0 16px 12px;
}

.asset-table td { padding: 4px 8px; }

.file-list {
  list-style: none;
  padding: 0 16px 12px;
  max-height: 300px;
  overflow-y: auto;
}

.file-list li { padding: 2px 0; font-size: 12px; }

footer {
  text-align: center;
  padding: 40px 0;
  color: var(--fg2);
  font-size: 12px;
}

.exploit-cell {
  max-width: 350px;
  font-size: 12px;
  color: #ff8844;
  white-space: normal;
  word-break: break-word;
}

.impact-cell {
  max-width: 200px;
  font-size: 12px;
  color: #ffaa00;
}

.chain-card {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-left: 4px solid #ff2222;
  border-radius: 8px;
  padding: 20px;
  margin-bottom: 16px;
}

.chain-header {
  margin-bottom: 12px;
  font-size: 16px;
}

.chain-num {
  color: var(--fg2);
  font-size: 12px;
  margin-right: 8px;
  letter-spacing: 1px;
}

.chain-steps { margin: 12px 0; }

.chain-step {
  padding: 8px 12px 8px 40px;
  position: relative;
  border-left: 2px solid var(--border);
  margin-left: 12px;
}

.chain-step::before {
  content: '';
  position: absolute;
  left: -6px;
  top: 12px;
  width: 10px;
  height: 10px;
  background: var(--accent);
  border-radius: 50%;
}

.step-num {
  position: absolute;
  left: -30px;
  top: 8px;
  color: var(--fg2);
  font-size: 11px;
  font-weight: 700;
}

.chain-cmd {
  margin: 4px 0 4px 52px;
  padding: 6px 10px;
  background: var(--bg3);
  border-radius: 4px;
  font-size: 11px;
  overflow-x: auto;
}

.chain-cmd code { color: #44aa44; white-space: pre-wrap; }

.chain-meta {
  font-size: 13px;
  margin-top: 8px;
  padding-top: 8px;
  border-top: 1px solid var(--border);
}

.cmd-block {
  background: var(--bg3);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 12px;
  font-size: 12px;
  overflow-x: auto;
  margin: 8px 16px 12px;
  color: #44aa44;
  white-space: pre-wrap;
}

@media print {
  .sidebar { display: none; }
  main { margin-left: 0; }
  body { background: #fff; color: #000; }
  .badge, .sev-tag, .grade, .grade-inline { print-color-adjust: exact; -webkit-print-color-adjust: exact; }
  section { break-inside: avoid; }
  #pdf-btn { display: none; }
  #attack-graph-canvas { display: none; }
  .compliance-table { font-size: 11px; }
}

@media (max-width: 768px) {
  .sidebar { display: none; }
  main { margin-left: 0; padding: 20px; }
}

/* PDF button */
#pdf-btn {
  position: fixed; bottom: 24px; right: 24px; z-index: 1000;
  background: #44aa44; color: #fff; border: none; border-radius: 8px;
  padding: 12px 20px; font-size: 14px; font-weight: 700; cursor: pointer;
  box-shadow: 0 4px 16px rgba(0,0,0,0.5); transition: all 0.2s;
}
#pdf-btn:hover { background: #55cc55; transform: translateY(-2px); }

/* OWASP Compliance */
.compliance-table { width: 100%; border-collapse: collapse; margin: 16px 0; }
.compliance-table th { text-align: left; padding: 10px; background: var(--bg3); border-bottom: 2px solid var(--border); font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
.compliance-table td { padding: 10px; border-bottom: 1px solid var(--border); font-size: 13px; }
.compliance-status { padding: 3px 10px; border-radius: 4px; font-weight: 700; font-size: 11px; }
.status-pass { background: #1a4a1a; color: #44aa44; }
.status-warn { background: #4a3a1a; color: #ffaa00; }
.status-fail { background: #4a1a1a; color: #ff4444; }

/* CVSS */
.cvss-badge { padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }
.cvss-critical { background: #990000; color: #fff; }
.cvss-high { background: #cc3300; color: #fff; }
.cvss-medium { background: #cc7700; color: #fff; }
.cvss-low { background: #2266aa; color: #fff; }

/* Attack graph */
#attack-graph-canvas { width: 100%; height: 500px; background: var(--bg2); border-radius: 8px; border: 1px solid var(--border); }
.graph-tooltip { position: absolute; background: var(--bg3); border: 1px solid var(--border); border-radius: 6px; padding: 10px; font-size: 12px; pointer-events: none; max-width: 300px; z-index: 100; }
"""

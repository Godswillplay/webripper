"""
CLI / Headless engine & Interactive Wizard for WebRipper Recon 5.0.

Provides dual-mode operational flexibility:
  1. Interactive Terminal Wizard for human operators (prompt-driven)
  2. Deterministic Headless Mode for AI agents (Claude Code, Antigravity, Cursor) & CI/CD
     with semantic exit codes (0=clean, 1=error, 2=critical/high, 3=target unreachable, 4=rate limited, 5=WAF blocked).
"""

from __future__ import annotations

import argparse
import os
import sys
import time
import webbrowser
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

from .models import RipperSettings, EventType, Finding


def _color(text: str, code: str) -> str:
    """Apply ANSI color code."""
    return f"\033[{code}m{text}\033[0m"


def _red(t: str) -> str: return _color(t, "91")
def _yellow(t: str) -> str: return _color(t, "93")
def _green(t: str) -> str: return _color(t, "92")
def _cyan(t: str) -> str: return _color(t, "96")
def _dim(t: str) -> str: return _color(t, "90")
def _bold(t: str) -> str: return _color(t, "1")


_BANNER = r"""
 __        __   _    ____  _                       ____                      
 \ \      / /__| |__| __ )(_)_ __  _ __   ___ _ __|  _ \ ___  ___ ___  _ __  
  \ \ /\ / / _ \ '_ \  _ \| | '_ \| '_ \ / _ \ '__| |_) / _ \/ __/ _ \| '_ \ 
   \ V  V /  __/ |_) | |_) | | |_) | |_) |  __/ |  |  _ \  __/ (_| (_) | | | |
    \_/\_/ \___|_.__/|____/|_| .__/| .__/ \___|_|  |_| \_\___|\___\___/|_| |_|
                             |_|   |_|                          v5.0 Engine  
"""


class ReconArgumentParser(argparse.ArgumentParser):
    """Custom ArgumentParser that exits with code 1 instead of 2 on syntax error."""
    def error(self, message: str):
        self.print_usage(sys.stderr)
        sys.stderr.write(f"{self.prog}: error: {message}\n")
        sys.exit(1)


def build_parser() -> argparse.ArgumentParser:
    p = ReconArgumentParser(
        prog="WebRipperRecon",
        description="WebRipper Recon 5.0 — Headless Security Reconnaissance Engine & CLI",
    )
    p.add_argument("target", nargs="?", default="", help="Target URL to scan (positional)")
    p.add_argument("--url", help="Target URL to scan")
    p.add_argument("--target", dest="target_flag", help="Target URL to scan (flag)")
    p.add_argument("--urls", help="File with one URL per line (multi-target)")
    p.add_argument("-w", "--wizard", "-i", "--interactive", dest="wizard", action="store_true", help="Launch interactive terminal wizard")
    p.add_argument("--mcp", action="store_true", help="Launch native stdio JSON-RPC 2.0 MCP server")
    p.add_argument("--headless", action="store_true", help="Explicit headless mode for AI agents and CI/CD")
    p.add_argument("--profile", choices=["quick", "standard", "aggressive"], default="standard", help="Scan intensity profile")
    p.add_argument("-o", "--output", help="Output report path (HTML file, e.g. report.html)")
    p.add_argument("--out-dir", help="Directory for downloaded assets and artifacts")
    p.add_argument("--json", dest="json_output", help="JSON output path")
    p.add_argument("--depth", type=int, default=2, help="Crawl depth (default: 2)")
    p.add_argument("--timeout", type=int, default=30, help="Per-request timeout in seconds (default: 30)")
    p.add_argument("--delay", type=float, default=0.0, help="Polite delay between requests in seconds (default: 0.0)")
    p.add_argument("--scanners", help="Comma-separated list of active scanners to run (e.g. secrets,headers,scenarios)")
    p.add_argument("--no-scenarios", action="store_true", help="Disable Scenario Intelligence (#21) canary probes")
    p.add_argument("--no-tools", action="store_true", help="Skip external tool orchestration (nmap, nuclei, etc.)")
    p.add_argument("--cookie", help="Cookie header value for authenticated scans")
    p.add_argument("--token", help="Bearer authorization token")
    p.add_argument("--identity-a-cookie", default="", help="Identity A cookie for dual-identity BOLA testing")
    p.add_argument("--identity-a-token", default="", help="Identity A bearer token for dual-identity BOLA testing")
    p.add_argument("--identity-b-cookie", default="", help="Identity B cookie for dual-identity BOLA testing")
    p.add_argument("--identity-b-token", default="", help="Identity B bearer token for dual-identity BOLA testing")
    p.add_argument("--graphql", action="store_true", help="Enable GraphQL schema and authorization auditor")
    p.add_argument("--llm", "--llmapp", dest="llmapp", action="store_true", help="Enable AI/LLM prompt injection canary scanner")
    p.add_argument("--mcp-target", dest="mcptarget", action="store_true", help="Enable MCP target auditor")
    p.add_argument("--authorized", action="store_true", help="Explicit target authorization scope for active modules")
    p.add_argument("--no-dedup", action="store_true", help="Disable SimHash clustering deduplication")
    p.add_argument("--watch", action="store_true", help="Start continuous monitoring watch mode")
    p.add_argument("--watch-config", default="", help="Path to watch mode targets config file")
    p.add_argument("--intel-update", action="store_true", help="Fetch intel updates and update local intel DB")
    p.add_argument("--feedback-stats", action="store_true", help="Display local false-positive feedback statistics")
    p.add_argument("--dismiss", default="", help="Dismiss a rule ID or finding pattern locally")
    p.add_argument("--dismiss-target", default="", help="Target scope for dismissal (optional)")
    p.add_argument("--header", action="append", help="Custom request header (Format: 'Key: Value')")
    p.add_argument("--open", action="store_true", help="Automatically open generated HTML report in browser")
    p.add_argument("--intel-query", help="Query local vulnerability intelligence SQLite database and exit")
    p.add_argument("--json-stream", action="store_true", help="Stream real-time NDJSON events to stdout (agent-native)")
    p.add_argument("--stream-file", help="Write real-time NDJSON telemetry stream to file")
    p.add_argument("--diff", help="Compare current audit against previous recon_report.json baseline")
    p.add_argument("-q", "--quiet", action="store_true", help="Minimal output (agent/pipeline friendly)")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose real-time progress logging")
    return p


def _parse_headers(headers: Optional[List[str]]) -> dict:
    result = {}
    if headers:
        for h in headers:
            if ":" in h:
                key, val = h.split(":", 1)
                result[key.strip()] = val.strip()
    return result


def run_wizard() -> int:
    """
    Interactive Terminal Wizard for human operators.
    Prompts for target, profile, tools, and report settings, then starts the scan.
    """
    if not sys.stdin.isatty():
        print("[!] Error: Interactive wizard requires an interactive TTY terminal.", file=sys.stderr)
        print("    For headless/CI usage, provide a target URL: py -m app.main <target_url> [options]", file=sys.stderr)
        return 1

    print(_cyan(_BANNER))
    print(_bold("=== WebRipper Recon 5.0 — Interactive Mission Setup ==="))
    print(_dim("Configure your security reconnaissance audit interactively.\n"))

    def _wizard_input(prompt: str, default: str = "") -> str:
        try:
            val = input(prompt).strip()
            return val if val else default
        except EOFError:
            print("\n[!] Setup aborted: EOF encountered on input.", file=sys.stderr)
            sys.exit(1)
        except KeyboardInterrupt:
            print("\n[!] Setup cancelled by operator.", file=sys.stderr)
            sys.exit(130)

    # 1. Target URL
    target_url = ""
    while not target_url:
        target_input = _wizard_input(_bold(_cyan("[?] Target URL: ")))
        if not target_input:
            print(_yellow("  Target URL cannot be empty."))
            continue
        if not target_input.startswith(("http://", "https://")):
            target_input = "https://" + target_input
        target_url = target_input

    # 2. Profile
    print("\nSelect Audit Profile:")
    print("  [1] quick      - Fast passive audit (metadata, headers, secrets, TLS)")
    print("  [2] standard   - Standard comprehensive recon (crawl, CVEs, ports, canary probes) [DEFAULT]")
    print("  [3] aggressive - Deep full-surface inspection (subdomains, all canary probes, active audits)")
    prof_choice = _wizard_input(_cyan("[?] Profile [1/2/3] (default: 2): "), "2")
    profile_map = {"1": "quick", "2": "standard", "3": "aggressive"}
    profile = profile_map.get(prof_choice, "standard")

    # 3. Crawl Depth
    depth_in = _wizard_input(_cyan("[?] Crawl Depth [1-5] (default: 2): "), "2")
    depth = int(depth_in) if depth_in.isdigit() and 1 <= int(depth_in) <= 10 else 2

    # 4. Scenario Canary Probes (#21 Bug Bounty Intel)
    scenario_in = _wizard_input(_cyan("[?] Enable Bug Bounty Scenario Canary Probes? [Y/n]: "), "y").lower()
    enable_scenarios = scenario_in != "n"

    # 5. External Tools
    tools_in = _wizard_input(_cyan("[?] Orchestrate installed external tools (nuclei, nmap)? [Y/n]: "), "y").lower()
    enable_tools = tools_in != "n"

    # 6. Auth Cookie
    cookie_in = _wizard_input(_cyan("[?] Session cookie for authenticated scanning (optional, press Enter to skip): "))

    # 7. Output Report
    out_report = _wizard_input(_cyan("[?] Output HTML Report path (default: report.html): "), "report.html")

    # 8. Auto-Open in Browser
    open_in = _wizard_input(_cyan("[?] Auto-open HTML report in web browser upon completion? [Y/n]: "), "y").lower()
    auto_open = open_in != "n"

    print(_green("\n[*] Mission configured successfully. Launching reconnaissance engine...\n"))

    # Synthesize CLI arguments and dispatch
    args = [
        target_url,
        "--profile", profile,
        "--depth", str(depth),
        "-o", out_report,
    ]
    if not enable_tools:
        args.append("--no-tools")
    if not enable_scenarios:
        args.append("--no-scenarios")
    if cookie_in:
        args.extend(["--cookie", cookie_in])
    if auto_open:
        args.append("--open")

    return run_cli(args)


def _handle_intel_query(query: str) -> int:
    """Execute SQLite FTS5 search across all intelligence datasets (Scenarios, Nuclei, PortSwigger, HackerOne, CISA KEV)."""
    from .intelligence.engine import ScenarioEngine
    engine = ScenarioEngine()
    print(_cyan(f"\n[*] Querying Security Intelligence Database (30,000+ entries) for: '{query}'\n"))

    scenarios = engine.search(query, limit=5)
    nuclei_templates = engine.search_nuclei(query, limit=5)
    portswigger = engine.search_portswigger(query, limit=3)
    h1_reports = engine.search_hackerone(query, limit=5)
    cisa_kevs = engine.search_cisa_kev(query, limit=5)

    total_found = len(scenarios) + len(nuclei_templates) + len(portswigger) + len(h1_reports) + len(cisa_kevs)
    if total_found == 0:
        print(_yellow(f"No intelligence entries matched query '{query}'."))
        return 0

    # 1. Scenarios
    if scenarios:
        print(_bold(_green(f"=== Curated Scenario Canary Recipes ({len(scenarios)}) ===")))
        for idx, sc in enumerate(scenarios, 1):
            print(_bold(f"  [{idx}] {sc.title} ({sc.id})"))
            print(f"      {_cyan('Tech:')} {', '.join(sc.tech_stack)} | {_cyan('Vector:')} {sc.cvss_vector} | {_cyan('CWE:')} {sc.cwe}")
            if sc.bounty_reference:
                print(f"      {_dim('Reference:')} {sc.bounty_reference}")
            print(f"      {_dim('Insight:')} {sc.author_insight}")
            print(f"      {_dim('Probe:')} {sc.probe_method} {sc.probe_path}")
            print()

    # 2. Nuclei Community Templates
    if nuclei_templates:
        print(_bold(_green(f"=== Nuclei Community Template Signatures ({len(nuclei_templates)}) ===")))
        for idx, nuc in enumerate(nuclei_templates, 1):
            sev_color = _red if nuc['severity'] in ('critical', 'high') else _yellow
            print(_bold(f"  [{idx}] {nuc['name']} ({nuc['id']}) - {sev_color(nuc['severity'].upper())}"))
            print(f"      {_cyan('Probe:')} {nuc['method']} {nuc['path']} | {_cyan('Matcher:')} {nuc['matcher'][:80]}")
            if nuc['cwe']:
                print(f"      {_cyan('CWE:')} {nuc['cwe']} | {_cyan('CVSS:')} {nuc['cvss']}")
            if nuc['description']:
                print(f"      {_dim('Description:')} {nuc['description'][:150]}")
            print()

    # 3. PortSwigger Web Security Research
    if portswigger:
        print(_bold(_yellow(f"=== PortSwigger Web Security Research ({len(portswigger)}) ===")))
        for idx, ps in enumerate(portswigger, 1):
            print(_bold(f"  [{idx}] {ps['title']} ({ps['id']})"))
            print(f"      {_cyan('Category:')} {ps['category']} | {_cyan('CWE:')} {ps['cwe']} | {_cyan('Vector:')} {ps['cvss_vector']}")
            print(f"      {_dim('Attack:')} {ps['attack_vector']}")
            print(f"      {_dim('Impact:')} {ps['impact']} ({ps['author_reference']})")
            print()

    # 4. HackerOne Disclosures
    if h1_reports:
        print(_bold(_cyan(f"=== Real-World HackerOne Disclosed Reports ({len(h1_reports)}) ===")))
        for idx, h1 in enumerate(h1_reports, 1):
            payout = f"${h1['bounty']:,.0f}" if h1['bounty'] > 0 else "Disclosed / VDP"
            print(_bold(f"  [{idx}] {h1['title']}"))
            print(f"      {_cyan('Program:')} {h1['program']} | {_green('Bounty:')} {payout} | {_cyan('Type:')} {h1['vuln_type']} | {_cyan('CWE:')} {h1['cwe']}")
            print(f"      {_dim('Link:')} https://{h1['link']}")
            print()

    # 5. CISA Known Exploited Vulnerabilities
    if cisa_kevs:
        print(_bold(_red(f"=== CISA Known Exploited Vulnerabilities (KEV) ({len(cisa_kevs)}) ===")))
        for idx, kev in enumerate(cisa_kevs, 1):
            print(_bold(f"  [{idx}] {kev['cve_id']}: {kev['vuln_name']}"))
            print(f"      {_cyan('Vendor/Product:')} {kev['vendor']} {kev['product']} | {_cyan('CWE:')} {kev['cwes']} | {_cyan('Added:')} {kev['date_added']}")
            print(f"      {_dim('Description:')} {kev['short_description']}")
            print(f"      {_yellow('Required Action:')} {kev['required_action']}")
            print()

    return 0


def run_cli(args: Optional[List[str]] = None) -> int:
    """
    Run CLI scan. Returns semantic exit code:
      0 = Clean scan (no high/critical findings, normal execution)
      1 = Fatal error / configuration failure
      2 = Security findings discovered (CRITICAL or HIGH severity)
      3 = Target unreachable (connection refused, host down, DNS error)
      4 = Rate-limited by target (429 Too Many Requests)
      5 = Target blocked audit via WAF / Security Gateway (403 Cloudflare/Akamai)
    """
    parser = build_parser()
    opts = parser.parse_args(args)

    # 0. MCP server mode requested
    if getattr(opts, "mcp", False):
        from .mcp.server import run_mcp_server
        return run_mcp_server()

    # 0.1 Subcommand dispatch (watch, intel update, intel feedback-stats, intel dismiss)
    raw_args = list(args) if args is not None else list(sys.argv[1:])
    if raw_args and raw_args[0] == "watch":
        from .watch.engine import run_watch_cli
        return run_watch_cli(raw_args[1:])

    if raw_args and raw_args[0] == "intel":
        subcmd = raw_args[1] if len(raw_args) > 1 else ""
        if subcmd == "update":
            from .intelligence.updater import run_intel_update
            res = run_intel_update()
            print(_green(f"[*] Intel DB updated successfully (Version {res.get('version', '')})."))
            return 0
        elif subcmd == "feedback-stats":
            from .intelligence.feedback import get_feedback_stats
            stats = get_feedback_stats()
            print(_cyan(f"\n[*] Local False-Positive Feedback Statistics:"))
            print(f"    Total rules dismissed: {stats.get('total_dismissals', 0)}")
            print(f"    Target scopes: {len(stats.get('by_target', {}))}")
            return 0
        elif subcmd == "dismiss":
            rule_id = raw_args[2] if len(raw_args) > 2 else ""
            if not rule_id:
                print(_red("Error: rule_id required: webripper intel dismiss <rule_id>"), file=sys.stderr)
                return 1
            from .intelligence.feedback import dismiss_finding
            dismiss_finding(pattern_type="rule_id", target="", rule_id=rule_id, rationale="Manual operator dismissal")
            print(_green(f"[*] Rule '{rule_id}' dismissed locally."))
            return 0

    if getattr(opts, "watch", False):
        from .watch.engine import run_watch_cli
        watch_args = ["--config", opts.watch_config] if getattr(opts, "watch_config", "") else []
        return run_watch_cli(watch_args)

    if getattr(opts, "intel_update", False):
        from .intelligence.updater import run_intel_update
        res = run_intel_update()
        print(_green(f"[*] Intel DB updated successfully (Version {res.get('version', '')})."))
        return 0

    if getattr(opts, "feedback_stats", False):
        from .intelligence.feedback import get_feedback_stats
        stats = get_feedback_stats()
        print(_cyan(f"\n[*] Local False-Positive Feedback Statistics:"))
        print(f"    Total rules dismissed: {stats.get('total_dismissals', 0)}")
        print(f"    Target scopes: {len(stats.get('by_target', {}))}")
        return 0

    if getattr(opts, "dismiss", ""):
        from .intelligence.feedback import dismiss_finding
        dismiss_finding(pattern_type="rule_id", target=getattr(opts, "dismiss_target", ""), rule_id=opts.dismiss, rationale="Operator CLI dismissal")
        print(_green(f"[*] Rule '{opts.dismiss}' dismissed locally."))
        return 0

    # 1. Wizard mode requested
    if opts.wizard:
        return run_wizard()

    # 2. Intelligence query requested
    if opts.intel_query:
        return _handle_intel_query(opts.intel_query)

    # 3. Suppress decorative banners and stdout text when streaming ndjson
    if opts.json_stream:
        opts.quiet = True

    # 4. Target resolution
    primary_url = opts.target or opts.url or opts.target_flag or ""
    if not primary_url and not opts.urls:
        # If no arguments provided in CLI invocation, guide user to wizard
        if not args:
            return run_wizard()
        print(_red("Error: Target URL or --urls file required"), file=sys.stderr)
        parser.print_help(sys.stderr)
        return 1

    if not opts.quiet:
        print(_cyan(_BANNER))

    targets = []
    if primary_url:
        targets.append(primary_url)
    if opts.urls:
        try:
            with open(opts.urls, "r", encoding="utf-8") as f:
                targets.extend(
                    line.strip() for line in f
                    if line.strip() and not line.strip().startswith("#")
                )
        except OSError as e:
            print(_red(f"Error reading {opts.urls}: {e}"), file=sys.stderr)
            return 1

    # Deduplicate while preserving order
    seen_targets = set()
    unique_targets = []
    for t in targets:
        if t not in seen_targets:
            seen_targets.add(t)
            unique_targets.append(t)
    targets = unique_targets

    if not targets:
        print(_red("Error: No valid targets found to scan."), file=sys.stderr)
        return 1

    worst_exit_code = 0
    _EXIT_CODE_PRIORITY = {2: 50, 3: 40, 5: 30, 4: 20, 1: 10, 0: 0}

    for i, url in enumerate(targets, 1):
        if len(targets) > 1 and not opts.quiet:
            print(_bold(f"\n{'='*60}"))
            print(_bold(f"  Target {i}/{len(targets)}: {url}"))
            print(_bold(f"{'='*60}"))

        exit_code = _scan_target(url, opts, target_index=i, total_targets=len(targets))
        # Prioritize non-zero exit codes: 2 (Critical/High) > 3 (Unreachable) > 5 (WAF) > 4 (RateLimit) > 1 (Error) > 0
        if _EXIT_CODE_PRIORITY.get(exit_code, 0) > _EXIT_CODE_PRIORITY.get(worst_exit_code, 0):
            worst_exit_code = exit_code

    return worst_exit_code


def _handle_diff(
    current_findings: List[Finding],
    baseline_path: str,
    asset_dir: str,
    quiet: bool = False,
    emit_fn: Optional[Any] = None,
) -> dict:
    """
    Compare current scan findings against a previous recon_report.json baseline.
    Identifies new findings (regressions), resolved findings (fixed), and persisting findings.
    Writes recon_diff.json to asset_dir and returns diff summary.
    """
    import json as json_mod

    diff_result = {
        "baseline_file": baseline_path,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "summary": {"new": 0, "resolved": 0, "persisting": 0},
        "new_findings": [],
        "resolved_findings": [],
        "persisting_findings": [],
    }

    if not os.path.exists(baseline_path):
        if not quiet:
            print(_yellow(f"\n[!] Diff Warning: Baseline file not found: {baseline_path}"))
        return diff_result

    try:
        with open(baseline_path, "r", encoding="utf-8") as f:
            base_data = json_mod.load(f)
    except Exception as e:
        if not quiet:
            print(_yellow(f"\n[!] Diff Warning: Could not parse baseline JSON: {e}"))
        return diff_result

    raw_base_findings = (
        base_data.get("findings", [])
        if isinstance(base_data, dict)
        else (base_data if isinstance(base_data, list) else [])
    )

    def _finding_key(item) -> tuple:
        if isinstance(item, Finding):
            return (item.category.strip().lower(), item.title.strip().lower())
        elif isinstance(item, dict):
            return (
                item.get("category", "").strip().lower(),
                item.get("title", "").strip().lower(),
            )
        return ("", "")

    base_map = {}
    for bf in raw_base_findings:
        k = _finding_key(bf)
        if k != ("", ""):
            base_map[k] = bf

    curr_map = {}
    for cf in current_findings:
        k = _finding_key(cf)
        if k != ("", ""):
            curr_map[k] = cf

    for k, cf in curr_map.items():
        if k not in base_map:
            diff_result["new_findings"].append({
                "severity": cf.severity.value,
                "category": cf.category,
                "title": cf.title,
                "description": cf.description,
            })
        else:
            diff_result["persisting_findings"].append({
                "severity": cf.severity.value,
                "category": cf.category,
                "title": cf.title,
                "description": cf.description,
            })

    for k, bf in base_map.items():
        if k not in curr_map:
            diff_result["resolved_findings"].append({
                "severity": (
                    bf.get("severity", "INFO")
                    if isinstance(bf, dict)
                    else getattr(bf, "severity", "INFO")
                ),
                "category": (
                    bf.get("category", "")
                    if isinstance(bf, dict)
                    else getattr(bf, "category", "")
                ),
                "title": (
                    bf.get("title", "")
                    if isinstance(bf, dict)
                    else getattr(bf, "title", "")
                ),
                "description": (
                    bf.get("description", "")
                    if isinstance(bf, dict)
                    else getattr(bf, "description", "")
                ),
            })

    diff_result["summary"] = {
        "new": len(diff_result["new_findings"]),
        "resolved": len(diff_result["resolved_findings"]),
        "persisting": len(diff_result["persisting_findings"]),
    }

    if not quiet:
        print(_bold(_cyan("\n=== Security Posture Diff vs Baseline ===")))
        print(f"  {_dim('Baseline:')} {baseline_path}")
        new_cnt = diff_result["summary"]["new"]
        res_cnt = diff_result["summary"]["resolved"]
        pers_cnt = diff_result["summary"]["persisting"]

        new_str = (
            _red(f"[+] New Vulnerabilities (Regressions): {new_cnt}")
            if new_cnt > 0
            else _green("[+] New Vulnerabilities: 0")
        )
        res_str = _green(f"[-] Remediated Vulnerabilities (Resolved): {res_cnt}")
        pers_str = _yellow(f"[=] Persisting Findings: {pers_cnt}")
        print(f"  {new_str}")
        print(f"  {res_str}")
        print(f"  {pers_str}")

        if new_cnt > 0:
            print(_bold(_red("\n  New Findings:")))
            for nf in diff_result["new_findings"][:10]:
                sev = nf["severity"]
                print(f"    {_red(f'+ [{sev}]')} {nf['title']} ({nf['category']})")

        if res_cnt > 0:
            print(_bold(_green("\n  Resolved Findings:")))
            for rf in diff_result["resolved_findings"][:10]:
                sev = rf["severity"]
                print(f"    {_green(f'- [{sev}]')} {rf['title']} ({rf['category']})")

    try:
        diff_out_path = os.path.join(asset_dir, "recon_diff.json")
        os.makedirs(asset_dir, exist_ok=True)
        with open(diff_out_path, "w", encoding="utf-8") as df:
            json_mod.dump(diff_result, df, indent=2, default=str)
        if not quiet:
            print(f"  Diff Report: {_green(os.path.abspath(diff_out_path))}")
    except Exception as e:
        if not quiet:
            print(_yellow(f"Could not save recon_diff.json: {e}"))

    if emit_fn:
        emit_fn({
            "event": "diff_completed",
            "baseline": baseline_path,
            "new": diff_result["summary"]["new"],
            "resolved": diff_result["summary"]["resolved"],
            "persisting": diff_result["summary"]["persisting"],
        })

    return diff_result


def _scan_target(url: str, opts, target_index: int = 1, total_targets: int = 1) -> int:
    """Scan a single target. Returns semantic exit code."""
    # Ensure scheme
    if "://" in url:
        scheme = url.split("://", 1)[0].lower()
        if scheme not in ("http", "https"):
            print(_red(f"Error: Invalid URL scheme '{scheme}'. Only http:// and https:// are supported."), file=sys.stderr)
            return 1
    elif not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed_url = urlparse(url)
    host = parsed_url.hostname or f"target{target_index}"
    port_suffix = f"_{parsed_url.port}" if parsed_url.port else ""
    dom_slug = f"{target_index}_{host}{port_suffix}".replace(".", "_")

    # Resolve output file paths for multi-target execution
    out_html = opts.output
    out_json = opts.json_output
    if total_targets > 1:
        if out_html:
            base, ext = os.path.splitext(out_html)
            out_html = f"{base}_{dom_slug}{ext}"
        if out_json:
            base, ext = os.path.splitext(out_json)
            out_json = f"{base}_{dom_slug}{ext}"

    # Resolve asset output directory with isolation for multi-target execution
    if opts.out_dir:
        base_asset_dir = opts.out_dir
    elif opts.json_output:
        base_asset_dir = os.path.dirname(os.path.abspath(opts.json_output))
    elif opts.output and not opts.output.lower().endswith((".html", ".htm", ".json")):
        base_asset_dir = opts.output
    elif opts.output:
        base_asset_dir = os.path.dirname(os.path.abspath(opts.output))
    else:
        base_asset_dir = os.path.join(os.getcwd(), "webripper_output")

    asset_dir = os.path.join(base_asset_dir, dom_slug) if total_targets > 1 else base_asset_dir

    if not out_html:
        default_html = f"recon_report_{dom_slug}.html" if total_targets > 1 else "recon_report.html"
        out_html = os.path.join(asset_dir, default_html)

    if not out_json:
        default_json = f"recon_report_{dom_slug}.json" if total_targets > 1 else "recon_report.json"
        out_json = os.path.join(asset_dir, default_json)

    # Parse active scanners if supplied
    active_scanners_list = []
    if opts.scanners:
        active_scanners_list = [s.strip() for s in opts.scanners.split(",") if s.strip()]

    settings = RipperSettings(
        url=url,
        output_dir=asset_dir,
        depth=opts.depth,
        timeout=opts.timeout,
        profile=opts.profile,
        delay=opts.delay,
        use_external_tools=not opts.no_tools,
        scan_scenarios=not opts.no_scenarios,
        active_scanners=active_scanners_list,
        auth_cookie=opts.cookie or "",
        auth_token=opts.token or "",
        identity_a_cookie=getattr(opts, "identity_a_cookie", "") or opts.cookie or "",
        identity_a_token=getattr(opts, "identity_a_token", "") or opts.token or "",
        identity_b_cookie=getattr(opts, "identity_b_cookie", "") or "",
        identity_b_token=getattr(opts, "identity_b_token", "") or "",
        scan_bola=bool(getattr(opts, "identity_a_cookie", "") or getattr(opts, "identity_a_token", "") or getattr(opts, "identity_b_cookie", "") or getattr(opts, "identity_b_token", "")),
        scan_graphql=bool(getattr(opts, "graphql", False)),
        scan_llmapp=bool(getattr(opts, "llmapp", False)),
        scan_mcptarget=bool(getattr(opts, "mcptarget", False)),
        authorized=bool(getattr(opts, "authorized", False)),
        enable_dedup=not getattr(opts, "no_dedup", False),
        custom_headers=_parse_headers(opts.header),
    )

    if not opts.quiet:
        print(f"\n{_cyan('Target:')} {url}")
        print(f"{_cyan('Profile:')} {opts.profile}")
        print(f"{_cyan('Depth:')} {opts.depth}")
        print(f"{_cyan('Tools:')} {'disabled' if opts.no_tools else 'enabled'}")
        print(f"{_cyan('Scenario Probes:')} {'disabled' if opts.no_scenarios else 'active (#21 Bug Bounty Intel)'}")
        if active_scanners_list:
            print(f"{_cyan('Filtered Scanners:')} {', '.join(active_scanners_list)}")
        print()

    try:
        from .worker import RipperWorker
        from .report import generate_html_report
        from . import history

        # Telemetry streamer for agent / CI-CD pipeline integration
        def emit_stream(data: dict):
            if not (getattr(opts, "json_stream", False) or getattr(opts, "stream_file", None)):
                return
            import json as json_mod
            line = json_mod.dumps(data, default=str)
            if getattr(opts, "json_stream", False):
                sys.stdout.write(line + "\n")
                sys.stdout.flush()
            if getattr(opts, "stream_file", None):
                try:
                    with open(opts.stream_file, "a", encoding="utf-8") as sf:
                        sf.write(line + "\n")
                except Exception:
                    pass

        emit_stream({
            "event": "scan_started",
            "target": url,
            "profile": opts.profile,
            "depth": opts.depth,
            "timestamp": time.time(),
        })

        worker = RipperWorker(settings)

        # Track WAF and rate limit indicators
        rate_limited = False
        waf_blocked = False

        # Connect progress to stdout
        def on_progress(event):
            nonlocal rate_limited, waf_blocked
            msg = (event.message or "").lower()
            if "http 429" in msg or "too many requests" in msg or "rate limited on" in msg:
                rate_limited = True
            if "waf block" in msg or "waf challenge" in msg or "access denied by waf" in msg:
                waf_blocked = True

            # Emit streaming NDJSON event
            if event.event_type == EventType.PHASE_CHANGE:
                emit_stream({
                    "event": "phase_change",
                    "target": url,
                    "phase": event.phase,
                    "message": event.message,
                    "timestamp": time.time(),
                })
            elif event.event_type == EventType.SCAN_FINDING and event.finding:
                f = event.finding
                emit_stream({
                    "event": "finding_discovered",
                    "target": url,
                    "severity": f.severity.value,
                    "category": f.category,
                    "title": f.title,
                    "url": f.url,
                    "timestamp": time.time(),
                })
            elif event.event_type == EventType.FILE_DOWNLOADED:
                emit_stream({
                    "event": "crawl_progress",
                    "target": url,
                    "downloaded": event.downloaded,
                    "total": event.total,
                    "timestamp": time.time(),
                })

            if opts.quiet:
                return
            if event.event_type == EventType.PHASE_CHANGE:
                print(f"\n{_bold(_cyan(f'[{event.phase}]'))}")
            elif event.event_type == EventType.LOG:
                if opts.verbose:
                    print(f"  {_dim(event.message)}")
            elif event.event_type == EventType.SCAN_FINDING:
                f = event.finding
                if f:
                    sev = f.severity.value
                    color_fn = _red if sev in ("CRITICAL", "HIGH") else (_yellow if sev == "MEDIUM" else _dim)
                    print(f"  {color_fn(f'[{sev}]')} {f.title}")
            elif event.event_type == EventType.FILE_DOWNLOADED:
                if opts.verbose:
                    print(f"  {_dim(f'Downloaded: {event.downloaded}/{event.total}')}")

        worker.progress.connect(on_progress)

        # Run the scan
        start = time.time()
        try:
            worker.run()
        except KeyboardInterrupt:
            worker.cancel()
            raise
        elapsed = time.time() - start

        report = worker.report
        if not report:
            print(_red("Scan produced no report"), file=sys.stderr)
            return 1

        # Check for unreachable target
        if getattr(report, "unreachable", False) is True or (
            getattr(report, "rip_report", None) and getattr(report.rip_report, "unreachable", False) is True
        ):
            print(_red(f"\nTarget unreachable: Could not connect to {url}"), file=sys.stderr)
            emit_stream({
                "event": "target_unreachable",
                "target": url,
                "error": "Connection failed / Target unreachable",
                "timestamp": time.time(),
            })
            return 3

        # Gather findings
        all_findings = []
        for sr in report.scan_results:
            all_findings.extend(sr.findings)

        attack_chains = getattr(report, "attack_chains", []) or []

        # Save to history
        try:
            history.save_scan(all_findings, url, attack_chains=attack_chains)
        except Exception:
            pass

        # Print summary
        crit = sum(1 for f in all_findings if f.severity.value == "CRITICAL")
        high = sum(1 for f in all_findings if f.severity.value == "HIGH")
        med = sum(1 for f in all_findings if f.severity.value == "MEDIUM")
        low = sum(1 for f in all_findings if f.severity.value == "LOW")
        info = sum(1 for f in all_findings if f.severity.value == "INFO")

        emit_stream({
            "event": "scan_completed",
            "target": url,
            "elapsed_seconds": round(elapsed, 2),
            "findings_count": len(all_findings),
            "critical": crit,
            "high": high,
            "medium": med,
            "low": low,
            "info": info,
            "attack_chains": len(attack_chains),
            "timestamp": time.time(),
        })

        # Detect WAF block or Rate limiting in findings
        for f in all_findings:
            title_lower = f.title.lower()
            cat_lower = f.category.lower()
            if "http 429" in title_lower or "too many requests" in title_lower or "rate limit encountered" in title_lower:
                rate_limited = True
            if ("waf" in cat_lower or "waf" in title_lower) and any(kw in title_lower for kw in ("challenge", "blocked", "access denied", "block", "enforced")):
                waf_blocked = True
            if f.metadata and f.metadata.get("waf_blocked") is True:
                waf_blocked = True

        if report.rip_report:
            for fr in report.rip_report.files:
                if fr.status == 429 or "rate limited" in (fr.error or "").lower():
                    rate_limited = True
                elif fr.status == 403 and any(w in (fr.error or "").lower() for w in ("waf", "cloudflare", "akamai", "blocked", "challenge")):
                    waf_blocked = True

            if report.rip_report.pages_crawled == 0 and not waf_blocked and not rate_limited:
                for fr in report.rip_report.files:
                    if fr.status == 403:
                        waf_blocked = True
                        break

        if not opts.quiet:
            verified_findings = [f for f in all_findings if getattr(f, "confidence", "") == "VERIFIED"]
            print(f"\n{_bold('Scan Complete')} ({elapsed:.1f}s)")
            print(f"  {_red(f'CRITICAL: {crit}')}  {_red(f'HIGH: {high}')}  "
                  f"{_yellow(f'MEDIUM: {med}')}  LOW: {low}  INFO: {info}")
            ver_note = f" ({len(verified_findings)} verified with machine proof)" if verified_findings else ""
            print(f"  Total: {len(all_findings)} findings{_green(ver_note)}")
            if verified_findings:
                print(f"  {_green(f'Verified Vulnerabilities ({len(verified_findings)}):')}")
                for vf in verified_findings:
                    vf_sev = getattr(vf.severity, "value", str(vf.severity))
                    sev_col = _red if vf_sev in ("CRITICAL", "HIGH") else _yellow
                    v_name = (vf.metadata or {}).get("proof", {}).get("validator", "proof-layer")
                    print(f"    ✓ {sev_col(f'[{vf_sev}]')} {vf.title} {_dim(f'[{v_name}: proof attached]')}")
            if attack_chains:
                print(f"  {_red(f'Attack Chains ({len(attack_chains)}):')}")
                for ch in attack_chains:
                    ch_sev = getattr(ch.severity, "value", str(ch.severity))
                    color_fn = _red if ch_sev in ("CRITICAL", "HIGH") else _yellow
                    step_count = len(getattr(ch, "steps", []))
                    print(f"    ➜ {color_fn(f'[{ch_sev}]')} {ch.name} ({step_count} steps)")

        # Generate HTML report
        if out_html:
            os.makedirs(os.path.dirname(os.path.abspath(out_html)), exist_ok=True)
            html = generate_html_report(report)
            with open(out_html, "w", encoding="utf-8") as f:
                f.write(html)
            if not opts.quiet:
                print(f"\n  Report: {_green(os.path.abspath(out_html))}")

            if opts.open:
                try:
                    webbrowser.open(f"file://{os.path.abspath(out_html)}")
                except Exception as wb_err:
                    if opts.verbose:
                        print(_yellow(f"Could not open browser: {wb_err}"))

        # Generate JSON report
        if out_json:
            import json as json_mod
            os.makedirs(os.path.dirname(os.path.abspath(out_json)), exist_ok=True)
            risk_score_val = getattr(report, "risk_score", "N/A")
            if not isinstance(risk_score_val, (str, int, float, bool)):
                risk_score_val = str(risk_score_val)

            chains_export = []
            for ch in attack_chains:
                if hasattr(ch, "to_dict"):
                    chains_export.append(ch.to_dict())
                elif isinstance(ch, dict):
                    chains_export.append(ch)

            exported_findings = []
            for f in all_findings:
                meta_clean = {}
                for k, v in (f.metadata or {}).items():
                    if k == "proof":
                        continue
                    if isinstance(v, (str, int, float, bool, dict, list)):
                        meta_clean[k] = v

                item = {
                    "severity": f.severity.value,
                    "category": f.category,
                    "title": f.title,
                    "description": f.description,
                    "evidence": f.evidence[:500] if f.evidence else "",
                    "confidence": f.confidence.value if hasattr(f.confidence, "value") else str(getattr(f, "confidence", "POSSIBLE")),
                    "metadata": meta_clean,
                }
                # Preserve proof artifact for verified findings
                if f.metadata and "proof" in f.metadata:
                    item["proof"] = f.metadata["proof"]
                    item["proof_attached"] = True
                    meta_clean["proof"] = f.metadata["proof"]
                    meta_clean["proof_attached"] = True

                exported_findings.append(item)

            data = {
                "target": url,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "elapsed_seconds": round(elapsed, 1),
                "risk_score": risk_score_val,
                "finding_count": len(all_findings),
                "verified_count": sum(
                    1 for f in all_findings
                    if (f.confidence.value if hasattr(f.confidence, "value") else str(getattr(f, "confidence", ""))) == "VERIFIED"
                ),
                "attack_chains": chains_export,
                "findings": exported_findings,
            }
            with open(out_json, "w", encoding="utf-8") as f:
                json_mod.dump(data, f, indent=2, default=str)
            if not opts.quiet:
                print(f"  JSON:   {_green(os.path.abspath(out_json))}")

        # Baseline Diffing
        if getattr(opts, "diff", None):
            _handle_diff(
                all_findings,
                opts.diff,
                asset_dir,
                quiet=opts.quiet,
                emit_fn=emit_stream,
            )

        # Semantic Exit Code Resolution:
        # 2 = CRITICAL or HIGH findings present
        # 3 = Target unreachable (connection refused, DNS failure, timeout)
        # 4 = Rate limited (429)
        # 5 = WAF blocked (403)
        # 0 = Clean scan
        if crit > 0 or high > 0:
            return 2
        if waf_blocked:
            return 5
        if rate_limited:
            return 4
        return 0

    except Exception as e:
        print(_red(f"Scan error: {e}"), file=sys.stderr)
        if opts.verbose:
            import traceback
            traceback.print_exc()
        return 1


cli_main = run_cli

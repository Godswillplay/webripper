"""
Agent Tool Library for WebRipper Recon AI.

Enables the 4B/8B model to:
- Inspect extracted files (JavaScript, HTML, sourcemaps, configs)
- Search across downloaded code using regex/grep
- Inspect web pages dynamically via Playwright stealth browser
- Send HTTP probe requests (routed via Burp Suite proxy when active)
- Run external security tools (Nmap, Nuclei, SQLmap)
- Access scan findings and attack chains
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import ssl
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class AgentToolbox:
    """Provides safe, sandboxed tools that the AI agent can execute."""

    def __init__(
        self,
        output_dir: str,
        recon_report: Optional[Any] = None,
        burp_proxy: Optional[str] = None,
    ):
        self.output_dir = Path(output_dir).resolve()
        self.recon_report = recon_report
        self.burp_proxy = burp_proxy

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """Return tool definitions for the agent system prompt."""
        return [
            {
                "name": "read_file",
                "description": "Read the contents of a file from the extracted website assets.",
                "parameters": {
                    "path": "Relative path to file in the output directory (e.g. 'js/app.js' or 'index.html')",
                    "max_lines": "Maximum number of lines to read (default 100)",
                },
            },
            {
                "name": "search_code",
                "description": "Search across all extracted source files using regex or plain text query.",
                "parameters": {
                    "query": "Regex or string to search for (e.g. 'apiKey', 'password', '/api/v1', 'graphql')",
                    "extension": "Optional file extension filter like '.js', '.html', or '.json'",
                },
            },
            {
                "name": "inspect_web_page",
                "description": "Drive the headless stealth browser to navigate to a live URL, inspect elements, forms, and cookies.",
                "parameters": {
                    "url": "Target URL to inspect",
                },
            },
            {
                "name": "http_probe",
                "description": "Send an HTTP request to an endpoint and inspect response status, headers, and body.",
                "parameters": {
                    "url": "Target URL to probe",
                    "method": "HTTP method: GET, POST, PUT, DELETE, OPTIONS, HEAD",
                    "headers": "Optional dictionary of custom headers",
                    "data": "Optional POST data / JSON string",
                },
            },
            {
                "name": "run_security_tool",
                "description": "Execute an installed external tool (nmap, nuclei, sqlmap) on a target.",
                "parameters": {
                    "tool": "Tool name: 'nmap', 'nuclei', or 'sqlmap'",
                    "args": "Command-line arguments string",
                },
            },
            {
                "name": "get_scan_findings",
                "description": "Get a summary of all security findings, endpoints, attack chains, and technologies discovered so far.",
                "parameters": {},
            },
            {
                "name": "lookup_vulnerability_intelligence",
                "description": "Query the local bug bounty vulnerability intelligence database (SQLite FTS5) for known attack patterns, scenario recipes, and remediation guidance.",
                "parameters": {
                    "query": "Search query or keyword (e.g. 'nextjs server action', 'supabase anon key', 'spring boot actuator', 'cors', 'graphql')",
                    "tech_stack": "Optional technology filter (e.g. 'next.js', 'django', 'laravel', 'firebase', 'aws')",
                },
            },
        ]

    def execute_tool(self, tool_name: str, args: Dict[str, Any]) -> str:
        """Dispatch and execute a tool call from the model."""
        try:
            if tool_name == "read_file":
                return self._tool_read_file(args.get("path", ""), args.get("max_lines", 100))
            elif tool_name == "search_code":
                return self._tool_search_code(args.get("query", ""), args.get("extension", ""))
            elif tool_name == "inspect_web_page":
                return self._tool_inspect_web_page(args.get("url", ""))
            elif tool_name == "http_probe":
                return self._tool_http_probe(
                    args.get("url", ""),
                    args.get("method", "GET"),
                    args.get("headers"),
                    args.get("data"),
                )
            elif tool_name == "run_security_tool":
                tool = args.get("tool") or args.get("tool_name") or args.get("name") or ""
                cmd_args = args.get("args") or args.get("command") or args.get("parameters") or ""
                return self._tool_run_security_tool(tool, cmd_args)
            elif tool_name == "get_scan_findings":
                return self._tool_get_scan_findings()
            elif tool_name == "lookup_vulnerability_intelligence":
                return self._tool_lookup_vulnerability_intelligence(
                    args.get("query", ""),
                    args.get("tech_stack"),
                )
            else:
                return f"Error: Unknown tool '{tool_name}'."
        except Exception as e:
            return f"Error executing {tool_name}: {e}"

    # -------------------------------------------------------------------------
    # Tool Implementations
    # -------------------------------------------------------------------------

    def _tool_read_file(self, file_path: str, max_lines: int = 100) -> str:
        """Read content from an extracted asset file."""
        if not file_path:
            return "Error: path is required."

        # Prevent directory traversal outside output_dir
        try:
            target = (self.output_dir / file_path).resolve()
            if not target.is_relative_to(self.output_dir):
                # Search strictly inside output_dir by basename
                matches = [m for m in self.output_dir.rglob(Path(file_path).name) if m.is_file()]
                if matches:
                    target = matches[0]
                else:
                    return f"Error: Access denied. '{file_path}' is outside output directory."
        except Exception as e:
            return f"Error resolving file path: {e}"

        if not target.is_file():
            # Try finding by basename inside output_dir if not found
            matches = [m for m in self.output_dir.rglob(Path(file_path).name) if m.is_file()]
            if matches:
                target = matches[0]
            else:
                return f"Error: '{file_path}' is not a file."

        try:
            max_lines_int = int(max_lines) if max_lines else 100
        except (ValueError, TypeError):
            max_lines_int = 100

        try:
            lines = []
            with open(target, "r", encoding="utf-8", errors="ignore") as f:
                for i, line in enumerate(f):
                    if i >= max_lines_int:
                        break
                    lines.append(line[:500])  # Cap line length to 500 chars
            content = "".join(lines)
            return f"=== File: {target.name} ({len(lines)} lines) ===\n{content}"
        except Exception as e:
            return f"Error reading file: {e}"

    def _tool_search_code(self, query: str, extension: str = "") -> str:
        """Grep across mirrored assets."""
        if not query:
            return "Error: query is required."

        results = []
        try:
            pattern = re.compile(query, re.IGNORECASE)
        except re.error as e:
            return f"Invalid regex query: {e}"

        count = 0
        for root, _, files in os.walk(self.output_dir):
            for file in files:
                if extension and not file.endswith(extension):
                    continue
                # Skip binary extensions
                if file.endswith((".png", ".jpg", ".jpeg", ".webp", ".gif", ".zip", ".exe", ".pdf", ".woff2")):
                    continue

                full_p = os.path.join(root, file)
                rel_p = os.path.relpath(full_p, self.output_dir)
                try:
                    with open(full_p, "r", encoding="utf-8", errors="ignore") as f:
                        for line_num, line in enumerate(f, 1):
                            if pattern.search(line):
                                results.append(f"{rel_p}:{line_num} | {line.strip()[:180]}")
                                count += 1
                                if count >= 15:
                                    break
                except Exception:
                    continue
            if count >= 15:
                break

        if not results:
            return f"No matches found for '{query}'."
        return "\n".join(results)

    def _tool_inspect_web_page(self, url: str) -> str:
        """Inspect a web page using Playwright stealth."""
        if not url:
            return "Error: url is required."

        try:
            from playwright.sync_api import sync_playwright
            from ..stealth import STEALTH_CHROMIUM_ARGS, STEALTH_INIT_SCRIPT

            with sync_playwright() as p:
                launch_kwargs = {
                    "headless": True,
                    "args": STEALTH_CHROMIUM_ARGS,
                }
                if self.burp_proxy:
                    launch_kwargs["proxy"] = {"server": self.burp_proxy}

                browser = p.chromium.launch(**launch_kwargs)
                try:
                    context = browser.new_context(ignore_https_errors=True)
                    context.add_init_script(STEALTH_INIT_SCRIPT)
                    page = context.new_page()

                    page.goto(url, timeout=15000, wait_until="domcontentloaded")
                    title = page.title()

                    # Extract forms
                    forms = page.evaluate("""
                        Array.from(document.forms).map(f => ({
                            action: f.action,
                            method: f.method,
                            inputs: Array.from(f.elements).map(e => ({ name: e.name, type: e.type }))
                        }))
                    """)

                    # Extract text preview
                    text = page.inner_text("body")[:1000] if page.query_selector("body") else ""

                    return (
                        f"Page Title: {title}\n"
                        f"Forms Discovered: {json.dumps(forms, indent=2)}\n"
                        f"Content Preview:\n{text[:500]}..."
                    )
                finally:
                    browser.close()
        except Exception as exc:
            return f"Browser inspection error: {exc}"

    def _tool_http_probe(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Any] = None,
    ) -> str:
        """Send an active HTTP probe request."""
        if not url:
            return "Error: url is required."

        try:
            req_headers = headers or {"User-Agent": "Mozilla/5.0 WebRipper-AI-Agent/5.0"}
            payload = None
            if data:
                if isinstance(data, dict):
                    payload = json.dumps(data).encode("utf-8")
                    req_headers["Content-Type"] = "application/json"
                else:
                    payload = str(data).encode("utf-8")

            # Route through Burp Suite proxy if active
            ssl_ctx = ssl._create_unverified_context()
            if self.burp_proxy:
                import urllib.request
                proxy_handler = urllib.request.ProxyHandler({"http": self.burp_proxy, "https": self.burp_proxy})
                https_handler = urllib.request.HTTPSHandler(context=ssl_ctx)
                opener = urllib.request.build_opener(proxy_handler, https_handler)
            else:
                opener = None

            req = Request(url, data=payload, headers=req_headers, method=method.upper())

            try:
                if opener:
                    resp = opener.open(req, timeout=15)
                else:
                    resp = urlopen(req, timeout=15, context=ssl_ctx)

                status = resp.status
                resp_headers = dict(resp.headers)
                body = resp.read(2000).decode("utf-8", errors="ignore")
            except HTTPError as exc:
                status = exc.code
                resp_headers = dict(exc.headers)
                body = exc.read(2000).decode("utf-8", errors="ignore")

            return (
                f"HTTP {status}\n"
                f"Headers:\n" + "\n".join(f"  {k}: {v}" for k, v in list(resp_headers.items())[:8]) + "\n"
                f"Body Preview:\n{body[:800]}"
            )
        except Exception as exc:
            return f"HTTP Probe error: {exc}"

    def _tool_run_security_tool(self, tool: str, args: str) -> str:
        """Run an external CLI tool."""
        tool = tool.lower().strip()
        if not tool:
            return (
                "Error: No tool name was specified in the action.\n"
                "Available tools in WebRipper: nuclei, httpx, subfinder, sqlmap, gobuster, nmap, sslscan.\n"
                "Usage: Action: {\"tool\": \"run_security_tool\", \"args\": {\"tool\": \"nuclei\", \"args\": \"-u https://target.com\"}}"
            )

        ALLOWED_TOOLS = {"nuclei", "httpx", "subfinder", "sqlmap", "gobuster", "nmap", "nikto", "wpscan", "katana", "sslscan"}
        if tool not in ALLOWED_TOOLS:
            return f"Error: Tool '{tool}' is not in the authorized tools whitelist ({', '.join(sorted(ALLOWED_TOOLS))})."

        tools_base = Path(os.environ.get("APPDATA", os.path.expanduser("~"))) / "WebRipper" / "tools"

        bin_path = None
        # 1. Check system PATH
        bin_path = shutil.which(tool) or shutil.which(f"{tool}.exe")

        # 2. Check specific known system paths
        if not bin_path:
            if tool == "nmap":
                for np in (r"C:\Program Files\Nmap\nmap.exe", r"C:\Program Files (x86)\Nmap\nmap.exe"):
                    if os.path.isfile(np):
                        bin_path = np
                        break
            elif tool == "sqlmap":
                sqlmap_py = tools_base / "sqlmap" / "sqlmap.py"
                if sqlmap_py.is_file():
                    bin_path = str(sqlmap_py)

        # 3. Check WebRipper managed tools directory (walk recursively to find binaries)
        if not bin_path:
            tool_dir = tools_base / tool
            if tool_dir.is_dir():
                for root, _, files in os.walk(tool_dir):
                    for f in files:
                        if f.lower() in (f"{tool}.exe", tool):
                            bin_path = os.path.join(root, f)
                            break
                        elif f.lower() == f"{tool}.py":
                            bin_path = os.path.join(root, f)
                            break
                    if bin_path:
                        break

        if not bin_path or not os.path.exists(bin_path):
            return f"Error: Tool '{tool}' is not installed or not found in PATH / WebRipper tools ({tools_base})."

        parsed_args = shlex.split(args, posix=False) if args else []
        if tool == "sqlmap" and "--batch" not in parsed_args:
            parsed_args.append("--batch")

        if bin_path.endswith(".py"):
            cmd = [sys.executable, bin_path] + parsed_args
        elif bin_path.endswith(".pl"):
            perl = shutil.which("perl")
            if perl:
                cmd = [perl, bin_path] + parsed_args
            else:
                return f"Error: Tool '{tool}' requires a Perl runtime. Please install ActivePerl/Strawberry Perl."
        else:
            cmd = [bin_path] + parsed_args

        try:
            flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            res = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=60,
                stdin=subprocess.DEVNULL, encoding="utf-8", errors="replace",
                creationflags=flags, shell=False
            )
            output = res.stdout if res.stdout else res.stderr
            return output[:2500] if output else "(Tool executed successfully with no output)"
        except Exception as exc:
            return f"Tool execution failed: {exc}"

    def _tool_get_scan_findings(self) -> str:
        """Return formatted summary of scan results from memory or disk."""
        report = self.recon_report
        if not report:
            # Check if recon_report.json exists in output directory
            report_file = self.output_dir / "recon_report.json"
            if report_file.is_file():
                try:
                    with open(report_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    findings = []
                    # Parse both "scans" and "all_findings"
                    for scan in data.get("scans", []):
                        for f in scan.get("findings", []):
                            findings.append(f"[{f.get('severity', 'INFO').upper()}] {f.get('title', '')} ({f.get('category', '')}) - {f.get('description', '')[:120]}")
                    if not findings:
                        for f in data.get("all_findings", []):
                            findings.append(f"[{f.get('severity', 'INFO').upper()}] {f.get('title', '')} ({f.get('category', '')}) - {f.get('description', '')[:120]}")
                    chains = []
                    for c in data.get("attack_chains", []):
                        chains.append(f"Attack Chain: {c.get('name', '')} (Severity: {c.get('severity', '')})")
                    return (
                        f"Target: {data.get('url', 'N/A')}\n"
                        f"Risk Score: {data.get('risk_score', 'N/A')}\n"
                        f"Total Findings: {len(findings)}\n"
                        f"Top Findings:\n" + "\n".join(findings[:15]) + "\n\n"
                        f"Attack Chains:\n" + ("\n".join(chains) if chains else "None")
                    )
                except Exception:
                    pass

        if not report:
            return (
                "NO_SCAN_DATA_AVAILABLE: No reconnaissance scan has been completed yet in this session "
                "and no 'recon_report.json' was found in the output directory.\n"
                "Please inform the operator:\n"
                "'No reconnaissance findings exist yet. Please run a reconnaissance audit via the CLI "
                "(e.g. py -m app.main <target_url>) or interactive wizard first, or provide a specific target URL so I can probe it directly using "
                "the 'http_probe' or 'inspect_web_page' tools.'\n"
                "Do NOT call 'run_security_tool' with empty arguments."
            )

        findings = []
        for sr in getattr(report, "scan_results", []):
            for f in sr.findings:
                sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                findings.append(f"[{sev_val.upper()}] {f.title} ({f.category}) - {f.description[:120]}")

        chains = []
        for c in getattr(report, "attack_chains", []):
            c_sev = c.severity.value if hasattr(c.severity, "value") else str(c.severity)
            chains.append(f"Attack Chain: {c.name} (Severity: {c_sev}) - Steps: {len(c.steps)}")

        return (
            f"Total Findings: {len(findings)}\n"
            f"Top Findings:\n" + "\n".join(findings[:12]) + "\n\n"
            f"Attack Chains:\n" + ("\n".join(chains) if chains else "None")
        )

    def _tool_lookup_vulnerability_intelligence(self, query: str = "", tech_stack: Optional[str] = None) -> str:
        """Query offline bug bounty vulnerability scenario intelligence database across 30,000+ entries."""
        try:
            from ..intelligence.engine import ScenarioEngine
            engine = ScenarioEngine()

            search_term = query or (tech_stack or "")
            if not search_term:
                return "Error: Either 'query' or 'tech_stack' parameter must be provided."

            recipes = []
            if query and tech_stack:
                tech_list = [t.strip() for t in tech_stack.split(",") if t.strip()]
                recipes = engine.search(query, tech_filter=tech_list, limit=4)
            elif tech_stack:
                tech_list = [t.strip() for t in tech_stack.split(",") if t.strip()]
                recipes = engine.find_scenarios_for_tech(tech_list, limit=4)
            elif query:
                recipes = engine.search(query, limit=4)

            # Query real-world datasets: Nuclei, PortSwigger, HackerOne reports, CISA KEV
            nuclei_matches = engine.search_nuclei(search_term, limit=3)
            ps_matches = engine.search_portswigger(search_term, limit=2)
            h1_reports = engine.search_hackerone(search_term, limit=3)
            cisa_kevs = engine.search_cisa_kev(search_term, limit=3)

            total_found = len(recipes) + len(nuclei_matches) + len(ps_matches) + len(h1_reports) + len(cisa_kevs)
            if total_found == 0:
                return f"No vulnerability intelligence entries found for query='{query}' tech_stack='{tech_stack}'."

            out = [f"=== Security & Bug Bounty Intelligence ({total_found} Records Found) ==="]

            if recipes:
                out.append("\n--- Curated Scenario Canary Recipes ---")
                for r in recipes:
                    out.append(
                        f"\n[SCENARIO] {r.title} ({r.id})\n"
                        f"CVSS: {r.cvss_vector} (CWE: {r.cwe})\n"
                        f"Technologies: {', '.join(r.tech_stack)}\n"
                        f"Reference: {r.bounty_reference or 'N/A'}\n"
                        f"Attack Pattern & Author Insight:\n  {r.author_insight}\n"
                        f"Canary Probe Pattern:\n  {r.probe_method} {r.probe_path}\n"
                        f"Remediation Guidance:\n  {r.remediation}"
                    )

            if nuclei_matches:
                out.append("\n--- Nuclei Community Template Signatures ---")
                for nuc in nuclei_matches:
                    out.append(
                        f"\n[NUCLEI] {nuc['name']} ({nuc['id']})\n"
                        f"Severity: {nuc['severity'].upper()} | CWE: {nuc['cwe']} | CVSS: {nuc['cvss']}\n"
                        f"Verification Probe: {nuc['method']} {nuc['path']}\n"
                        f"Signature Matcher: {nuc['matcher']}\n"
                        f"Description: {nuc['description']}"
                    )

            if ps_matches:
                out.append("\n--- PortSwigger Web Security Research ---")
                for ps in ps_matches:
                    out.append(
                        f"\n[PORTSWIGGER] {ps['title']} ({ps['id']})\n"
                        f"Category: {ps['category']} | CWE: {ps['cwe']} | CVSS: {ps['cvss_vector']}\n"
                        f"Attack Vector: {ps['attack_vector']}\n"
                        f"Diagnostic Probe: {ps['detection_probe']}\n"
                        f"Impact & Reference: {ps['impact']} ({ps['author_reference']})\n"
                        f"Remediation: {ps['remediation']}"
                    )

            if h1_reports:
                out.append("\n--- Real-World HackerOne Disclosed Reports ---")
                for h1 in h1_reports:
                    payout = f"${h1['bounty']:,.0f}" if h1['bounty'] > 0 else "Disclosed / VDP"
                    out.append(
                        f"\n[HACKERONE] {h1['title']}\n"
                        f"Program: {h1['program']} | Bounty: {payout} | Vulnerability: {h1['vuln_type']} ({h1['cwe']})\n"
                        f"Link: https://{h1['link']}"
                    )

            if cisa_kevs:
                out.append("\n--- CISA Known Exploited Vulnerabilities (KEV) ---")
                for kev in cisa_kevs:
                    out.append(
                        f"\n[CISA-KEV] {kev['cve_id']}: {kev['vuln_name']}\n"
                        f"Vendor/Product: {kev['vendor']} {kev['product']} | CWE: {kev['cwes']}\n"
                        f"Description: {kev['short_description'][:200]}\n"
                        f"Action: {kev['required_action']}"
                    )

            return "\n".join(out)
        except Exception as e:
            return f"Error querying vulnerability intelligence database: {e}"


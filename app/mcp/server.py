"""
WebRipper Recon 5.0 — Native Model Context Protocol (MCP) Server.

Enables Claude Code, Antigravity, Cursor, and other MCP-enabled AI coding agents
to perform reconnaissance, query security intelligence, execute canary probes,
and analyze attack chains natively via JSON-RPC 2.0 over stdio.
"""

from __future__ import annotations

import json
import logging
import os
import ssl
import sys
import time
from typing import Any, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen

# Setup logging to stderr to prevent corrupting stdio JSON-RPC protocol
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="[WebRipper-MCP] %(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("webripper_mcp")

SERVER_NAME = "webripper-recon"
SERVER_VERSION = "5.0.0"
PROTOCOL_VERSION = "2024-11-05"

# ---------------------------------------------------------------------------
# Tool Definitions
# ---------------------------------------------------------------------------

TOOLS: List[Dict[str, Any]] = [
    {
        "name": "webripper_scan",
        "description": "Execute an automated security reconnaissance audit against an authorized target URL. Discovers endpoints, secrets, CORS issues, missing headers, and fingerprint-targeted scenario vulnerabilities.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target base URL (e.g., https://example.com)"
                },
                "profile": {
                    "type": "string",
                    "enum": ["quick", "standard", "aggressive"],
                    "default": "quick",
                    "description": "Scan depth profile: 'quick' (passive/fast ~10s), 'standard' (balanced depth 2), 'aggressive' (deep active audit)"
                },
                "scanners": {
                    "type": "string",
                    "description": "Optional comma-separated list of scanners to run (e.g. 'secrets,headers,scenarios,cors,endpoints')"
                },
                "delay": {
                    "type": "number",
                    "default": 0.0,
                    "description": "Inter-request delay in seconds for respectful gateway pacing"
                }
            },
            "required": ["url"]
        }
    },
    {
        "name": "lookup_vulnerability_intelligence",
        "description": "Search the local 30,000+ security intelligence database across HackerOne writeups, Nuclei signatures, PortSwigger research, and CISA KEV active exploits.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search keyword, technology, or vulnerability name (e.g. 'Next.js', 'Spring Boot', 'Request Smuggling', 'Shopify')"
                },
                "tech_stack": {
                    "type": "string",
                    "description": "Optional technology filter (e.g. 'rails', 'nextjs', 'spring')"
                },
                "limit": {
                    "type": "integer",
                    "default": 5,
                    "description": "Maximum number of records to return per dataset"
                }
            },
            "required": ["query"]
        }
    },
    {
        "name": "run_canary_probe",
        "description": "Execute a focused, non-destructive canary verification check for a specific scenario ID on a target URL without running a full crawl.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {
                    "type": "string",
                    "description": "Target website base URL"
                },
                "scenario_id": {
                    "type": "string",
                    "description": "Identifier of the scenario canary recipe (e.g. 'H1-NEXTJS-001', 'H1-SPRING-001', 'H1-LARAVEL-001')"
                }
            },
            "required": ["target_url", "scenario_id"]
        }
    },
    {
        "name": "get_attack_chains",
        "description": "Retrieve correlated multi-step attack chains for a previously audited domain or target from the local history database.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Target domain or hostname"
                }
            },
            "required": ["domain"]
        }
    },
    {
        "name": "list_scans",
        "description": "List previous reconnaissance audit sessions and high-level vulnerability statistics from the local SQLite history.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "default": 10,
                    "description": "Maximum number of scans to retrieve"
                }
            }
        }
    },
    {
        "name": "webripper_watch_poll",
        "description": "Poll continuous monitoring watch mode targets and return change-only delta briefings.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Authorized target URL to monitor"
                },
                "authorized": {
                    "type": "boolean",
                    "description": "Explicit statement that target is authorized for monitoring"
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "webripper_diff_scans",
        "description": "Compute a change-only differential briefing between two scans.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "baseline_path": {
                    "type": "string",
                    "description": "Path to baseline scan JSON report"
                },
                "current_path": {
                    "type": "string",
                    "description": "Path to current scan JSON report"
                }
            },
            "required": ["baseline_path", "current_path"]
        }
    },
    {
        "name": "dismiss_finding",
        "description": "Dismiss a false-positive finding or rule pattern for local profile tuning.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "rule_id": {
                    "type": "string",
                    "description": "Rule identifier or title pattern to dismiss"
                },
                "target": {
                    "type": "string",
                    "description": "Optional target URL scope (empty for global)"
                },
                "rationale": {
                    "type": "string",
                    "description": "Reason for false-positive dismissal"
                }
            },
            "required": ["rule_id"]
        }
    },
    {
        "name": "get_feedback_stats",
        "description": "Retrieve statistics on local false-positive dismissals and profile tuning.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    }
]

# ---------------------------------------------------------------------------
# Tool Handlers
# ---------------------------------------------------------------------------

def _handle_scan(args: Dict[str, Any]) -> str:
    from ..models import RipperSettings
    from ..worker import RipperWorker

    url = (args.get("url") or args.get("target") or "").strip()
    profile = args.get("profile", "quick").strip().lower()
    scanners_arg = args.get("scanners", "")
    delay = float(args.get("delay", 0.0))
    authorized = bool(args.get("authorized", False) or args.get("explicit_authorization", False))

    if not url:
        return "Error: 'url' parameter is required."

    depth = 1 if profile == "quick" else (3 if profile == "aggressive" else 2)
    active_scanners = [s.strip() for s in scanners_arg.split(",") if s.strip()] if scanners_arg else []

    active_requested = any(s in active_scanners for s in ("vulns", "bola", "mcptarget", "graphql", "llmapp")) or profile in ("standard", "aggressive")
    if active_requested and not authorized:
        return (
            "Refused: Active verification modules (vulns, bola, mcptarget, graphql, llmapp) "
            "require explicit authorization on the target. Pass 'authorized': true in tool arguments "
            "if this target is within your authorized scope."
        )

    settings = RipperSettings(
        url=url,
        depth=depth,
        delay=delay,
        scan_scenarios=True,
        use_external_tools=False,
    )
    if active_scanners:
        settings.active_scanners = active_scanners

    events = []
    worker = RipperWorker(settings)
    worker.progress.connect(lambda ev: events.append(ev))
    worker.run()

    report = worker.report
    if not report:
        return f"Scan failed to generate report for {url}."

    findings = report.all_findings
    chains = report.attack_chains

    crit_count = sum(1 for f in findings if f.severity.value == "CRITICAL")
    high_count = sum(1 for f in findings if f.severity.value == "HIGH")
    med_count = sum(1 for f in findings if f.severity.value == "MEDIUM")
    low_count = sum(1 for f in findings if f.severity.value == "LOW")

    lines = [
        f"=== WebRipper Recon Scan Summary: {url} ===",
        f"Profile: {profile.upper()} | Risk Grade: {report.risk_score}",
        f"Findings: {len(findings)} total ({crit_count} Critical, {high_count} High, {med_count} Medium, {low_count} Low)",
        f"Correlated Attack Chains: {len(chains)}",
        "\n--- High & Critical Findings ---"
    ]

    high_crit = [f for f in findings if f.severity.value in ("CRITICAL", "HIGH")]
    if not high_crit:
        lines.append("Zero High or Critical findings detected.")
    else:
        for f in high_crit[:10]:
            lines.append(f"[{f.severity.value}] {f.title} ({f.category})")
            if f.url:
                lines.append(f"  URL: {f.url}")
            if f.remediation:
                lines.append(f"  Remediation: {f.remediation[:120]}")
            if f.poc_curl:
                lines.append(f"  PoC: {f.poc_curl}")

    if chains:
        lines.append("\n--- Identified Attack Chains ---")
        for c in chains:
            lines.append(f"⚡ [{c.severity.value}] {c.name}")
            lines.append(f"   Impact: {c.impact}")

    return "\n".join(lines)


def _handle_lookup_intel(args: Dict[str, Any]) -> str:
    from ..ai.tools import AgentToolbox
    toolbox = AgentToolbox(output_dir=".")
    query = args.get("query", "")
    tech = args.get("tech_stack", "")
    return toolbox.execute_tool("lookup_vulnerability_intelligence", {"query": query, "tech_stack": tech})


def _handle_run_canary(args: Dict[str, Any]) -> str:
    from ..intelligence.engine import get_engine
    target_url = args.get("target_url", "").strip()
    scenario_id = args.get("scenario_id", "").strip()

    if not target_url or not scenario_id:
        return "Error: Both 'target_url' and 'scenario_id' are required."

    engine = get_engine()
    recipe = engine.get_by_id(scenario_id)
    if not recipe:
        return f"Scenario ID '{scenario_id}' not found in intelligence database."

    probe_url = urljoin(target_url, recipe.probe_path.lstrip("/"))
    headers = {"User-Agent": "WebRipper-Recon/5.0 (MCP Authorized Security Assessment)"}
    if recipe.probe_headers:
        headers.update(recipe.probe_headers)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = Request(probe_url, headers=headers, method=recipe.probe_method)
    if recipe.probe_body:
        req.data = recipe.probe_body.encode("utf-8")

    status = 0
    body = ""
    try:
        with urlopen(req, timeout=15, context=ctx) as resp:
            status = resp.status
            body = resp.read().decode("utf-8", errors="ignore")[:3000]
    except HTTPError as e:
        status = e.code
        body = e.read().decode("utf-8", errors="ignore")[:3000]
    except Exception as e:
        return f"Canary probe failed to connect: {e}"

    import re
    is_match = False
    if status in recipe.match_status:
        if recipe.match_regex:
            is_match = bool(re.search(recipe.match_regex, body, re.IGNORECASE))
        else:
            is_match = True

    if is_match and recipe.negative_regex:
        if re.search(recipe.negative_regex, body, re.IGNORECASE):
            is_match = False

    result_status = "CONFIRMED VULNERABLE" if is_match else "NOT DETECTED / MITIGATED"
    return (
        f"=== Canary Probe Execution: {recipe.title} ({recipe.id}) ===\n"
        f"Target URL: {probe_url}\n"
        f"Status Code: {status}\n"
        f"Vulnerability Match Result: {result_status}\n"
        f"CVSS 3.1: {recipe.cvss_vector} (CWE: {recipe.cwe})\n"
        f"Historical Reference: {recipe.bounty_reference}\n"
        f"Evidence Excerpt:\n{body[:250].strip() or 'None'}\n"
        f"Remediation Guidance:\n{recipe.remediation}"
    )


def _handle_get_attack_chains(args: Dict[str, Any]) -> str:
    from ..history import list_scans
    domain = args.get("domain", "").strip()
    if not domain:
        return "Error: 'domain' is required."

    scans = list_scans(domain=domain)
    if not scans:
        return f"No previous reconnaissance scan history found for domain '{domain}'."

    out = [f"=== Attack Chains for Domain: {domain} ==="]
    chains_found = 0
    for sc in scans[:5]:
        chains = []
        if sc.path and os.path.exists(sc.path):
            try:
                with open(sc.path, "r", encoding="utf-8") as f:
                    hist_data = json.load(f)
                    chains = hist_data.get("attack_chains", [])
            except Exception:
                pass

        if chains:
            chains_found += len(chains)
            out.append(f"\nScan for {sc.domain} at {sc.timestamp} ({len(chains)} Attack Chains):")
            for c in chains:
                c_name = c.get("name", "Unnamed Chain")
                c_sev = c.get("severity", "HIGH")
                c_impact = c.get("impact", "")
                c_steps = c.get("steps", [])
                c_rem = c.get("remediation", "")
                out.append(f"  ● [{c_sev}] {c_name} ({len(c_steps)} steps)")
                if c_impact:
                    out.append(f"    Impact: {c_impact}")
                for s in c_steps:
                    s_desc = s.get("description", "")
                    s_cmd = s.get("command", "")
                    out.append(f"    ➜ Step: {s_desc}")
                    if s_cmd:
                        out.append(f"      PoC: {s_cmd}")
                if c_rem:
                    out.append(f"    Remediation: {c_rem}")
        else:
            out.append(f"\nScan for {sc.domain} at {sc.timestamp}: No attack chains formed (Findings: {sc.finding_count}).")

    if chains_found == 0:
        out.append(f"\nNo attack chains were formed in the recorded scans for domain '{domain}'.")

    return "\n".join(out)


def _handle_list_scans(args: Dict[str, Any]) -> str:
    from ..history import list_scans
    limit = int(args.get("limit", 10))
    scans = list_scans(limit=limit)
    if not scans:
        return "No scan history records found in local database."

    lines = [f"=== Recent Reconnaissance Audits ({len(scans[:limit])}) ==="]
    for s in scans[:limit]:
        lines.append(
            f"{s.timestamp} | Domain: {s.domain} | "
            f"Findings: {s.finding_count} (C:{s.critical_count}, H:{s.high_count}, M:{s.medium_count})"
        )
    return "\n".join(lines)


def _handle_watch_poll(args: Dict[str, Any]) -> str:
    from ..watch.engine import WatchEngine, WatchConfig, TargetConfig
    target = args.get("target", "").strip()
    authorized = bool(args.get("authorized", False))
    if not target:
        return "Error: 'target' is required."
    if not authorized:
        return "Error: Explicit authorization required ('authorized': true) to monitor this target."
    cfg = WatchConfig(targets=[TargetConfig(url=target, authorized=True)], schedule_interval="1h")
    engine = WatchEngine(cfg)
    report = engine.run_cycle_for_target(TargetConfig(url=target, authorized=True))
    if not report:
        return f"Watch poll cycle executed for {target}. No drift detected."
    return f"Watch cycle completed for {target}. New findings: {len(report.diff.new_findings)}, Resolved: {len(report.diff.resolved_findings)}."


def _handle_diff_scans(args: Dict[str, Any]) -> str:
    from ..watch.diff import HistoricalDiffEngine
    b_path = args.get("baseline_path", "").strip()
    c_path = args.get("current_path", "").strip()
    if not os.path.exists(b_path) or not os.path.exists(c_path):
        return "Error: Baseline or current scan path not found."
    with open(b_path, "r", encoding="utf-8") as f:
        b_data = json.load(f)
    with open(c_path, "r", encoding="utf-8") as f:
        c_data = json.load(f)
    diff = HistoricalDiffEngine().diff_scans(b_data, c_data)
    return diff.to_markdown()


def _handle_dismiss_finding(args: Dict[str, Any]) -> str:
    from ..intelligence.feedback import dismiss_finding
    rule_id = args.get("rule_id", "").strip()
    target = args.get("target", "").strip()
    rationale = args.get("rationale", "Dismissed via MCP")
    if not rule_id:
        return "Error: 'rule_id' is required."
    dismiss_finding(pattern_type="rule_id", target=target, rule_id=rule_id, rationale=rationale)
    return f"Rule '{rule_id}' has been dismissed in local profile feedback."


def _handle_get_feedback_stats(args: Dict[str, Any]) -> str:
    from ..intelligence.feedback import get_feedback_stats
    stats = get_feedback_stats()
    return json.dumps(stats, indent=2)


# ---------------------------------------------------------------------------
# JSON-RPC 2.0 Dispatcher
# ---------------------------------------------------------------------------

def process_request(request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Process single JSON-RPC 2.0 request and return response dict."""
    msg_id = request.get("id")
    method = request.get("method", "")
    params = request.get("params", {})

    if not method:
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32600, "message": "Invalid Request: missing method"}}

    # Notifications do not require responses
    if msg_id is None or method.startswith("notifications/"):
        return None

    if method == "ping":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {},
                    "resources": {},
                },
                "serverInfo": {
                    "name": SERVER_NAME,
                    "version": SERVER_VERSION
                }
            }
        }

    if method == "resources/list":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "resources": [
                    {
                        "uri": "recon://intelligence/stats",
                        "name": "Vulnerability Intelligence Statistics",
                        "description": "Statistics of indexed HackerOne disclosures, CVEs, Nuclei templates, and canary recipes.",
                        "mimeType": "application/json",
                    },
                    {
                        "uri": "recon://history/recent",
                        "name": "Recent Reconnaissance Audits",
                        "description": "Summary of historical reconnaissance scans and findings.",
                        "mimeType": "application/json",
                    },
                ]
            }
        }

    if method == "resources/read":
        uri = params.get("uri", "")
        if uri == "recon://intelligence/stats":
            from ..intelligence import get_engine
            engine = get_engine()
            stats = engine.stats()
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "contents": [{
                        "uri": uri,
                        "mimeType": "application/json",
                        "text": json.dumps(stats, indent=2),
                    }]
                }
            }
        elif uri == "recon://history/recent":
            from ..history import list_scans
            scans = list_scans(limit=10)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "contents": [{
                        "uri": uri,
                        "mimeType": "application/json",
                        "text": json.dumps([s.__dict__ if hasattr(s, "__dict__") else s for s in scans], indent=2),
                    }]
                }
            }
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32602, "message": f"Resource not found: {uri}"}
        }

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "tools": TOOLS
            }
        }

    if method == "tools/call":
        tool_name = params.get("name")
        args = params.get("arguments", {})

        try:
            if tool_name == "webripper_scan":
                content_text = _handle_scan(args)
            elif tool_name == "lookup_vulnerability_intelligence":
                content_text = _handle_lookup_intel(args)
            elif tool_name == "run_canary_probe":
                content_text = _handle_run_canary(args)
            elif tool_name == "get_attack_chains":
                content_text = _handle_get_attack_chains(args)
            elif tool_name == "list_scans":
                content_text = _handle_list_scans(args)
            elif tool_name == "webripper_watch_poll":
                content_text = _handle_watch_poll(args)
            elif tool_name == "webripper_diff_scans":
                content_text = _handle_diff_scans(args)
            elif tool_name == "dismiss_finding":
                content_text = _handle_dismiss_finding(args)
            elif tool_name == "get_feedback_stats":
                content_text = _handle_get_feedback_stats(args)
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [{"type": "text", "text": f"Error: Tool '{tool_name}' is not recognized."}],
                        "isError": True
                    }
                }

            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": content_text
                        }
                    ]
                }
            }
        except Exception as e:
            logger.error(f"Error executing tool {tool_name}: {e}")
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [{"type": "text", "text": f"Tool execution failed: {e}"}],
                    "isError": True
                }
            }

    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {"code": -32601, "message": f"Method '{method}' not found."}
    }


class WebRipperMCPServer:
    """Object wrapper for WebRipper MCP JSON-RPC Server."""

    def __init__(self):
        self.server_name = SERVER_NAME
        self.server_version = SERVER_VERSION

    def handle_request(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return process_request(request)


def run_mcp_server() -> int:
    """Run MCP server loop over stdin/stdout."""
    logger.info(f"Starting {SERVER_NAME} v{SERVER_VERSION} MCP Server over stdio...")

    # Set stdout to unbuffered or flush after each message
    for line in sys.stdin:
        line_clean = line.strip()
        if not line_clean:
            continue

        try:
            request = json.loads(line_clean)
            response = process_request(request)
            if response is not None:
                resp_json = json.dumps(response, separators=(',', ':'))
                sys.stdout.write(resp_json + "\n")
                sys.stdout.flush()
        except json.JSONDecodeError as err:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {err}"}
            }
            sys.stdout.write(json.dumps(err_resp) + "\n")
            sys.stdout.flush()
        except Exception as general_err:
            logger.error(f"Unexpected MCP server error: {general_err}")

    return 0


if __name__ == "__main__":
    sys.exit(run_mcp_server())

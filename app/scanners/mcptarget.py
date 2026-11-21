"""
Model Context Protocol (MCP) Server Auditor for WebRipper Recon.

Given an MCP server target (HTTP, SSE, or stdio JSON-RPC 2.0 endpoint), enumerates
all exposed tools via the standard JSON-RPC protocol (`tools/list`).

Audits exposed tools for:
  1. Dangerous exposed surfaces: shell, file execution, system tools (bash, exec,
     read_file, write_file, etc.) accessible without authentication or guardrails.
  2. Indirect prompt injection / instruction-injection patterns in tool descriptions
     (e.g., "Ignore previous instructions", system prompt overrides, evasion directives).

Strict Rule: Machine-checkable proof attached in metadata["proof"] with metadata["proof_attached"] = True.
"""

from __future__ import annotations

import hashlib
import json
import re
import ssl
import subprocess
import time
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse

from .base import BaseScanner
from ..models import (
    Finding,
    ProgressEvent,
    EventType,
    RipReport,
    RipperSettings,
    ScanResult,
    Severity,
)

# ---------------------------------------------------------------------------
# Dangerous Tool Patterns & Categorization
# ---------------------------------------------------------------------------

# Command execution / shell tools
_EXEC_TOOL_NAMES = frozenset({
    "bash", "sh", "zsh", "cmd", "powershell", "exec", "execute", "system_exec",
    "run_command", "run_shell", "terminal", "spawn", "eval", "system",
    "run_script", "run_process", "shell", "shell_command", "cli_run"
})

_EXEC_NAME_REGEX = re.compile(
    r"^(bash|sh|zsh|cmd|powershell|exec|execute|system_exec|run_command|run_shell|terminal|spawn|eval|system|run_script|shell)$"
    r"|(?:^|_)(bash|exec|shell|cmd|powershell|terminal)(?:_|$)",
    re.IGNORECASE,
)

_EXEC_DESC_REGEX = re.compile(
    r"(?:execute|run)\s+(?:arbitrary\s+)?(?:bash|shell|system|command|process|code)",
    re.IGNORECASE,
)

# Filesystem tools
_FS_TOOL_NAMES = frozenset({
    "read_file", "write_file", "edit_file", "delete_file", "fs_read", "fs_write",
    "list_directory", "rmdir", "unlink", "file_system", "file_read", "file_write",
    "remove_file", "modify_file", "cat_file"
})

_FS_NAME_REGEX = re.compile(
    r"^(read_file|write_file|edit_file|delete_file|fs_read|fs_write|modify_file|list_directory|rmdir|unlink|file_read|file_write|remove_file|cat_file)$"
    r"|(?:^|_)(read_file|write_file|edit_file|delete_file|fs_read|fs_write)(?:_|$)",
    re.IGNORECASE,
)

_FS_DESC_REGEX = re.compile(
    r"(?:read|write|delete|modify)\s+(?:arbitrary\s+)?(?:files|filesystem|file\b)",
    re.IGNORECASE,
)

# Sensitive / Network / Credential tools
_SENSITIVE_TOOL_NAMES = frozenset({
    "dump_env", "get_env", "read_secrets", "fetch_url", "curl", "http_request", "raw_socket"
})

# ---------------------------------------------------------------------------
# Instruction-Injection Patterns in Tool Descriptions
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"ignore\s+(?:all\s+|previous\s+|prior\s+)?instructions", re.IGNORECASE), "Instruction override ('ignore previous instructions')"),
    (re.compile(r"disregard\s+(?:all\s+|previous\s+|prior\s+)?instructions", re.IGNORECASE), "Instruction override ('disregard previous instructions')"),
    (re.compile(r"system\s*prompt\s*override", re.IGNORECASE), "System prompt override marker"),
    (re.compile(r"override\s+system\s+prompt", re.IGNORECASE), "System prompt override marker"),
    (re.compile(r"system\s*override", re.IGNORECASE), "System override directive"),
    (re.compile(r"new\s+(?:system\s+)?directive", re.IGNORECASE), "System directive injection"),
    (re.compile(r"you\s+must\s+(?:always\s+)?execute\s+this\s+tool", re.IGNORECASE), "Forced tool execution directive"),
    (re.compile(r"do\s+not\s+report\s+(?:errors|this)", re.IGNORECASE), "Stealth / evasion instruction"),
    (re.compile(r"(?:<system>|\[system\]|system:)", re.IGNORECASE), "System role spoofing marker"),
    (re.compile(r"(?:secretly\s+exfiltrate|send\s+(?:all\s+)?credentials)", re.IGNORECASE), "Exfiltration directive"),
    (re.compile(r"ai\s+assistant\s+directive", re.IGNORECASE), "AI assistant directive injection"),
]


class MCPTargetScanner(BaseScanner):
    """Audits Model Context Protocol (MCP) servers for dangerous tools and prompt injection."""

    @property
    def name(self) -> str:
        return "mcptarget"

    @property
    def description(self) -> str:
        return (
            "Audits Model Context Protocol (MCP) servers for exposed dangerous tools "
            "and indirect instruction-injection patterns in tool descriptions"
        )

    def _query_stdio_tools(self, command_str: str) -> List[Dict[str, Any]]:
        """Query tools/list from a stdio-based MCP server process."""
        cmd = command_str.replace("stdio://", "").replace("cmd://", "")
        req_msg = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {},
        }) + "\n"

        try:
            proc = subprocess.Popen(
                cmd,
                shell=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stdout_data, _ = proc.communicate(input=req_msg, timeout=10)
            for line in stdout_data.splitlines():
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    data = json.loads(line)
                    if "result" in data:
                        res = data["result"]
                        return res.get("tools", []) if isinstance(res, dict) else res
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            self._log(f"Stdio MCP query failed for command '{cmd}': {e}")
        return []

    def _query_http_tools(self, url: str) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Send JSON-RPC tools/list request to an HTTP or SSE MCP server endpoint.
        Returns (effective_endpoint, tools_list).
        """
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        headers = self._build_headers()
        headers["Content-Type"] = "application/json"
        headers["Accept"] = "application/json, text/event-stream, */*"

        timeout = min(getattr(self._settings, "timeout", 15), 15)
        proxy = self._get_proxy()
        opener = None
        if proxy:
            proxy_handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
            opener = urllib.request.build_opener(proxy_handler, urllib.request.HTTPSHandler(context=ctx))

        req_body = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {},
        }).encode("utf-8")

        # 1. First attempt direct POST to the given URL
        try:
            req = urllib.request.Request(url, data=req_body, headers=headers, method="POST")
            if opener:
                resp = opener.open(req, timeout=timeout)
            else:
                resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)

            with resp:
                content_type = resp.headers.get("Content-Type", "").lower()
                body_bytes = resp.read()
                body_str = body_bytes.decode("utf-8", errors="ignore")

                # If SSE response directly on POST
                if "text/event-stream" in content_type or "event:" in body_str:
                    tools = self._parse_sse_or_json(body_str)
                    if tools:
                        return url, tools

                # Normal JSON-RPC response
                try:
                    data = json.loads(body_str)
                    if "result" in data:
                        res = data["result"]
                        tools = res.get("tools", []) if isinstance(res, dict) else res
                        if isinstance(tools, list):
                            return url, tools
                except json.JSONDecodeError:
                    pass
        except Exception:
            pass

        # 2. Check SSE handshake (GET request to URL or /sse)
        try:
            req_get = urllib.request.Request(url, headers=headers, method="GET")
            if opener:
                resp_get = opener.open(req_get, timeout=timeout)
            else:
                resp_get = urllib.request.urlopen(req_get, timeout=timeout, context=ctx)

            with resp_get:
                sse_data = resp_get.read(4096).decode("utf-8", errors="ignore")
                # Parse endpoint event: event: endpoint\ndata: /messages?sessionId=...
                post_target = None
                lines = sse_data.splitlines()
                for i, line in enumerate(lines):
                    if line.startswith("event:") and "endpoint" in line:
                        for next_line in lines[i+1:]:
                            if next_line.startswith("data:"):
                                post_target = next_line.replace("data:", "").strip()
                                break
                    elif line.startswith("data:") and "/messages" in line:
                        post_target = line.replace("data:", "").strip()
                        break

                if post_target:
                    resolved_post_url = urljoin(url, post_target)
                    req_post = urllib.request.Request(resolved_post_url, data=req_body, headers=headers, method="POST")
                    if opener:
                        resp_post = opener.open(req_post, timeout=timeout)
                    else:
                        resp_post = urllib.request.urlopen(req_post, timeout=timeout, context=ctx)
                    with resp_post:
                        resp_post_data = resp_post.read().decode("utf-8", errors="ignore")
                        tools = self._parse_sse_or_json(resp_post_data)
                        if tools:
                            return resolved_post_url, tools
        except Exception:
            pass

        return url, []

    def _parse_sse_or_json(self, text: str) -> List[Dict[str, Any]]:
        """Extract tools from JSON string or SSE event data."""
        # Try direct JSON
        try:
            data = json.loads(text)
            if isinstance(data, dict) and "result" in data:
                res = data["result"]
                return res.get("tools", []) if isinstance(res, dict) else res
            elif isinstance(data, list):
                return data
        except json.JSONDecodeError:
            pass

        # Try lines in SSE format
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                payload = line[5:].strip()
                try:
                    data = json.loads(payload)
                    if isinstance(data, dict) and "result" in data:
                        res = data["result"]
                        return res.get("tools", []) if isinstance(res, dict) else res
                except json.JSONDecodeError:
                    continue
        return []

    def enumerate_tools(self, target: Optional[str] = None) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Enumerate exposed tools from the given target (or settings target URL) via JSON-RPC tools/list.
        Returns (effective_endpoint_url, tools_list).
        """
        url = target or self._settings.url or ""
        if not url:
            return "", []

        if url.startswith("stdio://") or url.startswith("cmd://"):
            return url, self._query_stdio_tools(url)

        # Try direct URL
        eff_url, tools = self._query_http_tools(url)
        if tools:
            return eff_url, tools

        # Try common MCP route candidates if base URL was provided
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        candidates = ["/mcp", "/sse", "/rpc", "/api/mcp", "/messages", "/"]
        for path in candidates:
            cand_url = urljoin(base, path)
            if cand_url == url:
                continue
            cand_eff, cand_tools = self._query_http_tools(cand_url)
            if cand_tools:
                return cand_eff, cand_tools

        return url, []

    def audit_tools(self, tools: List[Dict[str, Any]], endpoint_url: str = "") -> List[Finding]:
        """
        Audit a list of tool definitions for dangerous tools and instruction-injection patterns.
        Strictly produces deterministic proof with metadata["proof_attached"] = True.
        """
        findings: List[Finding] = []

        for tool in tools:
            if not isinstance(tool, dict):
                continue

            tool_name = str(tool.get("name", "")).strip()
            tool_desc = str(tool.get("description", "")).strip()
            tool_schema = tool.get("inputSchema", {}) or {}

            # -------------------------------------------------------------------
            # 1. Audit Exposed Dangerous Tools (Shell / Command / Filesystem)
            # -------------------------------------------------------------------
            is_exec_danger = (
                tool_name.lower() in _EXEC_TOOL_NAMES
                or bool(_EXEC_NAME_REGEX.search(tool_name))
                or bool(_EXEC_DESC_REGEX.search(tool_desc))
            )

            is_fs_danger = (
                tool_name.lower() in _FS_TOOL_NAMES
                or bool(_FS_NAME_REGEX.search(tool_name))
                or bool(_FS_DESC_REGEX.search(tool_desc))
            )

            is_sensitive_danger = tool_name.lower() in _SENSITIVE_TOOL_NAMES

            if is_exec_danger or is_fs_danger or is_sensitive_danger:
                if is_exec_danger:
                    severity = Severity.CRITICAL
                    risk_type = "Command / Shell Execution"
                    cwe = "CWE-78"
                elif is_fs_danger:
                    severity = Severity.HIGH
                    risk_type = "Arbitrary File System Access"
                    cwe = "CWE-73"
                else:
                    severity = Severity.HIGH
                    risk_type = "Sensitive Environment / Network Access"
                    cwe = "CWE-200"

                proof = {
                    "tool_name": tool_name,
                    "endpoint": endpoint_url,
                    "risk_type": risk_type,
                    "request": {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/list",
                    },
                    "response": {
                        "tool": tool,
                    },
                    "observed_delta": (
                        f"Dangerous system tool '{tool_name}' ({risk_type}) exposed without guardrails "
                        f"in JSON-RPC tools/list response."
                    ),
                }

                findings.append(Finding(
                    severity=severity,
                    category="mcptarget",
                    title=f"Exposed Dangerous MCP Tool: {tool_name} ({risk_type})",
                    description=(
                        f"The MCP server at '{endpoint_url or 'target'}' exposes a dangerous tool '{tool_name}' "
                        f"classified as {risk_type}. Without strict authentication and isolation, an AI agent or "
                        f"untrusted prompt can invoke this tool to compromise the host system."
                    ),
                    evidence=f"Tool: {tool_name} | Description: {tool_desc}",
                    url=endpoint_url,
                    confidence="VERIFIED",
                    remediation=(
                        "Restrict or disable dangerous tools in production MCP servers. Implement strict parameter "
                        "sandboxing, path containment, least-privilege execution containers, and require explicit human-in-the-loop "
                        "approval before tool invocation."
                    ),
                    metadata={
                        "proof": proof,
                        "proof_attached": True,
                        "tool_name": tool_name,
                        "tool_schema": tool_schema,
                        "tool_description": tool_desc,
                        "risk_type": risk_type,
                        "cwe": cwe,
                        "owasp": "ASI02:2025-Tool-Execution-Abuse",
                    },
                ))

            # -------------------------------------------------------------------
            # 2. Audit Tool Descriptions for Indirect Instruction Injection
            # -------------------------------------------------------------------
            for pattern, pattern_name in _INJECTION_PATTERNS:
                match = pattern.search(tool_desc)
                if match:
                    matched_snippet = match.group(0)

                    proof = {
                        "tool_name": tool_name,
                        "endpoint": endpoint_url,
                        "pattern_name": pattern_name,
                        "matched_snippet": matched_snippet,
                        "request": {
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "tools/list",
                        },
                        "response": {
                            "tool_name": tool_name,
                            "description": tool_desc,
                        },
                        "observed_delta": (
                            f"Indirect instruction injection detected in tool '{tool_name}' description: "
                            f"matched pattern '{matched_snippet}'."
                        ),
                    }

                    findings.append(Finding(
                        severity=Severity.HIGH,
                        category="mcptarget",
                        title=f"Instruction Injection in MCP Tool Description: {tool_name}",
                        description=(
                            f"The MCP tool '{tool_name}' carries an indirect instruction-injection pattern "
                            f"('{pattern_name}') inside its description: '{matched_snippet}'. When this MCP server "
                            f"is registered with an AI coding agent or LLM client, this description is injected into "
                            f"the agent's system prompt context, allowing untrusted tool providers to hijack agent behavior."
                        ),
                        evidence=f"Matched pattern '{pattern_name}' in tool '{tool_name}' description: '{matched_snippet}'",
                        url=endpoint_url,
                        confidence="VERIFIED",
                        remediation=(
                            "Sanitize tool descriptions before loading them into AI agent context. Strip instruction "
                            "override markers, and enforce delimiters to prevent tool metadata from acting as system directives."
                        ),
                        metadata={
                            "proof": proof,
                            "proof_attached": True,
                            "tool_name": tool_name,
                            "pattern_name": pattern_name,
                            "matched_text": matched_snippet,
                            "cwe": "CWE-77",
                            "owasp": "LLM01:2025-Prompt-Injection",
                        },
                    ))
                    break  # Avoid duplicate injection findings on the same tool description

        return findings

    def scan(self) -> ScanResult:
        """Run the MCP target scan, enumerate tools via JSON-RPC, and audit risks."""
        start = time.time()
        target_url = self._settings.url
        self._log(f"Auditing MCP target at: {target_url}")

        effective_url, tools = self.enumerate_tools()
        self._log(f"Enumerated {len(tools)} tool(s) from MCP target {effective_url}")

        if tools:
            findings = self.audit_tools(tools, endpoint_url=effective_url)
            for f in findings:
                self._add_finding(f)

        self._log(f"MCP audit complete: {len(self._findings)} finding(s) detected.")
        return self._build_result(
            start,
            tools_count=len(tools),
            effective_url=effective_url,
            findings_count=len(self._findings),
        )

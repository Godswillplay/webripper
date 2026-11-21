"""
API endpoint and route mapper for WebRipper Recon.

Extracts REST endpoints, GraphQL operations, WebSocket URLs, and route
definitions from JavaScript files.
"""

from __future__ import annotations

import os
import re
import time
from typing import Dict, List, Set
from urllib.parse import urlparse

from .base import BaseScanner
from ..models import Finding, ScanResult, Severity


# ---------------------------------------------------------------------------
# Regex patterns for endpoint extraction
# ---------------------------------------------------------------------------

# REST API paths in string literals
_RE_API_PATH = re.compile(
    r"""['"`]\s*(/(?:api|v[0-9]|auth|admin|user|users|account|profile|settings"""
    r"""|dashboard|upload|download|webhook|callback|search|health|status|metrics"""
    r"""|login|logout|register|signup|signin|verify|reset|confirm|graphql|gql"""
    r"""|ws|socket|notification|message|chat|feed|posts?|comments?|orders?"""
    r"""|products?|items?|cart|checkout|payment|billing|subscription"""
    r"""|config|token|session|oauth|sso|saml)"""
    r"""[/a-zA-Z0-9_\-{}:.?=&+$]*)['"`]""",
    re.IGNORECASE,
)

_THIRD_PARTY_DOMAINS = {
    "google-analytics.com", "googletagmanager.com", "sentry.io",
    "facebook.com", "twitter.com", "linkedin.com", "cloudflare.com",
    "jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com", "bootstrapcdn.com",
    "w3.org", "schema.org", "github.com",
}

# Axios/fetch with method
_RE_AXIOS_METHOD = re.compile(
    r"""(?:axios|fetch|http|api|request|client)\s*\.\s*(get|post|put|patch|delete|head|options)\s*\(\s*['"`]([^'"`]+)['"`]""",
    re.IGNORECASE,
)

# fetch() with method in options
_RE_FETCH_METHOD = re.compile(
    r"""fetch\s*\(\s*['"`]([^'"`]+)['"`]\s*,\s*\{[^}]*method\s*:\s*['"`](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['"`]""",
    re.IGNORECASE | re.DOTALL,
)

# Full API URLs
_RE_FULL_API_URL = re.compile(
    r"""['"`](https?://[^\s'"`]+/(?:api|v[0-9]|graphql|rest|rpc)[^\s'"`]*)['"`]""",
    re.IGNORECASE,
)

# GraphQL operations
_RE_GRAPHQL_OP = re.compile(
    r"""(?:query|mutation|subscription)\s+([A-Z][a-zA-Z0-9_]+)""",
)

# WebSocket URLs
_RE_WEBSOCKET = re.compile(
    r"""['"`](wss?://[^\s'"`]+)['"`]""",
    re.IGNORECASE,
)

# Base URL config
_RE_BASE_URL = re.compile(
    r"""(?:API_(?:BASE_)?URL|BASE_URL|BACKEND_URL|API_HOST|SERVER_URL|API_ENDPOINT|REACT_APP_API)\s*[:=]\s*['"`]([^'"`]+)['"`]""",
    re.IGNORECASE,
)

# Route definitions (React Router, Vue Router, etc.)
_RE_ROUTE_PATH = re.compile(
    r"""path\s*:\s*['"`](/[^'"`]*)['"`]""",
)
_RE_ROUTE_COMPONENT = re.compile(
    r"""Route[^>]*path\s*=\s*['"`](/[^'"`]*)['"`]""",
)

# URL template parameters
_RE_URL_PARAMS = re.compile(r":([a-zA-Z_][a-zA-Z0-9_]*)|{([a-zA-Z_][a-zA-Z0-9_]*)}")


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class EndpointScanner(BaseScanner):
    """Extracts API endpoints, routes, and service URLs from JavaScript files."""

    @property
    def name(self) -> str:
        return "endpoints"

    @property
    def description(self) -> str:
        return "Extracts API endpoints, routes, and service URLs from JavaScript files"

    def scan(self) -> ScanResult:
        start = time.time()

        js_files = self._get_downloaded_files((".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"))
        html_files = self._get_downloaded_files((".html", ".htm"))
        all_files = js_files + html_files

        self._log(f"Scanning {len(all_files)} files for API endpoints...")

        endpoints: Dict[str, Dict] = {}  # path -> {method, sources, ...}
        base_urls: Set[str] = set()
        graphql_ops: Set[str] = set()

        for file_result in all_files:
            try:
                with open(file_result.local_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(1_000_000)  # 1 MB max per file
            except (OSError, IOError):
                continue

            source = os.path.basename(file_result.local_path)

            # Extract API paths
            for m in _RE_API_PATH.finditer(content):
                path = m.group(1).strip()
                if len(path) > 3 and not path.startswith("//"):
                    key = path
                    if key not in endpoints:
                        endpoints[key] = {"method": "UNKNOWN", "sources": set(), "params": []}
                    endpoints[key]["sources"].add(source)

            # Extract method + URL from axios/fetch
            for m in _RE_AXIOS_METHOD.finditer(content):
                method = m.group(1).upper()
                path = m.group(2).strip()
                if path:
                    if path not in endpoints:
                        endpoints[path] = {"method": method, "sources": set(), "params": []}
                    else:
                        if endpoints[path]["method"] == "UNKNOWN":
                            endpoints[path]["method"] = method
                    endpoints[path]["sources"].add(source)

            # Extract fetch with method in options
            for m in _RE_FETCH_METHOD.finditer(content):
                path = m.group(1).strip()
                method = m.group(2).upper()
                if path:
                    if path not in endpoints:
                        endpoints[path] = {"method": method, "sources": set(), "params": []}
                    else:
                        if endpoints[path]["method"] == "UNKNOWN":
                            endpoints[path]["method"] = method
                    endpoints[path]["sources"].add(source)

            # Extract full API URLs
            for m in _RE_FULL_API_URL.finditer(content):
                url = m.group(1).strip()
                if url:
                    parsed_u = urlparse(url)
                    if any(tp in parsed_u.netloc.lower() for tp in _THIRD_PARTY_DOMAINS):
                        continue
                    if url not in endpoints:
                        endpoints[url] = {"method": "UNKNOWN", "sources": set(), "params": []}
                    endpoints[url]["sources"].add(source)

            # Extract GraphQL operations
            for m in _RE_GRAPHQL_OP.finditer(content):
                graphql_ops.add(m.group(1))

            # Extract WebSocket URLs
            for m in _RE_WEBSOCKET.finditer(content):
                ws_url = m.group(1).strip()
                if ws_url not in endpoints:
                    endpoints[ws_url] = {"method": "WS", "sources": set(), "params": []}
                endpoints[ws_url]["sources"].add(source)

            # Extract base URLs
            for m in _RE_BASE_URL.finditer(content):
                base_urls.add(m.group(1).strip())

            # Extract route definitions
            for pattern in (_RE_ROUTE_PATH, _RE_ROUTE_COMPONENT):
                for m in pattern.finditer(content):
                    path = m.group(1).strip()
                    if path and path not in endpoints:
                        endpoints[path] = {"method": "ROUTE", "sources": set(), "params": []}
                    if path:
                        endpoints[path]["sources"].add(source)

        # Ingest dynamic network requests recorded during stealth crawl
        captured = getattr(self._report, "captured_requests", [])
        for req in captured:
            if not isinstance(req, dict):
                continue
            req_url = req.get("url", "").strip() if isinstance(req.get("url"), str) else ""
            if not req_url:
                continue
            req_method = str(req.get("method", "GET")).upper()
            req_type = str(req.get("resource_type", "api"))
            src_tag = f"runtime:network ({req_type})"

            parsed_req = urlparse(req_url)
            path_key = parsed_req.path if parsed_req.path else req_url
            if parsed_req.query:
                path_key = f"{path_key}?{parsed_req.query}"

            if path_key not in endpoints:
                endpoints[path_key] = {"method": req_method, "sources": set(), "params": []}
            else:
                if endpoints[path_key]["method"] == "UNKNOWN":
                    endpoints[path_key]["method"] = req_method
            endpoints[path_key]["sources"].add(src_tag)

        # Extract URL parameters
        for path, info in endpoints.items():
            params = []
            for m in _RE_URL_PARAMS.finditer(path):
                params.append(m.group(1) or m.group(2))
            info["params"] = params

        # Create findings
        for path, info in sorted(endpoints.items()):
            method = info["method"]
            sources = sorted(info["sources"])
            params = info["params"]

            desc = f"Method: {method}"
            if params:
                desc += f", Parameters: {', '.join(params)}"
            desc += f", Found in: {', '.join(sources[:3])}"

            # Determine exploit intel based on endpoint characteristics
            ei_exploit = "Attacker tests this endpoint for: authentication bypass (access without token), IDOR (change IDs to access other users' data), injection (SQLi/NoSQLi in parameters), and rate limiting."
            ei_impact = "Unauthorized data access, injection attacks"
            ei_cwe = "CWE-200"
            ei_owasp = "A01:2021 Broken Access Control"
            ei_time = "~5-15 minutes per endpoint"
            path_lower = path.lower()

            if any(kw in path_lower for kw in ("/admin", "/dashboard", "/manage", "/internal")):
                ei_exploit = "Admin/internal endpoint exposed in client-side code. Attacker accesses directly — test for missing auth, default credentials, or privilege escalation."
                ei_impact = "Potential admin access, privilege escalation"
                ei_cwe = "CWE-284"
            elif any(kw in path_lower for kw in ("/upload", "/file", "/import")):
                ei_exploit = "File upload endpoint — attacker uploads webshell (.php, .jsp), path traversal filenames (../../etc/passwd), or oversized files for DoS."
                ei_impact = "Remote code execution via webshell, DoS"
                ei_cwe = "CWE-434"
                ei_owasp = "A04:2021 Insecure Design"
            elif any(kw in path_lower for kw in ("/auth", "/login", "/token", "/oauth", "/session")):
                ei_exploit = "Authentication endpoint — attacker tests for: credential stuffing, brute force, JWT manipulation, OAuth misconfiguration, session fixation."
                ei_impact = "Authentication bypass, account takeover"
                ei_cwe = "CWE-287"
                ei_owasp = "A07:2021 Identification and Authentication Failures"
            elif any(kw in path_lower for kw in ("/search", "/query", "/filter")):
                ei_exploit = "Search/query endpoint — high injection risk. Test: /search?q=' OR 1=1-- and /search?q=<script>alert(1)</script> for SQLi and reflected XSS."
                ei_impact = "SQL injection, XSS"
                ei_cwe = "CWE-89"
                ei_owasp = "A03:2021 Injection"
            elif method == "WS":
                ei_exploit = "WebSocket endpoint — often lacks same authentication as REST. Attacker connects directly with wscat and sends crafted messages to test for injection and auth bypass."
                ei_impact = "Real-time data interception, injection via WebSocket"
                ei_cwe = "CWE-345"

            self._add_finding(Finding(
                severity=Severity.INFO,
                category="endpoints",
                title=path,
                description=desc,
                evidence=f"{method} {path}",
                metadata={
                    "method": method,
                    "full_url": path,
                    "source_files": sources,
                    "params": params,
                    "exploit": ei_exploit,
                    "impact": ei_impact,
                    "cwe": ei_cwe,
                    "owasp": ei_owasp,
                    "time_to_exploit": ei_time,
                },
            ))

        # GraphQL operation findings
        for op_name in sorted(graphql_ops):
            self._add_finding(Finding(
                severity=Severity.INFO,
                category="endpoints",
                title=f"GraphQL: {op_name}",
                description=f"GraphQL operation '{op_name}' found in source code",
                evidence=op_name,
                metadata={
                    "type": "graphql_operation",
                    "exploit": "Attacker uses introspection query to map entire GraphQL schema: {__schema{types{name,fields{name,args{name}}}}}, then crafts targeted queries to extract all data, test for injection in arguments, and bypass field-level authorization.",
                    "impact": "Full API schema disclosure, targeted data extraction, potential injection",
                    "cwe": "CWE-200",
                    "owasp": "A01:2021 Broken Access Control",
                    "time_to_exploit": "~10 minutes",
                },
            ))

        # Organize by method for metadata
        by_method: Dict[str, List[str]] = {}
        for path, info in endpoints.items():
            method = info["method"]
            by_method.setdefault(method, []).append(path)

        self._log(f"Found {len(endpoints)} endpoints, {len(graphql_ops)} GraphQL operations")
        return self._build_result(
            start,
            total_unique_endpoints=len(endpoints),
            endpoints_by_method={k: len(v) for k, v in by_method.items()},
            base_urls=sorted(base_urls),
            graphql_operations=sorted(graphql_ops),
        )

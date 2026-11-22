"""
WebRipper Recon 5.0 — Data models.

Defines all dataclasses and enums shared across modules:
  - RipperSettings: crawl & scan configuration
  - ProgressEvent / EventType: real-time progress reporting
  - FileResult: per-file download result (with response headers)
  - RipReport: crawl session summary
  - Finding / Severity: individual security finding
  - ScanResult: output from a single scanner
  - AttackChain: correlated attack path across findings
  - ReconReport: full recon session output
  - ToolStatus: external tool detection status
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Size formatting
# ---------------------------------------------------------------------------

def _format_size(size_bytes: int) -> str:
    """Return human-readable file size string."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 ** 3:
        return f"{size_bytes / 1024 ** 2:.1f} MB"
    else:
        return f"{size_bytes / 1024 ** 3:.2f} GB"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class EventType(Enum):
    """Types of progress events emitted by the ripper engine."""
    PHASE_CHANGE = "phase_change"
    FILE_DOWNLOADED = "file_downloaded"
    FILE_FAILED = "file_failed"
    LOG = "log"
    COMPLETE = "complete"
    CANCELLED = "cancelled"
    SCAN_PROGRESS = "scan_progress"
    SCAN_FINDING = "scan_finding"
    SCAN_COMPLETE = "scan_complete"
    TOOL_PROGRESS = "tool_progress"
    TOOL_COMPLETE = "tool_complete"
    CORRELATION_COMPLETE = "correlation_complete"


class Severity(Enum):
    """Finding severity levels, ordered from most to least critical."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        """Numeric weight for scoring."""
        return {
            "CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 3, "INFO": 0,
        }[self.value]

    def __lt__(self, other: Any) -> bool:
        if isinstance(other, Severity):
            return self.weight < other.weight
        return NotImplemented

    def __le__(self, other: Any) -> bool:
        if isinstance(other, Severity):
            return self.weight <= other.weight
        return NotImplemented

    def __gt__(self, other: Any) -> bool:
        if isinstance(other, Severity):
            return self.weight > other.weight
        return NotImplemented

    def __ge__(self, other: Any) -> bool:
        if isinstance(other, Severity):
            return self.weight >= other.weight
        return NotImplemented


class Confidence(str, Enum):
    """Finding confidence levels — how certain we are this is real."""
    VERIFIED = "VERIFIED"    # Payload sent and response proves the vulnerability
    LIKELY = "LIKELY"        # Strong signal from active probing (e.g., specific error)
    POSSIBLE = "POSSIBLE"    # Heuristic or pattern match, may be false positive
    INFO = "INFO"            # Informational, not a vulnerability


class ScanProfile(Enum):
    """Scan depth profiles."""
    QUICK = "quick"         # Built-in scanners only, no port scan
    STANDARD = "standard"   # Built-in + port scan + tools if found
    AGGRESSIVE = "aggressive"  # Everything, full wordlists, all tools


# ---------------------------------------------------------------------------
# Crawl settings
# ---------------------------------------------------------------------------

@dataclass
class RipperSettings:
    """Configuration for a crawl + scan session."""
    url: str = ""
    output_dir: str = ""

    # Crawl behavior
    same_origin_only: bool = True
    include_external: bool = False
    max_files: int = 1000
    timeout: int = 30
    delay: float = 0.0
    rate_limit_delay: Optional[float] = None
    dynamic_capture: bool = True

    # Recursive crawling
    depth: int = 1              # 1 = single page, 2+ = follow links
    workers: int = 3            # concurrent download workers
    respect_robots: bool = False

    # Network
    proxy: str = ""             # e.g. http://127.0.0.1:8080 for Burp
    custom_headers: Dict[str, str] = field(default_factory=dict)
    custom_cookies: str = ""
    user_agent: str = "WebRipper-Recon/5.0"

    # Authentication
    auth_cookie: str = ""       # Cookie header value for authenticated scanning
    auth_token: str = ""        # Bearer token for authenticated scanning

    # Dual-identity differential scanning (BOLA/IDOR & BFLA)
    identity_a_cookie: str = ""
    identity_a_token: str = ""
    identity_b_cookie: str = ""
    identity_b_token: str = ""
    identity_a_tenant_marker: str = ""
    identity_b_tenant_marker: str = ""

    # Multi-target
    multi_targets: List[str] = field(default_factory=list)  # additional URLs

    # Scanner toggles (built-in)
    scan_secrets: bool = True
    scan_headers: bool = True
    scan_tech: bool = True
    scan_endpoints: bool = True
    scan_paths: bool = True
    scan_cors: bool = True
    scan_javascript: bool = True
    scan_forms: bool = True
    scan_tls: bool = True
    scan_cookies: bool = True
    scan_subdomains: bool = True
    scan_ports: bool = True
    scan_waf: bool = True
    scan_dns: bool = True
    scan_emails: bool = True
    scan_screenshots: bool = True
    scan_github_dork: bool = True
    scan_vulns: bool = True       # active vulnerability testing (XSS/SQLi/SSRF/LFI)
    scan_cves: bool = True        # CVE mapping for detected libraries
    scan_scenarios: bool = True   # Real-world bug bounty scenario intelligence
    scan_bola: bool = False       # Dual-identity differential BOLA/IDOR and BFLA (requires auth credentials)
    scan_llmapp: bool = False     # AI/LLM prompt injection canary scanner (active module)
    scan_mcptarget: bool = False  # Model Context Protocol target auditor (requires opt-in)
    scan_graphql: bool = False    # GraphQL schema & authorization auditor (active module)
    authorized: bool = False      # Explicit authorization scope for active verification modules
    enable_dedup: bool = True     # SimHash clustering and submission quality guard
    feedback_profile: str = ""    # Local feedback profile name (suppression & downranking)
    active_scanners: List[str] = field(default_factory=list)  # explicit scanner whitelist
    wordlist_path: str = ""     # custom wordlist override

    # Scan profile
    profile: str = "standard"   # quick / standard / aggressive

    # External tools
    use_external_tools: bool = True  # run detected tools
    enable_zap: bool = True          # OWASP ZAP passive proxy inspection
    tool_timeout: int = 120          # timeout for external tools (seconds)

    # Local AI settings
    enable_ai: bool = False
    ai_model: str = "dolphin3-cyber:8b"
    ai_endpoint: str = "http://127.0.0.1:11434"

    def __post_init__(self) -> None:
        if self.rate_limit_delay is not None:
            self.delay = self.rate_limit_delay
        elif self.delay:
            self.rate_limit_delay = self.delay

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "output_dir": self.output_dir,
            "same_origin_only": self.same_origin_only,
            "include_external": self.include_external,
            "max_files": self.max_files,
            "timeout": self.timeout,
            "delay": self.delay,
            "dynamic_capture": self.dynamic_capture,
            "depth": self.depth,
            "workers": self.workers,
            "respect_robots": self.respect_robots,
            "proxy": self.proxy,
            "custom_headers": self.custom_headers,
            "user_agent": self.user_agent,
            "profile": self.profile,
            "use_external_tools": self.use_external_tools,
            "enable_zap": self.enable_zap,
            "scan_secrets": self.scan_secrets,
            "scan_headers": self.scan_headers,
            "scan_tech": self.scan_tech,
            "scan_endpoints": self.scan_endpoints,
            "scan_paths": self.scan_paths,
            "scan_cors": self.scan_cors,
            "scan_javascript": self.scan_javascript,
            "scan_forms": self.scan_forms,
            "scan_tls": self.scan_tls,
            "scan_cookies": self.scan_cookies,
            "scan_subdomains": self.scan_subdomains,
            "scan_ports": self.scan_ports,
            "scan_waf": self.scan_waf,
            "scan_dns": self.scan_dns,
            "scan_emails": self.scan_emails,
            "scan_screenshots": self.scan_screenshots,
            "scan_github_dork": self.scan_github_dork,
            "scan_vulns": self.scan_vulns,
            "scan_cves": self.scan_cves,
            "scan_scenarios": self.scan_scenarios,
            "scan_bola": self.scan_bola,
            "scan_llmapp": self.scan_llmapp,
            "scan_mcptarget": self.scan_mcptarget,
            "scan_graphql": self.scan_graphql,
            "authorized": self.authorized,
            "enable_dedup": self.enable_dedup,
            "feedback_profile": self.feedback_profile,
            "identity_a_cookie": self.identity_a_cookie,
            "identity_a_token": self.identity_a_token,
            "identity_b_cookie": self.identity_b_cookie,
            "identity_b_token": self.identity_b_token,
            "identity_a_tenant_marker": self.identity_a_tenant_marker,
            "identity_b_tenant_marker": self.identity_b_tenant_marker,
            "active_scanners": self.active_scanners,
            "auth_cookie": self.auth_cookie,
            "auth_token": self.auth_token,
            "custom_cookies": self.custom_cookies,
            "wordlist_path": self.wordlist_path,
            "tool_timeout": self.tool_timeout,
            "multi_targets": self.multi_targets,
            "enable_ai": self.enable_ai,
            "ai_model": self.ai_model,
            "ai_endpoint": self.ai_endpoint,
        }


# ---------------------------------------------------------------------------
# Progress events
# ---------------------------------------------------------------------------

@dataclass
class ProgressEvent:
    """Real-time progress event emitted during crawl/scan."""
    event_type: EventType
    message: str = ""
    downloaded: int = 0
    failed: int = 0
    total: int = 0
    phase: str = ""
    finding: Optional[Finding] = None  # type: ignore[name-defined]  # forward ref


# ---------------------------------------------------------------------------
# File result
# ---------------------------------------------------------------------------

@dataclass
class FileResult:
    """Result of downloading a single file."""
    url: str = ""
    status: int = 0
    size: int = 0
    content_type: str = ""
    local_path: str = ""
    error: str = ""
    response_headers: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d: dict = {"url": self.url, "status": self.status, "size": self.size}
        if self.content_type:
            d["content_type"] = self.content_type
        if self.local_path:
            d["local_path"] = self.local_path
        if self.error:
            d["error"] = self.error
        if self.response_headers:
            d["response_headers"] = self.response_headers
        return d


# ---------------------------------------------------------------------------
# Rip report
# ---------------------------------------------------------------------------

@dataclass
class RipReport:
    """Summary of a completed crawl session."""
    url: str = ""
    start_time: str = ""
    end_time: str = ""
    settings: dict = field(default_factory=dict)
    files: List[FileResult] = field(default_factory=list)
    total_downloaded: int = 0
    total_failed: int = 0
    total_size: int = 0
    pages_crawled: int = 0
    pages: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    captured_requests: List[Dict[str, Any]] = field(default_factory=list)
    unreachable: bool = False

    def to_dict(self) -> dict:
        summary = {
            "total_downloaded": self.total_downloaded,
            "total_failed": self.total_failed,
            "total_size": self.total_size,
            "total_size_human": _format_size(self.total_size),
            "pages_crawled": self.pages_crawled,
        }
        return {
            "url": self.url,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "settings": self.settings,
            "pages_crawled": self.pages_crawled,
            "total_downloaded": self.total_downloaded,
            "total_failed": self.total_failed,
            "total_size": self.total_size,
            "total_size_human": _format_size(self.total_size),
            "summary": summary,
            "captured_requests": self.captured_requests,
            "files": [f.to_dict() for f in self.files],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)


# ---------------------------------------------------------------------------
# Security findings
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A single security finding from any scanner or tool."""
    severity: Severity
    category: str           # e.g. "secrets", "headers", "tech", "paths", "nmap", etc.
    title: str
    description: str
    evidence: str = ""
    file_path: str = ""
    line_number: int = 0
    url: str = ""
    remediation: str = ""
    confidence: str = "POSSIBLE"   # VERIFIED / LIKELY / POSSIBLE / INFO
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if hasattr(self.confidence, "value"):
            self.confidence = str(self.confidence.value)
        elif not isinstance(self.confidence, str):
            self.confidence = str(self.confidence)
        if isinstance(self.severity, str):
            try:
                self.severity = Severity[self.severity.upper()]
            except KeyError:
                self.severity = Severity.INFO

    def __setattr__(self, name: str, value: Any) -> None:
        if name == "confidence":
            if hasattr(value, "value"):
                value = str(value.value)
            elif value is not None and not isinstance(value, str):
                value = str(value)
        elif name == "severity":
            if isinstance(value, str):
                try:
                    value = Severity[value.upper()]
                except KeyError:
                    value = Severity.INFO
        super().__setattr__(name, value)

    @property
    def exploit_info(self) -> str:
        """Return the exploit scenario from metadata."""
        return self.metadata.get("exploit", "")

    @property
    def impact_info(self) -> str:
        """Return the impact description from metadata."""
        return self.metadata.get("impact", "")

    @property
    def cwe(self) -> str:
        """Return CWE identifier from metadata."""
        return self.metadata.get("cwe", "")

    @property
    def wasc(self) -> str:
        """Return WASC identifier from metadata."""
        return self.metadata.get("wasc", "")

    @property
    def owasp(self) -> str:
        """Return OWASP category from metadata."""
        return self.metadata.get("owasp", "")

    @property
    def poc_curl(self) -> str:
        """Return reproduction curl command if available or synthesize fallback."""
        if self.metadata and "poc_curl" in self.metadata:
            return self.metadata["poc_curl"]
        if self.url and (self.url.startswith("http://") or self.url.startswith("https://")):
            method = self.metadata.get("method", "GET") if self.metadata else "GET"
            return f"curl -i -s -k -X {method} '{self.url}'"
        return ""

    def to_dict(self) -> dict:
        d = {
            "severity": self.severity.value,
            "category": self.category,
            "title": self.title,
            "description": self.description,
        }
        if self.evidence:
            d["evidence"] = self.evidence
        if self.file_path:
            d["file_path"] = self.file_path
        if self.line_number:
            d["line_number"] = self.line_number
        if self.url:
            d["url"] = self.url
        if self.remediation:
            d["remediation"] = self.remediation
        if self.poc_curl:
            d["poc_curl"] = self.poc_curl
        if self.metadata:
            d["metadata"] = self.metadata
        if self.confidence:
            d["confidence"] = self.confidence.value if hasattr(self.confidence, "value") else str(self.confidence)
        return d


@dataclass
class ScanResult:
    """Output from a single scanner module or external tool."""
    scanner_name: str
    description: str = ""
    scan_time: float = 0.0  # seconds
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    def to_dict(self) -> dict:
        return {
            "scanner_name": self.scanner_name,
            "description": self.description,
            "scan_time": round(self.scan_time, 2),
            "summary": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
                "total": len(self.findings),
            },
            "findings": [f.to_dict() for f in self.findings],
            "metadata": self.metadata,
        }


# ---------------------------------------------------------------------------
# Attack chain (from correlator)
# ---------------------------------------------------------------------------

@dataclass
class AttackChainStep:
    """One step in an attack chain."""
    description: str
    finding: Optional[Finding] = None
    source: str = ""        # which scanner/tool produced this step
    command: str = ""       # exploit command for this step
    confidence: str = "POSSIBLE"

    def __post_init__(self) -> None:
        if hasattr(self.confidence, "value"):
            self.confidence = str(self.confidence.value)
        elif not isinstance(self.confidence, str):
            self.confidence = str(self.confidence)

    def __setattr__(self, name: str, value: Any) -> None:
        if name == "confidence":
            if hasattr(value, "value"):
                value = str(value.value)
            elif value is not None and not isinstance(value, str):
                value = str(value)
        super().__setattr__(name, value)

    def to_dict(self) -> dict:
        d = {"description": self.description, "source": self.source}
        if self.command:
            d["command"] = self.command
        if self.finding:
            d["finding"] = self.finding.to_dict()
        if hasattr(self, "confidence") and self.confidence:
            d["confidence"] = self.confidence.value if hasattr(self.confidence, "value") else str(self.confidence)
        return d


@dataclass
class AttackChain:
    """A correlated attack path across multiple findings."""
    name: str                   # e.g. "Source Code Leak → Database Compromise"
    severity: Severity
    steps: List[AttackChainStep] = field(default_factory=list)
    impact: str = ""            # what the attacker ultimately gains
    time_to_exploit: str = ""   # estimated time
    remediation: str = ""       # how to break the chain
    confidence: str = "POSSIBLE"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if hasattr(self.confidence, "value"):
            self.confidence = str(self.confidence.value)
        elif not isinstance(self.confidence, str):
            self.confidence = str(self.confidence)
        if isinstance(self.severity, str):
            try:
                self.severity = Severity[self.severity.upper()]
            except KeyError:
                self.severity = Severity.INFO

    def __setattr__(self, name: str, value: Any) -> None:
        if name == "confidence":
            if hasattr(value, "value"):
                value = str(value.value)
            elif value is not None and not isinstance(value, str):
                value = str(value)
        elif name == "severity":
            if isinstance(value, str):
                try:
                    value = Severity[value.upper()]
                except KeyError:
                    value = Severity.INFO
        super().__setattr__(name, value)

    def to_dict(self) -> dict:
        d = {
            "name": self.name,
            "severity": self.severity.value if hasattr(self.severity, "value") else str(self.severity),
            "steps": [s.to_dict() for s in self.steps],
            "impact": self.impact,
            "time_to_exploit": self.time_to_exploit,
            "remediation": self.remediation,
        }
        if hasattr(self, "confidence") and self.confidence:
            d["confidence"] = self.confidence.value if hasattr(self.confidence, "value") else str(self.confidence)
        if hasattr(self, "metadata") and self.metadata:
            d["metadata"] = self.metadata
        return d


# ---------------------------------------------------------------------------
# Tool status
# ---------------------------------------------------------------------------

@dataclass
class ToolStatus:
    """Status of an external security tool."""
    name: str
    installed: bool = False
    version: str = ""
    path: str = ""
    installable: bool = False   # can WebRipper auto-install it?
    install_size: str = ""      # estimated download size
    install_url: str = ""       # download URL

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "installed": self.installed,
            "version": self.version,
            "path": self.path,
            "installable": self.installable,
            "install_size": self.install_size,
        }


# ---------------------------------------------------------------------------
# Recon report (top-level output)
# ---------------------------------------------------------------------------

@dataclass
class ReconReport:
    """Complete recon session output including crawl + all scan results."""
    url: str = ""
    start_time: str = ""
    end_time: str = ""
    settings: dict = field(default_factory=dict)
    rip_report: Optional[RipReport] = None
    scan_results: List[ScanResult] = field(default_factory=list)
    attack_chains: List[AttackChain] = field(default_factory=list)
    tool_status: List[ToolStatus] = field(default_factory=list)
    tool_commands: Dict[str, str] = field(default_factory=dict)  # tool -> manual command
    ai_summary: str = ""                                         # AI-generated threat narrative
    unreachable: bool = False

    @property
    def scans(self) -> List[ScanResult]:
        """Convenience alias for scan_results."""
        return self.scan_results

    @property
    def technologies(self) -> List[str]:
        """Extract detected technology stack names from scan results."""
        techs: List[str] = []
        for sr in self.scan_results:
            if sr.scanner_name == "tech":
                for f in sr.findings:
                    if f.title:
                        techs.append(f.title)
        return list(dict.fromkeys(techs))

    @property
    def all_findings(self) -> List[Finding]:
        findings = []
        for sr in self.scan_results:
            findings.extend(sr.findings)
        return findings

    @property
    def risk_score(self) -> str:
        """Compute an overall risk grade A-F based on findings."""
        # Any verified critical finding or chain results in immediate failing grade
        has_critical = any(f.severity == Severity.CRITICAL for f in self.all_findings) or any(c.severity == Severity.CRITICAL for c in self.attack_chains)
        if has_critical:
            return "F"

        total = sum(f.severity.weight for f in self.all_findings)
        # Attack chains amplify risk
        chain_bonus = sum(c.severity.weight * 2 for c in self.attack_chains)
        total += chain_bonus

        if total == 0:
            return "A"
        elif total <= 10:
            return "B"
        elif total <= 30:
            return "C"
        elif total <= 80:
            return "D"
        else:
            return "F"

    def to_dict(self) -> dict:
        d = {
            "url": self.url,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "risk_score": self.risk_score,
            "settings": self.settings,
            "crawl": self.rip_report.to_dict() if self.rip_report else {},
            "scans": [sr.to_dict() for sr in self.scan_results],
            "attack_chains": [c.to_dict() for c in self.attack_chains],
            "tool_status": [t.to_dict() for t in self.tool_status],
            "tool_commands": self.tool_commands,
            "ai_summary": self.ai_summary,
        }
        if getattr(self, "unreachable", False):
            d["unreachable"] = True
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)


class WebRipperJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder handling Enum, datetime, dataclasses, and objects with to_dict."""
    def default(self, obj: Any) -> Any:
        if isinstance(obj, Enum) or hasattr(obj, "value"):
            return obj.value
        if hasattr(obj, "to_dict") and callable(obj.to_dict):
            return obj.to_dict()
        if hasattr(obj, "isoformat") and callable(obj.isoformat):
            return obj.isoformat()
        return str(obj)

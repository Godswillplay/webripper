# WEBRIPPER RECON 5.0 — TECHNICAL ENGINEERING SPECIFICATION

```
========================================================================================
WEBRIPPER RECON 5.0 — PURE-CLI & AGENT-NATIVE TECHNICAL SPECIFICATION
========================================================================================
```

## 1. Specification Scope

This document specifies the internal architecture, data contracts, and algorithmic behavior of **WebRipper Recon 5.0**. 

WebRipper Recon 5.0 is an authorized, non-destructive, agent-native web security reconnaissance and attack-surface auditing engine built in Python 3.11+. The system is designed for automated execution in CI/CD pipelines, autonomous AI coding agent workflows (Claude Code, Cursor, Antigravity), and interactive terminal sessions for human operators.

---

## 2. System Architecture & Component Inventory

### 2.1 File & Module Layout
```
c:\Users\JAI\Desktop\webripper2.0\
├── main.py                          # Unified launcher (delegates to app.main)
├── AGENT_GUIDE.md                   # Comprehensive guide for AI agents (Claude, Cursor)
├── CLAUDE.md                        # Developer cheat-sheet and command reference
├── README.md                        # Public repository README & user manual
├── WEBRIPPER_RECON_SPECIFICATION.md # Technical engineering specification (this file)
├── .cursorrules                     # Cursor AI IDE project rules
├── .cursorignore                    # Cursor AI semantic indexing exclusions
├── .cursor/
│   ├── mcp.json                     # Cursor MCP tool definitions
│   └── rules/
│       └── webripper.mdc            # Modular Cursor rules definition
├── app/
│   ├── __init__.py                  # Version declaration (__version__ = "5.0.0")
│   ├── main.py                      # Application bootstrap & CLI dispatcher
│   ├── cli.py                       # Terminal Wizard & Headless CLI Engine
│   ├── worker.py                    # Multi-stage asynchronous worker pipeline
│   ├── ripper.py                    # Stealth Playwright crawler & asset mirror
│   ├── stealth.py                   # Anti-fingerprint Playwright flags & AutoThrottle
│   ├── correlator.py                # 15 Correlated Attack Chains Engine
│   ├── cvss.py                      # CVSS v3.1 calculation & risk grading
│   ├── models.py                    # Dataclasses, Enums, and finding schemas
│   ├── report.py                    # D3.js interactive HTML & JSON reporter
│   ├── history.py                   # SQLite local scan database & diffing engine
│   ├── dependencies.py              # Playwright browser detector
│   ├── intelligence/
│   │   ├── __init__.py              # Intelligence module exports
│   │   ├── engine.py                # SQLite FTS5 hybrid search engine
│   │   ├── catalog.py               # Core scenario seed definitions
│   │   ├── models.py                # ScenarioRecipe schema
│   │   └── intel.db                 # SQLite FTS5 database (30,297 records)
│   ├── mcp/
│   │   ├── __init__.py              # Package init
│   │   ├── __main__.py              # python -m app.mcp entrypoint
│   │   └── server.py                # Stdio JSON-RPC 2.0 MCP Server
│   ├── scanners/                    # 21 specialized security audit scanners
│   │   ├── base.py                  # BaseScanner parent class
│   │   ├── scenarios.py             # Scanner #21: Targeted bug bounty canary probes
│   │   ├── tech.py                  # Framework & Favicon hash fingerprinting
│   │   ├── secrets.py               # Shannon entropy & regex key scanner
│   │   ├── endpoints.py             # Route & API discovery
│   │   ├── javascript.py            # Static taint analysis (DOM XSS sinks)
│   │   ├── forms.py                 # Form audit & CSRF validation
│   │   ├── cookies.py               # Cookie security analysis
│   │   ├── cves.py                  # Public CVE cross-referencing
│   │   ├── headers.py               # Security header validation
│   │   ├── cors.py                  # Active CORS origin reflection probing
│   │   ├── tls.py                   # SSL certificate & cipher auditing
│   │   ├── dns.py                   # DNS enumeration & subdomain takeover
│   │   ├── portscan.py              # Non-blocking TCP socket port scanner
│   │   ├── waf.py                   # WAF detection & evasion profiling
│   │   ├── subdomains.py            # Subdomain brute-force enumeration
│   │   ├── paths.py                 # Sensitive file fuzzing (.env, .git)
│   │   ├── vulns.py                 # Active benign injection probing
│   │   ├── github_dork.py           # GitHub leak reconnaissance
│   │   ├── emails.py                # Email & OSINT extraction
│   │   └── screenshots.py           # Playwright full-page screenshot renderer
│   └── tools/                       # External CLI tool orchestration
│       ├── base.py                  # Tool data structures
│       ├── detector.py              # Tool detection across PATH
│       ├── installer.py             # Asynchronous GitHub release installer
│       └── runner.py                # Tool execution with timeout control
├── docs/                            # Deep-dive documentation
│   ├── ARCHITECTURE.md              # Pipeline & concurrency architecture
│   ├── SCENARIO_INTELLIGENCE.md     # SQLite FTS5 database & canary probes
│   ├── ATTACK_CHAINS.md             # 15 attack chain catalog & PoCs
│   └── MCP_SPECIFICATION.md         # MCP tool schemas & wire protocol
└── tests/                           # Pytest test suite (185 tests passing)
```

---

## 3. Data Contracts & Model Specifications

### 3.1 Severity Metric (`Severity`)
Finding severities are strictly typed and ordered:
```python
class Severity(Enum):
    CRITICAL = "CRITICAL"  # Weight: 40
    HIGH = "HIGH"          # Weight: 20
    MEDIUM = "MEDIUM"      # Weight: 10
    LOW = "LOW"            # Weight: 3
    INFO = "INFO"          # Weight: 0
```

### 3.2 Finding Data Contract (`Finding`)
Each scanner produces normalized `Finding` objects:
```python
@dataclass
class Finding:
    id: str                          # Unique identifier (e.g. 'sec-001')
    title: str                       # Concise human-readable title
    category: str                    # Scanner category ('secrets', 'cors', etc.)
    severity: Severity               # Typed severity enum
    evidence: str                    # Sanitized excerpt or payload response
    description: str = ""            # Technical explanation of vulnerability
    url: str = ""                    # Vulnerable endpoint or asset path
    cvss: float = 0.0                # Calculated CVSS v3.1 score (0.0 - 10.0)
    cwe: str = ""                    # CWE taxonomy identifier (e.g. 'CWE-798')
    remediation: str = ""            # Step-by-step remediation advice
    confidence: Confidence = LIKELY  # VERIFIED, LIKELY, or POSSIBLE
    metadata: Dict[str, Any] = None  # Arbitrary auxiliary telemetry
```

### 3.3 Semantic Exit Codes
The CLI engine evaluates scan outcomes and returns standard semantic exit codes:
- **`0` (`EXIT_CLEAN`)**: All scanners finished without discovering CRITICAL or HIGH findings.
- **`1` (`EXIT_ERROR`)**: Unhandled exception, invalid CLI options, or network unreachability.
- **`2` (`EXIT_RISK_DETECTED`)**: One or more **CRITICAL** or **HIGH** severity findings detected.
- **`3` (`EXIT_WAF_BLOCKED`)**: Traffic restricted by a Web Application Firewall (HTTP 403 / Cloudflare).
- **`4` (`EXIT_RATE_LIMITED`)**: Target enforced HTTP 429 Too Many Requests.

---

## 4. Crawling & Auto-Throttling Mechanics

### 4.1 Anti-Fingerprint Evasion
`app/stealth.py` configures Playwright Chromium instances with:
- `AutomationControlled` disabled in Chromium Blink features.
- Realistic `User-Agent` strings matching modern Chrome desktop clients.
- JS evaluation hooks that delete `window.navigator.webdriver`.
- Viewport randomization within realistic desktop display boundaries.

### 4.2 AutoThrottle Algorithm
The `AutoThrottle` class regulates request pacing:
```python
class AutoThrottle:
    def __init__(self, target_latency: float = 1.0, min_delay: float = 0.0, max_delay: float = 60.0):
        self.target_latency = target_latency
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.current_delay = min_delay

    def record_response(self, latency: float, status_code: int) -> None:
        if status_code == 429:
            self.current_delay = min(self.max_delay, max(self.current_delay * 2, 1.0))
        elif latency > self.target_latency:
            self.current_delay = min(self.max_delay, self.current_delay + 0.1)
        else:
            self.current_delay = max(self.min_delay, self.current_delay * 0.95)

    def get_delay(self) -> float:
        """Deterministic base delay."""
        return self.current_delay

    def delay_for(self) -> float:
        """Jittered delay for socket sleep operations (±15%)."""
        jitter = random.uniform(0.85, 1.15)
        return self.current_delay * jitter
```

---

## 5. Testing & Quality Assurance Standards

- **Python Interpreter**: Python 3.11+
- **Test Suite**: Pytest suite in `tests/` covering:
  - CLI argument parsing, interactive wizard, and semantic exit codes.
  - Scanner logic across all 21 scanners.
  - Correlation engine and 15 attack chain synthesis.
  - SQLite FTS5 intelligence engine search and canary probe validation.
  - Model Context Protocol (MCP) server tools, resources, and error handling.
  - AutoThrottle latency adaptation and deterministic delay calculation.
  - Baseline diffing regression calculations.
- **All 185 tests must pass with zero errors and zero regressions**.

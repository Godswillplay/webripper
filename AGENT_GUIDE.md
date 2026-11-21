# WebRipper Recon 5.0 — Autonomous Security Agent & CI/CD Operational Guide

## 1. System Overview & Purpose
WebRipper Recon 5.0 is an authorized, non-destructive web security posture assessment and reconnaissance engine designed for software engineering teams, DevSecOps pipelines, and autonomous AI coding agents (Claude Code, Antigravity, Cursor, GitHub Copilot).

The engine operates under defensive security paradigms, adhering to RFC standards, OWASP Web Security Testing Guides (WSTG), CWE taxonomies, and CVSS 3.1 severity metrics to identify configuration oversights, credential leaks, and exposed service endpoints before production deployment.

---

## 2. Headless & Agent-Native Architecture
WebRipper Recon 5.0 is decoupled from graphical user interfaces. It runs as a pure Python 3.11+ headless engine with zero desktop framework dependencies, optimized for programmatic orchestration:
- **Zero-GUI / Pure Python Runtime**: Compatible with Linux containers, Docker runners, GitHub Actions, and headless cloud nodes.
- **Deterministic Semantic Exit Codes**: Enables automated build gating and CI/CD decision logic.
- **JSON & Structured Artifacts**: Full machine-readable audit reports (`report.json` and self-contained `report.html`).
- **Offline Intelligence Engine**: Embedded SQLite FTS5 database containing bug bounty scenario recipes, CVSS scores, and remediation advice.

---

## 3. Command-Line Reference & Flag Specification

### Common Invocations

```bash
# Automated audit with standard profile (default depth 2)
python -m app.main https://staging.example.com -o report.html --json report.json

# Focused security posture review (only secrets, headers, and scenario canary probes)
python -m app.main https://staging.example.com --scanners secrets,headers,scenarios --headless

# Rate-controlled audit with request pacing
python -m app.main https://staging.example.com --profile standard --delay 0.5 -q

# Query vulnerability scenario intelligence directly from CLI
python -m app.main --intel-query "Next.js Server Actions"

# Interactive wizard mode (for manual operator walkthrough)
python -m app.main --wizard
```

### Complete Parameter Matrix

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `target` or `--url` | String | Positional | Target domain or base URL for authorized audit. |
| `--profile` | Enum | `standard` | Audit depth: `quick` (passive), `standard` (balanced), `aggressive` (deep). |
| `-o`, `--output` | Path | None | Path for generated self-contained HTML executive report. |
| `--json` | Path | None | Path for structured JSON finding export. |
| `--depth` | Integer | `2` | Web crawler link traversal depth limit. |
| `--timeout` | Integer | `30` | Per-request network socket timeout in seconds. |
| `--delay` | Float | `0.0` | Injected delay between consecutive HTTP requests (seconds). |
| `--scanners` | Comma List| All | Selectively execute specific scanners (e.g. `secrets,headers,scenarios`). |
| `--no-scenarios` | Flag | False | Disables Scanner #21 (Bug bounty intelligence canary probes). |
| `--no-tools` | Flag | False | Disables external tool execution (Nmap, Nuclei, SQLmap). |
| `--cookie` | String | None | Session cookie string for authorized authenticated auditing. |
| `--token` | String | None | Bearer token for authorized API auditing. |
| `--header` | String | None | Custom HTTP header (format `'Key: Value'`, repeatable). |
| `--intel-query` | String | None | Queries local SQLite FTS5 intelligence catalog and exits. |
| `-q`, `--quiet` | Flag | False | Suppresses interactive console output; preserves machine exit code. |
| `-v`, `--verbose` | Flag | False | Enables detailed per-file download and scanner log streaming. |

---

## 4. Semantic Exit Codes for Autonomous Decision Making
When orchestrating WebRipper Recon within scripts or CI/CD pipelines, inspect `$LASTEXITCODE` (PowerShell) or `$?` (Bash):

| Exit Code | Classification | Meaning & Recommended Action |
| :---: | :--- | :--- |
| **`0`** | **CLEAN** | Audit completed successfully. Zero CRITICAL or HIGH findings detected. Deployment may proceed. |
| **`1`** | **ERROR** | Operational failure (network failure, DNS unresolvable, syntax or configuration error). Verify target connectivity. |
| **`2`** | **RISK_DETECTED** | Security findings of **CRITICAL** or **HIGH** severity detected (e.g., exposed API keys, unauthenticated endpoints). Review findings before production release. |
| **`3`** | **WAF_BLOCKED** | Audit traffic was restricted by a Security Gateway or Web Application Firewall (Cloudflare, Akamai 403). Lower concurrency or whitelist scanning IP. |
| **`4`** | **RATE_LIMITED** | Target enforced HTTP 429 Too Many Requests. Increase `--delay` (e.g. `--delay 1.0`) and re-run. |

---

## 5. Vulnerability Scenario Intelligence Engine (Scanner #21 & Offline DB)
WebRipper Recon 5.0 ships with a local, zero-dependency SQLite FTS5 database (`app/intelligence/intel.db`) containing **30,297 indexed security intelligence records**:
- **11,835 Nuclei Community Templates**: Request signatures, verification probes, headers, CVEs, CWEs, severity metrics, and matchers across all web protocols.
- **1,363 Scenario Canary Recipes**: Curated framework misconfigurations and high-confidence Nuclei verification probes with exact HTTP methods, paths, regex matchers, CVSS vectors, and remediation steps.
- **15,219 HackerOne Disclosed Bug Bounty Reports**: Real-world bug writeups, program names, payouts (up to $50,000+), upvotes, and direct disclosure links.
- **1,790 CISA Known Exploited Vulnerabilities (KEV)**: Catalog of actively exploited vulnerabilities in the wild, vendor/product affected, and mandatory mitigation requirements.
- **14 PortSwigger Web Security Research Methodologies**: Advanced attack patterns (HTTP Request Smuggling, Web Cache Poisoning/Deception, Prototype Pollution, OAuth traversal, JWT algorithm confusion, SSRF metadata exfiltration).
- **76 Subdomain Takeover Cloud Fingerprints**: CNAME patterns and response fingerprints from `can-i-take-over-xyz`.

### How Scanner #21 Operates
1. **Fingerprint Awareness**: Detects technology stacks (e.g. Next.js, Supabase, Spring Boot, Laravel, Django, WordPress, Apache, Kubernetes).
2. **Selective Canary Probing**: Issues 15–20 targeted, non-destructive canary requests tailored strictly to detected technologies (preventing rate-limiting and WAF bans).
3. **CISA KEV Cross-Referencing**: Automatically cross-references detected software components with active CISA KEV exploit advisories.
4. **Structured Attribution**: Findings include CVSS 3.1 scores, CWE references, HackerOne case citations, and explicit remediation code.

### Querying Intelligence via AI Agent Toolbox
AI agents can directly query the embedded intelligence using the `lookup_vulnerability_intelligence` tool:
```json
{
  "name": "lookup_vulnerability_intelligence",
  "arguments": {
    "query": "Shopify GraphQL",
    "tech_stack": "rails"
  }
}
```
This returns matching scenario canary probes, Nuclei community signatures, PortSwigger research patterns, real-world HackerOne disclosed reports with payouts, and active CISA KEV entries.

---

## 6. Native Model Context Protocol (MCP) Server
WebRipper Recon 5.0 includes a production-grade, zero-dependency MCP server operating over stdio via JSON-RPC 2.0:
- **Direct Invocation**:
  ```bash
  python -m app.mcp
  # or
  python -m app.main --mcp
  ```
- **Supported MCP Tools**:
  - `webripper_scan`: Initiates background reconnaissance audit against an authorized target and returns structured findings.
  - `lookup_vulnerability_intelligence`: Instant FTS5 search across 30,000+ Nuclei, HackerOne, CISA KEV, and Scenario records.
  - `run_canary_probe`: Executes a specific targeted non-destructive canary verification probe against a target URL.
  - `get_attack_chains`: Synthesizes correlated multi-step attack chains for a target domain from scan history.
  - `list_scans`: Lists past reconnaissance sessions with finding counts, grades, and timestamps from SQLite history.
- **Configured Clients**:
  Configured out-of-the-box for Cursor, Claude Code, and Antigravity via `.mcp.json` and `.cursor/mcp.json`.

---

## 7. Real-Time Telemetry Streaming & Baseline Diffing Engine

### NDJSON Telemetry Streaming (`--json-stream`, `--stream-file`)
Designed for pipeline orchestration and live monitoring in AI agent loops and CI/CD:
```bash
# Stream real-time events to stdout (suppresses decorative UI)
python -m app.main https://staging.example.com --json-stream

# Write telemetry stream to file while maintaining normal console output
python -m app.main https://staging.example.com --stream-file /var/log/recon_telemetry.ndjson
```
Event schema:
- `scan_started`: Target, timestamp, profile, crawl depth.
- `phase_change`: Active scanner phase transitions and progress descriptions.
- `finding_discovered`: Live vulnerability detection alerts with severity, category, and URL.
- `crawl_progress`: Real-time downloaded vs total queue statistics.
- `scan_completed`: Final summary, elapsed seconds, finding counts by severity.

### Baseline Diffing Engine (`--diff`)
Enables automated security regression testing between builds:
```bash
python -m app.main https://staging.example.com --diff baseline_report.json -o current_report.html
```
- **Automated Categorization**:
  - `[+] New Vulnerabilities (Regressions)`: Issues present in current scan but absent in baseline (flagged in red/yellow).
  - `[-] Remediated Vulnerabilities (Resolved)`: Issues resolved since baseline audit (flagged in green).
  - `[=] Persisting Findings`: Unchanged findings between audits.
- **Diff Artifact**: Emits `recon_diff.json` in asset directory containing complete regression analysis.

---

## 8. Modern Attack Chains (Chains 10–15)
The correlation engine (`app/correlator.py`) automatically discovers multi-finding exploitation paths:
- **Chain 10 (Next.js)**: Next.js Source Maps & Server Actions -> Internal API Exploitation.
- **Chain 11 (Spring Boot)**: Spring Boot Actuator Exposure -> Cloud IMDS / SSRF Infrastructure Takeover.
- **Chain 12 (Takeover)**: Subdomain Takeover + OAuth Redirect Whitelist -> Account Hijacking.
- **Chain 13 (CORS)**: CORS Origin Reflection + Sensitive API -> Client-Side Data Exfiltration.
- **Chain 14 (GraphQL)**: GraphQL Introspection -> Batched Mutation Rate-Limit Bypass.
- **Chain 15 (Smuggling)**: HTTP Request Smuggling (CL.TE / TE.CL) -> Web Cache Poisoning.

---

## 9. Passive Favicon Hash Fingerprinting
Scanner #02 (`TechScanner`) automatically extracts `/favicon.ico` and compares MD5 hashes against known enterprise and framework signatures (Spring Boot, Jenkins, Django, WordPress, GitLab, Grafana, Kibana, Tomcat, phpMyAdmin) to fingerprint backend frameworks even when HTTP headers are scrubbed.

---

## 10. Defensive Compliance & Responsible Usage
- **Authorization**: Audits must only be conducted against systems, domains, and applications where explicit authorization has been granted by the system owner.
- **Safe Probes**: All default canary probes are non-destructive and verify accessibility/configuration without modifying application state or injecting malicious payloads.
- **Reporting**: All outputs should be shared through secure internal reporting channels or coordinated vulnerability disclosure programs.

# CLAUDE.md — WebRipper Recon Developer & Agent Instructions

## Commands
- **Run All Tests**: `python -m pytest tests/ -v`
- **Run Single Test**: `python -m pytest tests/test_cli_and_wizard.py -v`
- **Run Interactive Wizard**: `python -m app.main` or `python -m app.main --wizard`
- **Run CLI Scan**: `python -m app.main https://target.local --profile standard -o report.html --json report.json`
- **Stream Telemetry**: `python -m app.main https://target.local --json-stream`
- **Diff Against Baseline**: `python -m app.main https://target.local --diff prev_report.json`
- **Run Native MCP Server**: `python -m app.mcp` or `python -m app.main --mcp`
- **Query Vulnerability Intel**: `python -m app.main --intel-query "query"`

---

## Architectural Principles
1. **Pure CLI / Headless Engine**: WebRipper Recon is an agent-native, pure Python 3.11+ security reconnaissance and posture assessment tool. Desktop GUI frameworks (PySide6/Qt) have been retired. Do not reintroduce Qt dependencies.
2. **Defensive Posture Assessment**: All features operate under ethical, authorized, non-destructive verification standards (OWASP WSTG, CWE, CVSS 3.1).
3. **Native MCP Server**: Embedded stdio JSON-RPC 2.0 server (`app.mcp`) provides direct tool execution (`webripper_scan`, `lookup_vulnerability_intelligence`, `run_canary_probe`, `get_attack_chains`, `list_scans`) for Claude Code, Cursor, and Antigravity.
4. **Real-Time Telemetry & Diffing**: CLI supports live NDJSON streaming (`--json-stream`, `--stream-file`) and automated baseline diffing (`--diff`) outputting `recon_diff.json`.
5. **Scenario Intelligence (Scanner #21)**: Real-world bug bounty intelligence is ingested into an offline SQLite FTS5 database (`app/intelligence/`). Scanner #21 matches detected technology stacks and issues a focused set of non-destructive canary probes (15-20 max) to prevent rate-limiting and WAF blocking.
6. **Modern Attack Chains**: Correlation engine connects multi-step vectors across Next.js, Spring Boot + Cloud IMDS, Subdomain Takeover + OAuth, CORS + REST, GraphQL Introspection, and Request Smuggling.
7. **Semantic Exit Codes**:
   - `0`: Clean execution, zero CRITICAL/HIGH findings.
   - `1`: Operational error / unhandled exception.
   - `2`: Security issues detected (CRITICAL or HIGH severity findings).
   - `3`: Gateway or Web Application Firewall block detected.
   - `4`: Target rate limiting (HTTP 429) detected.

---

## Code Style & Safety Guidelines
- **Typing**: Use standard Python type hints (`typing.Optional`, `typing.List`, `typing.Dict`).
- **Imports**: Avoid heavy imports at module load time; use dynamic imports for scanners or optional tools inside methods where appropriate.
- **Defensive Taxonomy**: Maintain professional, defensive security terminology in all code comments, docstrings, findings descriptions, and documentation to prevent false-positive AI safety filter activations.

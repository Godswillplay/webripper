# CLAUDE.md — WebRipper Recon Developer & Agent Instructions

## Primary Commands
- **Run Full Test Suite**: `.venv\Scripts\python.exe -m pytest tests/ -v` (Windows) or `pytest tests/ -v` (Linux/macOS)
- **Run Single Test**: `pytest tests/test_cli_and_wizard.py -v`
- **Interactive Terminal Wizard**: `python -m app.main --wizard` (or `python main.py`)
- **Execute Headless Scan**: `python -m app.main https://target.local --profile standard -o report.html --json report.json`
- **Stream Live NDJSON Telemetry**: `python -m app.main https://target.local --json-stream`
- **Baseline Regression Diffing**: `python -m app.main https://target.local --diff baseline_report.json`
- **Start Native MCP Server**: `python -m app.mcp` (or `python -m app.main --mcp`)
- **Query Offline Intelligence DB**: `python -m app.main --intel-query "Spring Boot Actuator"`

---

## Architectural Invariants & Code Rules
1. **Pure CLI / Headless Engine**:
   - WebRipper Recon 5.0 is an agent-native, pure Python 3.11+ reconnaissance tool.
   - Desktop GUI frameworks (PySide6 / Qt) have been completely retired. **Do not reintroduce Qt dependencies.**
   - All components must run cleanly in headless Docker containers and CI/CD pipelines.
2. **Python 3.11+ Compatibility**:
   - **No backslashes inside f-string expressions**: Python 3.11 raises `SyntaxError` on expressions like `{x.replace('\', '/')}`. Compute replacements in temporary variables prior to interpolation.
   - Use standard `typing` annotations (`Optional`, `List`, `Dict`, `Tuple`, `Any`).
3. **Defensive Posture & Ethical Scope**:
   - WebRipper Recon operates under authorized, non-destructive verification standards (OWASP WSTG, CWE, CVSS 3.1).
   - Maintain professional, defensive security terminology in all code comments, docstrings, findings descriptions, and documentation to prevent false-positive AI safety filter activations.
4. **Vulnerability Scenario Intelligence (Scanner #21)**:
   - Uses embedded SQLite FTS5 database (`app/intelligence/intel.db`) containing 30,297 records.
   - Scanner #21 matches detected technology stacks and issues a focused set of non-destructive canary probes (15–20 max) to prevent rate-limiting and WAF blocking.
5. **Deterministic Semantic Exit Codes**:
   - `0`: Clean execution, zero CRITICAL/HIGH findings.
   - `1`: Operational error / unhandled exception.
   - `2`: Security issues detected (CRITICAL or HIGH severity findings).
   - `3`: Target unreachable (connection refused, host unreachable, DNS resolution failed).
   - `4`: Target rate limiting (HTTP 429) detected.
   - `5`: Gateway or Web Application Firewall block detected (HTTP 403).
6. **Rate-Limiting & Jitter**:
   - Base delay calculations in `AutoThrottle.get_delay()` must remain deterministic for tests and backoff algorithms.
   - Actual network socket sleep operations apply timing jitter via `AutoThrottle.delay_for()`.

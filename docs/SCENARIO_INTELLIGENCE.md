# WebRipper Recon 5.0 — Vulnerability Scenario Intelligence Engine

## 1. Engine Overview

WebRipper Recon 5.0 includes an offline vulnerability intelligence engine powered by an embedded SQLite database ([`app/intelligence/intel.db`](file:///c:/Users/JAI/Desktop/webripper2.0/app/intelligence/intel.db)) utilizing **Full-Text Search (FTS5)**. 

The catalog contains **30,297 indexed intelligence records** curated from primary cybersecurity sources:
- **11,835 Nuclei Community Templates**: Signatures, matchers, CVEs, and CVSS vectors.
- **15,219 HackerOne Disclosed Reports**: Disclosed bug bounty reports with bounty amounts, programs, and writeup links.
- **1,790 CISA Known Exploited Vulnerabilities (KEV)**: Catalog of vulnerabilities actively exploited in the wild with required remediation deadlines.
- **1,363 Curated Scenario Canary Recipes**: Verified recipes with precise HTTP methods, paths, match regexes, and negative regexes.
- **76 Subdomain Takeover Fingerprints**: Cloud service CNAME patterns and response body fingerprints from `can-i-take-over-xyz`.
- **14 PortSwigger Advanced Research Methodologies**: Exploitation patterns for HTTP Request Smuggling, Web Cache Poisoning, and OAuth vulnerabilities.

---

## 2. Database Schema Specification

The intelligence database is structured into specialized relational tables and a unified FTS5 virtual table for fast full-text searching:

### Table: `scenarios`
Stores structured canary verification recipes:
```sql
CREATE TABLE scenarios (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    tech_stack TEXT NOT NULL,
    category TEXT NOT NULL,
    cwe TEXT NOT NULL,
    cvss_vector TEXT NOT NULL,
    probe_method TEXT NOT NULL,
    probe_path TEXT NOT NULL,
    probe_headers TEXT NOT NULL,
    probe_body TEXT NOT NULL,
    match_status TEXT NOT NULL,
    match_regex TEXT NOT NULL,
    negative_regex TEXT NOT NULL,
    bounty_reference TEXT NOT NULL,
    author_insight TEXT NOT NULL,
    remediation TEXT NOT NULL
);
CREATE INDEX idx_scenarios_cat ON scenarios(category);
CREATE INDEX idx_scenarios_tech ON scenarios(tech_stack);
```

### Table: `h1_disclosures`
Tracks real-world bug bounty payouts and technical disclosures:
```sql
CREATE TABLE h1_disclosures (
    id TEXT PRIMARY KEY,
    program TEXT NOT NULL,
    title TEXT NOT NULL,
    link TEXT NOT NULL,
    upvotes INTEGER NOT NULL,
    bounty REAL NOT NULL,
    vuln_type TEXT NOT NULL,
    cwe TEXT NOT NULL,
    tech_stack TEXT NOT NULL
);
CREATE INDEX idx_h1_prog ON h1_disclosures(program);
```

### Table: `cisa_kev`
Catalogs actively exploited vulnerabilities mandated for mitigation by CISA:
```sql
CREATE TABLE cisa_kev (
    cve_id TEXT PRIMARY KEY,
    vendor TEXT NOT NULL,
    product TEXT NOT NULL,
    vuln_name TEXT NOT NULL,
    short_description TEXT NOT NULL,
    required_action TEXT NOT NULL,
    notes TEXT NOT NULL,
    cwes TEXT NOT NULL,
    date_added TEXT NOT NULL,
    tech_stack TEXT NOT NULL
);
CREATE INDEX idx_cisa_vendor ON cisa_kev(vendor);
```

### Virtual Table: `fts_intel`
Provides SQLite FTS5 full-text indexing across all records with BM25 ranking:
```sql
CREATE VIRTUAL TABLE fts_intel USING fts5(
    source_table UNINDEXED,
    record_id UNINDEXED,
    title,
    tech_stack,
    content,
    tokenize = 'porter unicode61'
);
```

---

## 3. Targeted Canary Probing Mechanism (Scanner #21)

### The Anti-WAF Strategy
Traditional vulnerability scanners flood targets with tens of thousands of aggressive fuzzing payloads, triggering WAF bans, IP rate-limiting, and network socket exhaustion.

**Scanner #21 (`app/scanners/scenarios.py`)** solves this through fingerprint-targeted canary probing:
1. **Stack Identification**: Tech fingerprinting (`TechScanner`) identifies frameworks (e.g. `nextjs`, `spring`, `laravel`, `wordpress`, `django`, `rails`, `express`).
2. **Selective Querying**: The `ScenarioEngine` queries `intel.db` for scenarios matching the detected tech stack.
3. **Canary Verification**: Fires only **15–20 high-probability, non-destructive canary requests** specifically tailored to the target's stack.
4. **Validation Logic**:
   - HTTP status code matches `match_status`.
   - Response body matches `match_regex`.
   - Response body does **not** match `negative_regex` (eliminating generic custom error pages).
5. **CISA KEV Cross-Referencing**: Detected software versions are checked against active CISA KEV records; any match is immediately escalated to **CRITICAL**.

---

## 4. Querying Intelligence Programmatically

### Python API Example
```python
from app.intelligence.engine import ScenarioEngine

engine = ScenarioEngine()

# 1. Search full-text catalog
results = engine.search("Spring Boot Actuator", limit=5)
for item in results:
    print(f"[{item['source']}] {item['title']} (CWE: {item.get('cwe', 'N/A')})")

# 2. Retrieve tech-targeted canary recipes
recipes = engine.find_applicable_scenarios(["nextjs", "react"])
for r in recipes:
    print(f"Canary probe: {r.probe_method} {r.probe_path} -> checks {r.match_regex}")

# 3. Check CISA KEV
kev_matches = engine.query_cisa_kev("Apache Struts")
for cve in kev_matches:
    print(f"ACTIVE EXPLOIT: {cve['cve_id']} - {cve['vuln_name']}")
```

### CLI Command Example
```bash
python -m app.main --intel-query "Next.js Server Actions"
```
Output:
```
================================================================================
WEBRIPPER RECON VULNERABILITY INTELLIGENCE QUERY: Next.js Server Actions
================================================================================
[SCENARIO] Next.js Server Actions State Tampering & Host Header Reflection
  Tech Stack: nextjs | CWE: CWE-644 | CVSS: 7.5
  Probe: POST /api (Next-Action: canary)
  Reference: HackerOne #2245123 ($15,000 Payout)
  Remediation: Validate Host header and enforce origin checking in next.config.js.
```

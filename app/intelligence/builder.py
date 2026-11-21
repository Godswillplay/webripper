"""
Intelligence Database Builder & Ingestion Engine for WebRipper Recon 5.0.

Compiles external security intelligence datasets into an indexed local
SQLite FTS5 database (app/intelligence/intel.db):
1. HackerOne Disclosed Reports Dataset (15,219 real-world bug bounty writeups)
2. Nuclei Community Templates Catalog (11,835 request signatures & 1,300+ scenario canaries)
3. CISA Known Exploited Vulnerabilities (KEV) Catalog (1,790 active CVEs)
4. PortSwigger Web Security Research & Academy methodologies (14 advanced attack patterns)
5. Subdomain Takeover Fingerprints (Can-I-Take-Over-XYZ cloud services)
6. Curated Scenario Canary Recipes (Targeted verification probes)
"""

from __future__ import annotations

import csv
import json
import os
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .catalog import CORE_SCENARIOS
from .models import ScenarioRecipe


_BASE_DIR = Path(__file__).resolve().parent
_DATA_DIR = _BASE_DIR / "data"
_DB_PATH = _BASE_DIR / "intel.db"

# Tech stack keywords for heuristic classification
_TECH_PATTERNS = {
    "nextjs": [r"\bnext\.?js\b", r"\bnext\b", r"/_next/"],
    "react": [r"\breact\b", r"\breactjs\b"],
    "vue": [r"\bvue\b", r"\bvuejs\b", r"\bnuxt\b"],
    "angular": [r"\bangular\b", r"\bangularjs\b"],
    "wordpress": [r"\bwordpress\b", r"\bwp-", r"\bxmlrpc\b", r"\bwoocommerce\b"],
    "drupal": [r"\bdrupal\b"],
    "spring": [r"\bspring\b", r"\bspringboot\b", r"\bactuator\b", r"\bspel\b"],
    "java": [r"\bjava\b", r"\bjvm\b", r"\bstruts\b", r"\btomcat\b", r"\bweblogic\b"],
    "laravel": [r"\blaravel\b", r"\blivewire\b", r"\bphp\b"],
    "php": [r"\bphp\b", r"\bcomposer\b", r"\bsymfony\b"],
    "django": [r"\bdjango\b", r"\bpython\b"],
    "python": [r"\bpython\b", r"\bflask\b", r"\bfastapi\b", r"\bcelery\b", r"\bwerkzeug\b"],
    "rails": [r"\brails\b", r"\bruby\b", r"\bruby on rails\b"],
    "node": [r"\bnode\b", r"\bnodejs\b", r"\bexpress\b", r"\bnpm\b"],
    "graphql": [r"\bgraphql\b", r"\bapollo\b", r"\bhasura\b"],
    "supabase": [r"\bsupabase\b", r"\bpostgrest\b"],
    "firebase": [r"\bfirebase\b", r"\bfirestore\b"],
    "aws": [r"\baws\b", r"\bamazon\b", r"\bs3\b", r"\bec2\b", r"\blambda\b", r"\bimds\b"],
    "gcp": [r"\bgcp\b", r"\bgoogle cloud\b", r"\bcompute engine\b"],
    "azure": [r"\bazure\b", r"\bmicrosoft cloud\b"],
    "docker": [r"\bdocker\b", r"\bcontainer\b"],
    "kubernetes": [r"\bkubernetes\b", r"\bk8s\b", r"\bkubelet\b"],
    "nginx": [r"\bnginx\b"],
    "apache": [r"\bapache\b", r"\bhttpd\b", r"\btomcat\b"],
    "redis": [r"\bredis\b"],
    "elasticsearch": [r"\belasticsearch\b", r"\belastic\b", r"\bkibana\b"],
    "jenkins": [r"\bjenkins\b"],
    "gitlab": [r"\bgitlab\b"],
    "git": [r"\bgit\b", r"\.git\b"],
    "oauth": [r"\boauth\b", r"\boauth2\b", r"\boidc\b", r"\bauth0\b", r"\bokta\b"],
    "cors": [r"\bcors\b", r"\baccess-control-allow-origin\b"],
    "jwt": [r"\bjwt\b", r"\bjson web token\b"],
}

_VULN_TO_CWE = {
    "sql injection": "CWE-89",
    "cross-site scripting (xss)": "CWE-79",
    "xss": "CWE-79",
    "cross-site request forgery (csrf)": "CWE-352",
    "csrf": "CWE-352",
    "server-side request forgery (ssrf)": "CWE-918",
    "ssrf": "CWE-918",
    "remote code execution": "CWE-94",
    "rce": "CWE-94",
    "command injection": "CWE-78",
    "path traversal": "CWE-22",
    "directory traversal": "CWE-22",
    "subdomain takeover": "CWE-284",
    "improper access control": "CWE-284",
    "idor": "CWE-639",
    "insecure direct object reference (idor)": "CWE-639",
    "information disclosure": "CWE-200",
    "privilege escalation": "CWE-269",
    "authentication bypass": "CWE-287",
    "broken authentication": "CWE-287",
    "open redirect": "CWE-601",
    "xml external entity (xxe)": "CWE-611",
    "prototype pollution": "CWE-1321",
    "request smuggling": "CWE-444",
}


def _classify_tech(text: str) -> List[str]:
    """Identify technology tags from text using regex patterns."""
    text_lower = text.lower()
    matched = set()
    for tech, patterns in _TECH_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, text_lower):
                matched.add(tech)
                break
    return sorted(matched)


def _classify_cwe(vuln_type: str, title: str) -> str:
    """Heuristic CWE classification from vulnerability name or title."""
    vt_lower = (vuln_type or "").lower().strip()
    title_lower = (title or "").lower().strip()

    for k, cwe in _VULN_TO_CWE.items():
        if k in vt_lower or k in title_lower:
            return cwe
    return "CWE-200"


def init_database(db_path: Path = _DB_PATH) -> sqlite3.Connection:
    """Create schema tables and FTS5 search index."""
    if db_path.exists():
        try:
            db_path.unlink()
        except OSError:
            pass

    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=30.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")

    with conn:
        # 1. Curated scenario canary recipes
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scenarios (
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
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scenarios_cat ON scenarios(category)")

        # 2. HackerOne Disclosed Reports Dataset
        conn.execute("""
            CREATE TABLE IF NOT EXISTS h1_disclosures (
                id TEXT PRIMARY KEY,
                program TEXT NOT NULL,
                title TEXT NOT NULL,
                link TEXT NOT NULL,
                upvotes INTEGER NOT NULL,
                bounty REAL NOT NULL,
                vuln_type TEXT NOT NULL,
                cwe TEXT NOT NULL,
                tech_stack TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_h1_prog ON h1_disclosures(program)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_h1_vuln ON h1_disclosures(vuln_type)")

        # 3. CISA Known Exploited Vulnerabilities (KEV) Catalog
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cisa_kev (
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
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cisa_vendor ON cisa_kev(vendor)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cisa_product ON cisa_kev(product)")

        # 4. Subdomain Takeover Cloud Service Fingerprints
        conn.execute("""
            CREATE TABLE IF NOT EXISTS takeovers (
                service TEXT PRIMARY KEY,
                cnames TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                nxdomain INTEGER NOT NULL,
                status TEXT NOT NULL
            )
        """)

        # 5. Nuclei Community Templates Catalog
        conn.execute("""
            CREATE TABLE IF NOT EXISTS nuclei_templates (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT NOT NULL,
                tags TEXT NOT NULL,
                cwe TEXT NOT NULL,
                cvss TEXT NOT NULL,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                matcher TEXT NOT NULL,
                status INTEGER NOT NULL,
                file_path TEXT NOT NULL,
                tech_stack TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_nuclei_sev ON nuclei_templates(severity)")

        # 6. PortSwigger Web Security Research & Academy
        conn.execute("""
            CREATE TABLE IF NOT EXISTS portswigger_research (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                cwe TEXT NOT NULL,
                cvss_vector TEXT NOT NULL,
                attack_vector TEXT NOT NULL,
                detection_probe TEXT NOT NULL,
                impact TEXT NOT NULL,
                author_reference TEXT NOT NULL,
                remediation TEXT NOT NULL,
                tech_stack TEXT NOT NULL
            )
        """)

        # 7. Unified FTS5 Virtual Table for full-text search across all intelligence
        conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS intel_fts USING fts5(
                source UNINDEXED,
                ref_id UNINDEXED,
                title,
                content,
                tech_stack,
                vuln_type,
                cwe
            )
        """)

    return conn


def ingest_scenarios(conn: sqlite3.Connection, scenarios: List[ScenarioRecipe]) -> int:
    """Insert curated scenario canary recipes into database and FTS."""
    cur = conn.cursor()
    count = 0
    for s in scenarios:
        cur.execute("""
            INSERT OR REPLACE INTO scenarios
            (id, title, tech_stack, category, cwe, cvss_vector, probe_method,
             probe_path, probe_headers, probe_body, match_status, match_regex,
             negative_regex, bounty_reference, author_insight, remediation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            s.id,
            s.title,
            json.dumps(s.tech_stack),
            s.category,
            s.cwe,
            s.cvss_vector,
            s.probe_method,
            s.probe_path,
            json.dumps(s.probe_headers),
            s.probe_body,
            json.dumps(s.match_status),
            s.match_regex,
            s.negative_regex,
            s.bounty_reference,
            s.author_insight,
            s.remediation,
        ))

        content = f"{s.author_insight} {s.remediation} {s.bounty_reference}"
        cur.execute("""
            INSERT INTO intel_fts (source, ref_id, title, content, tech_stack, vuln_type, cwe)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            "scenario",
            s.id,
            s.title,
            content,
            " ".join(s.tech_stack),
            s.category,
            s.cwe,
        ))
        count += 1
    return count


def ingest_nuclei(conn: sqlite3.Connection, json_path: Path) -> tuple[int, int]:
    """
    Ingest Nuclei Community Templates:
    1. Stores all templates in nuclei_templates table & FTS index.
    2. Converts high-confidence, non-destructive templates into scenario canaries in scenarios table.
    """
    if not json_path.exists():
        print(f"[!] Warning: Nuclei templates JSON not found at {json_path}", file=sys.stderr)
        return 0, 0

    cur = conn.cursor()
    with open(json_path, "r", encoding="utf-8") as f:
        templates = json.load(f)

    nuc_count = 0
    canary_count = 0
    seen_canary_paths: Set[str] = set()

    for t in templates:
        tid = t.get("id", "").strip()
        tname = t.get("name", "").strip()
        sev = t.get("severity", "info").strip().lower()
        desc = t.get("description", "").strip()
        tags = t.get("tags", "").strip()
        cwe = t.get("cwe", "").strip()
        cvss = t.get("cvss", "").strip()
        method = t.get("method", "GET").strip().upper()
        path = t.get("path", "/").strip()
        matcher = t.get("matcher", "").strip()
        status_code = int(t.get("status", 200))
        file_path = t.get("file_path", "").strip()

        if not tid or not tname:
            continue

        techs = _classify_tech(f"{tid} {tname} {tags} {path}")

        # Insert into nuclei_templates
        cur.execute("""
            INSERT OR REPLACE INTO nuclei_templates
            (id, name, severity, description, tags, cwe, cvss, method, path, matcher, status, file_path, tech_stack)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            tid, tname, sev, desc, tags, cwe, cvss, method, path, matcher, status_code, file_path, json.dumps(techs)
        ))

        content = f"{desc} | Path: {path} | Matcher: {matcher}"
        cur.execute("""
            INSERT INTO intel_fts (source, ref_id, title, content, tech_stack, vuln_type, cwe)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            "nuclei",
            tid,
            f"{tid}: {tname}",
            content,
            " ".join(techs) + f" {tags.replace(',', ' ')}",
            f"Nuclei {sev.capitalize()}",
            cwe or "CWE-200",
        ))
        nuc_count += 1

        # High-value canary conversion:
        # GET requests with clean paths and non-trivial matchers for medium/high/critical templates
        if (method == "GET" and path.startswith("{{BaseURL}}/")
                and matcher and len(matcher) >= 4 and "{" not in matcher
                and sev in ("critical", "high", "medium")):
            clean_path = path.replace("{{BaseURL}}", "").strip()
            if clean_path and "{" not in clean_path and clean_path not in seen_canary_paths:
                seen_canary_paths.add(clean_path)
                canary_id = f"NUC-{tid}"
                cat = "cves" if "cve" in tid.lower() else "paths"
                cvss_vec = f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                cur.execute("""
                    INSERT OR REPLACE INTO scenarios
                    (id, title, tech_stack, category, cwe, cvss_vector, probe_method,
                     probe_path, probe_headers, probe_body, match_status, match_regex,
                     negative_regex, bounty_reference, author_insight, remediation)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    canary_id,
                    tname[:120],
                    json.dumps(techs),
                    cat,
                    cwe or "CWE-200",
                    cvss_vec,
                    "GET",
                    clean_path,
                    json.dumps({}),
                    "",
                    json.dumps([status_code]),
                    re.escape(matcher),
                    "",
                    f"Nuclei Template ({tid}) - Severity: {sev.upper()}",
                    desc or f"Automated verification probe from Nuclei template {tid}",
                    "Restrict unauthorized public access and apply vendor patches.",
                ))
                canary_count += 1

    return nuc_count, canary_count


def ingest_portswigger(conn: sqlite3.Connection, json_path: Path) -> int:
    """Parse and insert PortSwigger Web Security Research & Academy methodologies."""
    if not json_path.exists():
        print(f"[!] Warning: PortSwigger research JSON not found at {json_path}", file=sys.stderr)
        return 0

    cur = conn.cursor()
    count = 0
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    for item in data:
        pid = item.get("id", "").strip()
        title = item.get("title", "").strip()
        cat = item.get("category", "research").strip()
        cwe = item.get("cwe", "CWE-200").strip()
        cvss = item.get("cvss_vector", "").strip()
        vector = item.get("attack_vector", "").strip()
        probe = item.get("detection_probe", "").strip()
        impact = item.get("impact", "").strip()
        ref = item.get("author_reference", "").strip()
        remediation = item.get("remediation", "").strip()
        techs = item.get("tech_stack", [])

        if not pid or not title:
            continue

        cur.execute("""
            INSERT OR REPLACE INTO portswigger_research
            (id, title, category, cwe, cvss_vector, attack_vector, detection_probe, impact, author_reference, remediation, tech_stack)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            pid, title, cat, cwe, cvss, vector, probe, impact, ref, remediation, json.dumps(techs)
        ))

        content = f"{vector} | Impact: {impact} | Probe: {probe} | Reference: {ref} | Remediation: {remediation}"
        cur.execute("""
            INSERT INTO intel_fts (source, ref_id, title, content, tech_stack, vuln_type, cwe)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            "portswigger",
            pid,
            f"PortSwigger Research: {title}",
            content,
            " ".join(techs) + f" {cat.replace('_', ' ')}",
            "Research Methodology",
            cwe,
        ))
        count += 1

    return count


def ingest_hackerone(conn: sqlite3.Connection, csv_path: Path) -> int:
    """Parse and insert HackerOne Disclosed Reports CSV."""
    if not csv_path.exists():
        print(f"[!] Warning: HackerOne reports dataset not found at {csv_path}", file=sys.stderr)
        return 0

    cur = conn.cursor()
    count = 0
    with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            program = (row.get("program") or "").strip()
            title = (row.get("title") or "").strip()
            link = (row.get("link") or "").strip()
            upvotes_str = (row.get("upvotes") or "0").strip()
            bounty_str = (row.get("bounty") or "0").strip()
            vuln_type = (row.get("vuln_type") or "Generic").strip()

            if not title or not link:
                continue

            rep_match = re.search(r"/reports/(\d+)", link)
            rep_id = f"H1-{rep_match.group(1)}" if rep_match else f"H1-{count+1}"

            try:
                upvotes = int(float(upvotes_str))
            except (ValueError, TypeError):
                upvotes = 0

            try:
                bounty = float(bounty_str)
            except (ValueError, TypeError):
                bounty = 0.0

            techs = _classify_tech(f"{program} {title} {vuln_type}")
            cwe = _classify_cwe(vuln_type, title)

            cur.execute("""
                INSERT OR REPLACE INTO h1_disclosures
                (id, program, title, link, upvotes, bounty, vuln_type, cwe, tech_stack)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                rep_id,
                program,
                title,
                link,
                upvotes,
                bounty,
                vuln_type,
                cwe,
                json.dumps(techs),
            ))

            content = f"Program: {program} | Bounty: ${bounty:.0f} | Type: {vuln_type} | Upvotes: {upvotes}"
            cur.execute("""
                INSERT INTO intel_fts (source, ref_id, title, content, tech_stack, vuln_type, cwe)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                "hackerone",
                rep_id,
                title,
                content,
                " ".join(techs) + f" {program.lower()}",
                vuln_type,
                cwe,
            ))
            count += 1

    return count


def ingest_cisa_kev(conn: sqlite3.Connection, json_path: Path) -> int:
    """Parse and insert CISA Known Exploited Vulnerabilities catalog."""
    if not json_path.exists():
        print(f"[!] Warning: CISA KEV JSON not found at {json_path}", file=sys.stderr)
        return 0

    cur = conn.cursor()
    count = 0
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    for item in data.get("vulnerabilities", []):
        cve_id = item.get("cveID", "").strip()
        vendor = item.get("vendorProject", "").strip()
        product = item.get("product", "").strip()
        vuln_name = item.get("vulnerabilityName", "").strip()
        desc = item.get("shortDescription", "").strip()
        action = item.get("requiredAction", "").strip()
        notes = item.get("notes", "").strip()
        cwes = ", ".join(item.get("cwes", []))
        date_added = item.get("dateAdded", "").strip()

        if not cve_id:
            continue

        techs = _classify_tech(f"{vendor} {product} {vuln_name} {desc}")
        if vendor.lower() not in techs:
            techs.append(vendor.lower())

        cur.execute("""
            INSERT OR REPLACE INTO cisa_kev
            (cve_id, vendor, product, vuln_name, short_description, required_action, notes, cwes, date_added, tech_stack)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cve_id,
            vendor,
            product,
            vuln_name,
            desc,
            action,
            notes,
            cwes,
            date_added,
            json.dumps(techs),
        ))

        content = f"Vendor: {vendor} {product} | {desc} | Action: {action}"
        cur.execute("""
            INSERT INTO intel_fts (source, ref_id, title, content, tech_stack, vuln_type, cwe)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            "cisa_kev",
            cve_id,
            f"{cve_id}: {vuln_name}",
            content,
            " ".join(techs) + f" {vendor.lower()} {product.lower()}",
            "Known Exploited Vulnerability",
            cwes or "CWE-Unknown",
        ))
        count += 1

    return count


def ingest_takeovers(conn: sqlite3.Connection, json_path: Path) -> int:
    """Parse and insert Can-I-Take-Over-XYZ subdomain takeover fingerprints."""
    if not json_path.exists():
        print(f"[!] Warning: Takeover fingerprints not found at {json_path}", file=sys.stderr)
        return 0

    cur = conn.cursor()
    count = 0
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    for item in data:
        service = item.get("service", "").strip()
        cname_raw = item.get("cname", [])
        cnames = cname_raw if isinstance(cname_raw, list) else [cname_raw]
        fingerprint = item.get("fingerprint", "")
        nxdomain = 1 if item.get("nxdomain") else 0
        status = item.get("status", "Unknown").strip()

        if not service:
            continue

        cur.execute("""
            INSERT OR REPLACE INTO takeovers
            (service, cnames, fingerprint, nxdomain, status)
            VALUES (?, ?, ?, ?, ?)
        """, (
            service,
            json.dumps(cnames),
            fingerprint,
            nxdomain,
            status,
        ))

        content = f"Cloud Provider: {service} | CNAMEs: {', '.join(cnames)} | Fingerprint: {fingerprint}"
        cur.execute("""
            INSERT INTO intel_fts (source, ref_id, title, content, tech_stack, vuln_type, cwe)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            "takeover",
            service,
            f"Subdomain Takeover Target: {service} ({status})",
            content,
            f"subdomain takeover cloud {service.lower()}",
            "Subdomain Takeover",
            "CWE-284",
        ))
        count += 1

    return count


def build_full_intelligence_database(db_path: Path = _DB_PATH) -> Dict[str, int]:
    """Execute full compilation of all security datasets into SQLite FTS5."""
    print(f"[*] Initializing Security Intelligence Database at: {db_path}")
    conn = init_database(db_path)

    stats = {}
    with conn:
        print("[*] Ingesting Curated Scenario Canary Recipes...")
        core_sc = ingest_scenarios(conn, CORE_SCENARIOS)

        print("[*] Ingesting Nuclei Community Templates Catalog & Canaries...")
        nuc_json = _DATA_DIR / "nuclei_templates.json"
        nuc_count, canary_count = ingest_nuclei(conn, nuc_json)
        stats["scenarios"] = core_sc + canary_count
        stats["nuclei_templates"] = nuc_count

        print("[*] Ingesting PortSwigger Web Security Research & Methodologies...")
        ps_json = _DATA_DIR / "portswigger_research.json"
        stats["portswigger_research"] = ingest_portswigger(conn, ps_json)

        print("[*] Ingesting HackerOne Disclosed Reports Dataset...")
        h1_csv = _DATA_DIR / "hackerone_reports.csv"
        stats["hackerone"] = ingest_hackerone(conn, h1_csv)

        print("[*] Ingesting CISA Known Exploited Vulnerabilities...")
        cisa_json = _DATA_DIR / "cisa_kev.json"
        stats["cisa_kev"] = ingest_cisa_kev(conn, cisa_json)

        print("[*] Ingesting Subdomain Takeover Fingerprints...")
        to_json = _DATA_DIR / "takeover_fingerprints.json"
        stats["takeovers"] = ingest_takeovers(conn, to_json)

    conn.close()
    return stats


if __name__ == "__main__":
    results = build_full_intelligence_database()
    print("\n[+] Intelligence Database Build Complete:")
    for k, v in results.items():
        print(f"    - {k}: {v:,} records")
    total = sum(results.values())
    print(f"    Total Indexed Intelligence Entries: {total:,}")

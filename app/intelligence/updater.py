"""
WebRipper Intelligence Feed Updater & Delta Ingestion Engine.

Implements the logic behind `webripper intel update`:
1. Live Environment:
   - Fetches delta updates for CISA Known Exploited Vulnerabilities (KEV).
   - Fetches delta updates for HackerOne bug bounty disclosed reports.
   - Fetches delta updates for Nuclei community templates and canaries.
   - Provides safe offline fallback on network errors or timeouts.
2. Offline / Test Mode:
   - Safely updates and rebuilds metadata without network operations.
   - Stamps database version, per-table record counts, and last_updated timestamp.
3. Database Versioning:
   - Manages versioning and per-table audit tables (`intel_version`, `intel_metadata`) in intel.db.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from urllib.error import HTTPError, URLError

try:
    from .builder import _TECH_PATTERNS, _classify_tech, _classify_cwe
except ImportError:
    # Heuristic classification fallbacks if builder is not importable
    _TECH_PATTERNS = {
        "nextjs": [r"\bnext\.?js\b", r"\bnext\b", r"/_next/"],
        "react": [r"\breact\b", r"\breactjs\b"],
        "vue": [r"\bvue\b", r"\bvuejs\b", r"\bnuxt\b"],
        "angular": [r"\bangular\b", r"\bangularjs\b"],
        "wordpress": [r"\bwordpress\b", r"\bwp-", r"\bxmlrpc\b"],
        "spring": [r"\bspring\b", r"\bspringboot\b", r"\bactuator\b"],
        "graphql": [r"\bgraphql\b", r"\bapollo\b"],
        "aws": [r"\baws\b", r"\bamazon\b", r"\bs3\b"],
    }

    import re

    def _classify_tech(text: str) -> List[str]:
        text_lower = (text or "").lower()
        matched = set()
        for tech, patterns in _TECH_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, text_lower):
                    matched.add(tech)
                    break
        return sorted(matched)

    def _classify_cwe(vuln_type: str, title: str) -> str:
        return "CWE-200"


_DEFAULT_INTEL_DB = Path(__file__).resolve().parent / "intel.db"

CISA_KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
HACKERONE_FEED_URL = "https://raw.githubusercontent.com/webripper/intel-feed/main/h1_disclosures.json"
NUCLEI_FEED_URL = "https://raw.githubusercontent.com/webripper/intel-feed/main/nuclei_templates.json"

CORE_TABLES = [
    "scenarios",
    "h1_disclosures",
    "cisa_kev",
    "takeovers",
    "nuclei_templates",
    "portswigger_research",
]


def resolve_intel_db_path(custom_path: Optional[Union[str, Path]] = None) -> Path:
    """Resolve target intel.db path from parameter, env var, or package default."""
    if custom_path:
        return Path(custom_path).expanduser().resolve()
    env_path = os.environ.get("WEBRIPPER_INTEL_DB")
    if env_path:
        return Path(env_path).expanduser().resolve()
    return _DEFAULT_INTEL_DB.resolve()


def ensure_intel_schema(conn: sqlite3.Connection) -> None:
    """Ensure all core tables, indices, and version metadata tables exist without erasing data."""
    with conn:
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

        conn.execute("""
            CREATE TABLE IF NOT EXISTS takeovers (
                service TEXT PRIMARY KEY,
                cnames TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                nxdomain INTEGER NOT NULL,
                status TEXT NOT NULL
            )
        """)

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

        conn.execute("""
            CREATE TABLE IF NOT EXISTS intel_version (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                version TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                table_counts TEXT NOT NULL,
                source_status TEXT NOT NULL,
                details TEXT
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS intel_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        try:
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
        except sqlite3.OperationalError:
            pass


def count_table_rows(conn: sqlite3.Connection) -> Dict[str, int]:
    """Count rows across all security intelligence tables."""
    counts: Dict[str, int] = {}
    for table in CORE_TABLES:
        try:
            cur = conn.execute(f"SELECT COUNT(*) FROM {table}")
            counts[table] = cur.fetchone()[0]
        except sqlite3.OperationalError:
            counts[table] = 0
    return counts


def stamp_intel_version(
    conn: sqlite3.Connection,
    version: Optional[str] = None,
    source_status: str = "ok",
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Record DB version, per-table record counts, and timestamp into intel_version and intel_metadata."""
    ensure_intel_schema(conn)

    timestamp = datetime.now(timezone.utc).isoformat()
    if not version:
        version = f"5.0.0-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"

    counts = count_table_rows(conn)
    details_dict = details or {}
    total_records = sum(counts.values())

    with conn:
        conn.execute("""
            INSERT INTO intel_version (version, updated_at, table_counts, source_status, details)
            VALUES (?, ?, ?, ?, ?)
        """, (version, timestamp, json.dumps(counts), source_status, json.dumps(details_dict)))

        meta_entries = [
            ("version", version),
            ("last_updated", timestamp),
            ("source_status", source_status),
            ("table_counts", json.dumps(counts)),
            ("total_records", str(total_records)),
        ]
        for tbl, cnt in counts.items():
            meta_entries.append((f"{tbl}_count", str(cnt)))

        for k, v in meta_entries:
            conn.execute("""
                INSERT OR REPLACE INTO intel_metadata (key, value, updated_at)
                VALUES (?, ?, ?)
            """, (k, v, timestamp))

    return {
        "version": version,
        "updated_at": timestamp,
        "table_counts": counts,
        "total_records": total_records,
        "source_status": source_status,
        "details": details_dict,
    }


def get_intel_metadata(db_path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """Read version, timestamp, and record counts from intel.db metadata tables."""
    resolved_path = resolve_intel_db_path(db_path)
    if not resolved_path.exists():
        return {
            "version": "uninitialized",
            "updated_at": None,
            "table_counts": {},
            "total_records": 0,
            "source_status": "missing_database",
        }

    conn = sqlite3.connect(str(resolved_path), timeout=10.0)
    try:
        cur = conn.cursor()
        try:
            cur.execute(
                "SELECT version, updated_at, table_counts, source_status, details "
                "FROM intel_version ORDER BY id DESC LIMIT 1"
            )
            row = cur.fetchone()
            if row:
                counts = json.loads(row[2]) if row[2] else {}
                return {
                    "version": row[0],
                    "updated_at": row[1],
                    "table_counts": counts,
                    "total_records": sum(counts.values()),
                    "source_status": row[3],
                    "details": json.loads(row[4]) if row[4] else {},
                    "database_path": str(resolved_path),
                }
        except sqlite3.OperationalError:
            pass

        counts = count_table_rows(conn)
        return {
            "version": "5.0.0-unversioned",
            "updated_at": None,
            "table_counts": counts,
            "total_records": sum(counts.values()),
            "source_status": "unversioned",
            "details": {},
            "database_path": str(resolved_path),
        }
    finally:
        conn.close()


def ingest_cisa_kev_delta(conn: sqlite3.Connection, vulnerabilities: List[Dict[str, Any]]) -> int:
    """Ingest new or updated CISA KEV entries into cisa_kev and FTS search index."""
    cur = conn.cursor()
    count = 0
    for v in vulnerabilities:
        cve_id = (v.get("cveID") or v.get("cve_id") or "").strip().upper()
        if not cve_id:
            continue

        vendor = (v.get("vendorProject") or v.get("vendor") or "").strip()
        product = (v.get("product") or "").strip()
        vuln_name = (v.get("vulnerabilityName") or v.get("vuln_name") or "").strip()
        short_desc = (v.get("shortDescription") or v.get("short_description") or "").strip()
        action = (v.get("requiredAction") or v.get("required_action") or "").strip()
        notes = (v.get("notes") or "").strip()
        date_added = (v.get("dateAdded") or v.get("date_added") or "").strip()

        cwes_raw = v.get("cwes", [])
        cwes = json.dumps(cwes_raw) if isinstance(cwes_raw, list) else str(cwes_raw)

        tech_text = f"{vendor} {product} {vuln_name} {short_desc}"
        tech_stack = _classify_tech(tech_text)

        cur.execute("""
            INSERT OR REPLACE INTO cisa_kev
            (cve_id, vendor, product, vuln_name, short_description, required_action, notes, cwes, date_added, tech_stack)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (cve_id, vendor, product, vuln_name, short_desc, action, notes, cwes, date_added, json.dumps(tech_stack)))

        try:
            cur.execute("""
                INSERT INTO intel_fts (source, ref_id, title, content, tech_stack, vuln_type, cwe)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                "cisa_kev",
                cve_id,
                f"{cve_id}: {vuln_name}",
                f"{vendor} {product} {short_desc} {action}",
                " ".join(tech_stack),
                "Active Exploit",
                cwes,
            ))
        except sqlite3.OperationalError:
            pass
        count += 1
    return count


def ingest_h1_delta(conn: sqlite3.Connection, reports: List[Dict[str, Any]]) -> int:
    """Ingest new or updated HackerOne disclosures into h1_disclosures and FTS search index."""
    cur = conn.cursor()
    count = 0
    for r in reports:
        report_id = str(r.get("id") or "").strip()
        if not report_id:
            continue

        program = (r.get("program") or "").strip()
        title = (r.get("title") or "").strip()
        link = (r.get("link") or "").strip()
        upvotes = int(r.get("upvotes") or 0)
        bounty = float(r.get("bounty") or 0.0)
        vuln_type = (r.get("vuln_type") or "").strip()
        cwe = (r.get("cwe") or _classify_cwe(vuln_type, title)).strip()

        tech_stack_raw = r.get("tech_stack", [])
        if isinstance(tech_stack_raw, str):
            try:
                tech_stack = json.loads(tech_stack_raw)
            except Exception:
                tech_stack = _classify_tech(f"{program} {title} {vuln_type}")
        else:
            tech_stack = list(tech_stack_raw) if tech_stack_raw else _classify_tech(f"{program} {title} {vuln_type}")

        cur.execute("""
            INSERT OR REPLACE INTO h1_disclosures
            (id, program, title, link, upvotes, bounty, vuln_type, cwe, tech_stack)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (report_id, program, title, link, upvotes, bounty, vuln_type, cwe, json.dumps(tech_stack)))

        try:
            cur.execute("""
                INSERT INTO intel_fts (source, ref_id, title, content, tech_stack, vuln_type, cwe)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                "hackerone",
                report_id,
                title,
                f"Program: {program} | Bounty: ${bounty:,.2f} | Vulnerability: {vuln_type}",
                " ".join(tech_stack),
                vuln_type,
                cwe,
            ))
        except sqlite3.OperationalError:
            pass
        count += 1
    return count


def ingest_nuclei_delta(conn: sqlite3.Connection, templates: List[Dict[str, Any]]) -> int:
    """Ingest new or updated Nuclei templates into nuclei_templates and FTS search index."""
    cur = conn.cursor()
    count = 0
    for t in templates:
        t_id = (t.get("id") or "").strip()
        if not t_id:
            continue

        name = (t.get("name") or "").strip()
        severity = (t.get("severity") or "info").strip().lower()
        description = (t.get("description") or "").strip()
        tags = (t.get("tags") or "").strip()
        cwe = (t.get("cwe") or "CWE-200").strip()
        cvss = (t.get("cvss") or "").strip()
        method = (t.get("method") or "GET").strip().upper()
        path = (t.get("path") or "").strip()
        matcher = (t.get("matcher") or "").strip()
        status = int(t.get("status") or 200)
        file_path = (t.get("file_path") or "").strip()

        tech_stack_raw = t.get("tech_stack", [])
        if isinstance(tech_stack_raw, str):
            try:
                tech_stack = json.loads(tech_stack_raw)
            except Exception:
                tech_stack = _classify_tech(f"{name} {tags} {path}")
        else:
            tech_stack = list(tech_stack_raw) if tech_stack_raw else _classify_tech(f"{name} {tags} {path}")

        cur.execute("""
            INSERT OR REPLACE INTO nuclei_templates
            (id, name, severity, description, tags, cwe, cvss, method, path, matcher, status, file_path, tech_stack)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (t_id, name, severity, description, tags, cwe, cvss, method, path, matcher, status, file_path, json.dumps(tech_stack)))

        try:
            cur.execute("""
                INSERT INTO intel_fts (source, ref_id, title, content, tech_stack, vuln_type, cwe)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                "nuclei",
                t_id,
                f"Nuclei: {name}",
                f"ID: {t_id} | Path: {path} | Tags: {tags} | Description: {description}",
                " ".join(tech_stack),
                severity,
                cwe,
            ))
        except sqlite3.OperationalError:
            pass
        count += 1
    return count


def _default_http_fetch(url: str, timeout: float = 5.0) -> Any:
    """Safely fetch and parse remote JSON payload with strict timeout."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "WebRipper-IntelUpdate/5.0"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        content = resp.read().decode("utf-8", errors="ignore")
        return json.loads(content)


def update_intel(
    db_path: Optional[Union[str, Path]] = None,
    offline: bool = False,
    version: Optional[str] = None,
    custom_fetcher: Optional[Callable[[str], Any]] = None,
    sources: Optional[List[str]] = None,
    timeout: float = 5.0,
) -> Dict[str, Any]:
    """
    Execute intelligence database update.

    - If offline=True:
      Safely updates metadata, counts rows in all tables, and stamps database version.
    - If offline=False:
      Fetches delta updates for CISA KEV, HackerOne disclosures, and Nuclei templates
      using custom_fetcher (if provided) or HTTP fetch with safe offline fallback.
      Stamps updated version and per-table counts.
    """
    target_db = resolve_intel_db_path(db_path)
    target_db.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(target_db), timeout=15.0)
    try:
        ensure_intel_schema(conn)

        source_report: Dict[str, Any] = {}
        delta_counts: Dict[str, int] = {}

        if not offline:
            selected_sources = sources or ["cisa_kev", "hackerone", "nuclei"]
            fetch_fn = custom_fetcher or _default_http_fetch

            # 1. Update CISA KEV
            if "cisa_kev" in selected_sources:
                try:
                    raw_data = fetch_fn(CISA_KEV_FEED_URL)
                    if isinstance(raw_data, dict):
                        vulns = raw_data.get("vulnerabilities", [])
                    elif isinstance(raw_data, list):
                        vulns = raw_data
                    else:
                        vulns = []

                    with conn:
                        added = ingest_cisa_kev_delta(conn, vulns)
                    delta_counts["cisa_kev"] = added
                    source_report["cisa_kev"] = {"status": "updated", "records_processed": added}
                except Exception as e:
                    source_report["cisa_kev"] = {"status": "offline_fallback", "error": str(e), "records_processed": 0}

            # 2. Update HackerOne Disclosures
            if "hackerone" in selected_sources:
                try:
                    raw_data = fetch_fn(HACKERONE_FEED_URL)
                    if isinstance(raw_data, dict):
                        reports = raw_data.get("reports", [])
                    elif isinstance(raw_data, list):
                        reports = raw_data
                    else:
                        reports = []

                    with conn:
                        added = ingest_h1_delta(conn, reports)
                    delta_counts["h1_disclosures"] = added
                    source_report["hackerone"] = {"status": "updated", "records_processed": added}
                except Exception as e:
                    source_report["hackerone"] = {"status": "offline_fallback", "error": str(e), "records_processed": 0}

            # 3. Update Nuclei Community Templates
            if "nuclei" in selected_sources:
                try:
                    raw_data = fetch_fn(NUCLEI_FEED_URL)
                    if isinstance(raw_data, dict):
                        templates = raw_data.get("templates", [])
                    elif isinstance(raw_data, list):
                        templates = raw_data
                    else:
                        templates = []

                    with conn:
                        added = ingest_nuclei_delta(conn, templates)
                    delta_counts["nuclei_templates"] = added
                    source_report["nuclei"] = {"status": "updated", "records_processed": added}
                except Exception as e:
                    source_report["nuclei"] = {"status": "offline_fallback", "error": str(e), "records_processed": 0}

        # Determine overall source status
        if offline:
            overall_status = "offline_sync"
        elif any(s.get("status") == "updated" for s in source_report.values()):
            overall_status = "live_updated"
        else:
            overall_status = "fallback_offline"

        details = {
            "offline_mode": offline,
            "sources": source_report,
            "delta_counts": delta_counts,
        }

        # Stamp version and per-table record counts
        meta = stamp_intel_version(
            conn=conn,
            version=version,
            source_status=overall_status,
            details=details,
        )

        return {
            "status": "success",
            "offline_mode": offline,
            "version": meta["version"],
            "updated_at": meta["updated_at"],
            "table_counts": meta["table_counts"],
            "total_records": meta["total_records"],
            "deltas": delta_counts,
            "sources": source_report,
            "database_path": str(target_db),
        }
    finally:
        conn.close()


def main_update_cli(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint for `webripper intel update`."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="webripper intel update",
        description="Update WebRipper security intelligence database (CISA KEV, HackerOne, Nuclei).",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Rebuild metadata and stamp versions offline without network requests",
    )
    parser.add_argument(
        "--db",
        type=str,
        default=None,
        help="Custom path to intel.db SQLite database",
    )
    parser.add_argument(
        "--version-tag",
        type=str,
        default=None,
        help="Custom version tag to stamp into database",
    )
    args = parser.parse_args(argv)

    print(f"[*] Executing WebRipper intelligence update (mode: {'offline' if args.offline else 'live'})...")
    result = update_intel(
        db_path=args.db,
        offline=args.offline,
        version=args.version_tag,
    )

    print(f"[+] Intelligence Database Updated: Version {result['version']}")
    print(f"    Timestamp: {result['updated_at']}")
    print("    Indexed Records by Dataset:")
    for tbl, count in result["table_counts"].items():
        print(f"      - {tbl}: {count:,}")
    print(f"    Total Security Artifacts: {result['total_records']:,}")

    return 0


if __name__ == "__main__":
    sys.exit(main_update_cli(sys.argv[1:]))

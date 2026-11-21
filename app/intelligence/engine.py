"""
Scenario Intelligence Engine.
Stores and queries real-world bug bounty scenario recipes, Nuclei signatures,
PortSwigger research patterns, HackerOne writeups, and CISA KEV entries using SQLite FTS5,
providing fingerprint-targeted matching and BM25 full-text intelligence search.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .models import ScenarioRecipe
from .catalog import CORE_SCENARIOS


class ScenarioEngine:
    """Manages local vulnerability intelligence database."""

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            # 1. Prefer bundled database shipped directly in app/intelligence/intel.db
            bundled_db = Path(__file__).resolve().parent / "intel.db"
            if bundled_db.is_file():
                self.db_path = str(bundled_db)
            else:
                base_dir = os.path.join(
                    os.environ.get("APPDATA", os.path.expanduser("~")),
                    "WebRipper",
                    "intelligence",
                )
                os.makedirs(base_dir, exist_ok=True)
                self.db_path = os.path.join(base_dir, "intel.db")
        else:
            self.db_path = db_path

        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.OperationalError:
            pass  # Fallback for read-only database mounts or filesystems
        return conn

    def _init_db(self) -> None:
        """Create tables and FTS5 search index, seed with core scenarios."""
        try:
            conn = self._get_connection()
            try:
                cur = conn.cursor()
                cur.execute("SELECT 1 FROM scenarios LIMIT 1")
                if cur.fetchone():
                    conn.close()
                    return
            except Exception:
                pass

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
                CREATE VIRTUAL TABLE IF NOT EXISTS scenarios_fts USING fts5(
                    id UNINDEXED,
                    title,
                    tech_stack,
                    bounty_reference,
                    author_insight,
                    remediation,
                    cwe
                )
            """)

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

            # Ensure all current core scenarios are seeded/updated
            self._seed_scenarios(conn, CORE_SCENARIOS)
            conn.commit()
            conn.close()
        except sqlite3.OperationalError:
            pass
        except Exception:
            pass

    def _seed_scenarios(self, conn: sqlite3.Connection, scenarios: List[ScenarioRecipe]) -> None:
        """Batch insert scenario recipes and update FTS index."""
        cur = conn.cursor()
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
            tech_str = " ".join(s.tech_stack)
            cur.execute("DELETE FROM scenarios_fts WHERE id = ?", (s.id,))
            cur.execute("""
                INSERT INTO scenarios_fts (id, title, tech_stack, bounty_reference, author_insight, remediation, cwe)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (s.id, s.title, tech_str, s.bounty_reference, s.author_insight, s.remediation, s.cwe))

    def _row_to_recipe(self, row: tuple) -> ScenarioRecipe:
        return ScenarioRecipe(
            id=row[0],
            title=row[1],
            tech_stack=json.loads(row[2]) if row[2] else [],
            category=row[3],
            cwe=row[4],
            cvss_vector=row[5],
            probe_method=row[6],
            probe_path=row[7],
            probe_headers=json.loads(row[8]) if row[8] else {},
            probe_body=row[9],
            match_status=json.loads(row[10]) if row[10] else [200],
            match_regex=row[11],
            negative_regex=row[12],
            bounty_reference=row[13],
            author_insight=row[14],
            remediation=row[15],
        )

    def find_scenarios_for_tech(
        self,
        tech_list: Union[List[str], str],
        limit: Optional[int] = None,
    ) -> List[ScenarioRecipe]:
        """Find scenarios that match ANY of the detected technologies."""
        if isinstance(tech_list, str):
            tech_list = [t.strip() for t in tech_list.split(",") if t.strip()]

        if not tech_list:
            return []

        clean_techs = [t.lower().strip() for t in tech_list if t.strip()]
        if not clean_techs:
            return []

        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM scenarios")
        rows = cur.fetchall()
        conn.close()

        matched = []
        for r in rows:
            recipe = self._row_to_recipe(r)
            recipe_techs = [t.lower() for t in recipe.tech_stack]
            # Match if any detected tech overlaps or is substring
            if any(dt in rt or rt in dt for dt in clean_techs for rt in recipe_techs):
                matched.append(recipe)

        if limit and limit > 0:
            return matched[:limit]
        return matched

    def search(
        self,
        query: str,
        tech_filter: Optional[List[str]] = None,
        limit: int = 20,
    ) -> List[ScenarioRecipe]:
        """Full-text search across bug bounty scenarios with optional tech filter."""
        clean_query = query.strip()
        if not clean_query:
            return self.all_scenarios()[:limit]

        conn = self._get_connection()
        cur = conn.cursor()

        sanitized = "".join(c for c in clean_query if c.isalnum() or c in (" ", "_", "-")).strip()
        if not sanitized:
            return self.all_scenarios()[:limit]
        fts_query = f"{sanitized}*"

        try:
            cur.execute("""
                SELECT s.* FROM scenarios s
                JOIN scenarios_fts f ON s.id = f.id
                WHERE scenarios_fts MATCH ?
                ORDER BY rank
                LIMIT ?
            """, (fts_query, limit * 2))
            rows = cur.fetchall()
        except sqlite3.OperationalError:
            cur.execute("""
                SELECT * FROM scenarios
                WHERE title LIKE ? OR author_insight LIKE ? OR tech_stack LIKE ?
                LIMIT ?
            """, (f"%{clean_query}%", f"%{clean_query}%", f"%{clean_query}%", limit * 2))
            rows = cur.fetchall()

        conn.close()

        deduped = []
        seen = set()
        for r in rows:
            rec = self._row_to_recipe(r)
            if rec.id not in seen:
                seen.add(rec.id)
                deduped.append(rec)

        results = deduped

        if tech_filter:
            clean_tf = [t.lower() for t in tech_filter]
            results = [
                r for r in results
                if any(tf in rt or rt in tf for tf in clean_tf for rt in r.tech_stack)
            ]

        return results[:limit]

    def get_by_id(self, scenario_id: str) -> Optional[ScenarioRecipe]:
        """Retrieve a single scenario by its ID."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM scenarios WHERE id = ?", (scenario_id,))
        row = cur.fetchone()
        conn.close()
        return self._row_to_recipe(row) if row else None

    def all_scenarios(self) -> List[ScenarioRecipe]:
        """Retrieve all registered scenarios."""
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM scenarios ORDER BY id")
        rows = cur.fetchall()
        conn.close()
        return [self._row_to_recipe(r) for r in rows]

    def search_unified(self, query: str, limit: int = 15) -> List[Dict[str, Any]]:
        """
        Unified search across all intelligence datasets:
        Scenarios, Nuclei Templates, PortSwigger Research, HackerOne Disclosures,
        CISA KEV, and Subdomain Takeovers.
        """
        clean_query = query.strip()
        if not clean_query:
            return []

        conn = self._get_connection()
        cur = conn.cursor()
        sanitized = "".join(c for c in clean_query if c.isalnum() or c in (" ", "_", "-")).strip()
        if not sanitized:
            return self.all_scenarios()[:limit]
        fts_query = f"{sanitized}*"

        results = []
        try:
            cur.execute("""
                SELECT source, ref_id, title, content, tech_stack, vuln_type, cwe, rank
                FROM intel_fts
                WHERE intel_fts MATCH ?
                ORDER BY rank
                LIMIT ?
            """, (fts_query, limit))
            for row in cur.fetchall():
                results.append({
                    "source": row[0],
                    "ref_id": row[1],
                    "title": row[2],
                    "content": row[3],
                    "tech_stack": row[4],
                    "vuln_type": row[5],
                    "cwe": row[6],
                })
        except Exception:
            try:
                cur.execute("""
                    SELECT 'scenario', id, title, author_insight, tech_stack, category, cwe
                    FROM scenarios
                    WHERE title LIKE ? OR author_insight LIKE ?
                    LIMIT 5
                """, (f"%{clean_query}%", f"%{clean_query}%"))
                for row in cur.fetchall():
                    results.append({
                        "source": row[0], "ref_id": row[1], "title": row[2],
                        "content": row[3], "tech_stack": row[4], "vuln_type": row[5], "cwe": row[6]
                    })
            except Exception:
                pass

            try:
                cur.execute("""
                    SELECT 'hackerone', id, title, 'Bounty: $' || bounty || ' | ' || program, tech_stack, vuln_type, cwe
                    FROM h1_disclosures
                    WHERE title LIKE ? OR program LIKE ?
                    LIMIT 5
                """, (f"%{clean_query}%", f"%{clean_query}%"))
                for row in cur.fetchall():
                    results.append({
                        "source": row[0], "ref_id": row[1], "title": row[2],
                        "content": row[3], "tech_stack": row[4], "vuln_type": row[5], "cwe": row[6]
                    })
            except Exception:
                pass

        conn.close()
        return results

    def search_nuclei(self, query: str, severity: Optional[str] = None, limit: int = 10) -> List[Dict[str, Any]]:
        """Search Nuclei community templates catalog."""
        conn = self._get_connection()
        cur = conn.cursor()
        try:
            if severity:
                cur.execute("""
                    SELECT id, name, severity, description, tags, cwe, cvss, method, path, matcher, status
                    FROM nuclei_templates
                    WHERE (id LIKE ? OR name LIKE ? OR description LIKE ? OR tags LIKE ?) AND severity = ?
                    ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END
                    LIMIT ?
                """, (f"%{query}%", f"%{query}%", f"%{query}%", f"%{query}%", severity.lower(), limit))
            else:
                cur.execute("""
                    SELECT id, name, severity, description, tags, cwe, cvss, method, path, matcher, status
                    FROM nuclei_templates
                    WHERE id LIKE ? OR name LIKE ? OR description LIKE ? OR tags LIKE ?
                    ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END
                    LIMIT ?
                """, (f"%{query}%", f"%{query}%", f"%{query}%", f"%{query}%", limit))
            rows = cur.fetchall()
            return [
                {
                    "id": r[0], "name": r[1], "severity": r[2], "description": r[3],
                    "tags": r[4], "cwe": r[5], "cvss": r[6], "method": r[7],
                    "path": r[8], "matcher": r[9], "status": r[10]
                }
                for r in rows
            ]
        except Exception:
            return []
        finally:
            conn.close()

    def search_portswigger(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Search PortSwigger Web Security Research & Academy methodologies."""
        conn = self._get_connection()
        cur = conn.cursor()
        try:
            cur.execute("""
                SELECT id, title, category, cwe, cvss_vector, attack_vector, detection_probe, impact, author_reference, remediation
                FROM portswigger_research
                WHERE id LIKE ? OR title LIKE ? OR attack_vector LIKE ? OR category LIKE ?
                LIMIT ?
            """, (f"%{query}%", f"%{query}%", f"%{query}%", f"%{query}%", limit))
            rows = cur.fetchall()
            return [
                {
                    "id": r[0], "title": r[1], "category": r[2], "cwe": r[3],
                    "cvss_vector": r[4], "attack_vector": r[5], "detection_probe": r[6],
                    "impact": r[7], "author_reference": r[8], "remediation": r[9]
                }
                for r in rows
            ]
        except Exception:
            return []
        finally:
            conn.close()

    def search_hackerone(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Search HackerOne bug bounty reports."""
        conn = self._get_connection()
        cur = conn.cursor()
        try:
            cur.execute("""
                SELECT id, program, title, link, upvotes, bounty, vuln_type, cwe, tech_stack
                FROM h1_disclosures
                WHERE title LIKE ? OR program LIKE ? OR vuln_type LIKE ?
                ORDER BY bounty DESC, upvotes DESC
                LIMIT ?
            """, (f"%{query}%", f"%{query}%", f"%{query}%", limit))
            rows = cur.fetchall()
            return [
                {
                    "id": r[0], "program": r[1], "title": r[2], "link": r[3],
                    "upvotes": r[4], "bounty": r[5], "vuln_type": r[6], "cwe": r[7],
                    "tech_stack": json.loads(r[8]) if r[8] else []
                }
                for r in rows
            ]
        except Exception:
            return []
        finally:
            conn.close()

    def search_cisa_kev(self, query: str, limit: int = 10, include_description: bool = False) -> List[Dict[str, Any]]:
        """Search CISA Known Exploited Vulnerabilities catalog.

        For component/technology matching, matches against vendor and product using
        word-boundary/token semantics. Only searches short_description if include_description=True.
        """
        conn = self._get_connection()
        cur = conn.cursor()
        try:
            clean_query = query.strip()
            if not clean_query:
                return []

            if include_description:
                cur.execute("""
                    SELECT cve_id, vendor, product, vuln_name, short_description, required_action, notes, cwes, date_added
                    FROM cisa_kev
                    WHERE cve_id LIKE ? OR vendor LIKE ? OR product LIKE ? OR vuln_name LIKE ? OR short_description LIKE ?
                    ORDER BY date_added DESC, cve_id DESC
                    LIMIT ?
                """, (f"%{clean_query}%", f"%{clean_query}%", f"%{clean_query}%", f"%{clean_query}%", f"%{clean_query}%", limit * 4))
            else:
                cur.execute("""
                    SELECT cve_id, vendor, product, vuln_name, short_description, required_action, notes, cwes, date_added
                    FROM cisa_kev
                    WHERE cve_id LIKE ? OR vendor LIKE ? OR product LIKE ?
                    ORDER BY date_added DESC, cve_id DESC
                    LIMIT ?
                """, (f"%{clean_query}%", f"%{clean_query}%", f"%{clean_query}%", limit * 4))

            rows = cur.fetchall()
            token_pattern = re.compile(rf"\b{re.escape(clean_query)}\b", re.IGNORECASE)

            results = []
            for r in rows:
                cve_id, vendor, product, vuln_name, desc, req_act, notes, cwes, date_added = r
                matched_comp = None
                match_type = "component"

                if token_pattern.search(product):
                    matched_comp = product
                elif token_pattern.search(vendor):
                    matched_comp = vendor
                elif token_pattern.search(cve_id) or clean_query.lower() in cve_id.lower():
                    matched_comp = cve_id
                    match_type = "cve"
                elif include_description and (token_pattern.search(desc) or token_pattern.search(vuln_name)):
                    matched_comp = f"{vendor} {product}"
                    match_type = "description"
                else:
                    continue

                results.append({
                    "cve_id": cve_id, "vendor": vendor, "product": product, "vuln_name": vuln_name,
                    "short_description": desc, "required_action": req_act, "notes": notes,
                    "cwes": cwes, "date_added": date_added, "matched_component": matched_comp,
                    "match_type": match_type,
                })
                if len(results) >= limit:
                    break

            return results
        except Exception:
            return []
        finally:
            conn.close()

    def get_takeovers(self) -> List[Dict[str, Any]]:
        """Retrieve all subdomain takeover fingerprints."""
        conn = self._get_connection()
        cur = conn.cursor()
        try:
            cur.execute("SELECT service, cnames, fingerprint, nxdomain, status FROM takeovers")
            rows = cur.fetchall()
            return [
                {
                    "service": r[0],
                    "cnames": json.loads(r[1]) if r[1] else [],
                    "fingerprint": r[2],
                    "nxdomain": bool(r[3]),
                    "status": r[4],
                }
                for r in rows
            ]
        except Exception:
            return []
        finally:
            conn.close()

    def stats(self) -> Dict[str, Any]:
        """Return counts of all indexed security intelligence artifacts."""
        conn = self._get_connection()
        cur = conn.cursor()
        counts: Dict[str, Any] = {
            "version": "5.0",
            "scenarios": 0,
            "h1_disclosures": 0,
            "cisa_kev": 0,
            "nuclei_templates": 0,
            "portswigger_research": 0,
            "takeovers": 0,
            "total_records": 0,
        }
        for table in ("scenarios", "h1_disclosures", "cisa_kev", "nuclei_templates", "portswigger_research", "takeovers"):
            try:
                cur.execute(f"SELECT COUNT(*) FROM {table}")
                row = cur.fetchone()
                val = row[0] if row else 0
                counts[table] = val
                counts["total_records"] += val
            except Exception:
                pass
        conn.close()
        return counts


_global_engine: Optional[ScenarioEngine] = None


def get_engine() -> ScenarioEngine:
    """Get or create singleton ScenarioEngine."""
    global _global_engine
    if _global_engine is None:
        _global_engine = ScenarioEngine()
    return _global_engine

"""
WebRipper Recon 5.0 — Submission-Quality Guard & Duplicate Risk Scorer.

Evaluates findings against HackerOne disclosed reports and scenarios in intel.db
to predict duplicate risk, and flags findings that lack non-destructive proof
or exhibit high duplicate likelihood.
"""

from __future__ import annotations

import os
import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional


class DuplicateRiskScorer:
    """Evaluates the risk that a discovered finding is a known duplicate based on intel.db."""

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None or db_path == "":
            bundled_db = Path(__file__).resolve().parent.parent / "intelligence" / "intel.db"
            if bundled_db.is_file():
                self.db_path = str(bundled_db)
            else:
                base_dir = os.path.join(
                    os.environ.get("APPDATA", os.path.expanduser("~")),
                    "WebRipper",
                    "intelligence",
                )
                self.db_path = os.path.join(base_dir, "intel.db")
        else:
            self.db_path = db_path

    def calculate_risk(
        self,
        title: str,
        cwe: str = "",
        tech_stack: Optional[List[str]] = None,
        program: str = "",
    ) -> Dict[str, Any]:
        """
        Query intel.db and return duplicate risk telemetry.

        Formula:
          S_dup = 0.50 * S_title + 0.30 * S_cwe + 0.20 * S_tech
          (boosted by 0.25 if program matches)
        """
        if not self.db_path or not os.path.exists(self.db_path):
            return {
                "score": 0.0,
                "risk_level": "LOW",
                "similar_disclosures_count": 0,
                "top_disclosures": [],
                "rationale": "Database unavailable or not found",
            }

        conn: Optional[sqlite3.Connection] = None
        try:
            conn = sqlite3.connect(self.db_path, timeout=5.0)
            cur = conn.cursor()

            # Clean tokens for FTS / query
            clean_tokens = [w for w in re.findall(r"\w+", (title or "").lower()) if len(w) > 2]
            safe_tokens = [w for w in clean_tokens if w.upper() not in {"AND", "OR", "NOT"}]
            fts_query = " OR ".join(safe_tokens[:6])

            similar_reports: List[Dict[str, Any]] = []
            max_score = 0.0

            if fts_query:
                rows: List[tuple] = []
                try:
                    # Attempt SQLite FTS5 query with intel_fts
                    cur.execute(
                        """
                        SELECT h.id, h.program, h.title, h.bounty, h.cwe, h.tech_stack, h.link
                        FROM h1_disclosures h
                        JOIN intel_fts f ON h.id = f.ref_id
                        WHERE intel_fts MATCH ?
                        ORDER BY rank
                        LIMIT 25
                        """,
                        (fts_query,),
                    )
                    rows = cur.fetchall()
                except sqlite3.OperationalError:
                    # Fallback to direct LIKE queries on h1_disclosures
                    try:
                        like_tokens = safe_tokens[:4]
                        if like_tokens:
                            where_clause = " OR ".join(["h.title LIKE ?"] * len(like_tokens))
                            params = [f"%{tok}%" for tok in like_tokens]
                            cur.execute(
                                f"""
                                SELECT h.id, h.program, h.title, h.bounty, h.cwe, h.tech_stack, h.link
                                FROM h1_disclosures h
                                WHERE {where_clause}
                                LIMIT 25
                                """,
                                params,
                            )
                            rows = cur.fetchall()
                    except Exception:
                        rows = []

                finding_words = set(clean_tokens)
                for row in rows:
                    ref_id, h1_prog, h1_title, bounty, h1_cwe, h1_tech, link = row
                    h1_words = set(re.findall(r"\w+", (h1_title or "").lower()))
                    jaccard = len(finding_words & h1_words) / max(1, len(finding_words | h1_words))

                    cwe_score = 1.0 if (cwe and h1_cwe and cwe.lower().strip() == h1_cwe.lower().strip()) else 0.2
                    tech_overlap = 0.0
                    if tech_stack and h1_tech:
                        h1_t_set = set(t.lower() for t in re.findall(r"\w+", h1_tech))
                        curr_t_set = set(t.lower() for t in tech_stack)
                        if h1_t_set & curr_t_set:
                            tech_overlap = 1.0

                    score = (0.50 * jaccard) + (0.30 * cwe_score) + (0.20 * tech_overlap)
                    if program and h1_prog and program.lower() in h1_prog.lower():
                        score = min(1.0, score + 0.25)

                    if score > max_score:
                        max_score = score

                    if score >= 0.40:
                        link_str = link or ""
                        if link_str and not link_str.startswith("http"):
                            link_str = f"https://{link_str}"

                        similar_reports.append({
                            "id": ref_id,
                            "program": h1_prog or "",
                            "title": h1_title or "",
                            "bounty": float(bounty) if bounty is not None else 0.0,
                            "similarity": round(score, 2),
                            "link": link_str,
                        })

            similar_reports.sort(key=lambda x: x["similarity"], reverse=True)

            risk_level = "LOW"
            if max_score >= 0.70:
                risk_level = "HIGH"
            elif max_score >= 0.40:
                risk_level = "MEDIUM"

            return {
                "score": round(max_score, 2),
                "risk_level": risk_level,
                "similar_disclosures_count": len(similar_reports),
                "top_disclosures": similar_reports[:3],
                "rationale": (
                    f"Matched {len(similar_reports)} historical reports with peak similarity {round(max_score, 2)}"
                    if similar_reports
                    else "No significantly similar historical reports found"
                ),
            }
        except Exception:
            return {
                "score": 0.0,
                "risk_level": "LOW",
                "similar_disclosures_count": 0,
                "top_disclosures": [],
                "rationale": "Search bypassed",
            }
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def score_finding(
        self,
        finding: Any,
        program: str = "",
        tech_stack: Optional[List[str]] = None,
    ) -> Any:
        """
        Evaluate finding against intelligence DB, attach metadata['duplicate_risk'],
        and flag findings lacking proof or presenting high duplicate risk.
        """
        if not hasattr(finding, "metadata") or not isinstance(finding.metadata, dict):
            finding.metadata = {}

        title = getattr(finding, "title", "")
        cwe = getattr(finding, "cwe", "")
        if not cwe:
            cwe = finding.metadata.get("cwe", "")
        if tech_stack is None:
            tech_stack = finding.metadata.get("tech_stack", [])
        if isinstance(tech_stack, str):
            tech_stack = [tech_stack]

        risk = self.calculate_risk(title=title, cwe=cwe, tech_stack=tech_stack, program=program)
        finding.metadata["duplicate_risk"] = risk

        # Proof inspection: check proof_attached or presence of proof artifact
        has_proof = bool(
            finding.metadata.get("proof_attached") is True
            or finding.metadata.get("proof")
            or getattr(finding, "confidence", "") == "VERIFIED"
        )
        is_high_duplicate_risk = (risk.get("risk_level") == "HIGH")

        flags: List[str] = []
        if not has_proof:
            flags.append("NO_PROOF_ATTACHED")
        if is_high_duplicate_risk:
            flags.append("HIGH_DUPLICATE_RISK")

        finding.metadata["submission_flags"] = flags
        finding.metadata["flagged"] = len(flags) > 0
        finding.metadata["submission_ready"] = (len(flags) == 0)
        finding.metadata["is_duplicate_risk"] = is_high_duplicate_risk

        return finding

    def score_findings(
        self,
        findings: List[Any],
        program: str = "",
        tech_stack: Optional[List[str]] = None,
    ) -> List[Any]:
        """Score a collection of findings."""
        for f in findings:
            self.score_finding(f, program=program, tech_stack=tech_stack)
        return findings


def score_finding_submission_risk(
    finding: Any,
    db_path: Optional[str] = None,
    program: str = "",
    tech_stack: Optional[List[str]] = None,
) -> Any:
    """Helper function to score a finding using DuplicateRiskScorer."""
    scorer = DuplicateRiskScorer(db_path=db_path)
    return scorer.score_finding(finding, program=program, tech_stack=tech_stack)


def evaluate_submission_quality(
    finding: Any,
    db_path: Optional[str] = None,
    program: str = "",
    tech_stack: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Helper function to return submission quality evaluation dictionary."""
    scorer = DuplicateRiskScorer(db_path=db_path)
    scored = scorer.score_finding(finding, program=program, tech_stack=tech_stack)
    meta = scored.metadata
    return {
        "ready": meta.get("submission_ready", False),
        "flags": meta.get("submission_flags", []),
        "duplicate_risk": meta.get("duplicate_risk", {}),
    }

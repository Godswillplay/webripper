"""
Local False-Positive Feedback Loop and Finding Dismissal Store for WebRipper Recon 5.0.

Provides a strictly local, per-user SQLite feedback database stored at
~/.webripper/feedback.db (or configured via WEBRIPPER_FEEDBACK_DB env var or parameter).
Allows recording false-positive dismissals, querying feedback statistics,
and suppressing or downranking dismissed findings across future scans.

DATA PRIVACY:
This data is stored purely locally on the user's filesystem and is NEVER uploaded.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse

try:
    from ..models import Finding, Severity
except ImportError:
    Finding = Any  # type: ignore
    Severity = Any  # type: ignore


DEFAULT_FEEDBACK_DIR = Path.home() / ".webripper"
DEFAULT_FEEDBACK_DB = DEFAULT_FEEDBACK_DIR / "feedback.db"


def get_feedback_db_path(custom_path: Optional[Union[str, Path]] = None) -> Path:
    """Resolve feedback database path respecting parameter, env var, and default."""
    if custom_path:
        return Path(custom_path).expanduser().resolve()
    env_path = os.environ.get("WEBRIPPER_FEEDBACK_DB")
    if env_path:
        return Path(env_path).expanduser().resolve()
    return DEFAULT_FEEDBACK_DB.resolve()


def normalize_target(target: Optional[str]) -> str:
    """Normalize a target string (hostname, domain, URL, or wildcard)."""
    if not target or target.strip() in ("", "*"):
        return "*"
    t = target.strip().lower()
    if t.startswith("http://") or t.startswith("https://"):
        parsed = urlparse(t)
        host = parsed.netloc or parsed.path
        return host.split(":")[0].strip()
    return t.split("/")[0].split(":")[0].strip()


def _target_matches(rule_target: str, finding_target: str) -> bool:
    """Check if a rule target matches the finding's target."""
    if rule_target in ("*", "", "all"):
        return True
    if finding_target in ("*", "", "all"):
        return True
    norm_rule = normalize_target(rule_target)
    norm_target = normalize_target(finding_target)
    if norm_rule in ("*", "") or norm_target in ("*", ""):
        return True
    if norm_rule == norm_target:
        return True
    # Subdomain match: e.g. api.example.com matches example.com
    if norm_target.endswith("." + norm_rule):
        return True
    if norm_rule.endswith("." + norm_target):
        return True
    return False


def _extract_finding_info(finding: Any, target_override: Optional[str] = None) -> Tuple[Set[str], str, str]:
    """
    Extract (candidate_rule_ids, category, target) from a finding object, dict, or string.
    """
    candidate_ids: Set[str] = set()
    category = "*"
    extracted_target = target_override or "*"

    if isinstance(finding, str):
        candidate_ids.add(finding.strip().lower())
        return candidate_ids, category, normalize_target(extracted_target)

    if isinstance(finding, dict):
        if "rule_id" in finding and finding["rule_id"]:
            candidate_ids.add(str(finding["rule_id"]).strip().lower())
        if "title" in finding and finding["title"]:
            candidate_ids.add(str(finding["title"]).strip().lower())
        if "category" in finding and finding["category"]:
            category = str(finding["category"]).strip().lower()
            candidate_ids.add(category)
        if "url" in finding and finding["url"] and (not target_override or target_override == "*"):
            extracted_target = str(finding["url"])
        meta = finding.get("metadata", {}) or {}
        if isinstance(meta, dict):
            for k in ("scenario_id", "rule_id", "cve_id", "cve", "cwe", "owasp", "pattern_type"):
                if k in meta and meta[k]:
                    candidate_ids.add(str(meta[k]).strip().lower())
            if "target" in meta and meta["target"] and (not target_override or target_override == "*"):
                extracted_target = str(meta["target"])

    else:
        # Finding dataclass or object
        if hasattr(finding, "title") and finding.title:
            candidate_ids.add(str(finding.title).strip().lower())
        if hasattr(finding, "category") and finding.category:
            category = str(finding.category).strip().lower()
            candidate_ids.add(category)
        if hasattr(finding, "url") and finding.url and (not target_override or target_override == "*"):
            extracted_target = str(finding.url)
        meta = getattr(finding, "metadata", {}) or {}
        if isinstance(meta, dict):
            for k in ("scenario_id", "rule_id", "cve_id", "cve", "cwe", "owasp", "pattern_type"):
                if k in meta and meta[k]:
                    candidate_ids.add(str(meta[k]).strip().lower())
            if "target" in meta and meta["target"] and (not target_override or target_override == "*"):
                extracted_target = str(meta["target"])
        if hasattr(finding, "cwe") and finding.cwe:
            candidate_ids.add(str(finding.cwe).strip().lower())

    return candidate_ids, category, normalize_target(extracted_target)


class FeedbackDB:
    """Manages the local SQLite database of false-positive finding dismissals."""

    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        self.db_path = get_feedback_db_path(db_path)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.OperationalError:
            pass
        return conn

    def _init_db(self) -> None:
        """Create dismissals table and indices if they do not exist."""
        conn = self._get_connection()
        try:
            with conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS dismissals (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        pattern_type TEXT NOT NULL,
                        target TEXT NOT NULL DEFAULT '*',
                        rule_id TEXT NOT NULL,
                        rationale TEXT DEFAULT '',
                        action TEXT NOT NULL DEFAULT 'suppress',
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        UNIQUE(pattern_type, target, rule_id)
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_dismissals_rule ON dismissals(rule_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_dismissals_target ON dismissals(target)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_dismissals_pattern ON dismissals(pattern_type)")
        finally:
            conn.close()

    def dismiss(
        self,
        pattern_type: str,
        target: str = "*",
        rule_id: str = "*",
        rationale: str = "",
        action: str = "suppress",
    ) -> Dict[str, Any]:
        """Record or update a false-positive dismissal."""
        norm_target = normalize_target(target)
        p_type = (pattern_type or "*").strip()
        r_id = (rule_id or "*").strip()
        act = action.strip().lower() if action in ("suppress", "downrank") else "suppress"
        now = datetime.now(timezone.utc).isoformat()

        conn = self._get_connection()
        try:
            with conn:
                conn.execute("""
                    INSERT INTO dismissals (pattern_type, target, rule_id, rationale, action, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(pattern_type, target, rule_id) DO UPDATE SET
                        rationale = excluded.rationale,
                        action = excluded.action,
                        updated_at = excluded.updated_at
                """, (p_type, norm_target, r_id, rationale, act, now, now))
                cur = conn.execute(
                    "SELECT id, pattern_type, target, rule_id, rationale, action, created_at, updated_at "
                    "FROM dismissals WHERE pattern_type = ? AND target = ? AND rule_id = ?",
                    (p_type, norm_target, r_id),
                )
                row = cur.fetchone()
                return dict(row) if row else {}
        finally:
            conn.close()

    def revoke(
        self,
        rule_id: str,
        target: str = "*",
        pattern_type: Optional[str] = None,
    ) -> bool:
        """Revoke a previously recorded dismissal."""
        norm_target = normalize_target(target)
        conn = self._get_connection()
        try:
            with conn:
                if pattern_type:
                    cur = conn.execute(
                        "DELETE FROM dismissals WHERE rule_id = ? AND target = ? AND pattern_type = ?",
                        (rule_id.strip(), norm_target, pattern_type.strip()),
                    )
                else:
                    cur = conn.execute(
                        "DELETE FROM dismissals WHERE rule_id = ? AND target = ?",
                        (rule_id.strip(), norm_target),
                    )
                return cur.rowcount > 0
        finally:
            conn.close()

    def find_matching_dismissal(
        self,
        finding: Any,
        target: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Find the matching dismissal record for a finding, if any exists."""
        candidate_ids, category, finding_target = _extract_finding_info(finding, target)

        conn = self._get_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT id, pattern_type, target, rule_id, rationale, action, created_at, updated_at FROM dismissals"
            )
            rows = cur.fetchall()
            for row in rows:
                p_type = row["pattern_type"]
                r_target = row["target"]
                r_id = row["rule_id"]

                p_type_lower = p_type.strip().lower()
                rule_id_lower = r_id.strip().lower()

                # 1. Pattern type check: wildcard or matches finding category / candidate
                pattern_match = (
                    (category in ("*", "all", ""))
                    or (p_type_lower in ("*", "all", ""))
                    or (p_type_lower == category)
                    or (p_type_lower in candidate_ids)
                )
                if not pattern_match:
                    continue

                # 2. Target check: wildcard or matches finding target
                if not _target_matches(r_target, finding_target):
                    continue

                # 3. Rule ID check: wildcard or matches candidate IDs
                if rule_id_lower not in ("*", "all") and rule_id_lower not in candidate_ids:
                    # Also check for substring matching (e.g. title prefix or cwe)
                    substr_match = False
                    for cid in candidate_ids:
                        if rule_id_lower in cid or cid in rule_id_lower:
                            substr_match = True
                            break
                    if not substr_match:
                        continue

                return dict(row)

            return None
        finally:
            conn.close()

    def is_dismissed(self, finding: Any, target: Optional[str] = None) -> bool:
        """Check if a finding matches any dismissal record."""
        return self.find_matching_dismissal(finding, target=target) is not None

    def get_dismissed_rules(
        self,
        pattern_type: Optional[str] = None,
        target: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List recorded dismissal rules, optionally filtered by pattern_type or target."""
        conn = self._get_connection()
        try:
            cur = conn.cursor()
            query = "SELECT id, pattern_type, target, rule_id, rationale, action, created_at, updated_at FROM dismissals WHERE 1=1"
            params: List[Any] = []
            if pattern_type and pattern_type != "*":
                query += " AND pattern_type = ?"
                params.append(pattern_type.strip())
            if target and target != "*":
                query += " AND target = ?"
                params.append(normalize_target(target))
            query += " ORDER BY id DESC"
            cur.execute(query, params)
            return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

    def get_stats(self) -> Dict[str, Any]:
        """Return feedback statistics including counts of dismissed patterns, categories, and targets."""
        conn = self._get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM dismissals")
            total = cur.fetchone()[0]

            patterns: Dict[str, int] = {}
            cur.execute("SELECT pattern_type, COUNT(*) FROM dismissals GROUP BY pattern_type")
            for row in cur.fetchall():
                patterns[row[0]] = row[1]

            targets: Dict[str, int] = {}
            cur.execute("SELECT target, COUNT(*) FROM dismissals GROUP BY target")
            for row in cur.fetchall():
                targets[row[0]] = row[1]

            actions: Dict[str, int] = {}
            cur.execute("SELECT action, COUNT(*) FROM dismissals GROUP BY action")
            for row in cur.fetchall():
                actions[row[0]] = row[1]

            cur.execute("SELECT MAX(updated_at) FROM dismissals")
            latest_row = cur.fetchone()
            latest = latest_row[0] if latest_row else None

            return {
                "total": total,
                "total_dismissals": total,
                "patterns": patterns,
                "by_pattern_type": patterns,
                "categories": patterns,
                "by_category": patterns,
                "targets": targets,
                "by_target": targets,
                "actions": actions,
                "by_action": actions,
                "latest_dismissal": latest,
                "database_path": str(self.db_path),
            }
        finally:
            conn.close()

    def filter_findings(
        self,
        findings: List[Finding],
        target: Optional[str] = None,
    ) -> List[Finding]:
        """
        Apply feedback rules to findings:
        - Suppress (remove) findings with matching 'suppress' dismissal.
        - Downrank findings with matching 'downrank' dismissal (adjust severity and annotate metadata).
        """
        kept: List[Finding] = []
        for f in findings:
            match = self.find_matching_dismissal(f, target=target)
            if match is None:
                kept.append(f)
                continue

            action = match.get("action", "suppress").lower()
            if action == "suppress":
                # Suppress finding entirely
                continue
            elif action == "downrank":
                # Downrank severity to INFO / low confidence
                if hasattr(f, "severity"):
                    try:
                        f.severity = Severity.INFO if hasattr(Severity, "INFO") else "INFO"
                    except Exception:
                        pass
                if hasattr(f, "confidence"):
                    f.confidence = "POSSIBLE"
                if hasattr(f, "metadata") and isinstance(f.metadata, dict):
                    f.metadata["downranked"] = True
                    f.metadata["downrank_rationale"] = match.get("rationale", "")
                    f.metadata["feedback_rule_id"] = match.get("rule_id", "")
                elif isinstance(f, dict):
                    f["severity"] = "INFO"
                    f.setdefault("metadata", {})["downranked"] = True
                    f["metadata"]["downrank_rationale"] = match.get("rationale", "")
                    f["metadata"]["feedback_rule_id"] = match.get("rule_id", "")
                kept.append(f)
            else:
                continue
        return kept

    def clear(self) -> None:
        """Clear all dismissal records from feedback database (testing helper)."""
        conn = self._get_connection()
        try:
            with conn:
                conn.execute("DELETE FROM dismissals")
        finally:
            conn.close()


# Module-level convenience functions

def dismiss_finding(
    pattern_type: str,
    target: str = "*",
    rule_id: str = "*",
    rationale: str = "",
    action: str = "suppress",
    db_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Record a false-positive dismissal in the local feedback database."""
    store = FeedbackDB(db_path=db_path)
    return store.dismiss(
        pattern_type=pattern_type,
        target=target,
        rule_id=rule_id,
        rationale=rationale,
        action=action,
    )


def is_dismissed(
    finding: Any,
    target: Optional[str] = None,
    db_path: Optional[Union[str, Path]] = None,
) -> bool:
    """Check if a finding is dismissed according to local feedback store."""
    store = FeedbackDB(db_path=db_path)
    return store.is_dismissed(finding, target=target)


def get_dismissed_rules(
    pattern_type: Optional[str] = None,
    target: Optional[str] = None,
    db_path: Optional[Union[str, Path]] = None,
) -> List[Dict[str, Any]]:
    """Retrieve recorded dismissed rules matching optional pattern_type or target."""
    store = FeedbackDB(db_path=db_path)
    return store.get_dismissed_rules(pattern_type=pattern_type, target=target)


def get_feedback_stats(db_path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """Retrieve counts of dismissed patterns, categories, and targets."""
    store = FeedbackDB(db_path=db_path)
    return store.get_stats()


def suppress_or_downrank_findings(
    findings: List[Finding],
    target: Optional[str] = None,
    db_path: Optional[Union[str, Path]] = None,
) -> List[Finding]:
    """Suppress or downrank dismissed findings in future scans for the user profile."""
    store = FeedbackDB(db_path=db_path)
    return store.filter_findings(findings, target=target)

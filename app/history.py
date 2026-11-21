"""
Scan history, SQLite persistence, and diff for WebRipper Recon 5.0.

Saves scan results to %APPDATA%/WebRipper/history/ via both SQLite (history.db)
and JSON archives, providing fast indexing, historical search, and scan diffing.
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


@dataclass
class ScanRecord:
    """Metadata for a saved scan."""
    path: str
    domain: str
    timestamp: str
    finding_count: int
    critical_count: int
    high_count: int
    medium_count: int


@dataclass
class ScanDiff:
    """Comparison between two scans."""
    new_findings: List[Dict]
    fixed_findings: List[Dict]
    unchanged_findings: List[Dict]
    summary: str

    @property
    def new_count(self) -> int:
        return len(self.new_findings)

    @property
    def fixed_count(self) -> int:
        return len(self.fixed_findings)

    @property
    def unchanged_count(self) -> int:
        return len(self.unchanged_findings)


def _get_history_dir() -> str:
    import sys
    if sys.platform == "win32":
        base_dir = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or os.path.expanduser("~")
    elif sys.platform == "darwin":
        base_dir = os.path.join(os.path.expanduser("~"), "Library", "Application Support")
    else:
        base_dir = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    base = os.path.join(base_dir, "WebRipper", "history")
    os.makedirs(base, exist_ok=True)
    return base


def _get_db_path() -> str:
    return os.path.join(_get_history_dir(), "history.db")


import threading

_db_lock = threading.Lock()
_initialized_dbs: set[str] = set()


def _ensure_db_initialized() -> None:
    """Execute DDL schema creation once per database path under lock."""
    db_path = _get_db_path()
    if db_path in _initialized_dbs:
        return
    with _db_lock:
        if db_path in _initialized_dbs:
            return
        conn = sqlite3.connect(db_path, timeout=30.0)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys = ON")
            with conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS scans (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        domain TEXT NOT NULL,
                        target_url TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        finding_count INTEGER NOT NULL,
                        critical_count INTEGER NOT NULL,
                        high_count INTEGER NOT NULL,
                        medium_count INTEGER NOT NULL,
                        json_path TEXT NOT NULL
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp)")

                conn.execute("""
                    CREATE TABLE IF NOT EXISTS findings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER NOT NULL,
                        category TEXT NOT NULL,
                        title TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        description TEXT,
                        evidence TEXT,
                        remediation TEXT,
                        metadata TEXT,
                        url TEXT,
                        FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)")

                try:
                    conn.execute("ALTER TABLE findings ADD COLUMN url TEXT")
                except sqlite3.OperationalError:
                    pass
            _initialized_dbs.add(db_path)
        finally:
            conn.close()


def _get_connection() -> sqlite3.Connection:
    """Return an active connection with 30s busy timeout, schema initialized."""
    _ensure_db_initialized()
    conn = sqlite3.connect(_get_db_path(), timeout=30.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


_init_db = _get_connection


def _finding_key(f: Any) -> str:
    """Create a unique key for matching findings across scans."""
    if isinstance(f, dict):
        cat = str(f.get('category') or '').strip().lower()
        title = str(f.get('title') or '').strip()
        url = str(f.get('url') or '').strip()
        ev = str(f.get('evidence') or '').strip()[:100]
    else:
        cat = str(getattr(f, 'category', '') or '').strip().lower()
        title = str(getattr(f, 'title', '') or '').strip()
        url = str(getattr(f, 'url', '') or '').strip()
        ev = str(getattr(f, 'evidence', '') or '').strip()[:100]
    return f"{cat}|{title}|{url}|{ev}"


def save_scan(findings: list, target_url: str, scan_results: Optional[list] = None) -> str:
    """Save scan findings to history (both JSON and SQLite). Returns the saved JSON file path."""
    domain = urlparse(target_url).hostname or "unknown"
    ts_file = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    filename = f"{domain}_{ts_file}.json"
    path = os.path.join(_get_history_dir(), filename)
    iso_ts = datetime.now().isoformat()

    crit_count = sum(1 for f in findings if getattr(f.severity, "value", str(f.severity)).upper() == "CRITICAL")
    high_count = sum(1 for f in findings if getattr(f.severity, "value", str(f.severity)).upper() == "HIGH")
    med_count = sum(1 for f in findings if getattr(f.severity, "value", str(f.severity)).upper() == "MEDIUM")

    data: Dict[str, Any] = {
        "target_url": target_url,
        "domain": domain,
        "timestamp": iso_ts,
        "finding_count": len(findings),
        "critical_count": crit_count,
        "high_count": high_count,
        "medium_count": med_count,
        "findings": [],
    }

    findings_for_db = []
    for f in findings:
        sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        f_url = getattr(f, "url", "")
        f_dict = {
            "severity": sev_val,
            "category": f.category,
            "title": f.title,
            "description": f.description,
            "evidence": f.evidence[:1000] if f.evidence else "",
            "remediation": f.remediation,
            "url": f_url,
        }
        meta_dict = {}
        if getattr(f, "metadata", None):
            meta_dict = {
                k: v for k, v in f.metadata.items()
                if isinstance(v, (str, int, float, bool))
            }
            f_dict["metadata"] = meta_dict

        data["findings"].append(f_dict)
        findings_for_db.append((
            f.category,
            f.title,
            sev_val,
            f.description,
            f_dict["evidence"],
            f.remediation,
            json.dumps(meta_dict) if meta_dict else "",
            f_url,
        ))

    # Write JSON file
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)

    # Insert into SQLite
    conn = None
    try:
        conn = _init_db()
        with conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO scans (domain, target_url, timestamp, finding_count, critical_count, high_count, medium_count, json_path)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (domain, target_url, iso_ts, len(findings), crit_count, high_count, med_count, path))
            scan_id = cur.lastrowid
            if findings_for_db and scan_id:
                cur.executemany("""
                    INSERT INTO findings (scan_id, category, title, severity, description, evidence, remediation, metadata, url)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, [(scan_id, *fb) for fb in findings_for_db])
    except Exception:
        pass  # Gracefully fall back if SQLite is locked or unavailable
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

    return path


def list_scans(domain: Optional[str] = None, limit: Optional[int] = None) -> List[ScanRecord]:
    """List saved scans, optionally filtered by domain and limited by count."""
    records: List[ScanRecord] = []
    conn = None

    # Attempt fast SQLite lookup first
    try:
        conn = _init_db()
        cur = conn.cursor()
        query = """
            SELECT json_path, domain, timestamp, finding_count, critical_count, high_count, medium_count
            FROM scans
        """
        params: List[Any] = []
        if domain:
            query += " WHERE domain LIKE ?"
            params.append(f"%{domain}%")
        query += " ORDER BY timestamp DESC"
        if limit is not None and limit > 0:
            query += " LIMIT ?"
            params.append(limit)

        cur.execute(query, tuple(params))
        rows = cur.fetchall()

        if rows:
            for r in rows:
                records.append(ScanRecord(
                    path=r[0],
                    domain=r[1],
                    timestamp=r[2],
                    finding_count=r[3],
                    critical_count=r[4],
                    high_count=r[5],
                    medium_count=r[6],
                ))
            return records
    except Exception:
        records.clear()
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

    # Fallback to filesystem JSON scanning if SQLite not yet populated
    history_dir = _get_history_dir()
    for fname in sorted(os.listdir(history_dir), reverse=True):
        if not fname.endswith(".json"):
            continue
        if limit is not None and limit > 0 and len(records) >= limit:
            break
        fpath = os.path.join(history_dir, fname)
        try:
            with open(fpath, "r", encoding="utf-8") as fh:
                data = json.load(fh)

            scan_domain = data.get("domain", "")
            if domain and domain.lower() not in scan_domain.lower():
                continue

            findings = data.get("findings", [])
            records.append(ScanRecord(
                path=fpath,
                domain=scan_domain,
                timestamp=data.get("timestamp", ""),
                finding_count=len(findings),
                critical_count=sum(1 for f in findings if str(f.get("severity")).upper() == "CRITICAL"),
                high_count=sum(1 for f in findings if str(f.get("severity")).upper() == "HIGH"),
                medium_count=sum(1 for f in findings if str(f.get("severity")).upper() == "MEDIUM"),
            ))
        except (json.JSONDecodeError, OSError):
            continue

    return records


def load_scan(path: str) -> List[Dict]:
    """Load findings from a saved scan file or SQLite record."""
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data.get("findings", [])

    # If file was moved, try loading by path lookup in SQLite
    conn = None
    try:
        conn = _init_db()
        cur = conn.cursor()
        cur.execute("SELECT id FROM scans WHERE json_path = ?", (path,))
        row = cur.fetchone()
        if row:
            cur.execute("""
                SELECT category, title, severity, description, evidence, remediation, metadata, url
                FROM findings WHERE scan_id = ?
            """, (row[0],))
            loaded = []
            for f_row in cur.fetchall():
                meta = {}
                if f_row[6]:
                    try:
                        meta = json.loads(f_row[6])
                    except Exception:
                        pass
                loaded.append({
                    "category": f_row[0],
                    "title": f_row[1],
                    "severity": f_row[2],
                    "description": f_row[3],
                    "evidence": f_row[4],
                    "remediation": f_row[5],
                    "metadata": meta,
                    "url": f_row[7] if len(f_row) > 7 and f_row[7] else "",
                })
            return loaded
    except Exception:
        pass
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

    return []


def search_history(keyword: str = "", domain: Optional[str] = None, limit: int = 100) -> List[Dict]:
    """Search for findings across historical scans matching a keyword and/or domain."""
    results: List[Dict] = []
    conn = None
    try:
        conn = _init_db()
        cur = conn.cursor()
        query = """
            SELECT s.domain, s.timestamp, f.category, f.title, f.severity, f.evidence
            FROM findings f
            JOIN scans s ON f.scan_id = s.id
        """
        conditions: List[str] = []
        params: List[Any] = []
        if keyword:
            conditions.append("(f.title LIKE ? OR f.evidence LIKE ? OR f.description LIKE ?)")
            params.extend([f"%{keyword}%", f"%{keyword}%", f"%{keyword}%"])
        if domain:
            conditions.append("s.domain LIKE ?")
            params.append(f"%{domain}%")

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY s.timestamp DESC LIMIT ?"
        params.append(max(1, limit))

        cur.execute(query, params)
        for r in cur.fetchall():
            results.append({
                "domain": r[0],
                "timestamp": r[1],
                "category": r[2],
                "title": r[3],
                "severity": r[4],
                "evidence": r[5],
            })
    except Exception:
        pass
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
    return results


def diff_scans(old_path: str, new_path: str) -> ScanDiff:
    """Compare two scan files and return the diff."""
    old_findings = load_scan(old_path)
    new_findings = load_scan(new_path)

    old_keys = {_finding_key(f): f for f in old_findings}
    new_keys = {_finding_key(f): f for f in new_findings}

    new_set = set(new_keys.keys()) - set(old_keys.keys())
    fixed_set = set(old_keys.keys()) - set(new_keys.keys())
    unchanged_set = set(old_keys.keys()) & set(new_keys.keys())

    new_list = [new_keys[k] for k in new_set]
    fixed_list = [old_keys[k] for k in fixed_set]
    unchanged_list = [new_keys[k] for k in unchanged_set]

    summary = (
        f"New: {len(new_list)} | Fixed: {len(fixed_list)} | "
        f"Unchanged: {len(unchanged_list)} | "
        f"Total: {len(new_findings)} (was {len(old_findings)})"
    )

    return ScanDiff(
        new_findings=new_list,
        fixed_findings=fixed_list,
        unchanged_findings=unchanged_list,
        summary=summary,
    )

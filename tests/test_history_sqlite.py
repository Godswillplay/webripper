"""
Unit tests for the SQLite history persistence, search, and diffing engine.
"""

import os
import tempfile
from app import history
from app.models import Finding, Severity


def test_history_save_and_list(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        monkeypatch.setattr(history, "_get_history_dir", lambda: tmpdir)

        findings = [
            Finding(
                severity=Severity.CRITICAL,
                category="vulns",
                title="Command Injection",
                description="RCE via shell exec",
                evidence="; cat /etc/passwd",
                remediation="Sanitize input",
            ),
            Finding(
                severity=Severity.MEDIUM,
                category="headers",
                title="Missing HSTS",
                description="Strict-Transport-Security header missing",
            ),
        ]

        json_path = history.save_scan(findings, "https://target-app.com")
        assert os.path.isfile(json_path)

        scans = history.list_scans("target-app.com")
        assert len(scans) >= 1
        rec = scans[0]
        assert rec.domain == "target-app.com"
        assert rec.finding_count == 2
        assert rec.critical_count == 1
        assert rec.medium_count == 1


def test_history_search(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        monkeypatch.setattr(history, "_get_history_dir", lambda: tmpdir)

        findings = [
            Finding(
                severity=Severity.HIGH,
                category="secrets",
                title="Leaked AWS Key",
                description="Exposed AWS credential",
                evidence="AKIAIOSFODNN7EXAMPLE",
            )
        ]
        history.save_scan(findings, "https://cloud-target.org")

        results = history.search_history("AKIAIOSFODNN7EXAMPLE")
        assert len(results) == 1
        assert results[0]["title"] == "Leaked AWS Key"
        assert results[0]["domain"] == "cloud-target.org"


def test_history_diff(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        monkeypatch.setattr(history, "_get_history_dir", lambda: tmpdir)

        scan1_findings = [
            Finding(severity=Severity.HIGH, category="vulns", title="SQLi", description="SQL injection", evidence="id=1'"),
            Finding(severity=Severity.LOW, category="cookies", title="No SameSite", description="Missing SameSite", evidence="cookie"),
        ]
        path1 = history.save_scan(scan1_findings, "https://diff-target.com")

        scan2_findings = [
            # SQLi fixed, new XSS added, cookie unchanged
            Finding(severity=Severity.HIGH, category="vulns", title="XSS", description="Cross site scripting", evidence="q=<script>"),
            Finding(severity=Severity.LOW, category="cookies", title="No SameSite", description="Missing SameSite", evidence="cookie"),
        ]
        path2 = history.save_scan(scan2_findings, "https://diff-target.com")

        diff = history.diff_scans(path1, path2)
        assert diff.new_count == 1
        assert diff.fixed_count == 1
        assert diff.unchanged_count == 1
        assert "New: 1 | Fixed: 1 | Unchanged: 1" in diff.summary


def test_history_list_scans_with_limit(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        monkeypatch.setattr(history, "_get_history_dir", lambda: tmpdir)

        findings = [Finding(severity=Severity.INFO, category="test", title="T1", description="D1")]
        history.save_scan(findings, "https://app1.com")
        history.save_scan(findings, "https://app2.com")
        history.save_scan(findings, "https://app3.com")

        all_scans = history.list_scans()
        assert len(all_scans) == 3

        limited_scans = history.list_scans(limit=2)
        assert len(limited_scans) == 2

"""
Tests for Live Intel Update and Local Feedback Loop (#WebRipper Phase 5).

Covers:
1. Local feedback database creation, configuration, and isolation.
2. Recording false-positive dismissals (by pattern class, target, rule_id, rationale).
3. Checking if findings are dismissed (`is_dismissed`).
4. Suppressing or downranking dismissed findings on subsequent evaluation.
5. Feedback statistics (`get_feedback_stats`) accuracy.
6. Offline intel update logic stamping version and per-table counts on `intel.db`.
7. Mock live delta update ingestion for CISA KEV and HackerOne disclosures.
8. Safe offline fallback on network failure during live update.
9. Isolated temporary copy testing of `intel.db`.

ALL TESTS ARE 100% OFFLINE (ZERO NETWORK CALLS).
"""

import os
import shutil
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.error import URLError

import pytest

from app.intelligence.feedback import (
    FeedbackDB,
    dismiss_finding,
    get_dismissed_rules,
    get_feedback_stats,
    is_dismissed,
    suppress_or_downrank_findings,
)
from app.intelligence.updater import (
    get_intel_metadata,
    stamp_intel_version,
    update_intel,
)
from app.models import Finding, Severity


@pytest.fixture
def temp_feedback_db(tmp_path):
    """Provide an isolated temporary feedback database path."""
    db_file = tmp_path / "test_feedback.db"
    return db_file


@pytest.fixture
def temp_intel_db(tmp_path):
    """Provide an isolated temporary intel.db initialized with schema."""
    db_file = tmp_path / "test_intel.db"
    return db_file


# ---------------------------------------------------------------------------
# Feedback Database & Dismissal Tests
# ---------------------------------------------------------------------------

def test_feedback_db_creation_and_config(temp_feedback_db, monkeypatch):
    """Verify local feedback DB is created and respects environment variable."""
    monkeypatch.setenv("WEBRIPPER_FEEDBACK_DB", str(temp_feedback_db))

    store = FeedbackDB()
    assert Path(store.db_path) == temp_feedback_db.resolve()
    assert temp_feedback_db.exists()

    stats = get_feedback_stats()
    assert stats["total_dismissals"] == 0
    assert stats["patterns"] == {}
    assert stats["targets"] == {}


def test_dismiss_finding_and_is_dismissed(temp_feedback_db):
    """Verify recording a dismissal and evaluating findings against it."""
    # 1. Dismiss a specific scenario for a specific target
    res = dismiss_finding(
        pattern_type="scenarios",
        target="api.target.com",
        rule_id="nextjs-cache-poison",
        rationale="Known false positive behind staging CDN cache",
        action="suppress",
        db_path=temp_feedback_db,
    )
    assert res["rule_id"] == "nextjs-cache-poison"
    assert res["target"] == "api.target.com"
    assert res["action"] == "suppress"

    # 2. Finding matching rule_id in metadata on that target -> Dismissed
    matching_finding = Finding(
        severity=Severity.HIGH,
        category="scenarios",
        title="Scenario: Next.js Cache Poisoning",
        description="SSR cache poisoning vulnerability",
        url="https://api.target.com/docs",
        metadata={"scenario_id": "nextjs-cache-poison"},
    )
    assert is_dismissed(matching_finding, db_path=temp_feedback_db) is True

    # 3. Same finding on a different target domain -> NOT dismissed (target-scoped)
    different_target_finding = Finding(
        severity=Severity.HIGH,
        category="scenarios",
        title="Scenario: Next.js Cache Poisoning",
        description="SSR cache poisoning vulnerability",
        url="https://other-domain.org/docs",
        metadata={"scenario_id": "nextjs-cache-poison"},
    )
    assert is_dismissed(different_target_finding, db_path=temp_feedback_db) is False

    # 4. Different rule on the same target -> NOT dismissed
    different_rule_finding = Finding(
        severity=Severity.HIGH,
        category="scenarios",
        title="Scenario: Spring Actuator Leak",
        description="Spring Actuator heapdump exposed",
        url="https://api.target.com/actuator/env",
        metadata={"scenario_id": "spring-actuator-leak"},
    )
    assert is_dismissed(different_rule_finding, db_path=temp_feedback_db) is False

    # 5. String rule_id lookup
    assert is_dismissed("nextjs-cache-poison", target="api.target.com", db_path=temp_feedback_db) is True
    assert is_dismissed("unknown-rule", target="api.target.com", db_path=temp_feedback_db) is False


def test_global_wildcard_dismissal(temp_feedback_db):
    """Verify global dismissal with target='*' applies to all targets."""
    dismiss_finding(
        pattern_type="secrets",
        target="*",
        rule_id="generic-public-key",
        rationale="Benign public key false positive",
        action="suppress",
        db_path=temp_feedback_db,
    )

    finding1 = Finding(
        severity=Severity.MEDIUM,
        category="secrets",
        title="Exposed Public Key",
        description="RSA public key detected",
        url="https://app1.example.com/main.js",
        metadata={"rule_id": "generic-public-key"},
    )
    finding2 = Finding(
        severity=Severity.MEDIUM,
        category="secrets",
        title="Exposed Public Key",
        description="RSA public key detected",
        url="https://subdomain.acme.corp/bundle.js",
        metadata={"rule_id": "generic-public-key"},
    )

    assert is_dismissed(finding1, db_path=temp_feedback_db) is True
    assert is_dismissed(finding2, db_path=temp_feedback_db) is True


def test_suppress_and_downrank_evaluation(temp_feedback_db):
    """Verify findings are either suppressed (dropped) or downranked (severity lowered)."""
    # Rule 1: Suppress false positive scenario
    dismiss_finding(
        pattern_type="scenarios",
        target="example.com",
        rule_id="test-suppress-scenario",
        rationale="Suppressed completely",
        action="suppress",
        db_path=temp_feedback_db,
    )

    # Rule 2: Downrank noisy path finding
    dismiss_finding(
        pattern_type="paths",
        target="example.com",
        rule_id="test-downrank-path",
        rationale="Demoted to informational notice",
        action="downrank",
        db_path=temp_feedback_db,
    )

    finding_suppressed = Finding(
        severity=Severity.HIGH,
        category="scenarios",
        title="Test Suppressed Scenario",
        description="Should be dropped",
        url="https://example.com/api",
        metadata={"scenario_id": "test-suppress-scenario"},
    )

    finding_downranked = Finding(
        severity=Severity.HIGH,
        category="paths",
        title="Test Downranked Path",
        description="Should be demoted to INFO",
        url="https://example.com/robots.txt",
        metadata={"rule_id": "test-downrank-path"},
    )

    finding_untouched = Finding(
        severity=Severity.CRITICAL,
        category="cves",
        title="Real Critical Vulnerability",
        description="Should remain CRITICAL",
        url="https://example.com/vuln",
        metadata={"rule_id": "CVE-2024-99999"},
    )

    findings = [finding_suppressed, finding_downranked, finding_untouched]
    adjusted = suppress_or_downrank_findings(findings, target="example.com", db_path=temp_feedback_db)

    # finding_suppressed must be removed
    assert len(adjusted) == 2
    assert finding_suppressed not in adjusted

    # finding_downranked must be retained with lowered severity
    downranked_result = next(f for f in adjusted if f.title == "Test Downranked Path")
    assert downranked_result.severity == Severity.INFO
    assert downranked_result.metadata.get("downranked") is True
    assert downranked_result.metadata.get("downrank_rationale") == "Demoted to informational notice"

    # finding_untouched must retain its original severity
    untouched_result = next(f for f in adjusted if f.title == "Real Critical Vulnerability")
    assert untouched_result.severity == Severity.CRITICAL
    assert "downranked" not in untouched_result.metadata


def test_feedback_stats_counts(temp_feedback_db):
    """Verify get_feedback_stats calculates counts of patterns, categories, and targets accurately."""
    dismiss_finding("scenarios", "site1.com", "rule-a", "Reason 1", action="suppress", db_path=temp_feedback_db)
    dismiss_finding("scenarios", "site2.com", "rule-b", "Reason 2", action="downrank", db_path=temp_feedback_db)
    dismiss_finding("secrets", "site1.com", "rule-c", "Reason 3", action="suppress", db_path=temp_feedback_db)

    stats = get_feedback_stats(db_path=temp_feedback_db)

    assert stats["total_dismissals"] == 3
    assert stats["by_pattern_type"] == {"scenarios": 2, "secrets": 1}
    assert stats["by_category"] == {"scenarios": 2, "secrets": 1}
    assert stats["by_target"]["site1.com"] == 2
    assert stats["by_target"]["site2.com"] == 1
    assert stats["by_action"] == {"suppress": 2, "downrank": 1}
    assert stats["latest_dismissal"] is not None


def test_get_dismissed_rules_and_revocation(temp_feedback_db):
    """Verify listing dismissed rules with filters and revoking them."""
    store = FeedbackDB(db_path=temp_feedback_db)
    store.dismiss("scenarios", "target-a.com", "rule-1", "Dismiss rule 1")
    store.dismiss("cves", "target-b.com", "rule-2", "Dismiss rule 2")

    all_rules = store.get_dismissed_rules()
    assert len(all_rules) == 2

    scenario_rules = store.get_dismissed_rules(pattern_type="scenarios")
    assert len(scenario_rules) == 1
    assert scenario_rules[0]["rule_id"] == "rule-1"

    # Revoke rule 1
    revoked = store.revoke(rule_id="rule-1", target="target-a.com")
    assert revoked is True
    assert len(store.get_dismissed_rules()) == 1

    # Revoke non-existent
    assert store.revoke(rule_id="non-existent") is False


# ---------------------------------------------------------------------------
# Intel Update & Database Stamping Tests
# ---------------------------------------------------------------------------

def test_intel_update_offline_mode(temp_intel_db):
    """Verify offline intel update safely updates metadata and stamps version and table counts."""
    # Pre-populate one table to test accurate row counting
    conn = sqlite3.connect(str(temp_intel_db))
    conn.execute("""
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
        )
    """)
    conn.execute("""
        INSERT INTO scenarios (id, title, tech_stack, category, cwe, cvss_vector, probe_method, probe_path,
        probe_headers, probe_body, match_status, match_regex, negative_regex, bounty_reference, author_insight, remediation)
        VALUES ('sc-01', 'Test Recipe', '[]', 'paths', 'CWE-200', 'CVSS:3.1/AV:N', 'GET', '/test', '{}', '', '[]', '', '', '', '', '')
    """)
    conn.commit()
    conn.close()

    # Execute offline update
    result = update_intel(
        db_path=temp_intel_db,
        offline=True,
        version="5.0.0-test-offline",
    )

    assert result["status"] == "success"
    assert result["offline_mode"] is True
    assert result["version"] == "5.0.0-test-offline"
    assert result["table_counts"]["scenarios"] == 1
    assert result["table_counts"]["cisa_kev"] == 0

    # Verify metadata read-back
    meta = get_intel_metadata(temp_intel_db)
    assert meta["version"] == "5.0.0-test-offline"
    assert meta["table_counts"]["scenarios"] == 1
    assert meta["source_status"] == "offline_sync"
    assert meta["updated_at"] is not None


def test_intel_update_mock_delta_ingestion(temp_intel_db):
    """Verify live delta update ingestion for CISA KEV and HackerOne disclosures using mock fetcher."""
    mock_cisa_data = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-10001",
                "vendorProject": "Apache",
                "product": "Tomcat",
                "vulnerabilityName": "Apache Tomcat Remote Code Execution",
                "dateAdded": "2026-11-20",
                "shortDescription": "Critical RCE via custom header manipulation",
                "requiredAction": "Upgrade to latest version immediately",
                "cwes": ["CWE-94"],
            }
        ]
    }

    mock_h1_data = {
        "reports": [
            {
                "id": "999001",
                "program": "Shopify",
                "title": "OAuth Token Leak via Redirect Parameter",
                "link": "https://hackerone.com/reports/999001",
                "upvotes": 128,
                "bounty": 7500.0,
                "vuln_type": "OAuth Bypass",
                "cwe": "CWE-287",
                "tech_stack": ["oauth", "ruby"],
            }
        ]
    }

    mock_nuclei_data = {
        "templates": [
            {
                "id": "cve-2026-10001-tomcat-rce",
                "name": "Apache Tomcat RCE Probe",
                "severity": "critical",
                "description": "Detects Tomcat RCE vulnerability",
                "tags": "cve,tomcat,rce",
                "cwe": "CWE-94",
                "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "method": "GET",
                "path": "/test-probe",
                "matcher": "root:x:0:0",
                "status": 200,
                "file_path": "cves/2026/CVE-2026-10001.yaml",
                "tech_stack": ["tomcat", "java"],
            }
        ]
    }

    def mock_fetcher(url: str):
        if "cisa" in url:
            return mock_cisa_data
        elif "h1" in url or "hackerone" in url:
            return mock_h1_data
        elif "nuclei" in url:
            return mock_nuclei_data
        return {}

    result = update_intel(
        db_path=temp_intel_db,
        offline=False,
        custom_fetcher=mock_fetcher,
        version="5.0.0-delta-mock",
    )

    assert result["status"] == "success"
    assert result["offline_mode"] is False
    assert result["version"] == "5.0.0-delta-mock"
    assert result["deltas"]["cisa_kev"] == 1
    assert result["deltas"]["h1_disclosures"] == 1
    assert result["deltas"]["nuclei_templates"] == 1

    # Verify records exist in database
    conn = sqlite3.connect(str(temp_intel_db))
    cur = conn.cursor()

    cur.execute("SELECT cve_id, vendor, product FROM cisa_kev WHERE cve_id = 'CVE-2026-10001'")
    kev_row = cur.fetchone()
    assert kev_row == ("CVE-2026-10001", "Apache", "Tomcat")

    cur.execute("SELECT id, program, bounty FROM h1_disclosures WHERE id = '999001'")
    h1_row = cur.fetchone()
    assert h1_row == ("999001", "Shopify", 7500.0)

    cur.execute("SELECT id, severity FROM nuclei_templates WHERE id = 'cve-2026-10001-tomcat-rce'")
    nuc_row = cur.fetchone()
    assert nuc_row == ("cve-2026-10001-tomcat-rce", "critical")

    conn.close()


def test_intel_update_network_failure_fallback(temp_intel_db):
    """Verify live update gracefully falls back to offline sync when network request fails."""
    def failing_fetcher(url: str):
        raise URLError("Connection refused by test sandbox (zero-network enforcement)")

    result = update_intel(
        db_path=temp_intel_db,
        offline=False,
        custom_fetcher=failing_fetcher,
        version="5.0.0-fallback-test",
    )

    # Must succeed without raising an unhandled exception
    assert result["status"] == "success"
    assert result["version"] == "5.0.0-fallback-test"
    assert result["sources"]["cisa_kev"]["status"] == "offline_fallback"
    assert result["sources"]["hackerone"]["status"] == "offline_fallback"
    assert result["sources"]["nuclei"]["status"] == "offline_fallback"

    # Must still stamp version and metadata
    meta = get_intel_metadata(temp_intel_db)
    assert meta["version"] == "5.0.0-fallback-test"
    assert meta["source_status"] == "fallback_offline"


def test_intel_update_on_isolated_intel_db_copy(tmp_path):
    """Verify update logic operates cleanly on an isolated temporary copy of the project intel.db."""
    source_db = Path("app/intelligence/intel.db")
    if not source_db.exists():
        pytest.skip("Production app/intelligence/intel.db not found on disk")

    isolated_db = tmp_path / "intel_isolated_copy.db"
    shutil.copy2(source_db, isolated_db)

    # Perform offline update on isolated copy
    result = update_intel(
        db_path=isolated_db,
        offline=True,
        version="5.0.0-isolated-copy",
    )

    assert result["status"] == "success"
    assert result["version"] == "5.0.0-isolated-copy"
    assert result["table_counts"]["scenarios"] > 0
    assert result["total_records"] > 0

    # Ensure metadata read-back matches
    meta = get_intel_metadata(isolated_db)
    assert meta["version"] == "5.0.0-isolated-copy"
    assert meta["total_records"] == result["total_records"]

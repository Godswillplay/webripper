"""
Unit tests for WebRipper Phase 8 — Continuous Monitoring & Watch Mode.

Tests:
  - Historical diffing comparing Scan A and Scan B:
      * Scan A has Finding 1 and Finding 2.
      * Scan B has Finding 1 (unchanged) and Finding 3 (new), while Finding 2 is resolved.
      * Briefing contains exactly 1 new finding, 1 resolved finding, and 0 noise.
  - Markdown and JSON briefing formatting (briefing.md, briefing.json).
  - Changed findings detection (severity, confidence, proof status shifts).
  - Attack chain mutations (new/resolved attack paths).
  - Endpoint shape normalization (IDs, UUIDs, hashes, query shapes).
  - Target configuration parsing, intervals, and authorization enforcement.
  - WatchEngine programmatic runners, baseline cycles, and headless CLI driver.
  - 100% offline, deterministic execution.
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any, Dict, List

import pytest

from app.models import AttackChain, AttackChainStep, Finding, ReconReport, Severity
from app.watch import (
    ChangedFinding,
    HistoricalDiffEngine,
    TargetConfig,
    UnauthorizedTargetError,
    WatchConfig,
    WatchDiffBriefing,
    WatchEngine,
    compute_endpoint_shape,
    compute_finding_fingerprint,
    extract_proof_status,
    parse_interval,
    parse_watch_config,
    run_watch_cli,
)


# =====================================================================
# 1. Core Scan A vs Scan B Diffing & Zero Noise
# =====================================================================

def test_scan_a_vs_scan_b_delta_zero_noise():
    """
    Core requirement test:
      - Scan A has Finding 1 and Finding 2.
      - Scan B has Finding 1 (unchanged) and Finding 3 (new), while Finding 2 is gone (resolved).
      - Briefing contains exactly 1 new finding, 1 resolved finding, and 0 noise.
    """
    # Scan A (Baseline)
    f1_a = Finding(
        severity=Severity.HIGH,
        category="headers",
        title="Missing Content-Security-Policy",
        description="CSP header missing",
        url="https://target.local/",
    )
    f2_a = Finding(
        severity=Severity.MEDIUM,
        category="cookies",
        title="Cookie Missing SameSite Attribute",
        description="Session cookie without SameSite",
        url="https://target.local/login",
    )
    scan_a = [f1_a, f2_a]

    # Scan B (Current)
    f1_b = Finding(
        severity=Severity.HIGH,
        category="headers",
        title="Missing Content-Security-Policy",
        description="CSP header missing",
        url="https://target.local/",
    )
    f3_b = Finding(
        severity=Severity.CRITICAL,
        category="vulns",
        title="SQL Injection in /api/v1/search",
        description="Unsanitized query parameter 'q'",
        url="https://target.local/api/v1/search?q=test",
        evidence="syntax error in SQL statement",
        remediation="Use parameterized queries",
    )
    scan_b = [f1_b, f3_b]

    engine = HistoricalDiffEngine()
    briefing = engine.compare(previous_scan=scan_a, current_scan=scan_b, target="https://target.local")

    # Verify Summary counts
    assert briefing.summary["new"] == 1, "Expected exactly 1 new finding"
    assert briefing.summary["resolved"] == 1, "Expected exactly 1 resolved finding"
    assert briefing.summary["changed"] == 0, "Expected 0 changed findings"
    assert briefing.summary["unchanged"] == 1, "Expected 1 unchanged baseline finding"
    assert briefing.summary["has_changes"] is True

    # Verify New Findings: contains Finding 3
    assert len(briefing.new_findings) == 1
    new_f = briefing.new_findings[0]
    assert new_f["title"] == "SQL Injection in /api/v1/search"
    assert new_f["severity"] == "CRITICAL"
    assert new_f["category"] == "vulns"

    # Verify Resolved Findings: contains Finding 2
    assert len(briefing.resolved_findings) == 1
    res_f = briefing.resolved_findings[0]
    assert res_f["title"] == "Cookie Missing SameSite Attribute"
    assert res_f["severity"] == "MEDIUM"
    assert res_f["category"] == "cookies"

    # Verify Zero Noise: Finding 1 is not in new, resolved, or changed
    new_titles = [f["title"] for f in briefing.new_findings]
    resolved_titles = [f["title"] for f in briefing.resolved_findings]
    changed_titles = [f["title"] for f in briefing.changed_findings]

    assert "Missing Content-Security-Policy" not in new_titles
    assert "Missing Content-Security-Policy" not in resolved_titles
    assert "Missing Content-Security-Policy" not in changed_titles


# =====================================================================
# 2. Markdown and JSON Briefing Output Formatting
# =====================================================================

def test_briefing_markdown_and_json_formatting():
    """
    Verify change-only briefing.md and briefing.json formatting:
      - briefing.md contains sections for new and resolved findings, but NO noise for unchanged.
      - briefing.json has correct structure and summary counts.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        f_base = Finding(
            severity=Severity.LOW,
            category="info",
            title="Server Banner Disclosure",
            description="Apache/2.4 banner exposed",
            url="https://example.com/",
        )
        f_new = Finding(
            severity=Severity.CRITICAL,
            category="paths",
            title="Git Repository Exposed via .git/HEAD",
            description="Public .git folder exposed",
            url="https://example.com/.git/HEAD",
            evidence="ref: refs/heads/main",
            remediation="Deny access to .git",
        )
        f_resolved = Finding(
            severity=Severity.HIGH,
            category="cors",
            title="Overly Permissive CORS Policy",
            description="Access-Control-Allow-Origin: * with credentials",
            url="https://example.com/api/data",
        )

        scan_prev = [f_base, f_resolved]
        scan_curr = [f_base, f_new]

        engine = HistoricalDiffEngine()
        briefing = engine.compare(previous_scan=scan_prev, current_scan=scan_curr, target="https://example.com")
        md_path, json_path = engine.export_briefings(briefing, tmpdir)

        # 1. Verify files exist
        assert os.path.isfile(md_path)
        assert os.path.isfile(json_path)

        # 2. Inspect Markdown content
        with open(md_path, "r", encoding="utf-8") as f:
            md_content = f.read()

        assert "# 🛡️ WebRipper Watch Briefing — Security Delta" in md_content
        assert "Git Repository Exposed via .git/HEAD" in md_content
        assert "Overly Permissive CORS Policy" in md_content
        assert "🚨 **New Findings (Regressions)** | **1**" in md_content
        assert "✅ **Resolved Findings (Remediated)** | **1**" in md_content
        assert "🔒 **Unchanged Findings (Baseline)** | **1**" in md_content

        # Zero noise in finding listings: Server Banner Disclosure is NOT in markdown listings
        assert "### 1. [LOW] Server Banner Disclosure" not in md_content

        # 3. Inspect JSON delta content
        with open(json_path, "r", encoding="utf-8") as f:
            json_delta = json.load(f)

        assert json_delta["version"] == "1.0"
        assert json_delta["target"] == "https://example.com"
        assert json_delta["summary"]["new"] == 1
        assert json_delta["summary"]["resolved"] == 1
        assert json_delta["summary"]["changed"] == 0
        assert json_delta["summary"]["unchanged"] == 1
        assert len(json_delta["new_findings"]) == 1
        assert len(json_delta["resolved_findings"]) == 1
        assert len(json_delta["changed_findings"]) == 0
        assert json_delta["new_findings"][0]["title"] == "Git Repository Exposed via .git/HEAD"
        assert json_delta["resolved_findings"][0]["title"] == "Overly Permissive CORS Policy"


# =====================================================================
# 3. Changed Findings (Severity, Confidence, Proof Shifts)
# =====================================================================

def test_changed_findings_severity_confidence_and_proof():
    """
    Test detecting changed findings where the identity is constant
    but severity, confidence, or proof status changes.
    """
    # Baseline: Finding is MEDIUM, POSSIBLE, no proof
    f_prev = Finding(
        severity=Severity.MEDIUM,
        category="vulns",
        title="Potential Reflected XSS",
        description="Unfiltered user input reflected",
        url="https://target.local/search?q=alert",
        confidence="POSSIBLE",
        metadata={},
    )

    # Current: Upgraded to CRITICAL, VERIFIED, with proof attached
    f_curr = Finding(
        severity=Severity.CRITICAL,
        category="vulns",
        title="Potential Reflected XSS",
        description="Unfiltered user input reflected",
        url="https://target.local/search?q=alert",
        confidence="VERIFIED",
        metadata={
            "proof": {
                "validator": "xss",
                "verified_at": "2026-11-21T14:00:00Z",
                "observed_delta": "Payload <script>alert(1)</script> rendered unescaped",
            }
        },
    )

    engine = HistoricalDiffEngine()
    briefing = engine.compare(previous_scan=[f_prev], current_scan=[f_curr], target="https://target.local")

    assert briefing.summary["new"] == 0
    assert briefing.summary["resolved"] == 0
    assert briefing.summary["changed"] == 1
    assert briefing.summary["unchanged"] == 0

    ch = briefing.changed_findings[0]
    assert ch["title"] == "Potential Reflected XSS"
    assert "severity" in ch["changes"]
    assert ch["changes"]["severity"] == {"old": "MEDIUM", "new": "CRITICAL"}
    assert "confidence" in ch["changes"]
    assert ch["changes"]["confidence"] == {"old": "POSSIBLE", "new": "VERIFIED"}
    assert "proof_status" in ch["changes"]
    assert ch["changes"]["proof_status"]["old_has_proof"] is False
    assert ch["changes"]["proof_status"]["new_has_proof"] is True

    # Verify Markdown contains change explanation
    md = briefing.to_markdown()
    assert "Severity Shift:** `MEDIUM` ➔ `CRITICAL`" in md
    assert "Confidence Shift:** `POSSIBLE` ➔ `VERIFIED`" in md


# =====================================================================
# 4. Attack Chain Diffs (New & Resolved Chains)
# =====================================================================

def test_attack_chain_diffing():
    """Verify attack chain mutations are accurately identified."""
    chain_old = AttackChain(
        name="Source Code Leak to Database Compromise",
        severity=Severity.HIGH,
        steps=[
            AttackChainStep(description="Git HEAD exposed"),
            AttackChainStep(description="Database credentials found in config"),
        ],
        impact="Database read/write access",
    )
    chain_persisting = AttackChain(
        name="Missing Headers to Clickjacking",
        severity=Severity.LOW,
        steps=[AttackChainStep(description="X-Frame-Options missing")],
        impact="UI redressing",
    )
    chain_new = AttackChain(
        name="CORS Misconfiguration to Account Takeover",
        severity=Severity.CRITICAL,
        steps=[
            AttackChainStep(description="CORS allows arbitrary origin with credentials"),
            AttackChainStep(description="API key exfiltrated via cross-origin script"),
        ],
        impact="Full account compromise",
    )

    scan_a = {
        "findings": [],
        "attack_chains": [chain_old, chain_persisting],
        "url": "https://target.local",
    }
    scan_b = {
        "findings": [],
        "attack_chains": [chain_persisting, chain_new],
        "url": "https://target.local",
    }

    engine = HistoricalDiffEngine()
    briefing = engine.compare(previous_scan=scan_a, current_scan=scan_b)

    assert briefing.summary["new_attack_chains"] == 1
    assert briefing.summary["resolved_attack_chains"] == 1
    assert briefing.new_attack_chains[0]["name"] == "CORS Misconfiguration to Account Takeover"
    assert briefing.resolved_attack_chains[0]["name"] == "Source Code Leak to Database Compromise"


# =====================================================================
# 5. Endpoint Shape Normalization & Fingerprinting
# =====================================================================

def test_endpoint_shape_normalization():
    """Verify numeric IDs, UUIDs, hashes, and query keys are normalized."""
    # Numeric ID normalization
    shape1 = compute_endpoint_shape("https://api.example.com/v1/users/42/profile")
    shape2 = compute_endpoint_shape("https://api.example.com/v1/users/999/profile")
    assert shape1 == shape2 == "api.example.com/v1/users/{id}/profile"

    # UUID normalization
    uuid_url1 = "https://example.com/orders/c39d2c20-8025-4a62-9742-1264c679a836"
    uuid_url2 = "https://example.com/orders/12345678-1234-1234-1234-123456789abc"
    assert compute_endpoint_shape(uuid_url1) == compute_endpoint_shape(uuid_url2) == "example.com/orders/{uuid}"

    # Query key sorting (ignoring dynamic values)
    q1 = compute_endpoint_shape("https://example.com/search?order=desc&q=apple&page=1")
    q2 = compute_endpoint_shape("https://example.com/search?q=banana&page=2&order=asc")
    assert q1 == q2 == "example.com/search?keys=order,page,q"

    # Fingerprint consistency across varying query values
    f_a = Finding(
        severity=Severity.HIGH,
        category="vulns",
        title="SQL Injection",
        description="SQLi",
        url="https://example.com/search?q=foo&page=1",
    )
    f_b = Finding(
        severity=Severity.HIGH,
        category="vulns",
        title="SQL Injection",
        description="SQLi",
        url="https://example.com/search?q=bar&page=2",
    )
    assert compute_finding_fingerprint(f_a) == compute_finding_fingerprint(f_b)


# =====================================================================
# 6. Target Configuration Parsing & Interval Validation
# =====================================================================

def test_interval_parsing():
    """Verify parse_interval supports seconds, minutes, hours, days."""
    assert parse_interval(60) == 60.0
    assert parse_interval(120.5) == 120.5
    assert parse_interval("30s") == 30.0
    assert parse_interval("5m") == 300.0
    assert parse_interval("1h") == 3600.0
    assert parse_interval("2d") == 172800.0

    with pytest.raises(ValueError):
        parse_interval("0s")
    with pytest.raises(ValueError):
        parse_interval("-10m")
    with pytest.raises(ValueError):
        parse_interval("invalid_time")


def test_watch_config_parsing_and_authorisation():
    """Verify WatchConfig parsing from dictionary and JSON string."""
    config_dict = {
        "default_interval": "10m",
        "output_dir": "./custom_watch_out",
        "enforce_authorisation": True,
        "targets": [
            {
                "url": "https://auth1.example.com",
                "interval": "1m",
                "authorised": True,
                "profile": "quick",
            },
            {
                "url": "https://unauth.example.com",
                "interval": "5m",
                "authorised": False,
            },
        ],
    }

    config = parse_watch_config(config_dict)
    assert config.default_interval_seconds == 600.0
    assert len(config.targets) == 2
    assert config.targets[0].url == "https://auth1.example.com"
    assert config.targets[0].interval_seconds == 60.0
    assert config.targets[0].authorised is True
    assert config.targets[1].authorised is False

    # Test JSON string parsing
    json_str = json.dumps(config_dict)
    config_from_json = parse_watch_config(json_str)
    assert len(config_from_json.targets) == 2


# =====================================================================
# 7. WatchEngine Execution Cycles & Baseline Progression
# =====================================================================

def test_watch_engine_cycle_and_baseline_progression():
    """
    Test WatchEngine progression across cycles:
      - Cycle 1: Baseline established.
      - Cycle 2: Finding added -> 1 new finding detected.
      - Cycle 3: No change from Cycle 2 -> 0 changes (zero delta).
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        engine = WatchEngine(output_dir=tmpdir)
        target = "https://target.local"

        f1 = Finding(severity=Severity.LOW, category="headers", title="F1", description="D1", url=target)
        f2 = Finding(severity=Severity.HIGH, category="vulns", title="F2", description="D2", url=target)

        # Mock scan state
        current_findings = [f1]

        def mock_scanner(tgt: TargetConfig):
            return {"findings": [f.to_dict() for f in current_findings], "url": tgt.url}

        # Cycle 1: initial baseline
        b1 = engine.execute_cycle(TargetConfig(url=target, authorised=True), scan_fn=mock_scanner)
        assert b1.summary["new"] == 1  # From empty baseline to [f1]
        assert b1.summary["resolved"] == 0

        # Cycle 2: f2 is introduced
        current_findings = [f1, f2]
        b2 = engine.execute_cycle(TargetConfig(url=target, authorised=True), scan_fn=mock_scanner)
        assert b2.summary["new"] == 1
        assert b2.summary["resolved"] == 0
        assert b2.summary["unchanged"] == 1
        assert b2.new_findings[0]["title"] == "F2"

        # Cycle 3: unchanged scan
        b3 = engine.execute_cycle(TargetConfig(url=target, authorised=True), scan_fn=mock_scanner)
        assert b3.summary["new"] == 0
        assert b3.summary["resolved"] == 0
        assert b3.summary["unchanged"] == 2
        assert b3.has_changes is False


def test_watch_engine_unauthorised_target_refusal():
    """Verify unauthorized targets are refused execution."""
    engine = WatchEngine(enforce_authorisation=True)
    unauth_target = TargetConfig(url="https://rogue.example.com", authorised=False)

    with pytest.raises(UnauthorizedTargetError) as exc_info:
        engine.execute_cycle(unauth_target, scan_fn=lambda t: [])

    assert "not authorised for continuous monitoring" in str(exc_info.value)


# =====================================================================
# 8. Clean Headless CLI Driver (`webripper watch`)
# =====================================================================

def test_watch_cli_direct_file_diff(capsys):
    """Verify CLI runs cleanly with --baseline and --current files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        base_path = os.path.join(tmpdir, "base.json")
        curr_path = os.path.join(tmpdir, "curr.json")

        base_data = {
            "url": "https://example.com",
            "findings": [
                {"category": "headers", "title": "Missing HSTS", "severity": "MEDIUM", "url": "https://example.com/"}
            ],
        }
        curr_data = {
            "url": "https://example.com",
            "findings": [
                {"category": "headers", "title": "Missing HSTS", "severity": "MEDIUM", "url": "https://example.com/"},
                {"category": "vulns", "title": "Remote Code Execution", "severity": "CRITICAL", "url": "https://example.com/cmd"},
            ],
        }

        with open(base_path, "w", encoding="utf-8") as f:
            json.dump(base_data, f)
        with open(curr_path, "w", encoding="utf-8") as f:
            json.dump(curr_data, f)

        # CLI should return exit code 2 because of new CRITICAL finding
        exit_code = run_watch_cli([
            "--baseline", base_path,
            "--current", curr_path,
            "--output-dir", tmpdir,
            "--quiet",
        ])

        assert exit_code == 2

        # Verify output artifacts
        assert os.path.isfile(os.path.join(tmpdir, "briefing.md"))
        assert os.path.isfile(os.path.join(tmpdir, "briefing.json"))

        with open(os.path.join(tmpdir, "briefing.json"), "r", encoding="utf-8") as f:
            delta = json.load(f)

        assert delta["summary"]["new"] == 1
        assert delta["new_findings"][0]["title"] == "Remote Code Execution"


def test_watch_cli_zero_drift_exit_code():
    """Verify CLI returns exit code 0 when no critical/high regressions occur."""
    with tempfile.TemporaryDirectory() as tmpdir:
        base_path = os.path.join(tmpdir, "base.json")
        curr_path = os.path.join(tmpdir, "curr.json")

        data = {
            "url": "https://clean.example.com",
            "findings": [
                {"category": "headers", "title": "Missing HSTS", "severity": "MEDIUM", "url": "https://clean.example.com/"}
            ],
        }
        with open(base_path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        with open(curr_path, "w", encoding="utf-8") as f:
            json.dump(data, f)

        exit_code = run_watch_cli([
            "--baseline", base_path,
            "--current", curr_path,
            "--output-dir", tmpdir,
            "--quiet",
        ])

        assert exit_code == 0

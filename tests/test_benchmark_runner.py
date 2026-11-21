"""
Unit and integration tests for WebRipper Recon 5.0 Benchmark Harness & Scorecard Engine.

Verifies:
  - Deterministic metric calculations (Precision, Recall, F1-Score)
  - Canonical vulnerability classification
  - Standard testbeds (OWASP Juice Shop, WebGoat, crAPI) ground truth loading
  - Deterministic fixture execution across all testbeds
  - Markdown scorecard formatting and BENCHMARK.md output
  - 100% offline execution with zero network connectivity
  - CLI entrypoint and semantic threshold exit codes
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from app.models import Finding, Severity
from benchmarks.fixtures import (
    ALL_GROUND_TRUTH,
    GROUND_TRUTH_CRAPI,
    GROUND_TRUTH_JUICE_SHOP,
    GROUND_TRUTH_WEBGOAT,
    GroundTruthItem,
    get_all_testbed_keys,
    get_ground_truth,
    get_simulated_findings_for_testbed,
    get_testbed_display_name,
)
from benchmarks.runner import (
    CANONICAL_VULN_CLASSES,
    BenchmarkRunner,
    BenchmarkSuiteReport,
    TestbedScorecard,
    VulnerabilityClass,
    VulnerabilityClassScore,
    classify_vulnerability,
    compute_metrics,
    export_markdown_scorecard,
    generate_markdown_scorecard,
    main,
    run_benchmarks,
)


# ===========================================================================
# 1. Classification & Mapping Tests
# ===========================================================================

def test_vulnerability_classification_canonical():
    """Verify classification maps various titles and categories into canonical classes."""
    # Injection
    f_sqli = Finding(
        severity=Severity.HIGH,
        category="vulns",
        title="SQL Injection in user parameter",
        description="Union based SQLi",
    )
    assert classify_vulnerability(f_sqli) == VulnerabilityClass.INJECTION.value

    f_xss = Finding(
        severity=Severity.HIGH,
        category="vulns",
        title="Reflected Cross-Site Scripting (XSS)",
        description="Script tag reflected in DOM",
    )
    assert classify_vulnerability(f_xss) == VulnerabilityClass.INJECTION.value

    # Auth/IDOR
    f_idor = Finding(
        severity=Severity.HIGH,
        category="vulns",
        title="BOLA Insecure Object Reference",
        description="Accessing other user invoices via direct ID",
    )
    assert classify_vulnerability(f_idor) == VulnerabilityClass.AUTH_IDOR.value

    # CORS
    f_cors = Finding(
        severity=Severity.MEDIUM,
        category="cors",
        title="CORS Origin Reflection",
        description="Access-Control-Allow-Origin: null",
    )
    assert classify_vulnerability(f_cors) == VulnerabilityClass.CORS.value

    # Misconfigs
    f_misc = Finding(
        severity=Severity.LOW,
        category="paths",
        title="Exposed Swagger UI documentation",
        description="Public OpenAPI docs",
    )
    assert classify_vulnerability(f_misc) == VulnerabilityClass.MISCONFIGS.value

    # Crypto/Secrets
    f_sec = Finding(
        severity=Severity.CRITICAL,
        category="secrets",
        title="Leaked AWS Secret Access Key",
        description="Hardcoded key in frontend bundle",
    )
    assert classify_vulnerability(f_sec) == VulnerabilityClass.CRYPTO_SECRETS.value

    # Info Leak
    f_info = Finding(
        severity=Severity.LOW,
        category="headers",
        title="Internal Exception Stack Trace Disclosure",
        description="Debug trace exposed in 500 error response",
    )
    assert classify_vulnerability(f_info) == VulnerabilityClass.INFO_LEAK.value


def test_vulnerability_classification_explicit_metadata():
    """Verify that explicit metadata['vulnerability_class'] overrides heuristic matching."""
    f_custom = Finding(
        severity=Severity.MEDIUM,
        category="custom",
        title="Generic alert title",
        description="Generic description",
        metadata={"vulnerability_class": "Crypto/Secrets"},
    )
    assert classify_vulnerability(f_custom) == VulnerabilityClass.CRYPTO_SECRETS.value


# ===========================================================================
# 2. Mathematical Metric Calculations
# ===========================================================================

def test_compute_metrics_perfect_score():
    """Test 100% precision and recall."""
    prec, rec, f1 = compute_metrics(tp=10, fp=0, fn=0, verified=10)
    assert prec == 1.0
    assert rec == 1.0
    assert f1 == 1.0


def test_compute_metrics_zero_detections():
    """Test when no vulnerabilities are detected out of known ground truth."""
    prec, rec, f1 = compute_metrics(tp=0, fp=0, fn=5, verified=0)
    assert prec == 0.0
    assert rec == 0.0
    assert f1 == 0.0


def test_compute_metrics_all_false_positives():
    """Test when detections are entirely false positives."""
    prec, rec, f1 = compute_metrics(tp=0, fp=5, fn=0, verified=0)
    assert prec == 0.0
    assert rec == 1.0
    assert f1 == 0.0


def test_compute_metrics_zero_everything():
    """Test boundary when ground truth and alerts are both zero."""
    prec, rec, f1 = compute_metrics(tp=0, fp=0, fn=0, verified=0)
    assert prec == 1.0
    assert rec == 1.0
    assert f1 == 1.0


def test_compute_metrics_partial_scores():
    """Test standard partial precision and recall math."""
    # TP=8, FP=2, FN=2 (Ground truth=10, Total findings=10)
    # Precision = 8 / 10 = 0.8
    # Recall = 8 / 10 = 0.8
    # F1 = 2 * (0.8 * 0.8) / 1.6 = 0.8
    prec, rec, f1 = compute_metrics(tp=8, fp=2, fn=2, verified=6)
    assert round(prec, 4) == 0.8
    assert round(rec, 4) == 0.8
    assert round(f1, 4) == 0.8


# ===========================================================================
# 3. Ground Truth Testbeds & Fixture Data Integrity
# ===========================================================================

def test_ground_truth_testbeds_registered():
    """Verify all 3 testbeds exist and have valid ground truth."""
    testbeds = get_all_testbed_keys()
    assert "juice-shop" in testbeds
    assert "webgoat" in testbeds
    assert "crapi" in testbeds

    assert len(GROUND_TRUTH_JUICE_SHOP) >= 10
    assert len(GROUND_TRUTH_WEBGOAT) >= 10
    assert len(GROUND_TRUTH_CRAPI) >= 10


def test_ground_truth_class_coverage():
    """Verify all testbeds contain items covering canonical classes."""
    for tb_key in ("juice-shop", "webgoat", "crapi"):
        items = get_ground_truth(tb_key)
        classes = {item.vuln_class for item in items}
        # Check that standard classes are represented
        assert "Auth/IDOR" in classes
        assert "Misconfigs" in classes
        assert "Crypto/Secrets" in classes
        assert "Info Leak" in classes

        # Check item fields
        for item in items:
            assert item.id.startswith(tb_key.replace("-", "").upper()[:3]) or tb_key in item.testbed
            assert item.title
            assert item.endpoint
            assert item.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


# ===========================================================================
# 4. Deterministic Fixture Execution
# ===========================================================================

def test_benchmark_runner_deterministic_execution():
    """Verify that multiple executions against fixture suites produce identical scores."""
    runner = BenchmarkRunner()

    report1 = runner.run_deterministic_fixture_suite()
    report2 = runner.run_deterministic_fixture_suite()

    # Total counts must match identically
    assert report1.total_ground_truth == report2.total_ground_truth
    assert report1.total_detected == report2.total_detected
    assert report1.total_verified == report2.total_verified
    assert report1.total_missed == report2.total_missed
    assert report1.total_false_positives == report2.total_false_positives

    # Floating metrics must match exactly
    assert report1.overall_precision == report2.overall_precision
    assert report1.overall_recall == report2.overall_recall
    assert report1.overall_f1 == report2.overall_f1

    # Mathematical conservation invariants
    assert report1.total_detected + report1.total_missed == report1.total_ground_truth
    assert report1.total_verified <= report1.total_detected
    assert report1.total_ground_truth > 0
    assert report1.overall_f1 > 0.80  # WebRipper Recon Phase 9 target standard


def test_single_testbed_runs():
    """Verify running each testbed individually."""
    for tb_key in ("juice-shop", "webgoat", "crapi"):
        runner = BenchmarkRunner(testbeds=[tb_key])
        report = runner.run_deterministic_fixture_suite()

        assert len(report.testbeds) == 1
        sc = report.testbeds[tb_key]
        assert sc.testbed_id == tb_key
        assert sc.ground_truth_count == len(get_ground_truth(tb_key))
        assert sc.detected_count + sc.missed_count == sc.ground_truth_count
        assert sc.verified_count <= sc.detected_count
        assert sc.precision > 0.0
        assert sc.recall > 0.0
        assert sc.f1_score > 0.0

        # Verify class breakdown exists
        for c in CANONICAL_VULN_CLASSES:
            assert c in sc.class_scores
            cs = sc.class_scores[c]
            assert cs.detected_count + cs.missed_count == cs.ground_truth_count


# ===========================================================================
# 5. Markdown Scorecard Format & Output
# ===========================================================================

def test_markdown_scorecard_format():
    """Verify markdown scorecard includes all required sections and tables."""
    runner = BenchmarkRunner()
    report = runner.run_deterministic_fixture_suite()
    md = generate_markdown_scorecard(report)

    # Required headers
    assert "# WebRipper Recon 5.0 — Benchmark Scorecard" in md
    assert "Harness Version:" in md
    assert "Execution Mode:" in md

    # Executive summary table
    assert "## 1. Executive Summary" in md
    assert "Ground Truth Vulnerabilities" in md
    assert "Detected (True Positives)" in md
    assert "Verified with Proof" in md
    assert "Missed (False Negatives)" in md
    assert "Overall Precision" in md
    assert "Overall Recall" in md
    assert "Overall F1-Score" in md

    # Vulnerability class table
    assert "## 2. Accuracy Scorecard by Vulnerability Class (Aggregate)" in md
    for c in CANONICAL_VULN_CLASSES:
        assert f"| **{c}** |" in md

    # Check table headers
    assert "| Vulnerability Class | Ground Truth | Detected | Verified | Missed | False Positives | Precision | Recall | F1-Score |" in md
    assert "| **TOTAL / OVERALL** |" in md

    # Testbed breakdowns
    assert "## 3. Individual Testbed Breakdown" in md
    assert "OWASP Juice Shop" in md
    assert "WebGoat" in md
    assert "crAPI" in md


def test_markdown_scorecard_file_export(tmp_path):
    """Verify export_markdown_scorecard writes file correctly to disk."""
    runner = BenchmarkRunner()
    report = runner.run_deterministic_fixture_suite()
    out_file = tmp_path / "BENCHMARK_TEST.md"

    md_content = export_markdown_scorecard(report, filepath=str(out_file))

    assert out_file.exists()
    assert out_file.read_text(encoding="utf-8") == md_content


def test_json_scorecard_export(tmp_path):
    """Verify JSON export produces valid, readable JSON structure."""
    runner = BenchmarkRunner()
    report = runner.run_deterministic_fixture_suite()
    json_str = report.to_json()
    data = json.loads(json_str)

    assert data["version"] == report.version
    assert "summary" in data
    assert data["summary"]["total_ground_truth"] == report.total_ground_truth
    assert data["summary"]["total_detected"] == report.total_detected
    assert data["summary"]["total_verified"] == report.total_verified
    assert "aggregate_class_scores" in data
    assert "testbeds" in data


# ===========================================================================
# 6. Zero Network Guarantee (100% Offline)
# ===========================================================================

def test_benchmark_runs_strictly_offline():
    """Verify benchmark fixture suite makes zero network socket or HTTP requests."""
    with patch("socket.socket") as mock_sock, patch("urllib.request.urlopen") as mock_urlopen:
        mock_sock.side_effect = RuntimeError("Network socket call forbidden during benchmark!")
        mock_urlopen.side_effect = RuntimeError("HTTP call forbidden during benchmark!")

        runner = BenchmarkRunner()
        report = runner.run_deterministic_fixture_suite()

        assert report.total_ground_truth > 0
        assert report.overall_f1 > 0.0

        mock_sock.assert_not_called()
        mock_urlopen.assert_not_called()


# ===========================================================================
# 7. CLI Entrypoint & Threshold Exit Codes
# ===========================================================================

def test_cli_execution_success(tmp_path):
    """Verify CLI execution creates BENCHMARK.md and exits with 0."""
    out_md = tmp_path / "BENCHMARK_CLI.md"
    out_json = tmp_path / "BENCHMARK_CLI.json"

    exit_code = main([
        "--testbed", "all",
        "--output", str(out_md),
        "--json", str(out_json),
        "-q",
    ])

    assert exit_code == 0
    assert out_md.exists()
    assert out_json.exists()
    assert "# WebRipper Recon 5.0 — Benchmark Scorecard" in out_md.read_text(encoding="utf-8")


def test_cli_min_f1_threshold_pass():
    """Verify CLI exits with 0 when F1 meets or exceeds threshold."""
    exit_code = main([
        "--min-f1", "0.50",
        "--output", "",
        "-q",
    ])
    assert exit_code == 0


def test_cli_min_f1_threshold_failure():
    """Verify CLI exits with code 2 when F1 is below threshold."""
    exit_code = main([
        "--min-f1", "0.999",  # Unattainably high threshold
        "--output", "",
        "-q",
    ])
    assert exit_code == 2


# ===========================================================================
# 8. Custom Findings & Edge Case Evaluation
# ===========================================================================

def test_custom_findings_perfect_detector():
    """Verify that providing synthetic findings matching all GT yields 100% precision and recall."""
    gt_items = get_ground_truth("juice-shop")
    custom_findings: List[Finding] = []

    for item in gt_items:
        custom_findings.append(Finding(
            severity=Severity.HIGH,
            category="vulns",
            title=item.title,
            description="Synthetic perfect finding",
            url=f"http://127.0.0.1:3000{item.endpoint}",
            confidence="VERIFIED",
            metadata={
                "ground_truth_id": item.id,
                "vulnerability_class": item.vuln_class,
                "verified": True,
            },
        ))

    runner = BenchmarkRunner(testbeds=["juice-shop"])
    report = runner.run_deterministic_fixture_suite(custom_findings={"juice-shop": custom_findings})
    sc = report.testbeds["juice-shop"]

    assert sc.detected_count == len(gt_items)
    assert sc.verified_count == len(gt_items)
    assert sc.missed_count == 0
    assert sc.false_positive_count == 0
    assert sc.precision == 1.0
    assert sc.recall == 1.0
    assert sc.f1_score == 1.0

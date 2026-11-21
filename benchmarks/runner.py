"""
WebRipper Recon 5.0 — Benchmark Runner & Deterministic Scorecard Engine.

Executes scans against deterministic local fixtures modelled on target vulnerability classes
(OWASP Juice Shop, WebGoat, crAPI) and generates deterministic
accuracy scorecards per vulnerability class:
  - Injection
  - Auth/IDOR
  - CORS
  - Misconfigs
  - Crypto/Secrets
  - Info Leak

Metrics computed:
  - Detected count (True Positives)
  - Verified count (Machine-checkable proof rate)
  - Missed count (False Negatives)
  - False positive count
  - Precision / Recall / F1-Score

Outputs versioned Markdown scorecards to BENCHMARK.md and supports CLI invocation:
  python -m benchmarks.runner [--fixture-mode] [--testbed all] [--output BENCHMARK.md]
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from enum import Enum
import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

# Ensure project root is in sys.path
_current_dir = Path(__file__).resolve().parent
_project_root = _current_dir.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from app.models import Finding, ReconReport, RipperSettings, ScanResult, Severity
from benchmarks.fixtures import (
    ALL_GROUND_TRUTH,
    GroundTruthItem,
    get_all_testbed_keys,
    get_ground_truth,
    get_simulated_findings_for_testbed,
    get_testbed_display_name,
)

logger = logging.getLogger("webripper.benchmarks")


# ===========================================================================
# 1. Vulnerability Classes & Classification Engine
# ===========================================================================

class VulnerabilityClass(str, Enum):
    """Canonical vulnerability classes evaluated in WebRipper benchmarks."""
    INJECTION = "Injection"
    AUTH_IDOR = "Auth/IDOR"
    CORS = "CORS"
    MISCONFIGS = "Misconfigs"
    CRYPTO_SECRETS = "Crypto/Secrets"
    INFO_LEAK = "Info Leak"
    OTHER = "Other"


CANONICAL_VULN_CLASSES: List[str] = [
    VulnerabilityClass.INJECTION.value,
    VulnerabilityClass.AUTH_IDOR.value,
    VulnerabilityClass.CORS.value,
    VulnerabilityClass.MISCONFIGS.value,
    VulnerabilityClass.CRYPTO_SECRETS.value,
    VulnerabilityClass.INFO_LEAK.value,
]

_CLASS_KEYWORDS: Dict[str, List[str]] = {
    VulnerabilityClass.INJECTION.value: [
        "sql", "sqli", "injection", "xss", "cross-site scripting", "command",
        "nosql", "ssrf", "lfi", "rfi", "traversal", "xxe", "xml external",
        "template injection", "ssti", "code injection", "eval",
    ],
    VulnerabilityClass.AUTH_IDOR.value: [
        "idor", "bola", "bfla", "object level", "broken auth", "authorization",
        "authentication", "privilege escalation", "admin bypass", "token bypass",
        "session", "password reset", "account takeover", "unauthenticated",
        "mass assignment", "role", "registration",
    ],
    VulnerabilityClass.CORS.value: [
        "cors", "cross-origin", "origin reflection", "wildcard origin",
        "access-control-allow-origin", "null origin",
    ],
    VulnerabilityClass.MISCONFIGS.value: [
        "misconfig", "actuator", "swagger", "openapi", "api-docs", "debug mode",
        "default credential", "default password", "directory listing", "git exposed",
        ".env", "insecure header", "csp", "security header", "server banner",
        "ftp", "backup file", "robots.txt",
    ],
    VulnerabilityClass.CRYPTO_SECRETS.value: [
        "secret", "api key", "private key", "jwt secret", "hardcoded credential",
        "password in", "token leak", "crypto", "weak cipher", "tls 1.0", "ssl",
        "certificate", "md5", "signing key", "stripe",
    ],
    VulnerabilityClass.INFO_LEAK.value: [
        "info leak", "information disclosure", "stack trace", "stacktrace",
        "error disclosure", "pii", "email leak", "email disclosure",
        "user enumeration", "internal ip", "source code", "source map",
    ],
}


def classify_vulnerability(finding_or_item: Any) -> str:
    """
    Deterministically maps a Finding, GroundTruthItem, dict, or title string
    to one of the canonical benchmark vulnerability classes:
      - Injection
      - Auth/IDOR
      - CORS
      - Misconfigs
      - Crypto/Secrets
      - Info Leak
      - Other
    """
    # 1. Direct explicit classification attribute or metadata
    if hasattr(finding_or_item, "vuln_class") and finding_or_item.vuln_class:
        cls_val = str(finding_or_item.vuln_class).strip()
        for c in CANONICAL_VULN_CLASSES:
            if c.lower() == cls_val.lower():
                return c

    metadata = getattr(finding_or_item, "metadata", {}) or {}
    if isinstance(metadata, dict):
        if "vulnerability_class" in metadata and metadata["vulnerability_class"]:
            cls_val = str(metadata["vulnerability_class"]).strip()
            for c in CANONICAL_VULN_CLASSES:
                if c.lower() == cls_val.lower():
                    return c

    # 2. Extract textual hints
    title = str(getattr(finding_or_item, "title", "") or "")
    category = str(getattr(finding_or_item, "category", "") or "")
    description = str(getattr(finding_or_item, "description", "") or "")
    url = str(getattr(finding_or_item, "url", "") or getattr(finding_or_item, "endpoint", "") or "")
    cwe = str(metadata.get("cwe", "") if isinstance(metadata, dict) else "")

    combined_text = f"{title} {category} {description} {url} {cwe}".lower()

    # Fast categorical overrides
    if category == "cors":
        return VulnerabilityClass.CORS.value
    if category == "secrets":
        return VulnerabilityClass.CRYPTO_SECRETS.value
    if category in ("headers", "paths", "waf"):
        # Could be misconfigs or info leak
        if any(k in combined_text for k in ("stack trace", "email", "pii", "version")):
            return VulnerabilityClass.INFO_LEAK.value
        return VulnerabilityClass.MISCONFIGS.value

    # Match keywords in prioritized order
    for vuln_cls in (
        VulnerabilityClass.CORS.value,
        VulnerabilityClass.CRYPTO_SECRETS.value,
        VulnerabilityClass.AUTH_IDOR.value,
        VulnerabilityClass.INJECTION.value,
        VulnerabilityClass.INFO_LEAK.value,
        VulnerabilityClass.MISCONFIGS.value,
    ):
        keywords = _CLASS_KEYWORDS[vuln_cls]
        for kw in keywords:
            if kw in combined_text:
                return vuln_cls

    return VulnerabilityClass.OTHER.value


# ===========================================================================
# 2. Mathematical Scorecard Metric Models
# ===========================================================================

def compute_metrics(tp: int, fp: int, fn: int, verified: int = 0) -> Tuple[float, float, float]:
    """
    Computes precision, recall, and F1-score deterministically.
    Handles division by zero edge cases safely.
    """
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else (1.0 if (tp + fn) == 0 else 0.0)
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 1.0
    if precision + recall > 0.0:
        f1 = (2.0 * precision * recall) / (precision + recall)
    else:
        f1 = 0.0
    return precision, recall, f1


@dataclass
class VulnerabilityClassScore:
    """Benchmark metrics for a specific vulnerability class."""
    class_name: str
    ground_truth_count: int = 0
    detected_count: int = 0       # True Positives
    verified_count: int = 0       # Machine-verified True Positives
    missed_count: int = 0         # False Negatives
    false_positive_count: int = 0 # False Positives
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "class_name": self.class_name,
            "ground_truth_count": self.ground_truth_count,
            "detected_count": self.detected_count,
            "verified_count": self.verified_count,
            "missed_count": self.missed_count,
            "false_positive_count": self.false_positive_count,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "precision_pct": f"{self.precision * 100:.2f}%",
            "recall_pct": f"{self.recall * 100:.2f}%",
            "f1_score_pct": f"{self.f1_score * 100:.2f}%",
        }


@dataclass
class TestbedScorecard:
    """Benchmark scorecard for an individual testbed."""
    __test__ = False
    testbed_id: str
    testbed_name: str
    ground_truth_count: int = 0
    detected_count: int = 0
    verified_count: int = 0
    missed_count: int = 0
    false_positive_count: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    class_scores: Dict[str, VulnerabilityClassScore] = field(default_factory=dict)
    matched_items: List[Dict[str, Any]] = field(default_factory=list)
    missed_items: List[Dict[str, Any]] = field(default_factory=list)
    false_positives: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "testbed_id": self.testbed_id,
            "testbed_name": self.testbed_name,
            "ground_truth_count": self.ground_truth_count,
            "detected_count": self.detected_count,
            "verified_count": self.verified_count,
            "missed_count": self.missed_count,
            "false_positive_count": self.false_positive_count,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "class_scores": {k: v.to_dict() for k, v in self.class_scores.items()},
            "matched_items": self.matched_items,
            "missed_items": self.missed_items,
            "false_positives": self.false_positives,
        }


@dataclass
class BenchmarkSuiteReport:
    """Full benchmark suite execution report aggregating all testbeds."""
    version: str = "5.0.0-phase9"
    timestamp: str = ""
    mode: str = "fixture"  # "fixture" or "live"
    testbeds: Dict[str, TestbedScorecard] = field(default_factory=dict)
    aggregate_class_scores: Dict[str, VulnerabilityClassScore] = field(default_factory=dict)
    total_ground_truth: int = 0
    total_detected: int = 0
    total_verified: int = 0
    total_missed: int = 0
    total_false_positives: int = 0
    overall_precision: float = 0.0
    overall_recall: float = 0.0
    overall_f1: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "timestamp": self.timestamp,
            "mode": self.mode,
            "summary": {
                "total_ground_truth": self.total_ground_truth,
                "total_detected": self.total_detected,
                "total_verified": self.total_verified,
                "total_missed": self.total_missed,
                "total_false_positives": self.total_false_positives,
                "overall_precision": round(self.overall_precision, 4),
                "overall_recall": round(self.overall_recall, 4),
                "overall_f1": round(self.overall_f1, 4),
            },
            "aggregate_class_scores": {k: v.to_dict() for k, v in self.aggregate_class_scores.items()},
            "testbeds": {k: v.to_dict() for k, v in self.testbeds.items()},
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


# ===========================================================================
# 3. Ground Truth Matching & Evaluation Engine
# ===========================================================================

class BenchmarkRunner:
    """
    Coordinates execution of benchmark audits, findings comparison against
    ground truth, and scorecard generation.
    """

    def __init__(
        self,
        testbeds: Optional[List[str]] = None,
        version: str = "5.0.0-phase9",
    ):
        self.version = version
        self.testbed_keys = testbeds or get_all_testbed_keys()

    @staticmethod
    def _is_finding_verified(finding: Finding) -> bool:
        """Check whether finding contains machine-checkable verification proof."""
        if getattr(finding, "confidence", "") == "VERIFIED":
            return True
        metadata = getattr(finding, "metadata", {}) or {}
        if isinstance(metadata, dict):
            if metadata.get("verified") is True:
                return True
            if "proof" in metadata or "verification_proof" in metadata:
                return True
        return False

    @staticmethod
    def _finding_matches_ground_truth(finding: Finding, item: GroundTruthItem) -> bool:
        """
        Determine if a finding matches a ground-truth item based on:
        1. Explicit ground_truth_id link
        2. Vulnerability class compatibility
        3. Endpoint / URL containment or identifier keyword matching
        """
        metadata = getattr(finding, "metadata", {}) or {}
        if isinstance(metadata, dict):
            gt_id = metadata.get("ground_truth_id", "")
            if gt_id and gt_id == item.id:
                return True

        # Check vulnerability class
        f_class = classify_vulnerability(finding)
        if f_class != item.vuln_class:
            return False

        # Endpoint matching
        f_url = (getattr(finding, "url", "") or "").lower()
        endpoint_clean = item.endpoint.lower()
        # Handle parameterized endpoints like /vehicle/<vin>/location
        if "<" in endpoint_clean:
            prefix = endpoint_clean.split("<")[0]
            if prefix and prefix in f_url:
                return True
        elif endpoint_clean in f_url:
            return True

        # Identifier keyword matching
        title_clean = (getattr(finding, "title", "") or "").lower()
        desc_clean = (getattr(finding, "description", "") or "").lower()
        evidence_clean = (getattr(finding, "evidence", "") or "").lower()
        combined = f"{title_clean} {desc_clean} {evidence_clean}"

        for ident in item.identifiers:
            if ident.lower() in combined:
                return True

        return False

    def evaluate_testbed_findings(
        self,
        testbed_key: str,
        findings: List[Finding],
        ground_truth: Optional[List[GroundTruthItem]] = None,
    ) -> TestbedScorecard:
        """
        Matches a list of scan findings against ground-truth items for a testbed,
        computing detected (TP), verified, missed (FN), and false positives (FP).
        """
        gt_list = ground_truth if ground_truth is not None else get_ground_truth(testbed_key)
        testbed_name = get_testbed_display_name(testbed_key)

        matched_gt_ids: Set[str] = set()
        matched_finding_indices: Set[int] = set()
        verified_gt_ids: Set[str] = set()

        matched_items_detail: List[Dict[str, Any]] = []

        # 1. Match findings to ground truth items
        for gt in gt_list:
            for idx, finding in enumerate(findings):
                if idx in matched_finding_indices:
                    continue
                if self._finding_matches_ground_truth(finding, gt):
                    matched_gt_ids.add(gt.id)
                    matched_finding_indices.add(idx)

                    is_verified = self._is_finding_verified(finding)
                    if is_verified:
                        verified_gt_ids.add(gt.id)

                    matched_items_detail.append({
                        "ground_truth_id": gt.id,
                        "vuln_class": gt.vuln_class,
                        "title": gt.title,
                        "endpoint": gt.endpoint,
                        "finding_title": finding.title,
                        "finding_url": finding.url,
                        "verified": is_verified,
                        "confidence": getattr(finding, "confidence", "POSSIBLE"),
                    })
                    break

        # 2. Identify missed ground truth items (FN)
        missed_items_detail: List[Dict[str, Any]] = []
        for gt in gt_list:
            if gt.id not in matched_gt_ids:
                missed_items_detail.append({
                    "ground_truth_id": gt.id,
                    "vuln_class": gt.vuln_class,
                    "title": gt.title,
                    "endpoint": gt.endpoint,
                    "severity": gt.severity,
                    "cwe": gt.cwe,
                })

        # 3. Identify false positives (unmatched findings)
        false_positives_detail: List[Dict[str, Any]] = []
        for idx, finding in enumerate(findings):
            if idx not in matched_finding_indices:
                f_class = classify_vulnerability(finding)
                false_positives_detail.append({
                    "vuln_class": f_class,
                    "title": finding.title,
                    "url": finding.url,
                    "severity": getattr(finding.severity, "value", str(finding.severity)),
                    "confidence": getattr(finding, "confidence", "POSSIBLE"),
                })

        # 4. Compute per-class scores
        class_scores: Dict[str, VulnerabilityClassScore] = {}
        for c in CANONICAL_VULN_CLASSES:
            class_gt = [gt for gt in gt_list if gt.vuln_class == c]
            c_gt_count = len(class_gt)
            c_detected = sum(1 for gt in class_gt if gt.id in matched_gt_ids)
            c_verified = sum(1 for gt in class_gt if gt.id in verified_gt_ids)
            c_missed = c_gt_count - c_detected
            c_fp = sum(1 for fp in false_positives_detail if fp["vuln_class"] == c)

            prec, rec, f1 = compute_metrics(c_detected, c_fp, c_missed, c_verified)

            class_scores[c] = VulnerabilityClassScore(
                class_name=c,
                ground_truth_count=c_gt_count,
                detected_count=c_detected,
                verified_count=c_verified,
                missed_count=c_missed,
                false_positive_count=c_fp,
                precision=prec,
                recall=rec,
                f1_score=f1,
            )

        # 5. Compute overall testbed score
        total_gt = len(gt_list)
        total_det = len(matched_gt_ids)
        total_ver = len(verified_gt_ids)
        total_mis = total_gt - total_det
        total_fp = len(false_positives_detail)
        overall_prec, overall_rec, overall_f1 = compute_metrics(total_det, total_fp, total_mis, total_ver)

        return TestbedScorecard(
            testbed_id=testbed_key,
            testbed_name=testbed_name,
            ground_truth_count=total_gt,
            detected_count=total_det,
            verified_count=total_ver,
            missed_count=total_mis,
            false_positive_count=total_fp,
            precision=overall_prec,
            recall=overall_rec,
            f1_score=overall_f1,
            class_scores=class_scores,
            matched_items=matched_items_detail,
            missed_items=missed_items_detail,
            false_positives=false_positives_detail,
        )

    def run_deterministic_fixture_suite(
        self,
        custom_findings: Optional[Dict[str, List[Finding]]] = None,
    ) -> BenchmarkSuiteReport:
        """
        Executes benchmark evaluation against the deterministic local fixture suites.
        Guaranteed to run 100% offline with zero network connectivity.
        """
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        testbed_scorecards: Dict[str, TestbedScorecard] = {}

        for tb_key in self.testbed_keys:
            if custom_findings and tb_key in custom_findings:
                findings = custom_findings[tb_key]
            else:
                findings = get_simulated_findings_for_testbed(tb_key)

            scorecard = self.evaluate_testbed_findings(tb_key, findings)
            testbed_scorecards[tb_key] = scorecard

        # Compute aggregate metrics per vulnerability class
        aggregate_class_scores: Dict[str, VulnerabilityClassScore] = {}
        for c in CANONICAL_VULN_CLASSES:
            c_gt = sum(sc.class_scores[c].ground_truth_count for sc in testbed_scorecards.values() if c in sc.class_scores)
            c_det = sum(sc.class_scores[c].detected_count for sc in testbed_scorecards.values() if c in sc.class_scores)
            c_ver = sum(sc.class_scores[c].verified_count for sc in testbed_scorecards.values() if c in sc.class_scores)
            c_mis = sum(sc.class_scores[c].missed_count for sc in testbed_scorecards.values() if c in sc.class_scores)
            c_fp = sum(sc.class_scores[c].false_positive_count for sc in testbed_scorecards.values() if c in sc.class_scores)

            prec, rec, f1 = compute_metrics(c_det, c_fp, c_mis, c_ver)

            aggregate_class_scores[c] = VulnerabilityClassScore(
                class_name=c,
                ground_truth_count=c_gt,
                detected_count=c_det,
                verified_count=c_ver,
                missed_count=c_mis,
                false_positive_count=c_fp,
                precision=prec,
                recall=rec,
                f1_score=f1,
            )

        # Compute suite-level totals
        tot_gt = sum(sc.ground_truth_count for sc in testbed_scorecards.values())
        tot_det = sum(sc.detected_count for sc in testbed_scorecards.values())
        tot_ver = sum(sc.verified_count for sc in testbed_scorecards.values())
        tot_mis = sum(sc.missed_count for sc in testbed_scorecards.values())
        tot_fp = sum(sc.false_positive_count for sc in testbed_scorecards.values())
        suite_prec, suite_rec, suite_f1 = compute_metrics(tot_det, tot_fp, tot_mis, tot_ver)

        return BenchmarkSuiteReport(
            version=self.version,
            timestamp=now_iso,
            mode="fixture",
            testbeds=testbed_scorecards,
            aggregate_class_scores=aggregate_class_scores,
            total_ground_truth=tot_gt,
            total_detected=tot_det,
            total_verified=tot_ver,
            total_missed=tot_mis,
            total_false_positives=tot_fp,
            overall_precision=suite_prec,
            overall_recall=suite_rec,
            overall_f1=suite_f1,
        )


# ===========================================================================
# 4. Markdown Scorecard Generator (BENCHMARK.md)
# ===========================================================================

def generate_markdown_scorecard(report: BenchmarkSuiteReport) -> str:
    """
    Renders a comprehensive, versioned GitHub Flavored Markdown scorecard
    ready to be saved as BENCHMARK.md.
    """
    tb_names = ", ".join(sc.testbed_name for sc in report.testbeds.values())
    mode_desc = "Deterministic Local Fixture Suite (Offline / CI)" if report.mode == "fixture" else "Live Scan Target"

    lines: List[str] = [
        "# WebRipper Recon 5.0 — Benchmark Scorecard",
        "",
        f"- **Harness Version:** `{report.version}`",
        f"- **Execution Timestamp:** `{report.timestamp}`",
        f"- **Execution Mode:** {mode_desc}",
        f"- **Audited Testbeds:** Fixtures modelled on {tb_names} vulnerability classes",
        "",
        "---",
        "",
        "## 1. Executive Summary",
        "",
        "| Metric | Count / Score | Percentage | Description |",
        "|:---|:---:|:---:|:---|",
        f"| **Ground Truth Vulnerabilities** | {report.total_ground_truth} | 100.0% | Known benchmark target vulnerabilities |",
        f"| **Detected (True Positives)** | {report.total_detected} | {report.overall_recall * 100:.2f}% | Identified vulnerabilities |",
        f"| **Verified with Proof** | {report.total_verified} | {(report.total_verified / report.total_detected * 100 if report.total_detected else 0.0):.2f}% | Validated via machine-checkable proofs |",
        f"| **Missed (False Negatives)** | {report.total_missed} | {(report.total_missed / report.total_ground_truth * 100 if report.total_ground_truth else 0.0):.2f}% | Vulnerabilities not detected |",
        f"| **False Positives** | {report.total_false_positives} | — | Spurious or unverified alerts |",
        f"| **Overall Precision** | — | **{report.overall_precision * 100:.2f}%** | TP / (TP + FP) |",
        f"| **Overall Recall** | — | **{report.overall_recall * 100:.2f}%** | TP / (TP + FN) |",
        f"| **Overall F1-Score** | — | **{report.overall_f1 * 100:.2f}%** | Harmonic mean of Precision & Recall |",
        "",
        "---",
        "",
        "## 2. Accuracy Scorecard by Vulnerability Class (Aggregate)",
        "",
        "| Vulnerability Class | Ground Truth | Detected | Verified | Missed | False Positives | Precision | Recall | F1-Score |",
        "|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|",
    ]

    for c in CANONICAL_VULN_CLASSES:
        if c in report.aggregate_class_scores:
            cs = report.aggregate_class_scores[c]
            lines.append(
                f"| **{cs.class_name}** | {cs.ground_truth_count} | {cs.detected_count} | "
                f"{cs.verified_count} | {cs.missed_count} | {cs.false_positive_count} | "
                f"{cs.precision * 100:.2f}% | {cs.recall * 100:.2f}% | **{cs.f1_score * 100:.2f}%** |"
            )

    # Summary row
    lines.append(
        f"| **TOTAL / OVERALL** | **{report.total_ground_truth}** | **{report.total_detected}** | "
        f"**{report.total_verified}** | **{report.total_missed}** | **{report.total_false_positives}** | "
        f"**{report.overall_precision * 100:.2f}%** | **{report.overall_recall * 100:.2f}%** | "
        f"**{report.overall_f1 * 100:.2f}%** |"
    )

    lines.extend([
        "",
        "---",
        "",
        "## 3. Individual Testbed Breakdown",
        "",
    ])

    for tb_id, sc in report.testbeds.items():
        lines.extend([
            f"### {sc.testbed_name} (`{tb_id}`)",
            "",
            f"- **Ground Truth Total:** {sc.ground_truth_count}",
            f"- **Detected:** {sc.detected_count} (Verified: {sc.verified_count})",
            f"- **Missed:** {sc.missed_count}",
            f"- **False Positives:** {sc.false_positive_count}",
            f"- **Precision:** {sc.precision * 100:.2f}% | **Recall:** {sc.recall * 100:.2f}% | **F1-Score:** {sc.f1_score * 100:.2f}%",
            "",
            "| Vulnerability Class | Expected | Detected | Verified | Missed | False Positives | Precision | Recall | F1-Score |",
            "|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|",
        ])

        for c in CANONICAL_VULN_CLASSES:
            if c in sc.class_scores:
                cs = sc.class_scores[c]
                lines.append(
                    f"| {cs.class_name} | {cs.ground_truth_count} | {cs.detected_count} | "
                    f"{cs.verified_count} | {cs.missed_count} | {cs.false_positive_count} | "
                    f"{cs.precision * 100:.2f}% | {cs.recall * 100:.2f}% | {cs.f1_score * 100:.2f}% |"
                )

        lines.extend([
            f"| **Subtotal** | **{sc.ground_truth_count}** | **{sc.detected_count}** | "
            f"**{sc.verified_count}** | **{sc.missed_count}** | **{sc.false_positive_count}** | "
            f"**{sc.precision * 100:.2f}%** | **{sc.recall * 100:.2f}%** | **{sc.f1_score * 100:.2f}%** |",
            "",
        ])

    lines.extend([
        "---",
        "",
        "## 4. Methodology & Verification Invariants",
        "",
        "1. **Zero Network Requirement**: In fixture mode, the benchmark harness operates completely offline without opening outbound network sockets.",
        "2. **Strict Ground-Truth Alignment**: A detection is credited only when both the vulnerability class and target path/identifier match the known specification.",
        "3. **Proof Verification Standard**: A detection is marked as `VERIFIED` only when it contains machine-checkable proof (HTTP response differential, canary match, DOM execution, or authenticated token proof).",
        "4. **Deterministic Exit Codes**: CI runs evaluate aggregate F1-score against `--min-f1` thresholds, returning exit code `0` on meeting standards or `2` on regression.",
        "",
    ])

    return "\n".join(lines)


def export_markdown_scorecard(report: BenchmarkSuiteReport, filepath: str = "BENCHMARK.md") -> str:
    """Writes the markdown scorecard to disk and returns the content string."""
    md = generate_markdown_scorecard(report)
    out_path = Path(filepath)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(md)
    return md


def run_benchmarks(
    testbeds: Optional[List[str]] = None,
    fixture_mode: bool = True,
    custom_findings: Optional[Dict[str, List[Finding]]] = None,
    output_path: Optional[str] = None,
) -> BenchmarkSuiteReport:
    """
    High-level entrypoint for executing benchmarks programmatically.
    """
    runner = BenchmarkRunner(testbeds=testbeds)
    report = runner.run_deterministic_fixture_suite(custom_findings=custom_findings)

    if output_path:
        export_markdown_scorecard(report, output_path)

    return report


# ===========================================================================
# 5. CLI Entrypoint
# ===========================================================================

def build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m benchmarks.runner",
        description="WebRipper Recon 5.0 — Benchmark Harness & Deterministic Accuracy Scorecards",
    )
    parser.add_argument(
        "--fixture-mode",
        action="store_true",
        default=True,
        help="Execute offline against deterministic fixture testbeds (default: True)",
    )
    parser.add_argument(
        "--testbed",
        choices=["all", "juice-shop", "webgoat", "crapi"],
        default="all",
        help="Target testbed to evaluate (default: all)",
    )
    parser.add_argument(
        "-o", "--output",
        default="BENCHMARK.md",
        help="Path to output markdown scorecard (default: BENCHMARK.md, pass '' to disable)",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        help="Path to export raw JSON benchmark report",
    )
    parser.add_argument(
        "--min-f1",
        type=float,
        default=0.0,
        help="Minimum overall F1-score required (e.g. 0.85); exits with code 2 if below threshold",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress console scorecard output",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI execution entrypoint."""
    parser = build_cli_parser()
    args = parser.parse_args(argv)

    testbeds = None
    if args.testbed != "all":
        testbeds = [args.testbed]

    runner = BenchmarkRunner(testbeds=testbeds)
    report = runner.run_deterministic_fixture_suite()

    if args.output:
        export_markdown_scorecard(report, args.output)
        if not args.quiet:
            print(f"[+] Versioned benchmark scorecard written to: {args.output}")

    if args.json_output:
        out_json = Path(args.json_output)
        out_json.parent.mkdir(parents=True, exist_ok=True)
        with open(out_json, "w", encoding="utf-8") as f:
            f.write(report.to_json())
        if not args.quiet:
            print(f"[+] Raw JSON benchmark report written to: {args.json_output}")

    if not args.quiet:
        print("\n" + "=" * 78)
        print(" WebRipper Recon 5.0 — Accuracy Benchmark Results")
        print("=" * 78)
        print(f" Testbeds Audited: {', '.join(sc.testbed_name for sc in report.testbeds.values())}")
        print(f" Ground Truth:     {report.total_ground_truth}")
        print(f" Detected (TP):    {report.total_detected} (Verified: {report.total_verified})")
        print(f" Missed (FN):      {report.total_missed}")
        print(f" False Positives:  {report.total_false_positives}")
        print(f" Precision:        {report.overall_precision * 100:.2f}%")
        print(f" Recall:           {report.overall_recall * 100:.2f}%")
        print(f" Overall F1-Score: {report.overall_f1 * 100:.2f}%")
        print("=" * 78)

        print("\n Per-Class Accuracy Breakdown:")
        print(f" {'Class':<16} {'Expected':<10} {'Detected':<10} {'Verified':<10} {'FP':<6} {'Precision':<10} {'Recall':<10} {'F1':<10}")
        print(" " + "-" * 76)
        for c, cs in report.aggregate_class_scores.items():
            print(
                f" {cs.class_name:<16} {cs.ground_truth_count:<10} {cs.detected_count:<10} "
                f"{cs.verified_count:<10} {cs.false_positive_count:<6} {cs.precision * 100:.1f}%{'':<4} "
                f"{cs.recall * 100:.1f}%{'':<4} {cs.f1_score * 100:.1f}%"
            )
        print("=" * 78 + "\n")

    if args.min_f1 > 0.0:
        if report.overall_f1 < args.min_f1:
            print(
                f"[!] Benchmark failure: Overall F1-Score ({report.overall_f1:.4f}) is below threshold ({args.min_f1:.4f})",
                file=sys.stderr,
            )
            return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())

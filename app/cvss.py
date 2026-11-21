"""
CVSS 3.1 auto-scoring and mathematical calculator for WebRipper Recon 5.0.

Provides:
- Full FIRST CVSS v3.1 base metric specification equations.
- Vector string parsing and serialization.
- CWE identifier to CVSS base metric/vector mappings.
- Automatic finding scoring with metric breakdown.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


def _cvss_roundup(val: float) -> float:
    """Official FIRST CVSS v3.1 roundup function to 1 decimal place."""
    int_input = round(val * 100000)
    if (int_input % 10000) == 0:
        return round(int_input / 100000, 1)
    return round((math.floor(int_input / 10000) + 1) / 10, 1)


# Metric weight tables according to CVSS v3.1 Specification
_AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC_WEIGHTS = {"L": 0.77, "H": 0.44}
_PR_WEIGHTS = {
    # (Scope Unchanged, Scope Changed)
    "N": (0.85, 0.85),
    "L": (0.62, 0.68),
    "H": (0.27, 0.50),
}
_UI_WEIGHTS = {"N": 0.85, "R": 0.62}
_CIA_WEIGHTS = {"H": 0.56, "L": 0.22, "N": 0.00}


def calculate_cvss31(
    av: str = "N",
    ac: str = "L",
    pr: str = "N",
    ui: str = "N",
    s: str = "U",
    c: str = "H",
    i: str = "H",
    a: str = "H",
) -> Tuple[float, float, float]:
    """Calculate CVSS v3.1 base score, impact sub-score, and exploitability sub-score.

    Returns:
        (base_score, impact_score, exploitability_score)
    """
    av_val = _AV_WEIGHTS.get(av.upper(), 0.85)
    ac_val = _AC_WEIGHTS.get(ac.upper(), 0.77)
    s_changed = s.upper() == "C"
    pr_pair = _PR_WEIGHTS.get(pr.upper(), (0.85, 0.85))
    pr_val = pr_pair[1] if s_changed else pr_pair[0]
    ui_val = _UI_WEIGHTS.get(ui.upper(), 0.85)

    c_val = _CIA_WEIGHTS.get(c.upper(), 0.0)
    i_val = _CIA_WEIGHTS.get(i.upper(), 0.0)
    a_val = _CIA_WEIGHTS.get(a.upper(), 0.0)

    # ISS = 1 - [ (1 - ImpactConf) * (1 - ImpactInteg) * (1 - ImpactAvail) ]
    iss = 1.0 - ((1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val))

    if s_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * av_val * ac_val * pr_val * ui_val

    if impact <= 0:
        impact = 0.0
        base_score = 0.0
    else:
        if s_changed:
            base_score = _cvss_roundup(min(1.08 * (impact + exploitability), 10.0))
        else:
            base_score = _cvss_roundup(min(impact + exploitability, 10.0))

    impact_rounded = round(impact, 1)
    exploit_rounded = round(exploitability, 1)
    return base_score, impact_rounded, exploit_rounded


def parse_vector(vector: str) -> Dict[str, str]:
    """Parse CVSS:3.1 vector string into metric dictionary."""
    metrics: Dict[str, str] = {}
    clean_vec = vector.strip()
    if clean_vec.startswith("CVSS:3.1/"):
        clean_vec = clean_vec[9:]
    elif clean_vec.startswith("CVSS:3.0/"):
        clean_vec = clean_vec[9:]

    for part in clean_vec.split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k.upper()] = v.upper()
    return metrics


@dataclass
class CVSSScore:
    """CVSS 3.1 base score for a finding."""
    score: float
    vector: str
    label: str  # Critical / High / Medium / Low / None
    impact: float = 0.0
    exploitability: float = 0.0
    metrics: Dict[str, str] = field(default_factory=dict)

    @staticmethod
    def from_score(score: float, vector: str = "") -> "CVSSScore":
        """Build CVSSScore from raw score and optional vector."""
        metrics: Dict[str, str] = {}
        impact = 0.0
        exploit = 0.0
        if vector:
            metrics = parse_vector(vector)
            if len(metrics) >= 8:
                calc_score, impact, exploit = calculate_cvss31(
                    av=metrics.get("AV", "N"),
                    ac=metrics.get("AC", "L"),
                    pr=metrics.get("PR", "N"),
                    ui=metrics.get("UI", "N"),
                    s=metrics.get("S", "U"),
                    c=metrics.get("C", "N"),
                    i=metrics.get("I", "N"),
                    a=metrics.get("A", "N"),
                )
                score = calc_score

        rounded_score = round(score, 1)
        if rounded_score >= 9.0:
            label = "Critical"
        elif rounded_score >= 7.0:
            label = "High"
        elif rounded_score >= 4.0:
            label = "Medium"
        elif rounded_score > 0.0:
            label = "Low"
        else:
            label = "None"

        return CVSSScore(
            score=rounded_score,
            vector=vector,
            label=label,
            impact=impact,
            exploitability=exploit,
            metrics=metrics,
        )

    @staticmethod
    def from_vector(vector: str) -> "CVSSScore":
        """Compute exact CVSS 3.1 score directly from vector string."""
        metrics = parse_vector(vector)
        score, impact, exploit = calculate_cvss31(
            av=metrics.get("AV", "N"),
            ac=metrics.get("AC", "L"),
            pr=metrics.get("PR", "N"),
            ui=metrics.get("UI", "N"),
            s=metrics.get("S", "U"),
            c=metrics.get("C", "N"),
            i=metrics.get("I", "N"),
            a=metrics.get("A", "N"),
        )
        return CVSSScore.from_score(score, vector)


# CWE -> (CVSS score, vector string)
_CWE_MAP: Dict[str, Tuple[float, str]] = {
    "CWE-798": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "CWE-321": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "CWE-89":  (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "CWE-287": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "CWE-434": (8.8, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    "CWE-538": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "CWE-312": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "CWE-942": (6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"),
    "CWE-352": (6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"),
    "CWE-79":  (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "CWE-95":  (6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    "CWE-94":  (8.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "CWE-319": (5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "CWE-614": (5.9, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "CWE-200": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "CWE-16":  (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "CWE-693": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "CWE-290": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"),
    "CWE-1021": (4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"),
    "CWE-1004": (4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    "CWE-1104": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "CWE-284": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    "CWE-250": (4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    "CWE-215": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "CWE-615": (3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "CWE-288": (6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"),
    "CWE-345": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
}

# Severity fallback scores
_SEVERITY_SCORES = {
    "CRITICAL": 9.5,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 3.0,
    "INFO": 0.0,
}


def score_finding(finding) -> CVSSScore:
    """Calculate CVSS 3.1 score for a single finding."""
    cwe = ""
    if finding.metadata:
        cwe = finding.metadata.get("cwe", "")

    if cwe and cwe in _CWE_MAP:
        score, vector = _CWE_MAP[cwe]
        return CVSSScore.from_score(score, vector)

    # Fallback to severity-based scoring
    sev_val = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
    sev_score = _SEVERITY_SCORES.get(sev_val.upper(), 0.0)
    return CVSSScore.from_score(sev_score)


def score_all(findings: list) -> Dict[str, CVSSScore]:
    """Score all findings. Returns dict keyed by finding title."""
    results = {}
    for f in findings:
        key = f"{f.category}:{f.title}"
        results[key] = score_finding(f)
    return results

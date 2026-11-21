"""
WebRipper Recon 5.0 — Deduplication & Submission-Quality Guard Package.

Provides 64-bit SimHash locality-sensitive clustering, endpoint shape normalization,
and duplicate risk scoring against HackerOne disclosures in intel.db.
"""

from __future__ import annotations

from .simhash import (
    compute_finding_simhash,
    extract_endpoint_shape,
    simhash_hamming_distance,
    simhash_similarity,
)
from .cluster import (
    cluster_findings,
)
from .submission import (
    DuplicateRiskScorer,
    score_finding_submission_risk,
    evaluate_submission_quality,
)

__all__ = [
    "extract_endpoint_shape",
    "compute_finding_simhash",
    "simhash_hamming_distance",
    "simhash_similarity",
    "cluster_findings",
    "DuplicateRiskScorer",
    "score_finding_submission_risk",
    "evaluate_submission_quality",
]

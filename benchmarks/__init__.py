"""
WebRipper Recon 5.0 — Benchmark Harness & Accuracy Scorecards (Phase 9).
"""

from .fixtures import (
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

__all__ = [
    "ALL_GROUND_TRUTH",
    "BenchmarkRunner",
    "BenchmarkSuiteReport",
    "GROUND_TRUTH_CRAPI",
    "GROUND_TRUTH_JUICE_SHOP",
    "GROUND_TRUTH_WEBGOAT",
    "GroundTruthItem",
    "TestbedScorecard",
    "VulnerabilityClass",
    "VulnerabilityClassScore",
    "classify_vulnerability",
    "compute_metrics",
    "generate_markdown_scorecard",
    "get_all_testbed_keys",
    "get_ground_truth",
    "get_simulated_findings_for_testbed",
    "get_testbed_display_name",
    "run_benchmarks",
]


def __getattr__(name: str):
    if name in (
        "BenchmarkRunner",
        "BenchmarkSuiteReport",
        "TestbedScorecard",
        "VulnerabilityClass",
        "VulnerabilityClassScore",
        "classify_vulnerability",
        "compute_metrics",
        "generate_markdown_scorecard",
        "run_benchmarks",
    ):
        import benchmarks.runner as _runner
        return getattr(_runner, name)
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


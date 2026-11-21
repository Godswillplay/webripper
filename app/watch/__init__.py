"""
WebRipper Recon 5.0 — Continuous Monitoring & Watch Mode (Phase 8).

Provides:
  - Historical diffing engine & fingerprinting:
      * compute_endpoint_shape
      * compute_finding_fingerprint
      * extract_proof_status
      * HistoricalDiffEngine
      * WatchDiffBriefing
      * ChangedFinding
  - Target configuration & scheduler:
      * TargetConfig
      * WatchConfig
      * parse_interval
      * parse_watch_config
      * UnauthorizedTargetError
  - Watch engine & CLI:
      * WatchEngine
      * run_watch_cli
"""

from .diff import (
    ChangedFinding,
    HistoricalDiffEngine,
    WatchDiffBriefing,
    compute_endpoint_shape,
    compute_finding_fingerprint,
    extract_proof_status,
    finding_to_dict,
)
from .engine import (
    TargetConfig,
    UnauthorizedTargetError,
    WatchConfig,
    WatchEngine,
    parse_interval,
    parse_watch_config,
    run_watch_cli,
)

__all__ = [
    "ChangedFinding",
    "HistoricalDiffEngine",
    "WatchDiffBriefing",
    "compute_endpoint_shape",
    "compute_finding_fingerprint",
    "extract_proof_status",
    "finding_to_dict",
    "TargetConfig",
    "UnauthorizedTargetError",
    "WatchConfig",
    "WatchEngine",
    "parse_interval",
    "parse_watch_config",
    "run_watch_cli",
]

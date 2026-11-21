"""
WebRipper Recon 5.0 — Attack Chain Verification Package (Phase 4).

Exports:
  - ChainVerifier
  - verify_attack_chains
  - compute_chain_confidence
  - StepVerificationResult
  - ChainVerificationResult
"""

from .verifier import (
    ChainVerificationResult,
    ChainVerifier,
    StepVerificationResult,
    compute_chain_confidence,
    verify_attack_chains,
)

__all__ = [
    "ChainVerificationResult",
    "ChainVerifier",
    "StepVerificationResult",
    "compute_chain_confidence",
    "verify_attack_chains",
]

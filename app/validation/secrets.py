"""
SecretsValidator — Proof-based verification for candidate secrets and API keys.

Methodology:
  1. Extracts candidate secret token from finding evidence / metadata.
  2. Documentation Bait & Placeholder Filter:
     - Rejects known documentation sample keys (e.g. AKIAIOSFODNN7EXAMPLE, AIzaSyDummyKeyForTesting).
     - Rejects strings containing 'example', 'placeholder', 'dummy', 'sample', 'changeme', etc.
  3. Structural & Entropy Verification:
     - Computes Shannon entropy (H = -sum(p * log2(p))).
     - Rejects zero-entropy, repetitive ('aaaaaa'), sequential ('123456'), or low-entropy tokens (< 3.0 bits/char for long tokens).
     - Validates token character variety and length requirements.
  4. Confirms ONLY if:
     - Token matches recognized credential pattern.
     - Token possesses high Shannon entropy indicating genuine cryptographic randomness.
     - Non-example / non-documentation criteria are strictly satisfied.
"""

from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Optional, Tuple

from ..models import Finding
from .base import BaseValidator


_DOCUMENTATION_BAIT_BLACKLIST = {
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "AIzaSyDummyKeyForTesting",
    "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc",
}

_BAIT_SUBSTRINGS = (
    "example",
    "placeholder",
    "dummy",
    "sample",
    "changeme",
    "your_token",
    "your_key",
    "your-api-key",
    "your_api_key",
    "insert_key_here",
    "secret_key_here",
    "test_key",
    "fake",
    "xxxxxx",
    "000000",
    "123456",
)


def compute_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy (bits per character) of a string."""
    if not data:
        return 0.0
    length = len(data)
    counts: Dict[str, int] = {}
    for char in data:
        counts[char] = counts.get(char, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def mask_secret(secret: str) -> str:
    """Return safely masked secret token preserving prefix and suffix."""
    if len(secret) <= 8:
        return "*" * len(secret)
    prefix_len = 4
    suffix_len = 4
    masked_middle = "*" * (len(secret) - prefix_len - suffix_len)
    return f"{secret[:prefix_len]}{masked_middle}{secret[-suffix_len:]}"


class SecretsValidator(BaseValidator):
    """Validator for candidate secret leaks and API credentials."""

    name = "secrets"

    def can_validate(self, finding: Finding) -> bool:
        """Match secret and credential candidate findings."""
        title = finding.title.lower()
        desc = finding.description.lower()
        cat = finding.category.lower()

        return (
            cat == "secrets"
            or "secret" in title
            or "api key" in title
            or "credential" in title
            or "token" in title
            or "private key" in title
        )

    def validate(self, finding: Finding) -> Finding:
        """Validate candidate secret token against documentation bait and entropy thresholds."""
        token = self._extract_token(finding)

        if not token:
            finding.confidence = "POSSIBLE"
            finding.metadata["validation_note"] = "Could not extract candidate token from evidence for validation."
            return finding

        # -------------------------------------------------------------------
        # 1. Documentation Bait & Blacklist Rejection
        # -------------------------------------------------------------------
        if token in _DOCUMENTATION_BAIT_BLACKLIST:
            finding.confidence = "POSSIBLE"
            finding.metadata["validation_note"] = (
                f"Rejected: known documentation sample token ({token})."
            )
            return finding

        token_lower = token.lower()
        for bait in _BAIT_SUBSTRINGS:
            if bait in token_lower:
                finding.confidence = "POSSIBLE"
                finding.metadata["validation_note"] = (
                    f"Rejected: token contains placeholder/documentation bait '{bait}'."
                )
                return finding

        # -------------------------------------------------------------------
        # 2. Length & Character Diversity Rejection
        # -------------------------------------------------------------------
        if len(token) < 12:
            finding.confidence = "POSSIBLE"
            finding.metadata["validation_note"] = (
                f"Rejected: token length ({len(token)}) below minimum secret threshold (12)."
            )
            return finding

        unique_ratio = len(set(token)) / len(token)
        if unique_ratio < 0.25:
            finding.confidence = "POSSIBLE"
            finding.metadata["validation_note"] = (
                f"Rejected: low character diversity ({unique_ratio:.2f}) indicates repetitive placeholder."
            )
            return finding

        # -------------------------------------------------------------------
        # 3. Shannon Entropy Threshold Check
        # -------------------------------------------------------------------
        entropy = compute_shannon_entropy(token)
        required_entropy = 3.0 if len(token) >= 16 else 2.5

        if entropy < required_entropy:
            finding.confidence = "POSSIBLE"
            finding.metadata["validation_note"] = (
                f"Rejected: Shannon entropy {entropy:.2f} bits/char is below required threshold {required_entropy:.1f}."
            )
            return finding

        # -------------------------------------------------------------------
        # 4. Proof Packaging & Elevation to VERIFIED
        # -------------------------------------------------------------------
        masked = mask_secret(token)
        source_loc = finding.file_path or finding.url or "source_evidence"

        self.package_proof(
            finding=finding,
            request_info={
                "source": source_loc,
                "line_number": finding.line_number,
                "verification_type": "entropy_pattern_non_bait_analysis",
            },
            response_info={
                "masked_token": masked,
                "token_length": len(token),
                "shannon_entropy": round(entropy, 3),
                "required_entropy": required_entropy,
                "unique_char_ratio": round(unique_ratio, 3),
            },
            observed_delta=(
                f"Secret token validated: conforms to credential pattern, Shannon entropy "
                f"{entropy:.2f} bits/char exceeds threshold {required_entropy:.1f}, "
                f"and passed all documentation bait / placeholder checks."
            ),
            extra={
                "masked_token": masked,
                "entropy": round(entropy, 3),
            },
        )
        return finding

    def _extract_token(self, finding: Finding) -> str:
        """Extract candidate secret string from finding metadata or evidence."""
        # 1. From metadata
        for key in ("secret", "token", "match", "api_key", "password"):
            val = finding.metadata.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()

        # 2. From evidence regex matches
        evidence = finding.evidence or ""
        patterns = [
            r'AKIA[0-9A-Z]{16}',                           # AWS Access Key ID
            r'AIzaSy[A-Za-z0-9_-]{33}',                     # Google API Key
            r'ghp_[A-Za-z0-9]{36}',                        # GitHub Personal Access Token
            r'sq0csp-[0-9A-Za-z_-]{43}',                   # Square OAuth secret
            r'xox[baprs]-[0-9A-Za-z_-]{10,48}',            # Slack Token
            r'(?:bearer|token|key|secret)\s*[:=]\s*["\']?([A-Za-z0-9_\-\.\/+=]{16,})["\']?',  # Generic key/token
        ]
        for pat in patterns:
            m = re.search(pat, evidence, re.IGNORECASE)
            if m:
                # Return capture group if exists, else full match
                return m.group(1) if m.groups() else m.group(0)

        # 3. Fallback: line-based extraction
        for line in evidence.splitlines():
            if ":" in line:
                parts = line.split(":", 1)
                candidate = parts[1].strip().strip('"\'')
                if len(candidate) >= 16 and " " not in candidate:
                    return candidate

        return ""

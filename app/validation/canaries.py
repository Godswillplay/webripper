"""
CanaryValidator — Proof-based differential verification for Scenario Canaries.

Methodology:
  1. Retrieves probe specification from scenario candidate metadata (probe_method, probe_path, probe_headers, probe_body, match_regex).
  2. Enforces code guard:
     - Empty, wildcard, or overly permissive regex (e.g. '', '.*', '^.*$') MUST NEVER verify.
  3. Differential Probe:
     - Baseline request: clean request without canary headers, payloads, or probe path.
     - Probe request: request configured with the scenario canary probe.
  4. Meaningful Delta Analysis:
     - Confirms ONLY if:
       - The canary marker / regex pattern matches in the probe response AND is absent in the baseline response.
       - Or a measurable timing delta (> 1.5s delay) is observed.
     - Strictly rejects verification on HTTP status code alone.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from ..models import Finding
from .base import BaseValidator, HTTPResponse


_WILDCARD_REGEXES = {"", ".*", "^.*$", "^.*", ".*$"}


class CanaryValidator(BaseValidator):
    """Differential validator for Scenario Intelligence canary probes."""

    name = "canaries"

    def can_validate(self, finding: Finding) -> bool:
        """Match scenario canary candidates."""
        cat = finding.category.lower()
        return (
            cat in ("scenarios", "canaries")
            or "scenario" in cat
            or "scenario_id" in finding.metadata
        )

    def validate(self, finding: Finding) -> Finding:
        """Execute differential baseline vs canary probe verification."""
        target_url = finding.url or finding.metadata.get("url", "")
        if not target_url:
            finding.confidence = "POSSIBLE"
            finding.metadata["validation_note"] = "No target URL provided for scenario canary verification."
            return finding

        match_regex = str(finding.metadata.get("match_regex", "")).strip()

        # -------------------------------------------------------------------
        # 1. Code Guard: Wildcard / Empty Regex Rejection
        # -------------------------------------------------------------------
        if not match_regex or match_regex in _WILDCARD_REGEXES:
            finding.confidence = "POSSIBLE"
            finding.metadata["validation_note"] = (
                "Rejected: match_regex is empty or wildcard; cannot verify without specific canary signature."
            )
            return finding

        # Compile regex safely
        try:
            pattern = re.compile(match_regex, re.IGNORECASE)
        except re.error as e:
            finding.confidence = "POSSIBLE"
            finding.metadata["validation_note"] = f"Rejected: invalid match_regex syntax ({e})."
            return finding

        probe_method = finding.metadata.get("probe_method", "GET").upper()
        probe_path = finding.metadata.get("probe_path", "")
        probe_headers = finding.metadata.get("probe_headers", {}) or {}
        probe_body = finding.metadata.get("probe_body", "")

        parsed = urlparse(target_url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"

        # Determine probe URL
        if probe_path:
            probe_url = urljoin(base_origin, probe_path.lstrip("/"))
        else:
            probe_url = target_url

        # Baseline request: clean request to base or without probe canary headers/body
        baseline_url = base_origin if probe_path else target_url
        baseline = self.send_request(baseline_url, method="GET")

        # Probe request: request with canary headers, body, and method
        probe = self.send_request(
            probe_url,
            method=probe_method,
            headers=probe_headers,
            data=probe_body if probe_body else None,
        )

        # -------------------------------------------------------------------
        # 2. Meaningful Delta Evaluation
        # -------------------------------------------------------------------
        # Corpus search: body + formatted headers
        probe_corpus = f"{probe.body}\n" + "\n".join(f"{k}: {v}" for k, v in probe.headers.items())
        baseline_corpus = f"{baseline.body}\n" + "\n".join(f"{k}: {v}" for k, v in baseline.headers.items())

        probe_match = pattern.search(probe_corpus)
        baseline_match = pattern.search(baseline_corpus)

        marker_confirmed = False
        matched_str = ""

        # Requirement: marker must be present in probe and ABSENT in baseline
        if probe_match and not baseline_match:
            marker_confirmed = True
            matched_str = probe_match.group(0)[:100]

        # Timing differential fallback (for time-based scenario probes)
        timing_delta = probe.elapsed_ms - baseline.elapsed_ms
        timing_confirmed = timing_delta >= 1500.0 and probe.elapsed_ms >= 1600.0

        if not marker_confirmed and not timing_confirmed:
            finding.confidence = "POSSIBLE"
            finding.metadata["validation_note"] = (
                "Canary probe did not produce a meaningful differential delta "
                "(pattern was either absent or already present in baseline; status code alone is insufficient)."
            )
            return finding

        # -------------------------------------------------------------------
        # 3. Proof Packaging & Elevation to VERIFIED
        # -------------------------------------------------------------------
        observed_delta_desc = (
            f"Canary marker reflection confirmed: pattern '{match_regex}' (matched: '{matched_str}') "
            f"was observed uniquely in probe response and was absent in baseline. "
            f"Status code alone was not relied upon."
            if marker_confirmed else
            f"Canary timing differential confirmed: probe took {probe.elapsed_ms:.1f}ms "
            f"vs baseline {baseline.elapsed_ms:.1f}ms (+{timing_delta:.1f}ms delay)."
        )

        self.package_proof(
            finding=finding,
            request_info={
                "method": probe_method,
                "url": probe_url,
                "headers": probe_headers,
                "verification_type": "differential_canary_reflection",
            },
            response_info={
                "status": probe.status,
                "body_hash": probe.body_hash,
                "elapsed_ms": probe.elapsed_ms,
                "matched_signature": matched_str,
            },
            observed_delta=observed_delta_desc,
            extra={
                "match_regex": match_regex,
                "baseline_status": baseline.status,
                "probe_status": probe.status,
            },
        )
        return finding

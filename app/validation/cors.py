"""
CORSValidator — Proof-based differential verification for Cross-Origin Resource Sharing (CORS) candidates.

Methodology:
  1. Sends baseline request without an Origin header.
  2. Sends probe request with an untrusted attacker Origin (and Origin: null).
  3. Evaluates response headers:
     - Access-Control-Allow-Origin (ACAO)
     - Access-Control-Allow-Credentials (ACAC)
  4. Confirms ONLY if:
     - Origin is dynamically reflected AND credentials flag is explicitly true.
     - Wildcard '*' without credentials or without origin reflection does NOT verify.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from ..models import Finding
from .base import BaseValidator, HTTPResponse


_TEST_ORIGIN = "https://attacker-controlled.example.com"
_NULL_ORIGIN = "null"


class CORSValidator(BaseValidator):
    """Differential validator for candidate CORS misconfiguration findings."""

    name = "cors"

    def can_validate(self, finding: Finding) -> bool:
        """Match CORS candidates."""
        title = finding.title.lower()
        desc = finding.description.lower()
        cat = finding.category.lower()

        return (
            "cors" in title
            or "cross-origin" in desc
            or cat == "cors"
            or ("vulns" in cat and "cors" in title)
        )

    def validate(self, finding: Finding) -> Finding:
        """Perform differential CORS verification."""
        target_url = finding.url or finding.metadata.get("url", "")
        if not target_url:
            finding.confidence = "POSSIBLE"
            finding.metadata["validation_note"] = "No target URL provided for CORS verification."
            return finding

        # 1. Baseline Request (no Origin header)
        baseline = self.send_request(target_url, method="GET")

        # 2. Probe Request with untrusted Origin
        probe_origin = self.send_request(
            target_url,
            method="GET",
            headers={
                "Origin": _TEST_ORIGIN,
                "Access-Control-Request-Method": "GET",
            },
        )

        acao_probe = probe_origin.header("access-control-allow-origin").strip()
        acac_probe = probe_origin.header("access-control-allow-credentials").strip().lower()

        # Check for dynamic arbitrary origin reflection + credentials: true
        confirmed = False
        verified_origin = ""

        if acao_probe.lower() == _TEST_ORIGIN.lower() and acac_probe == "true":
            confirmed = True
            verified_origin = _TEST_ORIGIN
        elif acao_probe == "*":
            # Wildcard * does NOT verify per security mandate
            confirmed = False
        else:
            # 3. Probe Request with Origin: null
            probe_null = self.send_request(
                target_url,
                method="GET",
                headers={
                    "Origin": _NULL_ORIGIN,
                    "Access-Control-Request-Method": "GET",
                },
            )
            acao_null = probe_null.header("access-control-allow-origin").strip().lower()
            acac_null = probe_null.header("access-control-allow-credentials").strip().lower()

            if acao_null == "null" and acac_null == "true":
                confirmed = True
                verified_origin = "null"
                probe_origin = probe_null

        if confirmed:
            base_acao = baseline.header("access-control-allow-origin") or "<none>"
            self.package_proof(
                finding=finding,
                request_info={
                    "method": "GET",
                    "url": target_url,
                    "headers": {
                        "Origin": verified_origin,
                        "Access-Control-Request-Method": "GET",
                    },
                    "verification_type": "differential_cors_origin_reflection",
                },
                response_info={
                    "status": probe_origin.status,
                    "access_control_allow_origin": probe_origin.header("access-control-allow-origin"),
                    "access_control_allow_credentials": probe_origin.header("access-control-allow-credentials"),
                    "baseline_acao": base_acao,
                },
                observed_delta=(
                    f"Differential CORS verification confirmed: Origin '{verified_origin}' "
                    f"was reflected in Access-Control-Allow-Origin with Access-Control-Allow-Credentials: true. "
                    f"Baseline request without Origin header returned: '{base_acao}'."
                ),
                extra={
                    "origin_tested": verified_origin,
                    "credentials_allowed": True,
                },
            )
            return finding

        finding.confidence = "POSSIBLE"
        finding.metadata["validation_note"] = (
            "CORS validation failed: Origin was not reflected with credentials=true "
            "(wildcard without credentials or unreflected origin does not verify)."
        )
        return finding

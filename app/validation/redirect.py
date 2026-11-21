"""
OpenRedirectValidator — Proof-based differential verification for Open Redirect candidates.

Methodology:
  1. Sends baseline request without redirect payload (or with internal path next=/).
  2. Sends probe request targeting an external attacker destination (e.g. https://attacker.example.com/defense-proof).
  3. Prohibits following redirects (allow_redirects=False) to directly inspect the response status and headers.
  4. Confirms ONLY if:
     - Response status is 301, 302, 303, 307, or 308.
     - Location header strictly matches or points to the external redirection target.
     - Location header exhibits a machine-checkable delta from baseline.
"""

from __future__ import annotations

import urllib.parse
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlencode, urlparse

from ..models import Finding
from .base import BaseValidator, HTTPResponse


_EXTERNAL_TARGET = "https://attacker.example.com/defense-proof"
_EXTERNAL_HOST = "attacker.example.com"
_SCHEME_RELATIVE = "//attacker.example.com/defense-proof"


class OpenRedirectValidator(BaseValidator):
    """Differential validator for candidate Open Redirect findings."""

    name = "redirect"

    def can_validate(self, finding: Finding) -> bool:
        """Match redirect candidates."""
        title = finding.title.lower()
        desc = finding.description.lower()
        cat = finding.category.lower()
        vuln_type = str(finding.metadata.get("vuln_type", "")).lower()

        return (
            "redirect" in title
            or "open redirect" in desc
            or "redirect" in vuln_type
            or cat == "redirect"
            or ("vulns" in cat and "redirect" in title)
        )

    def validate(self, finding: Finding) -> Finding:
        """Perform differential baseline vs probe check for Open Redirect."""
        target_url = finding.url or finding.metadata.get("url", "")
        param = finding.metadata.get("parameter", "")

        if not target_url:
            finding.confidence = "POSSIBLE"
            finding.metadata["validation_note"] = "No target URL provided for open redirect verification."
            return finding

        parsed = urlparse(target_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not param and params:
            common_redirect_names = (
                "redirect", "url", "next", "return", "returnto", "goto",
                "continue", "dest", "destination", "redir", "return_url",
                "callback", "forward", "out", "view", "target", "rurl",
            )
            for cp in common_redirect_names:
                if cp in params:
                    param = cp
                    break
            if not param:
                param = list(params.keys())[0]

        if not param:
            finding.confidence = "POSSIBLE"
            finding.metadata["validation_note"] = "No redirect parameter identified for probe."
            return finding

        # 1. Baseline Request (safe internal redirect target)
        baseline_params = dict(params)
        baseline_params[param] = ["/"]
        baseline_url = urllib.parse.urlunparse(parsed._replace(query=urlencode(baseline_params, doseq=True)))
        baseline = self.send_request(baseline_url, method="GET", allow_redirects=False)

        baseline_loc = baseline.header("location").strip()

        # 2. Probe Requests (Candidate payload, Absolute URL & Scheme-Relative URL)
        test_payloads = []
        candidate_payload = finding.metadata.get("payload") or finding.metadata.get("redirect_to")
        if candidate_payload and isinstance(candidate_payload, str):
            test_payloads.append(candidate_payload.strip())

        param_orig = params.get(param, [""])[0]
        if param_orig and (param_orig.startswith("http://") or param_orig.startswith("https://") or param_orig.startswith("//")):
            if param_orig not in test_payloads:
                test_payloads.append(param_orig)

        for default_p in (_EXTERNAL_TARGET, _SCHEME_RELATIVE):
            if default_p not in test_payloads:
                test_payloads.append(default_p)

        for payload in test_payloads:
            probe_params = dict(params)
            probe_params[param] = [payload]
            probe_url = urllib.parse.urlunparse(parsed._replace(query=urlencode(probe_params, doseq=True)))

            probe = self.send_request(probe_url, method="GET", allow_redirects=False)
            probe_loc = probe.header("location").strip()

            # Verification check: HTTP 3xx and Location matches external host
            if probe.status in (301, 302, 303, 307, 308) and probe_loc:
                loc_parsed = urlparse(probe_loc)
                loc_netloc = loc_parsed.netloc.lower()
                target_netloc = urlparse(payload).netloc.lower()

                # Strictly matching external redirection target
                is_external_target = (
                    (target_netloc and loc_netloc == target_netloc)
                    or loc_netloc == _EXTERNAL_HOST
                    or probe_loc.startswith(payload)
                    or probe_loc.startswith(_EXTERNAL_TARGET)
                    or probe_loc.startswith(_SCHEME_RELATIVE)
                )
                location_changed = probe_loc != baseline_loc

                if is_external_target and location_changed:
                    self.package_proof(
                        finding=finding,
                        request_info={
                            "method": "GET",
                            "url": probe_url,
                            "parameter": param,
                            "payload": payload,
                            "allow_redirects": False,
                            "verification_type": "differential_location_header",
                        },
                        response_info={
                            "status": probe.status,
                            "location": probe_loc,
                            "baseline_location": baseline_loc or "<none>",
                        },
                        observed_delta=(
                            f"Location header delta strictly confirmed external redirection: "
                            f"shifted from '{baseline_loc or '<none>'}' to '{probe_loc}' "
                            f"matching external redirection target '{payload}'."
                        ),
                        extra={
                            "redirect_target": payload,
                            "external_host": target_netloc or _EXTERNAL_HOST,
                        },
                    )
                    return finding

        finding.confidence = "POSSIBLE"
        finding.metadata["validation_note"] = (
            "Open redirect validation failed: Location header did not strictly match external redirection target."
        )
        return finding

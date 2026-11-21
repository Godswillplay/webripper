"""
SQLiValidator — Proof-based differential verification for SQL Injection candidates.

Methodology:
  1. Executes baseline request to establish clean response characteristics (timing, length, error state).
  2. Executes differential probes:
     a) Error signature delta: syntax breaker probe reveals authentic DB error absent in baseline.
     b) Boolean condition delta: TRUE condition matches baseline while FALSE condition differs.
     c) Timing delta: time-delay probe incurs a measurable server-side delay (> 1.8s differential).
  3. Elevates finding confidence to "VERIFIED" only when a machine-checkable differential delta is confirmed.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse

from ..models import Finding
from .base import BaseValidator, DifferentialDelta, HTTPResponse


_KNOWN_SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql_",
    "check the manual that corresponds to your mysql server version",
    "pg_query(): query failed",
    "syntax error at or near",
    "valid postgresql result",
    "unterminated quoted string",
    "sqlite3.operationalerror",
    "sqlite3.warning",
    "unrecognized token",
    "ora-00933",
    "ora-01756",
    "ora-00942",
    "unclosed quotation mark",
    "microsoft ole db provider for odbc drivers",
    "syntax error",
    "sqlstate[42000]",
    "org.hibernate.exception",
    "system.data.sqlclient.sqlexception",
]


class SQLiValidator(BaseValidator):
    """Differential validator for candidate SQL Injection findings."""

    name = "sqli"

    def can_validate(self, finding: Finding) -> bool:
        """Match SQLi candidates."""
        title = finding.title.lower()
        desc = finding.description.lower()
        cat = finding.category.lower()
        vuln_type = str(finding.metadata.get("vuln_type", "")).lower()

        return (
            "sqli" in title
            or "sql injection" in desc
            or "sql" in vuln_type
            or cat == "sqli"
            or ("vulns" in cat and "sqli" in title)
        )

    def validate(self, finding: Finding) -> Finding:
        """Perform differential baseline vs probe verification for SQLi."""
        target_url = finding.url or finding.metadata.get("url", "")
        param = finding.metadata.get("parameter", "")

        if not target_url:
            finding.confidence = "POSSIBLE"
            finding.metadata["validation_note"] = "No target URL provided for SQLi differential verification."
            return finding

        parsed = urlparse(target_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not param and params:
            param = list(params.keys())[0]

        if not param:
            finding.confidence = "POSSIBLE"
            finding.metadata["validation_note"] = "No injectable parameter identified for differential analysis."
            return finding

        orig_val = params.get(param, ["1"])[0]

        # -------------------------------------------------------------------
        # 1. Baseline Request
        # -------------------------------------------------------------------
        baseline = self.send_request(target_url, method="GET")
        if baseline.error:
            finding.confidence = "POSSIBLE"
            finding.metadata["validation_note"] = f"Baseline request failed: {baseline.error}"
            return finding

        def build_probe_url(injected_val: str) -> str:
            probe_params = dict(params)
            probe_params[param] = [injected_val]
            new_query = urlencode(probe_params, doseq=True)
            return urllib.parse.urlunparse(parsed._replace(query=new_query))

        # -------------------------------------------------------------------
        # 2. Error-Based Differential Probe
        # -------------------------------------------------------------------
        error_probes = [
            f"{orig_val}'",
            f"{orig_val}'\"",
            f"{orig_val}'))",
        ]
        for ep in error_probes:
            probe_url = build_probe_url(ep)
            probe_resp = self.send_request(probe_url, method="GET")

            delta = self.compare_responses(baseline, probe_resp, signatures=_KNOWN_SQL_ERRORS)
            if delta.signatures_found:
                matched_sig = delta.signatures_found[0]
                self.package_proof(
                    finding=finding,
                    request_info={
                        "method": "GET",
                        "url": probe_url,
                        "parameter": param,
                        "payload": ep,
                        "verification_type": "differential_error_signature",
                    },
                    response_info={
                        "status": probe_resp.status,
                        "body_hash": probe_resp.body_hash,
                        "elapsed_ms": probe_resp.elapsed_ms,
                        "matched_error": matched_sig,
                    },
                    observed_delta=(
                        f"SQL syntax error signature detected in probe response ('{matched_sig}') "
                        f"which was absent in baseline response."
                    ),
                    extra={"delta": delta.to_dict()},
                )
                return finding

        # -------------------------------------------------------------------
        # 3. Boolean Differential Probe (TRUE vs FALSE condition)
        # -------------------------------------------------------------------
        true_probes = [
            f"{orig_val} AND 1=1",
            f"{orig_val}' AND '1'='1",
        ]
        false_probes = [
            f"{orig_val} AND 1=2",
            f"{orig_val}' AND '1'='2",
        ]

        for tp, fp in zip(true_probes, false_probes):
            true_url = build_probe_url(tp)
            false_url = build_probe_url(fp)

            true_resp = self.send_request(true_url, method="GET")
            false_resp = self.send_request(false_url, method="GET")

            true_delta = self.compare_responses(baseline, true_resp)
            false_delta = self.compare_responses(baseline, false_resp)

            # TRUE should align with baseline, FALSE should diverge significantly
            true_matches_base = (
                true_resp.status == baseline.status
                and true_delta.similarity_ratio >= 0.80
                and abs(true_delta.length_delta) < 200
            )
            false_diverges = (
                false_resp.status != baseline.status
                or false_delta.similarity_ratio < 0.70
                or abs(false_delta.length_delta) > 50
            )

            if true_matches_base and false_diverges:
                self.package_proof(
                    finding=finding,
                    request_info={
                        "method": "GET",
                        "url_true": true_url,
                        "url_false": false_url,
                        "parameter": param,
                        "payload_true": tp,
                        "payload_false": fp,
                        "verification_type": "differential_boolean",
                    },
                    response_info={
                        "status_true": true_resp.status,
                        "status_false": false_resp.status,
                        "hash_true": true_resp.body_hash,
                        "hash_false": false_resp.body_hash,
                        "length_delta_false": false_delta.length_delta,
                    },
                    observed_delta=(
                        f"Boolean differential confirmed: TRUE probe matched baseline "
                        f"(similarity {true_delta.similarity_ratio:.2f}), FALSE probe diverged "
                        f"(similarity {false_delta.similarity_ratio:.2f}, length delta {false_delta.length_delta:+d} bytes)."
                    ),
                    extra={
                        "true_delta": true_delta.to_dict(),
                        "false_delta": false_delta.to_dict(),
                    },
                )
                return finding

        # -------------------------------------------------------------------
        # 4. Timing Differential Probe (Blind SQLi)
        # -------------------------------------------------------------------
        if baseline.elapsed_ms < 1000.0:  # Only test timing if baseline is fast
            time_probes = [
                f"{orig_val} AND (SELECT 1 FROM (SELECT(SLEEP(2)))a)--",
                f"{orig_val}'; WAITFOR DELAY '0:0:2'--",
                f"{orig_val} AND pg_sleep(2)--",
            ]
            for time_payload in time_probes:
                time_url = build_probe_url(time_payload)
                time_resp = self.send_request(time_url, method="GET", timeout=8.0)

                timing_delta = time_resp.elapsed_ms - baseline.elapsed_ms
                if timing_delta >= 1800.0 and time_resp.elapsed_ms >= 1900.0:
                    self.package_proof(
                        finding=finding,
                        request_info={
                            "method": "GET",
                            "url": time_url,
                            "parameter": param,
                            "payload": time_payload,
                            "verification_type": "differential_timing",
                        },
                        response_info={
                            "status": time_resp.status,
                            "baseline_elapsed_ms": baseline.elapsed_ms,
                            "probe_elapsed_ms": time_resp.elapsed_ms,
                            "delta_ms": timing_delta,
                        },
                        observed_delta=(
                            f"Time-based blind SQLi confirmed: probe took {time_resp.elapsed_ms:.1f}ms "
                            f"vs baseline {baseline.elapsed_ms:.1f}ms (+{timing_delta:.1f}ms delay)."
                        ),
                    )
                    return finding

        # If none of the differential probes confirmed a meaningful delta:
        finding.confidence = "POSSIBLE"
        finding.metadata["validation_note"] = (
            "Differential probes (error, boolean, timing) observed no confirmed database execution delta."
        )
        return finding

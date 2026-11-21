"""
ExposedFilesValidator — Proof-based verification for exposed files and path candidates.

Methodology:
  1. Sends a request to a randomized non-existent path to detect soft-404 / catch-all routing.
  2. Sends a request to the target sensitive path candidate (e.g. /.git/HEAD, /.env, /config.json).
  3. Rejects false positives:
     - Target does not return HTTP 200.
     - Soft-404 detected and target response is identical or highly similar to the catch-all page.
     - Content is generic HTML (e.g. <!DOCTYPE html>) when a non-HTML file was requested.
  4. Confirms ONLY if:
     - Target path returns HTTP 200.
     - Target response is distinct from baseline.
     - Target response contains authentic content signatures (.git/HEAD 'ref: refs/', .env KEY=value, valid non-empty JSON, SQL dump statements).
"""

from __future__ import annotations

import difflib
import json
import re
import urllib.parse
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse

from ..models import Finding
from .base import BaseValidator, HTTPResponse


_RANDOM_BASELINE_PATH = "/wr_probe_nonexistent_catchall_404_test_7f9b8c"


class ExposedFilesValidator(BaseValidator):
    """Validator for candidate exposed files and sensitive paths."""

    name = "exposed_files"

    def can_validate(self, finding: Finding) -> bool:
        """Match exposed files and sensitive path candidates."""
        title = finding.title.lower()
        desc = finding.description.lower()
        cat = finding.category.lower()
        url = finding.url.lower()

        path_indicators = (
            ".git", ".env", ".json", ".sql", ".bak", ".dump", ".yml",
            ".yaml", ".conf", ".config", "phpinfo", "swagger", "openapi",
            "heapdump", "actuator", "backup",
        )
        return (
            cat in ("paths", "exposed_files")
            or "exposed" in title
            or any(pi in title or pi in url for pi in path_indicators)
        )

    def validate(self, finding: Finding) -> Finding:
        """Perform soft-404 detection, distinctness check, and authentic signature verification."""
        target_url = finding.url or finding.metadata.get("url", "")
        if not target_url:
            finding.confidence = "POSSIBLE"
            finding.metadata["validation_note"] = "No target URL provided for path verification."
            return finding

        parsed = urlparse(target_url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"
        baseline_url = urljoin(base_origin, _RANDOM_BASELINE_PATH)

        # -------------------------------------------------------------------
        # 1. Baseline Request to Detect Soft-404 / Catch-All
        # -------------------------------------------------------------------
        baseline = self.send_request(baseline_url, method="GET")
        is_soft_404 = (baseline.status == 200)

        # -------------------------------------------------------------------
        # 2. Target Path Request
        # -------------------------------------------------------------------
        target_resp = self.send_request(target_url, method="GET")

        if target_resp.status != 200:
            finding.confidence = "POSSIBLE"
            finding.metadata["validation_note"] = (
                f"Target path returned HTTP {target_resp.status} (expected 200 for exposed file verification)."
            )
            return finding

        # -------------------------------------------------------------------
        # 3. Distinctness from Baseline Check
        # -------------------------------------------------------------------
        if is_soft_404:
            # If server serves 200 for random non-existent paths, target MUST diverge
            if target_resp.body_hash == baseline.body_hash:
                finding.confidence = "POSSIBLE"
                finding.metadata["validation_note"] = (
                    "Soft-404 catch-all detected: target response body is identical to non-existent path baseline."
                )
                return finding

            # Compute similarity ratio
            matcher = difflib.SequenceMatcher(None, baseline.body[:2000], target_resp.body[:2000])
            similarity = matcher.quick_ratio()
            if similarity > 0.85:
                finding.confidence = "POSSIBLE"
                finding.metadata["validation_note"] = (
                    f"Soft-404 catch-all detected: target body has {similarity:.1%} similarity to 404 template."
                )
                return finding

        # -------------------------------------------------------------------
        # 4. Authentic Signature Verification
        # -------------------------------------------------------------------
        sig_verified, sig_name, sig_detail = self._verify_authentic_signature(parsed.path, target_resp.body)

        if not sig_verified:
            finding.confidence = "POSSIBLE"
            finding.metadata["validation_note"] = (
                f"Path returned HTTP 200 but failed authentic content signature verification ({sig_detail})."
            )
            return finding

        # -------------------------------------------------------------------
        # 5. Proof Packaging & Verification
        # -------------------------------------------------------------------
        self.package_proof(
            finding=finding,
            request_info={
                "method": "GET",
                "url": target_url,
                "verification_type": "soft404_differential_authentic_signature",
            },
            response_info={
                "status": target_resp.status,
                "body_hash": target_resp.body_hash,
                "content_length": len(target_resp.body),
                "content_type": target_resp.header("content-type"),
                "signature_verified": sig_name,
            },
            observed_delta=(
                f"Target path returned HTTP 200 with authentic {sig_name} signature ('{sig_detail}'). "
                f"Distinct from non-existent path baseline (baseline status: {baseline.status}, "
                f"body length delta: {len(target_resp.body) - len(baseline.body):+d} bytes)."
            ),
            extra={
                "soft_404_detected_on_host": is_soft_404,
                "signature_name": sig_name,
            },
        )
        return finding

    def _verify_authentic_signature(self, path: str, body: str) -> Tuple[bool, str, str]:
        """Verify that body contains authentic signatures appropriate for the requested path."""
        path_lower = path.lower()
        body_stripped = body.strip()
        body_lower = body_stripped.lower()

        # Reject HTML catch-all for binary/config requests
        is_html = (
            body_lower.startswith("<!doctype html")
            or body_lower.startswith("<html")
            or ("<head>" in body_lower and "<body>" in body_lower)
        )

        # 1. Git Repository
        if ".git/head" in path_lower:
            if "ref: refs/" in body:
                return True, "Git HEAD Reference", "ref: refs/"
            return False, "Git HEAD", "Missing 'ref: refs/' signature"

        if ".git/config" in path_lower:
            if "[core]" in body:
                return True, "Git Config File", "[core] section found"
            return False, "Git Config", "Missing '[core]' section"

        # 2. Environment Variables (.env)
        if ".env" in path_lower:
            if is_html:
                return False, ".env File", "HTML response body received instead of env key=value pairs"
            env_match = re.search(r'^[A-Z0-9_]{2,}\s*=\s*.+', body, re.MULTILINE)
            if env_match:
                return True, "Environment Variables (.env)", f"Matched: {env_match.group(0)[:30]}"
            return False, ".env File", "No valid KEY=value pairs found"

        # 3. JSON Configuration or OpenAPI / Swagger
        if path_lower.endswith(".json") or "swagger" in path_lower or "openapi" in path_lower:
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    # Check for non-trivial JSON structure (not generic error JSON)
                    if any(k in data for k in ("openapi", "swagger", "paths", "info", "database", "secret", "version", "name")):
                        return True, "Valid JSON Config/Schema", f"Keys: {list(data.keys())[:5]}"
                    if len(data) >= 2 and not ("error" in data and len(data) == 1):
                        return True, "Valid JSON Structure", f"Keys: {list(data.keys())[:5]}"
                elif isinstance(data, list) and len(data) > 0:
                    return True, "Valid JSON List", f"Length: {len(data)}"
            except Exception:
                pass
            if path_lower.endswith(".json"):
                return False, "JSON File", "Invalid JSON syntax"

        # 4. SQL Backups
        if any(path_lower.endswith(ext) for ext in (".sql", ".dump", ".bak")):
            sql_match = re.search(r'\b(CREATE TABLE|INSERT INTO|DROP TABLE|BEGIN TRANSACTION)\b', body, re.IGNORECASE)
            if sql_match:
                return True, "SQL Dump File", sql_match.group(0)
            return False, "SQL Backup", "Missing SQL DDL/DML statements"

        # 5. PHP Info
        if "phpinfo" in path_lower:
            if "php version" in body_lower and ("configuration" in body_lower or "php extension" in body_lower):
                return True, "phpinfo() Diagnostic", "PHP Version & Configuration tables confirmed"
            return False, "phpinfo()", "Missing PHP diagnostic signatures"

        # 6. Generic Sensitive File
        if not is_html and len(body_stripped) > 20:
            return True, "Non-HTML Plain Content", f"Size: {len(body_stripped)} bytes"

        return False, "Generic Path", "Generic HTML or empty content returned"

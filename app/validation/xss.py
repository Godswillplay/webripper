"""
XSSValidator — Proof-based verification for Cross-Site Scripting (XSS) candidates.

Methodology:
  1. Identifies XSS candidate findings.
  2. Synthesizes safe DOM canary payload (e.g. window.__wr_xss_proof = 1337).
  3. Attempts real browser execution via Playwright Chromium (headless).
  4. If browser launches and executes payload / triggers DOM canary:
       -> Sets confidence = "VERIFIED", attaches machine-checkable proof
          with browser execution log and DOM canary state.
  5. If Playwright or browser binary is not installed / available:
       -> Gracefully degrades confidence to "POSSIBLE" per defensive policy.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

from ..models import Finding
from .base import BaseValidator, HTTPResponse


_DOM_CANARY_VAR = "__wr_xss_proof"
_DOM_CANARY_VALUE = 1337
_CANARY_PAYLOADS = [
    f"<script>window.{_DOM_CANARY_VAR}={_DOM_CANARY_VALUE};</script>",
    f"<img src=x onerror=\"window.{_DOM_CANARY_VAR}={_DOM_CANARY_VALUE}\">",
    f"<svg onload=\"window.{_DOM_CANARY_VAR}={_DOM_CANARY_VALUE}\">",
]


class XSSValidator(BaseValidator):
    """Validator for candidate Cross-Site Scripting (XSS) findings."""

    name = "xss"

    def can_validate(self, finding: Finding) -> bool:
        """Match XSS candidates from vulnerability scanner or other sources."""
        title = finding.title.lower()
        desc = finding.description.lower()
        cat = finding.category.lower()
        vuln_type = str(finding.metadata.get("vuln_type", "")).lower()

        return (
            "xss" in title
            or "cross-site scripting" in desc
            or "xss" in vuln_type
            or cat == "xss"
            or ("vulns" in cat and "xss" in title)
        )

    def validate(self, finding: Finding) -> Finding:
        """
        Validate XSS finding using real browser execution.
        Degrades gracefully to POSSIBLE if browser is not available.
        """
        target_url = finding.url or finding.metadata.get("url", "")
        param = finding.metadata.get("parameter", "")

        if not target_url:
            # Cannot probe without a target URL
            finding.confidence = "POSSIBLE"
            finding.metadata["validation_note"] = "No target URL provided for browser verification; degraded to POSSIBLE."
            return finding

        # Determine injection URL
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not param and params:
            param = list(params.keys())[0]

        # Try Playwright real browser execution
        browser_available = False
        execution_verified = False
        execution_details: Dict[str, Any] = {}

        try:
            from playwright.sync_api import sync_playwright

            # Attempt browser launch
            with sync_playwright() as p:
                browser = None
                try:
                    browser = p.chromium.launch(
                        headless=True,
                        args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
                    )
                except Exception:
                    # Browser binary not found or failed to spawn
                    browser = None

                if browser is not None:
                    browser_available = True
                    try:
                        context = browser.new_context(ignore_https_errors=True)
                        page = context.new_page()

                        # Collect console logs and dialog triggers
                        dialog_messages: List[str] = []
                        page.on("dialog", lambda d: (dialog_messages.append(d.message), d.dismiss()))

                        for payload in _CANARY_PAYLOADS:
                            if param:
                                probe_params = dict(params)
                                probe_params[param] = [payload]
                                new_query = urlencode(probe_params, doseq=True)
                                probe_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                            else:
                                sep = "&" if "?" in target_url else "?"
                                probe_url = f"{target_url}{sep}xss={urllib.parse.quote(payload)}"

                            try:
                                page.goto(probe_url, timeout=4000, wait_until="domcontentloaded")
                            except Exception:
                                pass

                            # Evaluate if canary variable was executed in DOM
                            canary_val = page.evaluate(f"() => window.{_DOM_CANARY_VAR}")
                            if canary_val == _DOM_CANARY_VALUE or dialog_messages:
                                execution_verified = True
                                execution_details = {
                                    "engine": "Playwright Headless Chromium",
                                    "probe_url": probe_url,
                                    "payload": payload,
                                    "canary_variable": _DOM_CANARY_VAR,
                                    "canary_value": canary_val,
                                    "dialog_triggered": bool(dialog_messages),
                                    "dialog_messages": dialog_messages,
                                }
                                break
                    finally:
                        try:
                            browser.close()
                        except Exception:
                            pass
        except ImportError:
            browser_available = False
        except Exception as exc:
            execution_details["error"] = str(exc)

        if execution_verified:
            # Verified with real browser execution proof!
            self.package_proof(
                finding=finding,
                request_info={
                    "method": "GET",
                    "url": execution_details.get("probe_url", target_url),
                    "parameter": param,
                    "payload": execution_details.get("payload", ""),
                    "verification_method": "headless_browser_dom_execution",
                },
                response_info={
                    "dom_execution_confirmed": True,
                    "canary_value": execution_details.get("canary_value"),
                    "browser_engine": execution_details.get("engine"),
                },
                observed_delta=(
                    f"Real browser executed XSS payload in victim DOM context: "
                    f"window.{_DOM_CANARY_VAR} set to {execution_details.get('canary_value')}."
                ),
                extra=execution_details,
            )
            return finding

        # Graceful degradation policy
        finding.confidence = "POSSIBLE"
        if not browser_available:
            finding.metadata["validation_note"] = (
                "Playwright browser engine not available or executable missing; "
                "gracefully degraded candidate to POSSIBLE per defensive policy."
            )
        else:
            finding.metadata["validation_note"] = (
                "Browser executed without DOM canary trigger; retained as POSSIBLE."
            )
        return finding

"""
BaseValidator — Foundation for all proof-based validators in WebRipper Recon 5.0.

Provides:
  - HTTPResponse dataclass
  - DifferentialDelta dataclass
  - BaseValidator class with:
      - HTTP baseline / probe dispatch (urllib-based, non-destructive, lab/test SSL safe)
      - Differential response analysis
      - Machine-checkable proof packaging (request, response hash/snippet, observed delta)
      - Standardized confidence elevation to VERIFIED
"""

from __future__ import annotations

import difflib
import hashlib
import json
import ssl
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.error import HTTPError, URLError

from ..models import Finding, RipperSettings


# ---------------------------------------------------------------------------
# HTTP Response & Differential Delta Models
# ---------------------------------------------------------------------------

@dataclass
class HTTPResponse:
    """Standardized HTTP response representation for validators."""
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    raw_headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    body_hash: str = ""
    elapsed_ms: float = 0.0
    url: str = ""
    error: str = ""

    def header(self, name: str, default: str = "") -> str:
        """Case-insensitive header lookup."""
        return self.headers.get(name.lower(), default)

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "headers": self.headers,
            "body_hash": self.body_hash,
            "body_snippet": self.body[:500] if self.body else "",
            "elapsed_ms": round(self.elapsed_ms, 2),
            "url": self.url,
            "error": self.error,
        }


@dataclass
class DifferentialDelta:
    """Differential analysis result comparing baseline and probe responses."""
    status_changed: bool = False
    baseline_status: int = 0
    probe_status: int = 0
    length_delta: int = 0
    time_delta_ms: float = 0.0
    header_diffs: Dict[str, Tuple[Optional[str], Optional[str]]] = field(default_factory=dict)
    signatures_found: List[str] = field(default_factory=list)
    signatures_absent: List[str] = field(default_factory=list)
    similarity_ratio: float = 1.0
    meaningful: bool = False
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "status_changed": self.status_changed,
            "baseline_status": self.baseline_status,
            "probe_status": self.probe_status,
            "length_delta": self.length_delta,
            "time_delta_ms": round(self.time_delta_ms, 2),
            "header_diffs": self.header_diffs,
            "signatures_found": self.signatures_found,
            "signatures_absent": self.signatures_absent,
            "similarity_ratio": round(self.similarity_ratio, 3),
            "meaningful": self.meaningful,
            "summary": self.summary,
        }


# ---------------------------------------------------------------------------
# Redirect Control Handler
# ---------------------------------------------------------------------------

class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Custom handler to prevent following redirects during open redirect validation."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# ---------------------------------------------------------------------------
# Base Validator
# ---------------------------------------------------------------------------

class BaseValidator:
    """
    Abstract base validator for WebRipper Recon 5.0.

    Subclasses must implement:
      - `can_validate(finding: Finding) -> bool`
      - `validate(finding: Finding) -> Finding`
    """

    name: str = "base"

    def __init__(self, settings: Optional[RipperSettings] = None):
        self.settings = settings or RipperSettings()
        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE

    # -----------------------------------------------------------------------
    # Hashing & Utilities
    # -----------------------------------------------------------------------

    @staticmethod
    def compute_hash(data: Union[str, bytes]) -> str:
        """Compute SHA-256 hash of response body."""
        if isinstance(data, str):
            data = data.encode("utf-8", errors="ignore")
        return hashlib.sha256(data).hexdigest()

    # -----------------------------------------------------------------------
    # HTTP Probing
    # -----------------------------------------------------------------------

    def send_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Union[str, bytes, dict]] = None,
        timeout: Optional[float] = None,
        allow_redirects: bool = True,
    ) -> HTTPResponse:
        """
        Execute an HTTP request and return a standardized HTTPResponse.
        Uses urllib.request (zero extra dependencies, fully local/fixture compatible).
        """
        req_headers = {
            "User-Agent": getattr(self.settings, "user_agent", "WebRipper-Validator/5.0"),
            "Accept": "*/*",
        }
        if headers:
            req_headers.update(headers)

        # Auth credentials if configured in settings
        if getattr(self.settings, "auth_cookie", "") and "Cookie" not in req_headers:
            req_headers["Cookie"] = self.settings.auth_cookie
        if getattr(self.settings, "auth_token", "") and "Authorization" not in req_headers:
            req_headers["Authorization"] = f"Bearer {self.settings.auth_token}"

        body_bytes: Optional[bytes] = None
        if data is not None:
            if isinstance(data, dict):
                body_bytes = urllib.parse.urlencode(data).encode("utf-8")
                req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            elif isinstance(data, str):
                body_bytes = data.encode("utf-8")
            elif isinstance(data, bytes):
                body_bytes = data

        timeout_sec = timeout if timeout is not None else float(getattr(self.settings, "timeout", 10))

        # Build opener with handlers
        handlers: List[Any] = [urllib.request.HTTPSHandler(context=self._ssl_ctx)]
        proxy = getattr(self.settings, "proxy", "")
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
        if not allow_redirects:
            handlers.append(_NoRedirectHandler())

        opener = urllib.request.build_opener(*handlers)
        req = urllib.request.Request(url, data=body_bytes, headers=req_headers, method=method)

        t0 = time.perf_counter()
        status_code = 0
        resp_headers: Dict[str, str] = {}
        raw_headers: Dict[str, str] = {}
        body = ""
        error_msg = ""

        try:
            with opener.open(req, timeout=timeout_sec) as resp:
                status_code = resp.status
                raw_bytes = resp.read()
                body = raw_bytes.decode("utf-8", errors="ignore")
                for k, v in resp.headers.items():
                    raw_headers[k] = v
                    resp_headers[k.lower()] = v
        except HTTPError as e:
            status_code = e.code
            try:
                raw_bytes = e.read()
                body = raw_bytes.decode("utf-8", errors="ignore")
            except Exception:
                body = ""
            for k, v in e.headers.items():
                raw_headers[k] = v
                resp_headers[k.lower()] = v
        except URLError as e:
            error_msg = str(e.reason)
        except Exception as e:
            error_msg = str(e)

        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        return HTTPResponse(
            status=status_code,
            headers=resp_headers,
            raw_headers=raw_headers,
            body=body,
            body_hash=self.compute_hash(body),
            elapsed_ms=elapsed_ms,
            url=url,
            error=error_msg,
        )

    # -----------------------------------------------------------------------
    # Differential Analysis
    # -----------------------------------------------------------------------

    def compare_responses(
        self,
        baseline: HTTPResponse,
        probe: HTTPResponse,
        signatures: Optional[List[str]] = None,
    ) -> DifferentialDelta:
        """
        Perform differential analysis between baseline and probe HTTP responses.
        Calculates status delta, length delta, time delta, header changes,
        and signature emergence.
        """
        status_changed = baseline.status != probe.status
        length_delta = len(probe.body) - len(baseline.body)
        time_delta_ms = probe.elapsed_ms - baseline.elapsed_ms

        # Header differences (relevant security headers)
        header_diffs: Dict[str, Tuple[Optional[str], Optional[str]]] = {}
        all_keys = set(baseline.headers.keys()).union(set(probe.headers.keys()))
        for k in all_keys:
            v_base = baseline.headers.get(k)
            v_probe = probe.headers.get(k)
            if v_base != v_probe:
                header_diffs[k] = (v_base, v_probe)

        # Signatures that emerged in probe but were absent in baseline
        signatures_found = []
        signatures_absent = []
        if signatures:
            probe_lower = probe.body.lower()
            base_lower = baseline.body.lower()
            for sig in signatures:
                sig_lower = sig.lower()
                if sig_lower in probe_lower and sig_lower not in base_lower:
                    signatures_found.append(sig)
                elif sig_lower in base_lower and sig_lower not in probe_lower:
                    signatures_absent.append(sig)

        # Body similarity
        similarity = 1.0
        if baseline.body or probe.body:
            matcher = difflib.SequenceMatcher(None, baseline.body[:2000], probe.body[:2000])
            similarity = matcher.quick_ratio()

        meaningful = (
            status_changed
            or bool(signatures_found)
            or abs(length_delta) > 50
            or abs(time_delta_ms) > 1500
        )

        summary_parts = []
        if status_changed:
            summary_parts.append(f"Status changed {baseline.status} -> {probe.status}")
        if signatures_found:
            summary_parts.append(f"Signatures emerged: {signatures_found}")
        if abs(length_delta) > 0:
            summary_parts.append(f"Length delta: {length_delta:+d} bytes")
        if abs(time_delta_ms) > 500:
            summary_parts.append(f"Time delta: {time_delta_ms:+.1f} ms")
        summary = "; ".join(summary_parts) if summary_parts else "No significant differential observed"

        return DifferentialDelta(
            status_changed=status_changed,
            baseline_status=baseline.status,
            probe_status=probe.status,
            length_delta=length_delta,
            time_delta_ms=time_delta_ms,
            header_diffs=header_diffs,
            signatures_found=signatures_found,
            signatures_absent=signatures_absent,
            similarity_ratio=similarity,
            meaningful=meaningful,
            summary=summary,
        )

    # -----------------------------------------------------------------------
    # Proof Packaging
    # -----------------------------------------------------------------------

    def package_proof(
        self,
        finding: Finding,
        request_info: Dict[str, Any],
        response_info: Dict[str, Any],
        observed_delta: Any,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Package machine-checkable proof into finding.metadata["proof"]
        and elevate finding confidence to VERIFIED.

        Adheres strictly to the mandate:
          - Only mark VERIFIED if machine-checkable proof exists.
          - Proof must contain request, response or hash, and observed delta.
        """
        proof: Dict[str, Any] = {
            "validator": self.name,
            "verified_at": datetime.now(timezone.utc).isoformat(),
            "request": request_info,
            "response": response_info,
            "observed_delta": observed_delta if isinstance(observed_delta, (str, dict, list)) else str(observed_delta),
        }
        if extra:
            proof["extra"] = extra

        finding.metadata["proof"] = proof
        finding.metadata["proof_attached"] = True
        finding.confidence = "VERIFIED"
        return proof

    # -----------------------------------------------------------------------
    # Contract Methods
    # -----------------------------------------------------------------------

    def can_validate(self, finding: Finding) -> bool:
        """Return True if this validator can verify the given finding."""
        raise NotImplementedError

    def validate(self, finding: Finding) -> Finding:
        """
        Perform verification on candidate finding.
        Returns the finding (updated in-place with VERIFIED confidence & proof if verified,
        or unchanged/downgraded if unverified).
        """
        raise NotImplementedError

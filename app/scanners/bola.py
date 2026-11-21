"""
Dual-Identity Differential Engine for BOLA/IDOR & BFLA Detection.

Phase 3 Core Security Engine:
- Replays recorded requests across Identity A (owner/admin), Identity B (cross-tenant),
  and Anonymous (unauthenticated) credentials.
- Performs non-destructive differential verification comparing HTTP status codes,
  body similarity (Levenshtein/difflib ratio & token Jaccard), and tenant ownership markers.
- Only elevates findings to confidence="VERIFIED" when unauthorized cross-tenant or
  privileged function access is machine-provable with attached proof artifacts.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import re
import ssl
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, parse_qs, urlencode, urljoin, urlparse

from .base import BaseScanner
from ..models import (
    Confidence,
    EventType,
    Finding,
    ProgressEvent,
    RipReport,
    RipperSettings,
    ScanResult,
    Severity,
)


# ---------------------------------------------------------------------------
# Object ID & Admin Route Regex Patterns
# ---------------------------------------------------------------------------

_RE_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_RE_HASH = re.compile(r"^[0-9a-f]{16,64}$", re.IGNORECASE)
_RE_INT = re.compile(r"^\d+$")

_ID_PATH_PATTERN = re.compile(
    r"/(?:users|accounts|orders|invoices|orgs|organizations|documents|items|profiles|messages|files|projects|tenants|customers|records|data|reports|private|members|clients)/([a-zA-Z0-9_\-]+)",
    re.IGNORECASE,
)

_ID_QUERY_KEYS = frozenset({
    "id", "user_id", "userid", "account_id", "accountid", "order_id",
    "invoice_id", "doc_id", "document_id", "tenant_id", "profile_id",
    "item_id", "file_id", "project_id", "record_id", "uuid", "member_id",
})

_ADMIN_ROUTE_PATTERNS = re.compile(
    r"/(?:admin|api/admin|management|internal|system|settings/users|roles|permissions|export|audit_log)(?:/|$)",
    re.IGNORECASE,
)

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


# ---------------------------------------------------------------------------
# Data Models for Replay Responses
# ---------------------------------------------------------------------------

@dataclass
class ReplayResponse:
    """Standardized HTTP response representation for multi-identity replays."""
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    body_hash: str = ""
    url: str = ""
    elapsed_ms: float = 0.0
    error: str = ""

    def header(self, name: str, default: str = "") -> str:
        """Case-insensitive header lookup."""
        return self.headers.get(name.lower(), default)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "headers": self.headers,
            "body_hash": self.body_hash,
            "body_snippet": self.body[:500] if self.body else "",
            "elapsed_ms": round(self.elapsed_ms, 2),
            "url": self.url,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Redirect Handler (suppresses auto-redirects to capture 302 login bounces)
# ---------------------------------------------------------------------------

class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Prevents following redirects so 301/302 auth-redirects can be inspected."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# ---------------------------------------------------------------------------
# Candidate Extraction & Safety Utilities
# ---------------------------------------------------------------------------

def is_safe_method_or_dry_run(method: str, candidate_meta: Optional[Dict[str, Any]] = None) -> bool:
    """
    Ensure non-destructive testing:
    Allows GET, HEAD, OPTIONS, or explicitly flagged safe/dry-run requests.
    """
    m = (method or "GET").upper()
    if m in _SAFE_METHODS:
        return True
    meta = candidate_meta or {}
    if meta.get("dry_run") or meta.get("is_safe") or meta.get("safe"):
        return True
    return False


def extract_object_id_candidates(captured_requests_or_urls: List[Any]) -> List[Dict[str, Any]]:
    """
    Identify requests referencing object identifiers (path segment, UUID, hash, query, or body).
    Returns deduplicated candidate definitions.
    """
    candidates = []
    seen = set()

    for item in captured_requests_or_urls:
        if isinstance(item, str):
            req = {"url": item, "method": "GET"}
        elif isinstance(item, dict):
            req = item
        elif hasattr(item, "url"):
            req = {"url": item.url, "method": getattr(item, "method", "GET")}
        else:
            continue

        url = req.get("url", "")
        if not url or not (url.startswith("http://") or url.startswith("https://")):
            continue

        method = req.get("method", "GET").upper()
        if not is_safe_method_or_dry_run(method, req):
            continue

        parsed = urlparse(url)
        path = parsed.path
        obj_id: Optional[str] = None
        id_location: Optional[str] = None

        # 1. Resource path regex match (e.g. /documents/{doc_id})
        path_match = _ID_PATH_PATTERN.search(path)
        if path_match:
            obj_id = path_match.group(1)
            id_location = "path"
        else:
            # 2. Check path segments for numeric, UUID, or hash tokens
            segments = [s for s in path.split("/") if s]
            for seg in segments:
                if _RE_INT.match(seg):
                    obj_id = seg
                    id_location = "path_numeric"
                    break
                elif _RE_UUID.match(seg):
                    obj_id = seg
                    id_location = "path_uuid"
                    break
                elif _RE_HASH.match(seg):
                    obj_id = seg
                    id_location = "path_hash"
                    break

        # 3. Check query parameters
        if not obj_id and parsed.query:
            query_params = dict(parse_qsl(parsed.query))
            for k, val in query_params.items():
                if k.lower() in _ID_QUERY_KEYS and val:
                    obj_id = val
                    id_location = f"query:{k}"
                    break

        # 4. Check JSON body if provided
        if not obj_id and req.get("body"):
            body_raw = req["body"]
            body_dict = None
            if isinstance(body_raw, dict):
                body_dict = body_raw
            elif isinstance(body_raw, str):
                try:
                    parsed_json = json.loads(body_raw)
                    if isinstance(parsed_json, dict):
                        body_dict = parsed_json
                except Exception:
                    body_dict = None
            if body_dict:
                for k, val in body_dict.items():
                    if k.lower() in _ID_QUERY_KEYS and isinstance(val, (str, int)) and val:
                        obj_id = str(val)
                        id_location = f"body:{k}"
                        break

        if obj_id:
            dedup_key = f"{method}:{parsed.netloc}{parsed.path}"
            if dedup_key not in seen:
                seen.add(dedup_key)
                candidates.append({
                    "url": url,
                    "method": method,
                    "object_id": obj_id,
                    "id_location": id_location,
                    "headers": req.get("headers", {}),
                    "body": req.get("body", None),
                    "original_status": req.get("status", 200),
                })

    return candidates


def extract_admin_route_candidates(captured_requests_or_urls: List[Any]) -> List[Dict[str, Any]]:
    """
    Identify administrative or privileged routes suitable for BFLA differential testing.
    """
    candidates = []
    seen = set()

    for item in captured_requests_or_urls:
        if isinstance(item, str):
            req = {"url": item, "method": "GET"}
        elif isinstance(item, dict):
            req = item
        elif hasattr(item, "url"):
            req = {"url": item.url, "method": getattr(item, "method", "GET")}
        else:
            continue

        url = req.get("url", "")
        if not url or not (url.startswith("http://") or url.startswith("https://")):
            continue

        method = req.get("method", "GET").upper()
        if not is_safe_method_or_dry_run(method, req):
            continue

        parsed = urlparse(url)
        path = parsed.path.lower()

        is_admin = bool(_ADMIN_ROUTE_PATTERNS.search(path) or "/admin/" in path or path.endswith("/admin"))
        if is_admin:
            dedup_key = f"{method}:{parsed.netloc}{parsed.path}"
            if dedup_key not in seen:
                seen.add(dedup_key)
                candidates.append({
                    "url": url,
                    "method": method,
                    "headers": req.get("headers", {}),
                    "body": req.get("body", None),
                    "original_status": req.get("status", 200),
                })

    return candidates


# ---------------------------------------------------------------------------
# Similarity & Response Analysis Helpers
# ---------------------------------------------------------------------------

def compute_body_similarity(body_a: str, body_b: str) -> float:
    """Compute structural similarity ratio between two response bodies."""
    if not body_a and not body_b:
        return 1.0
    if not body_a or not body_b:
        return 0.0
    if body_a == body_b:
        return 1.0
    matcher = difflib.SequenceMatcher(None, body_a[:2000], body_b[:2000])
    return matcher.ratio()


def compute_token_jaccard(body_a: str, body_b: str) -> float:
    """Compute token-level Jaccard similarity."""
    toks_a = set(re.findall(r"\w+", body_a.lower()))
    toks_b = set(re.findall(r"\w+", body_b.lower()))
    if not toks_a and not toks_b:
        return 1.0
    if not toks_a or not toks_b:
        return 0.0
    return len(toks_a & toks_b) / len(toks_a | toks_b)


def is_login_or_error_response(resp: ReplayResponse, baseline_content_type: str = "") -> bool:
    """
    Check if a 200 OK response is actually a soft-404, generic error, or login page bounce.
    """
    if resp.status != 200:
        return True
    if not resp.body or len(resp.body.strip()) == 0:
        return True

    body_lower = resp.body.lower()
    ct = resp.header("content-type").lower()

    # Baseline was JSON but response returned HTML login/error template
    if baseline_content_type and "application/json" in baseline_content_type.lower() and "text/html" in ct:
        if "<html" in body_lower or "<!doctype html" in body_lower:
            return True

    # Standard login forms and error signposts
    login_indicators = [
        'type="password"',
        "type='password'",
        'action="/login"',
        "action='/login'",
        'action="/signin"',
        "action='/signin'",
        "please log in",
        "please sign in",
        "sign in to continue",
        "session expired",
        "session has expired",
        "access denied",
        "unauthorized access",
        "404 not found",
        "page not found",
        "cannot get",
        "cannot post",
    ]
    for ind in login_indicators:
        if ind in body_lower:
            return True

    return False


def generate_poc_curl(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Optional[str] = None,
) -> str:
    """Generate reproduction curl command for findings."""
    parts = ["curl", "-i", "-s", "-k", "-X", method.upper()]
    if headers:
        for k, v in headers.items():
            if k.lower() in ("user-agent", "accept") and "webripper" in v.lower():
                continue
            parts.append(f"-H '{k}: {v}'")
    if data:
        parts.append(f"-d '{data}'")
    parts.append(f"'{url}'")
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Differential Evaluation Logic (BOLA & BFLA)
# ---------------------------------------------------------------------------

def evaluate_differential_response(
    resp_a: ReplayResponse,
    resp_b: ReplayResponse,
    resp_anon: ReplayResponse,
    marker_a: str = "",
) -> Tuple[bool, str, Confidence, Severity]:
    """
    Evaluate responses from Identity A (owner), Identity B (cross-tenant), and Anonymous.
    Returns: (is_vulnerable, classification, confidence, severity)
    """
    # 1. Baseline Identity A check: Must succeed with 2xx and non-empty body
    if resp_a.status < 200 or resp_a.status >= 300 or not resp_a.body:
        return False, "BASELINE_FAILED", Confidence.INFO, Severity.INFO

    ct_a = resp_a.header("content-type")

    # 2. Check Anonymous access (Missing Authentication / Unauthenticated IDOR)
    if resp_anon.status == 200 and not is_login_or_error_response(resp_anon, ct_a):
        marker_in_anon = bool(marker_a and marker_a.lower() in resp_anon.body.lower())
        sim_anon = compute_body_similarity(resp_a.body, resp_anon.body)
        if marker_in_anon:
            return True, "MISSING_AUTHENTICATION_WITH_MARKER", Confidence.VERIFIED, Severity.CRITICAL
        elif sim_anon >= 0.85:
            return True, "MISSING_AUTHENTICATION_HIGH_SIMILARITY", Confidence.VERIFIED, Severity.CRITICAL

    # 3. Check Identity B access (BOLA / IDOR)
    if resp_b.status == 200 and not is_login_or_error_response(resp_b, ct_a):
        marker_leaked = bool(marker_a and marker_a.lower() in resp_b.body.lower())
        sim_b = compute_body_similarity(resp_a.body, resp_b.body)

        if marker_leaked:
            # Absolute machine-provable proof: Identity B received Identity A's private identifier
            return True, "BOLA_VERIFIED_WITH_MARKER", Confidence.VERIFIED, Severity.CRITICAL
        elif sim_b >= 0.85:
            # Near identical resource payload returned to Identity B
            return True, "BOLA_HIGH_SIMILARITY", Confidence.VERIFIED, Severity.HIGH
        elif sim_b >= 0.60:
            return True, "BOLA_SUSPECTED", Confidence.LIKELY, Severity.MEDIUM

    # 4. Access control enforced (401, 403, 404, or redirected to login)
    return False, "ACCESS_CONTROL_ENFORCED", Confidence.INFO, Severity.INFO


def evaluate_bfla_response(
    resp_a: ReplayResponse,
    resp_b: ReplayResponse,
    resp_anon: ReplayResponse,
) -> Tuple[bool, str, Confidence, Severity]:
    """
    Evaluate administrative endpoint responses across Identity A (Admin),
    Identity B (Standard user), and Anonymous.
    Returns: (is_vulnerable, classification, confidence, severity)
    """
    # 1. Baseline Identity A (Admin) check
    if resp_a.status < 200 or resp_a.status >= 300 or not resp_a.body:
        return False, "BASELINE_ADMIN_FAILED", Confidence.INFO, Severity.INFO

    ct_a = resp_a.header("content-type")

    # 2. Check Anonymous access to admin endpoint
    if resp_anon.status == 200 and not is_login_or_error_response(resp_anon, ct_a):
        sim_anon = compute_body_similarity(resp_a.body, resp_anon.body)
        if sim_anon >= 0.70:
            return True, "BFLA_UNAUTHENTICATED_ADMIN_ACCESS", Confidence.VERIFIED, Severity.CRITICAL

    # 3. Check Standard User (Identity B) access to admin endpoint
    if resp_b.status == 200 and not is_login_or_error_response(resp_b, ct_a):
        sim_b = compute_body_similarity(resp_a.body, resp_b.body)
        if sim_b >= 0.70:
            return True, "BFLA_ADMIN_ACCESS_BY_STANDARD_USER", Confidence.VERIFIED, Severity.HIGH
        elif sim_b >= 0.50:
            return True, "BFLA_ADMIN_ACCESS_SUSPECTED", Confidence.LIKELY, Severity.MEDIUM

    # Access control properly rejected non-admin
    return False, "BFLA_ACCESS_CONTROL_ENFORCED", Confidence.INFO, Severity.INFO


# ---------------------------------------------------------------------------
# BOLAScanner Implementation
# ---------------------------------------------------------------------------

class BOLAScanner(BaseScanner):
    """
    Dual-Identity Differential Engine for BOLA/IDOR and BFLA detection.

    Conducts multi-identity request replay using Identity A, Identity B, and
    Anonymous contexts. Attaches verifiable machine-checkable proof artifacts
    upon finding confirmation.
    """

    def __init__(
        self,
        rip_report: RipReport,
        settings: RipperSettings,
        progress_callback: Optional[Callable[[ProgressEvent], None]] = None,
        recon: Optional[Any] = None,
        identity_a_cookie: str = "",
        identity_a_token: str = "",
        identity_b_cookie: str = "",
        identity_b_token: str = "",
        identity_a_marker: str = "",
        identity_b_marker: str = "",
    ) -> None:
        super().__init__(rip_report, settings, progress_callback, recon)
        self._override_a_cookie = identity_a_cookie
        self._override_a_token = identity_a_token
        self._override_b_cookie = identity_b_cookie
        self._override_b_token = identity_b_token
        self._override_a_marker = identity_a_marker
        self._override_b_marker = identity_b_marker

        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE

    @property
    def name(self) -> str:
        return "bola"

    @property
    def description(self) -> str:
        return "Dual-identity differential engine for BOLA/IDOR and BFLA authorization flaw detection"

    # -----------------------------------------------------------------------
    # Identity Configuration Resolution
    # -----------------------------------------------------------------------

    def _get_identity_configs(self) -> Dict[str, str]:
        """Resolve cookies, tokens, and tenant markers with backward-compatible fallbacks."""
        a_cookie = (
            self._override_a_cookie
            or getattr(self._settings, "identity_a_cookie", "")
            or getattr(self._settings, "auth_cookie", "")
            or getattr(self._settings, "custom_cookies", "")
        )
        a_token = (
            self._override_a_token
            or getattr(self._settings, "identity_a_token", "")
            or getattr(self._settings, "auth_token", "")
        )
        b_cookie = (
            self._override_b_cookie
            or getattr(self._settings, "identity_b_cookie", "")
        )
        b_token = (
            self._override_b_token
            or getattr(self._settings, "identity_b_token", "")
        )
        a_marker = (
            self._override_a_marker
            or getattr(self._settings, "identity_a_tenant_marker", "")
            or getattr(self._settings, "identity_a_marker", "")
        )
        b_marker = (
            self._override_b_marker
            or getattr(self._settings, "identity_b_tenant_marker", "")
            or getattr(self._settings, "identity_b_marker", "")
        )

        return {
            "a_cookie": a_cookie,
            "a_token": a_token,
            "b_cookie": b_cookie,
            "b_token": b_token,
            "a_marker": a_marker,
            "b_marker": b_marker,
        }

    def _build_identity_headers(
        self,
        identity: str,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        """Build request headers isolated to the requested identity context."""
        headers = {
            "User-Agent": getattr(self._settings, "user_agent", "WebRipper-Recon/5.0"),
            "Accept": "*/*",
        }
        if self._settings.custom_headers:
            for k, v in self._settings.custom_headers.items():
                if k.lower() not in ("cookie", "authorization"):
                    headers[k] = v

        if extra_headers:
            for k, v in extra_headers.items():
                if k.lower() not in ("cookie", "authorization"):
                    headers[k] = v

        cfg = self._get_identity_configs()
        id_upper = identity.upper()

        if id_upper == "A":
            cookie = cfg["a_cookie"]
            token = cfg["a_token"]
            if cookie:
                headers["Cookie"] = cookie
            if token:
                auth_val = token if token.lower().startswith(("bearer ", "basic ", "token ")) else f"Bearer {token}"
                headers["Authorization"] = auth_val
        elif id_upper == "B":
            cookie = cfg["b_cookie"]
            token = cfg["b_token"]
            if cookie:
                headers["Cookie"] = cookie
            if token:
                auth_val = token if token.lower().startswith(("bearer ", "basic ", "token ")) else f"Bearer {token}"
                headers["Authorization"] = auth_val
        elif id_upper in ("ANON", "ANONYMOUS"):
            # Anonymous context has neither Cookie nor Authorization headers
            pass

        return headers

    # -----------------------------------------------------------------------
    # Replay Request Dispatcher
    # -----------------------------------------------------------------------

    def _send_replay_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Union[str, bytes, dict]] = None,
        timeout: Optional[float] = None,
    ) -> ReplayResponse:
        """Send HTTP probe request using standard urllib.request with redirect suppression."""
        req_headers = dict(headers or {})
        body_bytes: Optional[bytes] = None
        if data is not None:
            if isinstance(data, dict):
                body_bytes = urllib.parse.urlencode(data).encode("utf-8")
                req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            elif isinstance(data, str):
                body_bytes = data.encode("utf-8")
            elif isinstance(data, bytes):
                body_bytes = data

        timeout_sec = timeout if timeout is not None else float(getattr(self._settings, "timeout", 10) or 10)

        handlers: List[Any] = [
            urllib.request.HTTPSHandler(context=self._ssl_ctx),
            _NoRedirectHandler(),
        ]
        proxy = self._get_proxy()
        if proxy:
            handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))

        opener = urllib.request.build_opener(*handlers)
        req = urllib.request.Request(url, data=body_bytes, headers=req_headers, method=method.upper())

        t0 = time.perf_counter()
        status_code = 0
        resp_headers: Dict[str, str] = {}
        body = ""
        error_msg = ""

        try:
            with opener.open(req, timeout=timeout_sec) as resp:
                status_code = resp.status
                raw_bytes = resp.read()
                body = raw_bytes.decode("utf-8", errors="ignore")
                for k, v in resp.headers.items():
                    resp_headers[k.lower()] = v
        except HTTPError as e:
            status_code = e.code
            try:
                raw_bytes = e.read()
                body = raw_bytes.decode("utf-8", errors="ignore")
            except Exception:
                body = ""
            for k, v in e.headers.items():
                resp_headers[k.lower()] = v
        except URLError as e:
            error_msg = str(e.reason)
        except Exception as e:
            error_msg = str(e)

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        body_hash = hashlib.sha256(body.encode("utf-8", errors="ignore")).hexdigest()

        return ReplayResponse(
            status=status_code,
            headers=resp_headers,
            body=body,
            body_hash=body_hash,
            url=url,
            elapsed_ms=elapsed_ms,
            error=error_msg,
        )

    # -----------------------------------------------------------------------
    # Proof Packaging & Finding Synthesis
    # -----------------------------------------------------------------------

    def _sanitize_headers_for_proof(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Redact sensitive auth tokens slightly for safe display in proof."""
        clean = {}
        for k, v in headers.items():
            k_lower = k.lower()
            if k_lower in ("cookie", "authorization"):
                if len(v) > 16:
                    clean[k] = f"{v[:6]}...{v[-4:]}"
                else:
                    clean[k] = "***redacted***"
            else:
                clean[k] = v
        return clean

    def _package_proof(
        self,
        vuln_type: str,
        classification: str,
        url: str,
        method: str,
        headers_a: Dict[str, str],
        headers_b: Dict[str, str],
        resp_a: ReplayResponse,
        resp_b: ReplayResponse,
        resp_anon: ReplayResponse,
        marker_a: str,
        poc_curl: str,
    ) -> Dict[str, Any]:
        """Construct structured machine-checkable proof dictionary."""
        sim_b = compute_body_similarity(resp_a.body, resp_b.body)
        sim_anon = compute_body_similarity(resp_a.body, resp_anon.body)
        marker_leaked = bool(marker_a and marker_a.lower() in resp_b.body.lower())

        return {
            "scanner": "bola",
            "verified_at": datetime.now(timezone.utc).isoformat(),
            "vulnerability_type": vuln_type,
            "classification": classification,
            "target_url": url,
            "method": method,
            "baseline_request": {
                "url": url,
                "method": method,
                "identity": "Identity A",
                "headers": self._sanitize_headers_for_proof(headers_a),
            },
            "baseline_response": {
                "status": resp_a.status,
                "body_hash": resp_a.body_hash,
                "body_snippet": resp_a.body[:500] if resp_a.body else "",
                "length": len(resp_a.body),
            },
            "replay_request": {
                "url": url,
                "method": method,
                "identity": "Identity B",
                "headers": self._sanitize_headers_for_proof(headers_b),
            },
            "replay_response": {
                "status": resp_b.status,
                "body_hash": resp_b.body_hash,
                "body_snippet": resp_b.body[:500] if resp_b.body else "",
                "length": len(resp_b.body),
            },
            "anonymous_response": {
                "status": resp_anon.status,
                "body_snippet": resp_anon.body[:500] if resp_anon.body else "",
                "length": len(resp_anon.body),
            },
            "observed_delta": {
                "classification": classification,
                "similarity_ratio_b": round(sim_b, 3),
                "similarity_ratio_anon": round(sim_anon, 3),
                "marker_leaked": marker_leaked,
                "tenant_marker": marker_a if marker_leaked else "",
                "status_a": resp_a.status,
                "status_b": resp_b.status,
                "status_anon": resp_anon.status,
            },
            "poc_curl": poc_curl,
        }

    # -----------------------------------------------------------------------
    # Candidate Testing Methods
    # -----------------------------------------------------------------------

    def _test_candidate_bola(
        self,
        candidate: Dict[str, Any],
        cfg: Dict[str, str],
    ) -> Optional[Finding]:
        """Perform multi-identity replay for a BOLA/IDOR candidate."""
        url = candidate["url"]
        method = candidate.get("method", "GET").upper()
        req_headers = candidate.get("headers", {})
        req_body = candidate.get("body", None)
        obj_id = candidate.get("object_id", "")
        id_location = candidate.get("id_location", "path")

        headers_a = self._build_identity_headers("A", req_headers)
        headers_b = self._build_identity_headers("B", req_headers)
        headers_anon = self._build_identity_headers("ANON", req_headers)

        # Baseline request with Identity A
        resp_a = self._send_replay_request(url, method=method, headers=headers_a, data=req_body)
        if resp_a.status < 200 or resp_a.status >= 300:
            return None

        # Cross-tenant replay with Identity B
        resp_b = self._send_replay_request(url, method=method, headers=headers_b, data=req_body)

        # Unauthenticated replay with Anonymous
        resp_anon = self._send_replay_request(url, method=method, headers=headers_anon, data=req_body)

        marker_a = cfg["a_marker"]
        is_vuln, classification, confidence, severity = evaluate_differential_response(
            resp_a=resp_a,
            resp_b=resp_b,
            resp_anon=resp_anon,
            marker_a=marker_a,
        )

        if not is_vuln:
            return None

        # Construct reproduction PoC using Identity B headers
        b_auth_headers = {}
        if headers_b.get("Cookie"):
            b_auth_headers["Cookie"] = headers_b["Cookie"]
        if headers_b.get("Authorization"):
            b_auth_headers["Authorization"] = headers_b["Authorization"]
        poc_curl = generate_poc_curl(url, method=method, headers=b_auth_headers, data=req_body)

        proof = self._package_proof(
            vuln_type="BOLA",
            classification=classification,
            url=url,
            method=method,
            headers_a=headers_a,
            headers_b=headers_b,
            resp_a=resp_a,
            resp_b=resp_b,
            resp_anon=resp_anon,
            marker_a=marker_a,
            poc_curl=poc_curl,
        )

        parsed_path = urlparse(url).path
        sim_pct = round(compute_body_similarity(resp_a.body, resp_b.body) * 100, 1)

        evidence_lines = [
            f"Baseline [Identity A]: HTTP {resp_a.status} OK (Length: {len(resp_a.body)})",
            f"Replay   [Identity B]: HTTP {resp_b.status} OK (Length: {len(resp_b.body)}, Similarity: {sim_pct}%)",
            f"Anonymous:             HTTP {resp_anon.status}",
        ]
        if marker_a and marker_a.lower() in resp_b.body.lower():
            evidence_lines.append(f"Tenant Marker Leak:    '{marker_a}' disclosed to Identity B")

        title = f"Broken Object Level Authorization (BOLA / IDOR): {parsed_path}"
        description = (
            f"Dual-identity differential replay identified Broken Object Level Authorization on {url}. "
            f"Resource belonging to Identity A was readable using Identity B credentials with HTTP {resp_b.status}."
        )

        return Finding(
            severity=severity,
            category="bola",
            title=title,
            description=description,
            evidence="\n".join(evidence_lines),
            url=url,
            confidence=confidence.value,
            remediation=(
                "Implement strict server-side authorization checks verifying that the authenticated user "
                "owns or is permitted to access the specific requested object ID before returning data."
            ),
            metadata={
                "proof": proof,
                "proof_attached": (confidence == Confidence.VERIFIED),
                "poc_curl": poc_curl,
                "cwe": "CWE-639",
                "owasp": "API1:2023 - Broken Object Level Authorization",
                "method": method,
                "object_id": obj_id,
                "id_location": id_location,
                "classification": classification,
            },
        )

    def _test_candidate_bfla(
        self,
        candidate: Dict[str, Any],
        cfg: Dict[str, str],
    ) -> Optional[Finding]:
        """Perform multi-identity replay for a BFLA administrative candidate."""
        url = candidate["url"]
        method = candidate.get("method", "GET").upper()
        req_headers = candidate.get("headers", {})
        req_body = candidate.get("body", None)

        headers_a = self._build_identity_headers("A", req_headers)
        headers_b = self._build_identity_headers("B", req_headers)
        headers_anon = self._build_identity_headers("ANON", req_headers)

        # Baseline request with Identity A (Admin)
        resp_a = self._send_replay_request(url, method=method, headers=headers_a, data=req_body)
        if resp_a.status < 200 or resp_a.status >= 300:
            return None

        # Replay with Identity B (Standard non-admin user)
        resp_b = self._send_replay_request(url, method=method, headers=headers_b, data=req_body)

        # Replay with Anonymous
        resp_anon = self._send_replay_request(url, method=method, headers=headers_anon, data=req_body)

        is_vuln, classification, confidence, severity = evaluate_bfla_response(
            resp_a=resp_a,
            resp_b=resp_b,
            resp_anon=resp_anon,
        )

        if not is_vuln:
            return None

        # Construct reproduction PoC using Identity B headers
        b_auth_headers = {}
        if headers_b.get("Cookie"):
            b_auth_headers["Cookie"] = headers_b["Cookie"]
        if headers_b.get("Authorization"):
            b_auth_headers["Authorization"] = headers_b["Authorization"]
        poc_curl = generate_poc_curl(url, method=method, headers=b_auth_headers, data=req_body)

        proof = self._package_proof(
            vuln_type="BFLA",
            classification=classification,
            url=url,
            method=method,
            headers_a=headers_a,
            headers_b=headers_b,
            resp_a=resp_a,
            resp_b=resp_b,
            resp_anon=resp_anon,
            marker_a="",
            poc_curl=poc_curl,
        )

        parsed_path = urlparse(url).path
        sim_pct = round(compute_body_similarity(resp_a.body, resp_b.body) * 100, 1)

        evidence_lines = [
            f"Baseline [Identity A Admin]: HTTP {resp_a.status} OK (Length: {len(resp_a.body)})",
            f"Replay   [Identity B User]:  HTTP {resp_b.status} OK (Length: {len(resp_b.body)}, Similarity: {sim_pct}%)",
            f"Anonymous:                   HTTP {resp_anon.status}",
        ]

        title = f"Broken Function Level Authorization (BFLA): {parsed_path} Accessible by Standard User"
        description = (
            f"Dual-identity differential replay identified Broken Function Level Authorization on administrative endpoint {url}. "
            f"Identity B (standard non-admin user) received HTTP {resp_b.status} OK with administrative data."
        )

        return Finding(
            severity=severity,
            category="bfla",
            title=title,
            description=description,
            evidence="\n".join(evidence_lines),
            url=url,
            confidence=confidence.value,
            remediation=(
                "Enforce strict role-based access control (RBAC) on all administrative routes, validating that "
                "the calling user's authenticated session possesses the required administrative privilege."
            ),
            metadata={
                "proof": proof,
                "proof_attached": (confidence == Confidence.VERIFIED),
                "poc_curl": poc_curl,
                "cwe": "CWE-285",
                "owasp": "API5:2023 - Broken Function Level Authorization",
                "method": method,
                "classification": classification,
            },
        )

    # -----------------------------------------------------------------------
    # Scan Orchestration
    # -----------------------------------------------------------------------

    def scan(self) -> ScanResult:
        """Execute the dual-identity differential scan across candidate endpoints."""
        start_time = time.time()
        self._log("Initializing dual-identity differential scan")

        cfg = self._get_identity_configs()
        has_id_b = bool(cfg["b_cookie"] or cfg["b_token"])

        # Gather all target candidates from report requests, files, pages, and settings
        captured = getattr(self._report, "captured_requests", []) or []
        files = getattr(self._report, "files", []) or []
        pages = getattr(self._report, "pages", []) or []

        all_items: List[Any] = list(captured)
        for f in files:
            u = getattr(f, "url", "")
            if u:
                all_items.append({"url": u, "method": "GET"})
        for p in pages:
            if isinstance(p, str) and p:
                all_items.append({"url": p, "method": "GET"})

        target_url = self._get_target_url()
        if target_url:
            all_items.append({"url": target_url, "method": "GET"})

        for mt in getattr(self._settings, "multi_targets", []) or []:
            if mt:
                all_items.append({"url": mt, "method": "GET"})

        # Extract candidates
        bola_candidates = extract_object_id_candidates(all_items)
        bfla_candidates = extract_admin_route_candidates(all_items)

        self._log(f"Extracted {len(bola_candidates)} BOLA candidates and {len(bfla_candidates)} BFLA candidates")

        # Test BOLA candidates
        for cand in bola_candidates:
            try:
                finding = self._test_candidate_bola(cand, cfg)
                if finding:
                    self._add_finding(finding)
            except Exception as e:
                self._log(f"Error testing BOLA on {cand.get('url', '')}: {e}")

        # Test BFLA candidates
        for cand in bfla_candidates:
            try:
                finding = self._test_candidate_bfla(cand, cfg)
                if finding:
                    self._add_finding(finding)
            except Exception as e:
                self._log(f"Error testing BFLA on {cand.get('url', '')}: {e}")

        verified_count = sum(1 for f in self._findings if f.confidence == "VERIFIED")
        self._log(f"Dual-identity scan complete: {len(self._findings)} findings ({verified_count} VERIFIED)")

        return self._build_result(
            start_time,
            bola_candidates_count=len(bola_candidates),
            bfla_candidates_count=len(bfla_candidates),
            dual_identity_configured=has_id_b,
        )

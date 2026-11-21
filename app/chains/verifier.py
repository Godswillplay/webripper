"""
WebRipper Recon 5.0 — Validated Attack Chains (Phase 4).

Non-destructive read-only step verification for correlated attack chains
produced by `app/correlator.py`. Governed by the strict weakest-link rule:
    Confidence(Chain) = min_{s}(Confidence(s))

Architectural Invariants:
1. Strict Non-Destructive Operation: Probes are strictly read-only (GET/HEAD or
   read-only introspection). Never execute state changes, injections, or brute force.
2. Weakest-Link Rule:
   Chain confidence = min(step confidences).
   If all steps are VERIFIED, chain confidence is VERIFIED.
   If any step is unverified or cannot be actively proven without destructive actions,
   chain confidence stays POSSIBLE or LIKELY and is marked hypothetical:
   `chain.metadata["hypothetical"] = True`
"""

from __future__ import annotations

import difflib
import json
import math
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urljoin, urlparse

from app.models import AttackChain, AttackChainStep, Confidence, Finding, Severity


# ---------------------------------------------------------------------------
# Confidence Weight Mapping (Weakest-Link Evaluation)
# ---------------------------------------------------------------------------

_CONFIDENCE_WEIGHT: Dict[Any, int] = {
    Confidence.VERIFIED: 3,
    Confidence.LIKELY: 2,
    Confidence.POSSIBLE: 1,
    Confidence.INFO: 0,
    "VERIFIED": 3,
    "LIKELY": 2,
    "POSSIBLE": 1,
    "INFO": 0,
}

_WEIGHT_TO_CONFIDENCE: Dict[int, Confidence] = {
    3: Confidence.VERIFIED,
    2: Confidence.LIKELY,
    1: Confidence.POSSIBLE,
    0: Confidence.INFO,
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
    "fake",
    "xxxxxx",
)

_SERVICE_PATTERNS = {
    "aws_access_key": re.compile(r"^AKIA[0-9A-Z]{16}$"),
    "github_token": re.compile(r"^gh[pousr]_[A-Za-z0-9_]{36,}$"),
    "slack_token": re.compile(r"^xox[baprs]-[0-9A-Za-z-]{10,}$"),
    "jwt": re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"),
}


def normalize_confidence(val: Any) -> Confidence:
    """Normalize any confidence representation to a Confidence enum."""
    if isinstance(val, Confidence):
        return val
    if isinstance(val, str):
        val_upper = val.strip().upper()
        if val_upper in Confidence.__members__:
            return Confidence[val_upper]
    return Confidence.POSSIBLE


def compute_chain_confidence(chain: AttackChain) -> Tuple[Confidence, bool]:
    """
    Compute chain confidence using the weakest-link rule.
    Returns (composite_confidence, is_verified).
    """
    if not chain.steps:
        return Confidence.POSSIBLE, False

    def _step_conf(step: AttackChainStep) -> int:
        f = step.finding
        if f is not None and hasattr(f, "confidence") and f.confidence is not None:
            c = f.confidence
            return _CONFIDENCE_WEIGHT.get(c, _CONFIDENCE_WEIGHT.get(str(c).upper(), 1))
        if hasattr(step, "confidence") and step.confidence is not None:
            c = step.confidence
            return _CONFIDENCE_WEIGHT.get(c, _CONFIDENCE_WEIGHT.get(str(c).upper(), 1))
        return 1

    min_weight = min(_step_conf(step) for step in chain.steps)
    chain_confidence = _WEIGHT_TO_CONFIDENCE.get(min_weight, Confidence.POSSIBLE)
    is_fully_verified = (chain_confidence == Confidence.VERIFIED)
    return chain_confidence, is_fully_verified


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class StepVerificationResult:
    """Detailed verification outcome for an individual step."""
    step_index: int
    step_description: str
    confidence: Confidence
    is_verified: bool
    reason: str
    probe_url: str = ""
    status_code: int = 0
    probe_details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "step_index": self.step_index,
            "step_description": self.step_description,
            "confidence": self.confidence.value,
            "is_verified": self.is_verified,
            "reason": self.reason,
            "probe_url": self.probe_url,
            "status_code": self.status_code,
            "probe_details": self.probe_details,
        }


@dataclass
class ChainVerificationResult:
    """Detailed verification outcome for an entire attack chain."""
    chain_name: str
    confidence: Confidence
    is_verified: bool
    hypothetical: bool
    step_results: List[StepVerificationResult] = field(default_factory=list)
    weakest_link_index: Optional[int] = None
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "chain_name": self.chain_name,
            "confidence": self.confidence.value,
            "is_verified": self.is_verified,
            "hypothetical": self.hypothetical,
            "weakest_link_index": self.weakest_link_index,
            "summary": self.summary,
            "steps": [s.to_dict() for s in self.step_results],
        }


# ---------------------------------------------------------------------------
# HTTP Response Helper
# ---------------------------------------------------------------------------

@dataclass
class _ProbeResponse:
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    error: str = ""


# ---------------------------------------------------------------------------
# Chain Verifier Engine
# ---------------------------------------------------------------------------

class ChainVerifier:
    """
    Non-destructive read-only step verification engine for correlated attack chains.
    Enforces the weakest-link rule to separate proven attack paths from hypothetical chains.
    """

    def __init__(
        self,
        base_url: str = "",
        timeout: float = 2.5,
        custom_headers: Optional[Dict[str, str]] = None,
        verify_ssl: bool = False,
        proxy: str = "",
    ):
        self.base_url = (base_url or "").rstrip("/")
        self.timeout = timeout
        self.custom_headers = custom_headers or {}
        self.verify_ssl = verify_ssl
        self.proxy = proxy

        self._ssl_ctx = ssl.create_default_context()
        if not self.verify_ssl:
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode = ssl.CERT_NONE

    # -----------------------------------------------------------------------
    # Low-level Network Probing (Strictly Read-Only)
    # -----------------------------------------------------------------------

    def send_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Union[str, bytes]] = None,
    ) -> _ProbeResponse:
        """Execute a safe, non-destructive HTTP request."""
        # Safety invariant: Only safe/read-only HTTP methods are permitted
        safe_method = method.upper()
        if safe_method not in ("GET", "HEAD", "OPTIONS", "POST"):
            safe_method = "GET"

        req_headers = {
            "User-Agent": "WebRipper-ChainVerifier/5.0 (Security Audit Canary)",
            "Accept": "*/*",
        }
        if self.custom_headers:
            req_headers.update(self.custom_headers)
        if headers:
            req_headers.update(headers)

        body_bytes: Optional[bytes] = None
        if data is not None:
            if isinstance(data, str):
                body_bytes = data.encode("utf-8")
            elif isinstance(data, bytes):
                body_bytes = data

        handlers: List[Any] = [urllib.request.HTTPSHandler(context=self._ssl_ctx)]
        if self.proxy:
            handlers.append(urllib.request.ProxyHandler({"http": self.proxy, "https": self.proxy}))

        opener = urllib.request.build_opener(*handlers)
        req = urllib.request.Request(url, data=body_bytes, headers=req_headers, method=safe_method)

        resp_obj = _ProbeResponse()
        try:
            with opener.open(req, timeout=self.timeout) as resp:
                resp_obj.status = resp.status
                resp_obj.headers = {k.lower(): v for k, v in resp.headers.items()}
                raw_body = resp.read()
                resp_obj.body = raw_body.decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as he:
            resp_obj.status = he.code
            try:
                resp_obj.headers = {k.lower(): v for k, v in he.headers.items()}
                raw_body = he.read()
                resp_obj.body = raw_body.decode("utf-8", errors="ignore")
            except Exception:
                pass
            resp_obj.error = f"HTTPError {he.code}"
        except (urllib.error.URLError, socket.timeout, ConnectionError, OSError) as ue:
            resp_obj.error = str(ue)
        except Exception as ex:
            resp_obj.error = str(ex)

        return resp_obj

    def check_port_open(self, host: str, port: int, timeout: float = 2.0) -> Tuple[bool, str]:
        """Perform a non-blocking TCP socket handshake and safe banner read."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            banner = ""
            sock.settimeout(0.5)
            try:
                raw = sock.recv(1024)
                banner = raw.decode("utf-8", errors="ignore").strip()
            except (socket.timeout, OSError):
                pass
            return True, banner
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            return False, str(e)
        finally:
            try:
                sock.close()
            except Exception:
                pass

    # -----------------------------------------------------------------------
    # Chain Verification Pipeline
    # -----------------------------------------------------------------------

    def verify_chains(self, chains: List[AttackChain]) -> List[AttackChain]:
        """
        Verify a list of proposed attack chains.
        Mutates each chain in-place with its verified confidence and metadata,
        and returns the list of chains.
        """
        for chain in chains:
            self.verify_chain(chain)
        return chains

    def verify_chain(self, chain: AttackChain) -> ChainVerificationResult:
        """
        Perform active step verification for a single composite attack chain.
        Enforces the weakest-link rule to compute final chain confidence.
        """
        if not hasattr(chain, "metadata") or chain.metadata is None:
            chain.metadata = {}

        # 1. Build chain context by discovering endpoints and credentials across steps
        chain_context: Dict[str, Any] = {
            "base_url": self.base_url,
            "candidate_endpoints": [],
            "candidate_tokens": [],
            "verified_tokens": [],
            "step_results": [],
        }

        # Pre-scan steps to extract targets and candidate credentials
        for step in chain.steps:
            f = step.finding
            if f:
                if f.url and self._is_candidate_auth_endpoint(f.url, f):
                    if f.url not in chain_context["candidate_endpoints"]:
                        chain_context["candidate_endpoints"].append(f.url)
                if f.metadata and isinstance(f.metadata, dict):
                    for k in ("secret", "token", "credential", "api_key", "password"):
                        v = f.metadata.get(k)
                        if v and isinstance(v, str) and v not in chain_context["candidate_tokens"]:
                            chain_context["candidate_tokens"].append(v)
                # Look for token inside evidence
                if f.evidence:
                    extracted = self._extract_secrets_from_text(f.evidence)
                    for tok in extracted:
                        if tok not in chain_context["candidate_tokens"]:
                            chain_context["candidate_tokens"].append(tok)

        # 2. Verify each step in order
        step_results: List[StepVerificationResult] = []
        for idx, step in enumerate(chain.steps):
            step_res = self.verify_step(step, chain_context, step_idx=idx)
            step_results.append(step_res)

            # Update step confidence in-place
            step.confidence = step_res.confidence.value if hasattr(step_res.confidence, "value") else str(step_res.confidence)
            if step.finding:
                step.finding.confidence = step_res.confidence.value if hasattr(step_res.confidence, "value") else str(step_res.confidence)
                if not hasattr(step.finding, "metadata") or step.finding.metadata is None:
                    step.finding.metadata = {}
                step.finding.metadata["verification"] = step_res.to_dict()

        # 3. Apply Weakest-Link Rule:
        # Confidence(Chain) = min_{s}(Confidence(s))
        if not step_results:
            chain_confidence = Confidence.POSSIBLE
            is_verified = False
            weakest_idx: Optional[int] = None
        else:
            min_weight = 3  # Start at max weight (VERIFIED)
            weakest_idx = 0
            for idx, res in enumerate(step_results):
                w = _CONFIDENCE_WEIGHT.get(res.confidence, 1)
                if w < min_weight:
                    min_weight = w
                    weakest_idx = idx

            chain_confidence = _WEIGHT_TO_CONFIDENCE.get(min_weight, Confidence.POSSIBLE)
            is_verified = (chain_confidence == Confidence.VERIFIED)

        chain.confidence = chain_confidence.value if hasattr(chain_confidence, "value") else str(chain_confidence)

        if is_verified:
            chain.metadata["status"] = "VERIFIED"
            chain.metadata["hypothetical"] = False
            chain.metadata["weakest_link_step"] = None
            summary = f"Chain fully VERIFIED across all {len(step_results)} steps."
        else:
            chain.metadata["status"] = "HYPOTHETICAL"
            chain.metadata["hypothetical"] = True
            chain.metadata["weakest_link_step"] = weakest_idx
            weak_desc = step_results[weakest_idx].step_description if weakest_idx is not None else "unknown"
            summary = (
                f"Chain is HYPOTHETICAL ({chain_confidence.value}) due to weakest link at "
                f"step {weakest_idx}: {weak_desc}"
            )

        chain.metadata["verification"] = {
            "confidence": chain_confidence.value,
            "is_verified": is_verified,
            "hypothetical": not is_verified,
            "weakest_link_step": weakest_idx if not is_verified else None,
            "summary": summary,
            "steps": [s.to_dict() for s in step_results],
        }

        return ChainVerificationResult(
            chain_name=chain.name,
            confidence=chain_confidence,
            is_verified=is_verified,
            hypothetical=not is_verified,
            step_results=step_results,
            weakest_link_index=weakest_idx if not is_verified else None,
            summary=summary,
        )

    # -----------------------------------------------------------------------
    # Individual Step Verification Dispatcher
    # -----------------------------------------------------------------------

    def verify_step(
        self,
        step: AttackChainStep,
        chain_context: Dict[str, Any],
        step_idx: int = 0,
    ) -> StepVerificationResult:
        """
        Verify a single step non-destructively based on its characteristics.
        """
        f = step.finding
        cat = (f.category if f else step.source or "").lower()
        desc = step.description or ""
        desc_lower = desc.lower()
        title_lower = (f.title if f else "").lower()

        # Category-first deterministic matching
        if cat == "cors" or "cors" in desc_lower:
            return self._verify_cors(step, chain_context, step_idx)

        if cat in ("portscan", "nmap"):
            return self._verify_port(step, chain_context, step_idx)

        if cat == "secrets":
            return self._verify_credential(step, chain_context, step_idx)

        if cat in ("endpoints", "api"):
            return self._verify_authenticated_endpoint(step, chain_context, step_idx)

        if cat in ("paths", "exposed_files"):
            if any(k in desc_lower or k in title_lower for k in ("admin", "api route", "protected endpoint", "/api/")):
                return self._verify_authenticated_endpoint(step, chain_context, step_idx)
            return self._verify_source_leak(step, chain_context, step_idx)

        if cat in ("headers", "cookies"):
            return self._verify_headers_cookies(step, chain_context, step_idx)

        # Keyword matching fallback
        if ".git" in desc_lower or ".git" in title_lower or ".env" in desc_lower or "actuator" in desc_lower or "source map" in desc_lower:
            return self._verify_source_leak(step, chain_context, step_idx)

        if "graphql" in desc_lower or "introspection" in desc_lower:
            return self._verify_graphql(step, chain_context, step_idx)

        if "port" in desc_lower:
            return self._verify_port(step, chain_context, step_idx)

        if any(k in desc_lower for k in ("admin", "protected", "api route", "authenticated endpoint", "endpoint")):
            return self._verify_authenticated_endpoint(step, chain_context, step_idx)

        if any(k in desc_lower for k in ("credential", "token", "secret", "password", "api key")):
            return self._verify_credential(step, chain_context, step_idx)

        # Destructive or unprovable step
        return self._verify_general_step(step, chain_context, step_idx)

    # -----------------------------------------------------------------------
    # Step-Specific Verifiers
    # -----------------------------------------------------------------------

    def _resolve_url(self, step: AttackChainStep, default_path: str = "") -> str:
        """Resolve full target URL for a step."""
        f = step.finding
        url = ""
        if f and f.url:
            url = f.url
        elif default_path:
            url = default_path

        if not url and self.base_url and default_path:
            return urljoin(self.base_url + "/", default_path.lstrip("/"))

        if url.startswith("http://") or url.startswith("https://"):
            return url
        elif self.base_url:
            return urljoin(self.base_url + "/", url.lstrip("/"))
        return url

    @staticmethod
    def _is_candidate_auth_endpoint(url: str, finding: Optional[Finding] = None) -> bool:
        """Filter URLs to identify realistic candidate authentication / API endpoints."""
        if not url:
            return False
        url_lower = url.lower()
        if any(ignore in url_lower for ignore in (".git", ".env", ".map", "health", "metrics", "favicon")):
            return False
        if finding and finding.category in ("endpoints", "api"):
            return True
        return any(p in url_lower for p in ("api", "admin", "user", "protect", "auth", "profile", "v1", "v2", "account", "dashboard"))

    def _verify_source_leak(
        self,
        step: AttackChainStep,
        chain_context: Dict[str, Any],
        step_idx: int,
    ) -> StepVerificationResult:
        """Non-destructively verify exposed repository, environment, or actuator endpoints."""
        desc_lower = (step.description or "").lower()
        title_lower = (step.finding.title if step.finding else "").lower()

        # 1. Exposed .git
        if ".git" in desc_lower or ".git" in title_lower:
            target_url = self._resolve_url(step, default_path="/.git/HEAD")
            if not target_url.endswith("/HEAD") and not target_url.endswith("/HEAD/"):
                target_url = target_url.rstrip("/") + "/HEAD"

            resp = self.send_request(target_url, method="GET")
            body_clean = resp.body.strip()
            # Canonical .git/HEAD patterns
            is_git_head = body_clean.startswith("ref: refs/") or bool(re.match(r"^[0-9a-f]{40}$", body_clean))

            if resp.status == 200 and is_git_head:
                return StepVerificationResult(
                    step_index=step_idx,
                    step_description=step.description,
                    confidence=Confidence.VERIFIED,
                    is_verified=True,
                    reason=f"Exposed .git/HEAD confirmed readable: {body_clean[:60]}",
                    probe_url=target_url,
                    status_code=resp.status,
                    probe_details={"head_content": body_clean[:100]},
                )
            return StepVerificationResult(
                step_index=step_idx,
                step_description=step.description,
                confidence=Confidence.POSSIBLE,
                is_verified=False,
                reason=f"Exposed .git probe failed: HTTP {resp.status} ({resp.error or 'invalid git HEAD signature'})",
                probe_url=target_url,
                status_code=resp.status,
            )

        # 2. Exposed .env file
        if ".env" in desc_lower or ".env" in title_lower:
            target_url = self._resolve_url(step, default_path="/.env")
            resp = self.send_request(target_url, method="GET")
            if resp.status == 200:
                lines = [ln.strip() for ln in resp.body.splitlines() if ln.strip() and not ln.startswith("#")]
                env_keys = [ln for ln in lines if re.match(r"^[A-Za-z0-9_]+\s*=", ln)]
                if len(env_keys) >= 1:
                    # Also extract tokens into chain_context
                    extracted = self._extract_secrets_from_text(resp.body)
                    for tok in extracted:
                        if tok not in chain_context["candidate_tokens"]:
                            chain_context["candidate_tokens"].append(tok)

                    return StepVerificationResult(
                        step_index=step_idx,
                        step_description=step.description,
                        confidence=Confidence.VERIFIED,
                        is_verified=True,
                        reason=f"Exposed .env confirmed: {len(env_keys)} environment variables found",
                        probe_url=target_url,
                        status_code=resp.status,
                        probe_details={"keys_found": len(env_keys)},
                    )
            return StepVerificationResult(
                step_index=step_idx,
                step_description=step.description,
                confidence=Confidence.POSSIBLE,
                is_verified=False,
                reason=f"Exposed .env probe failed: HTTP {resp.status} ({resp.error or 'no valid env keys'})",
                probe_url=target_url,
                status_code=resp.status,
            )

        # 3. Spring Boot Actuator
        if "actuator" in desc_lower or "actuator" in title_lower:
            target_url = self._resolve_url(step, default_path="/actuator/health")
            resp = self.send_request(target_url, method="GET")
            if resp.status == 200 and any(k in resp.body for k in ('"status"', '"UP"', '"propertySources"')):
                return StepVerificationResult(
                    step_index=step_idx,
                    step_description=step.description,
                    confidence=Confidence.VERIFIED,
                    is_verified=True,
                    reason="Spring Boot Actuator endpoint verified active",
                    probe_url=target_url,
                    status_code=resp.status,
                )
            return StepVerificationResult(
                step_index=step_idx,
                step_description=step.description,
                confidence=Confidence.POSSIBLE,
                is_verified=False,
                reason=f"Actuator probe returned HTTP {resp.status}",
                probe_url=target_url,
                status_code=resp.status,
            )

        # Generic path probe
        target_url = self._resolve_url(step)
        if target_url:
            resp = self.send_request(target_url, method="GET")
            if resp.status == 200:
                return StepVerificationResult(
                    step_index=step_idx,
                    step_description=step.description,
                    confidence=Confidence.VERIFIED,
                    is_verified=True,
                    reason=f"Sensitive path accessible: HTTP 200 ({len(resp.body)} bytes)",
                    probe_url=target_url,
                    status_code=resp.status,
                )

        return StepVerificationResult(
            step_index=step_idx,
            step_description=step.description,
            confidence=Confidence.POSSIBLE,
            is_verified=False,
            reason="Path could not be confirmed accessible",
            probe_url=target_url,
        )

    def _verify_credential(
        self,
        step: AttackChainStep,
        chain_context: Dict[str, Any],
        step_idx: int,
    ) -> StepVerificationResult:
        """
        Verify discovered credentials.
        Extracts token candidates, validates format/entropy, and performs safe read-only
        canary probe against known or candidate authenticated endpoints.
        """
        f = step.finding
        extracted_tokens: List[str] = []

        # Extract from finding metadata
        if f and f.metadata and isinstance(f.metadata, dict):
            for k in ("secret", "token", "credential", "api_key", "password"):
                val = f.metadata.get(k)
                if val and isinstance(val, str):
                    extracted_tokens.append(val)

        # Extract from finding evidence
        if f and f.evidence:
            extracted_tokens.extend(self._extract_secrets_from_text(f.evidence))

        # Check candidate tokens in chain context
        extracted_tokens.extend(chain_context.get("candidate_tokens", []))

        # Filter out obvious documentation bait and duplicates
        clean_tokens = [tok for tok in dict.fromkeys(extracted_tokens) if not self._is_bait(tok)]

        if not clean_tokens:
            return StepVerificationResult(
                step_index=step_idx,
                step_description=step.description,
                confidence=Confidence.POSSIBLE,
                is_verified=False,
                reason="No verifiable credential token found or token matches placeholder bait",
            )

        # Test token against candidate authenticated endpoints if available
        all_candidate_endpoints = chain_context.get("candidate_endpoints", [])
        candidate_endpoints = [
            ep for ep in all_candidate_endpoints
            if ep and not any(ext in ep.lower() for ext in (".git", ".env", ".bak", ".map", ".sql", ".dump"))
        ]
        for tok in clean_tokens:
            for ep in candidate_endpoints:
                if not ep:
                    continue
                # Safe read-only canary request
                probe_resp = self.send_request(
                    ep,
                    method="GET",
                    headers={"Authorization": f"Bearer {tok}"},
                )
                if probe_resp.status == 200:
                    # Confirmed functional credential!
                    if tok not in chain_context["verified_tokens"]:
                        chain_context["verified_tokens"].append(tok)
                    return StepVerificationResult(
                        step_index=step_idx,
                        step_description=step.description,
                        confidence=Confidence.VERIFIED,
                        is_verified=True,
                        reason=f"Credential actively verified against {ep} (HTTP 200)",
                        probe_url=ep,
                        status_code=probe_resp.status,
                        probe_details={"token_length": len(tok)},
                    )

        # If no endpoint was probeable, test against recognized service formats
        for tok in clean_tokens:
            for s_name, pat in _SERVICE_PATTERNS.items():
                if pat.search(tok):
                    if tok not in chain_context["verified_tokens"]:
                        chain_context["verified_tokens"].append(tok)
                    return StepVerificationResult(
                        step_index=step_idx,
                        step_description=step.description,
                        confidence=Confidence.VERIFIED,
                        is_verified=True,
                        reason=f"Credential matches recognized high-confidence format: {s_name}",
                        probe_details={"service": s_name, "token_prefix": tok[:6]},
                    )

        # If high entropy and reasonable length, classify as LIKELY but not verified without active probe
        best_entropy = max(self._compute_entropy(tok) for tok in clean_tokens)
        if best_entropy >= 3.0:
            return StepVerificationResult(
                step_index=step_idx,
                step_description=step.description,
                confidence=Confidence.LIKELY,
                is_verified=False,
                reason=f"Credential has high Shannon entropy ({best_entropy:.2f} bits/char) but lacked active verification endpoint",
                probe_details={"entropy": best_entropy},
            )

        return StepVerificationResult(
            step_index=step_idx,
            step_description=step.description,
            confidence=Confidence.POSSIBLE,
            is_verified=False,
            reason="Credential format could not be verified against an active service or pattern",
        )

    def _verify_authenticated_endpoint(
        self,
        step: AttackChainStep,
        chain_context: Dict[str, Any],
        step_idx: int,
    ) -> StepVerificationResult:
        """
        Non-destructively probe an authenticated endpoint using credentials from prior steps.
        Compares authenticated request with unauthenticated baseline.
        """
        target_url = self._resolve_url(step)
        if not target_url:
            return StepVerificationResult(
                step_index=step_idx,
                step_description=step.description,
                confidence=Confidence.POSSIBLE,
                is_verified=False,
                reason="No target URL found for authenticated endpoint",
            )

        # Find best credential token
        token = ""
        if chain_context.get("verified_tokens"):
            token = chain_context["verified_tokens"][0]
        elif chain_context.get("candidate_tokens"):
            clean = [t for t in chain_context["candidate_tokens"] if not self._is_bait(t)]
            if clean:
                token = clean[0]

        headers: Dict[str, str] = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        # 1. Baseline unauthenticated request
        baseline_resp = self.send_request(target_url, method="GET")

        # 2. Authenticated probe request
        auth_resp = self.send_request(target_url, method="GET", headers=headers)

        if auth_resp.status == 200:
            is_auth_enforced = baseline_resp.status in (401, 403)
            return StepVerificationResult(
                step_index=step_idx,
                step_description=step.description,
                confidence=Confidence.VERIFIED,
                is_verified=True,
                reason=(
                    f"Authenticated access confirmed: HTTP 200 OK"
                    + (" (Unauthenticated baseline: HTTP 401/403)" if is_auth_enforced else "")
                ),
                probe_url=target_url,
                status_code=auth_resp.status,
                probe_details={
                    "baseline_status": baseline_resp.status,
                    "authenticated_status": auth_resp.status,
                },
            )
        elif auth_resp.status in (401, 403):
            return StepVerificationResult(
                step_index=step_idx,
                step_description=step.description,
                confidence=Confidence.POSSIBLE,
                is_verified=False,
                reason=f"Access denied: endpoint returned HTTP {auth_resp.status} with provided credentials",
                probe_url=target_url,
                status_code=auth_resp.status,
            )

        return StepVerificationResult(
            step_index=step_idx,
            step_description=step.description,
            confidence=Confidence.POSSIBLE,
            is_verified=False,
            reason=f"Endpoint probe returned HTTP {auth_resp.status} ({auth_resp.error or 'unreachable'})",
            probe_url=target_url,
            status_code=auth_resp.status,
        )

    def _verify_cors(
        self,
        step: AttackChainStep,
        chain_context: Dict[str, Any],
        step_idx: int,
    ) -> StepVerificationResult:
        """Active CORS verification with canary origin reflection and credentials check."""
        target_url = self._resolve_url(step)
        if not target_url and self.base_url:
            target_url = self.base_url

        canary_origin = "https://evil-webripper-canary.com"
        resp = self.send_request(target_url, method="GET", headers={"Origin": canary_origin})

        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "").lower() == "true"

        reflects = (acao == canary_origin or acao == "*")
        if reflects and acac:
            return StepVerificationResult(
                step_index=step_idx,
                step_description=step.description,
                confidence=Confidence.VERIFIED,
                is_verified=True,
                reason=f"CORS arbitrary origin reflection with credentials verified: Origin={acao}",
                probe_url=target_url,
                status_code=resp.status,
                probe_details={"acao": acao, "acac": acac},
            )
        elif reflects:
            return StepVerificationResult(
                step_index=step_idx,
                step_description=step.description,
                confidence=Confidence.LIKELY,
                is_verified=False,
                reason=f"CORS reflects origin {acao} but Access-Control-Allow-Credentials is missing",
                probe_url=target_url,
                status_code=resp.status,
            )

        return StepVerificationResult(
            step_index=step_idx,
            step_description=step.description,
            confidence=Confidence.POSSIBLE,
            is_verified=False,
            reason="CORS origin reflection not observed on target endpoint",
            probe_url=target_url,
            status_code=resp.status,
        )

    def _verify_port(
        self,
        step: AttackChainStep,
        chain_context: Dict[str, Any],
        step_idx: int,
    ) -> StepVerificationResult:
        """Non-destructive TCP socket connect to confirm open service port."""
        f = step.finding
        host = ""
        port = 0

        # 1. Try explicit metadata
        if f and f.metadata and isinstance(f.metadata, dict) and "port" in f.metadata:
            try:
                port = int(f.metadata["port"])
            except (ValueError, TypeError):
                pass

        # 2. Try regex extraction
        if not port:
            text = f"{step.description} {f.title if f else ''} {f.evidence if f else ''}"
            port_match = re.search(r"(?:port\s*[:=]?\s*|:\s*)(\d{2,5})\b", text, re.IGNORECASE)
            if port_match:
                port = int(port_match.group(1))
            else:
                common_match = re.search(r"\b(3306|5432|27017|6379|22|21|23|8080|8443|9200)\b", text)
                if common_match:
                    port = int(common_match.group(1))

        # Extract host
        target_url = self._resolve_url(step)
        if target_url:
            parsed = urlparse(target_url)
            host = parsed.hostname or ""
            if not port and parsed.port:
                port = parsed.port
        if not host and self.base_url:
            host = urlparse(self.base_url).hostname or ""

        if not host:
            host = "127.0.0.1"

        if not port:
            # Default to checking if finding was already verified
            if f and normalize_confidence(f.confidence) == Confidence.VERIFIED:
                return StepVerificationResult(
                    step_index=step_idx,
                    step_description=step.description,
                    confidence=Confidence.VERIFIED,
                    is_verified=True,
                    reason="Port service previously verified by port scanner",
                )
            return StepVerificationResult(
                step_index=step_idx,
                step_description=step.description,
                confidence=Confidence.POSSIBLE,
                is_verified=False,
                reason="Could not determine target host/port for socket verification",
            )

        is_open, banner = self.check_port_open(host, port, timeout=2.0)
        if is_open:
            return StepVerificationResult(
                step_index=step_idx,
                step_description=step.description,
                confidence=Confidence.VERIFIED,
                is_verified=True,
                reason=f"TCP handshake confirmed open on {host}:{port}" + (f" (Banner: {banner[:40]})" if banner else ""),
                probe_details={"host": host, "port": port, "banner": banner[:100]},
            )

        return StepVerificationResult(
            step_index=step_idx,
            step_description=step.description,
            confidence=Confidence.POSSIBLE,
            is_verified=False,
            reason=f"TCP port {port} on {host} unreachable or firewalled",
            probe_details={"host": host, "port": port, "error": banner},
        )

    def _verify_graphql(
        self,
        step: AttackChainStep,
        chain_context: Dict[str, Any],
        step_idx: int,
    ) -> StepVerificationResult:
        """Non-destructive GraphQL schema introspection verification."""
        target_url = self._resolve_url(step, default_path="/graphql")
        query_payload = json.dumps({"query": "query{__schema{queryType{name}}}"}).encode("utf-8")
        resp = self.send_request(
            target_url,
            method="POST",
            headers={"Content-Type": "application/json"},
            data=query_payload,
        )

        if resp.status == 200 and "__schema" in resp.body:
            return StepVerificationResult(
                step_index=step_idx,
                step_description=step.description,
                confidence=Confidence.VERIFIED,
                is_verified=True,
                reason="GraphQL schema introspection query confirmed active",
                probe_url=target_url,
                status_code=resp.status,
            )

        return StepVerificationResult(
            step_index=step_idx,
            step_description=step.description,
            confidence=Confidence.POSSIBLE,
            is_verified=False,
            reason=f"GraphQL introspection failed (HTTP {resp.status})",
            probe_url=target_url,
            status_code=resp.status,
        )

    def _verify_headers_cookies(
        self,
        step: AttackChainStep,
        chain_context: Dict[str, Any],
        step_idx: int,
    ) -> StepVerificationResult:
        """Verify missing security headers or insecure cookies."""
        target_url = self._resolve_url(step) or self.base_url
        resp = self.send_request(target_url, method="GET")

        desc_lower = (step.description or "").lower()
        if "content-security-policy" in desc_lower or "csp" in desc_lower:
            has_csp = "content-security-policy" in resp.headers
            if not has_csp:
                return StepVerificationResult(
                    step_index=step_idx,
                    step_description=step.description,
                    confidence=Confidence.VERIFIED,
                    is_verified=True,
                    reason="Absence of Content-Security-Policy header confirmed in live response",
                    probe_url=target_url,
                    status_code=resp.status,
                )

        if "httponly" in desc_lower or "cookie" in desc_lower:
            set_cookie = resp.headers.get("set-cookie", "").lower()
            if set_cookie and "httponly" not in set_cookie:
                return StepVerificationResult(
                    step_index=step_idx,
                    step_description=step.description,
                    confidence=Confidence.VERIFIED,
                    is_verified=True,
                    reason="Cookie set without HttpOnly flag confirmed in live response",
                    probe_url=target_url,
                    status_code=resp.status,
                )

        # If underlying finding was verified, inherit verification
        if step.finding and normalize_confidence(step.finding.confidence) == Confidence.VERIFIED:
            return StepVerificationResult(
                step_index=step_idx,
                step_description=step.description,
                confidence=Confidence.VERIFIED,
                is_verified=True,
                reason="Verified from static/passive scanner evidence",
                probe_url=target_url,
                status_code=resp.status,
            )

        return StepVerificationResult(
            step_index=step_idx,
            step_description=step.description,
            confidence=Confidence.POSSIBLE,
            is_verified=False,
            reason="Header / cookie check unconfirmed",
            probe_url=target_url,
            status_code=resp.status,
        )

    def _verify_general_step(
        self,
        step: AttackChainStep,
        chain_context: Dict[str, Any],
        step_idx: int,
    ) -> StepVerificationResult:
        """
        Handle steps that cannot be actively tested without destructive actions,
        or steps inheriting verified findings.
        """
        f = step.finding
        if f and normalize_confidence(f.confidence) == Confidence.VERIFIED:
            return StepVerificationResult(
                step_index=step_idx,
                step_description=step.description,
                confidence=Confidence.VERIFIED,
                is_verified=True,
                reason=f"Step verified by scanner finding ({f.title})",
            )

        # Destructive action / unverified step: strictly do NOT execute.
        # Mark hypothetical to prevent false-positive panic.
        return StepVerificationResult(
            step_index=step_idx,
            step_description=step.description,
            confidence=Confidence.POSSIBLE,
            is_verified=False,
            reason="Step cannot be actively proven without destructive actions; kept as hypothetical.",
        )

    # -----------------------------------------------------------------------
    # Helper Utilities
    # -----------------------------------------------------------------------

    @staticmethod
    def _is_bait(token: str) -> bool:
        """Check if candidate token is documentation bait or placeholder."""
        tok_lower = token.lower()
        if len(token) < 8:
            return True
        if token in ("12345678", "123456789", "00000000", "abcdefgh", "password"):
            return True
        for sub in _BAIT_SUBSTRINGS:
            if sub in ("123456", "000000", "xxxxxx"):
                if tok_lower == sub or sub * 2 in tok_lower:
                    return True
            elif sub in tok_lower:
                return True
        return False

    @staticmethod
    def _compute_entropy(text: str) -> float:
        """Compute Shannon entropy in bits per character."""
        if not text:
            return 0.0
        counts: Dict[str, int] = {}
        for c in text:
            counts[c] = counts.get(c, 0) + 1
        n = len(text)
        return -sum((cnt / n) * math.log2(cnt / n) for cnt in counts.values())

    @staticmethod
    def _extract_secrets_from_text(text: str) -> List[str]:
        """Extract candidate secrets/tokens from arbitrary text."""
        candidates = []
        # Pattern 1: key/token assignment
        for m in re.finditer(r"""(?:key|secret|token|password|auth|bearer|api)\s*[:=]\s*['"]?([A-Za-z0-9_\-\.]{8,})['"]?""", text, re.IGNORECASE):
            candidates.append(m.group(1))

        # Pattern 2: quoted strings
        for m in re.finditer(r"""['"]([A-Za-z0-9_\-\.]{16,})['"]""", text):
            candidates.append(m.group(1))

        # Pattern 3: Bearer token header
        for m in re.finditer(r"""Bearer\s+([A-Za-z0-9_\-\.]{8,})""", text, re.IGNORECASE):
            candidates.append(m.group(1))

        # Pattern 4: raw token string
        stripped = text.strip().strip("'\"")
        if len(stripped) >= 8 and " " not in stripped and re.match(r"^[A-Za-z0-9_\-\.]+$", stripped):
            candidates.append(stripped)

        return list(dict.fromkeys(candidates))


# ---------------------------------------------------------------------------
# Module-level convenience function
# ---------------------------------------------------------------------------

def verify_attack_chains(
    chains: List[AttackChain],
    base_url: str = "",
    timeout: float = 2.5,
    custom_headers: Optional[Dict[str, str]] = None,
    verify_ssl: bool = False,
    proxy: str = "",
) -> List[AttackChain]:
    """
    Top-level entry point to verify correlated attack chains.
    Takes a list of AttackChain instances, validates each step non-destructively,
    and returns the chains with updated confidence and metadata.
    """
    verifier = ChainVerifier(
        base_url=base_url,
        timeout=timeout,
        custom_headers=custom_headers,
        verify_ssl=verify_ssl,
        proxy=proxy,
    )
    return verifier.verify_chains(chains)

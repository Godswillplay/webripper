"""
Base scanner interface for WebRipper Recon.

All scanner modules inherit from BaseScanner and implement the scan() method.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any, Callable, List, Optional

from ..models import (
    Finding,
    ProgressEvent,
    EventType,
    RipReport,
    RipperSettings,
    ScanResult,
)


_MULTI_PART_TLDS = frozenset({
    "co.uk", "gov.uk", "ac.uk", "org.uk", "net.uk", "me.uk", "ltd.uk",
    "com.au", "gov.au", "edu.au", "org.au", "net.au",
    "co.nz", "govt.nz", "ac.nz", "org.nz",
    "com.br", "gov.br", "edu.br", "org.br",
    "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp",
    "co.in", "gov.in", "edu.in", "org.in", "net.in",
    "co.za", "gov.za", "edu.za", "org.za",
    "qc.ca", "gc.ca",
})


def extract_base_domain(hostname: str) -> str:
    """Robust apex domain extractor aware of multi-part ccTLDs and IP addresses."""
    if not hostname:
        return ""
    clean_host = hostname.lower().strip(".").split(":")[0]
    parts = clean_host.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return clean_host
    if len(parts) <= 2:
        return ".".join(parts)
    two_part = f"{parts[-2]}.{parts[-1]}"
    if two_part in _MULTI_PART_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


class BaseScanner(ABC):
    """Abstract base class for all scanner modules.

    Subclasses must implement:
        - name: str property
        - description: str property
        - scan(): performs the analysis and returns a ScanResult
    """

    def __init__(
        self,
        rip_report: RipReport,
        settings: RipperSettings,
        progress_callback: Optional[Callable[[ProgressEvent], None]] = None,
        recon: Optional[Any] = None,
    ) -> None:
        self._report = rip_report
        self._settings = settings
        self._callback = progress_callback or (lambda e: None)
        self._recon = recon
        self._findings: List[Finding] = []

    @property
    @abstractmethod
    def name(self) -> str:
        """Short scanner identifier (e.g. 'secrets', 'headers')."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what this scanner checks."""
        ...

    @abstractmethod
    def scan(self) -> ScanResult:
        """Run the scan and return a ScanResult."""
        ...

    # ------------------------------------------------------------------
    # Helpers available to all scanners
    # ------------------------------------------------------------------

    def _add_finding(self, finding: Finding) -> None:
        """Record a finding and emit a progress event."""
        self._findings.append(finding)
        self._callback(ProgressEvent(
            event_type=EventType.SCAN_FINDING,
            message=f"[{finding.severity.value}] {finding.title}",
            finding=finding,
        ))

    def _log(self, message: str) -> None:
        """Emit a scan progress log message."""
        self._callback(ProgressEvent(
            event_type=EventType.SCAN_PROGRESS,
            message=f"[{self.name.upper()}] {message}",
        ))

    def _build_result(self, start_time: float, **metadata) -> ScanResult:
        """Build the final ScanResult from accumulated findings."""
        return ScanResult(
            scanner_name=self.name,
            description=self.description,
            scan_time=time.time() - start_time,
            findings=list(self._findings),
            metadata=metadata,
        )

    def _get_downloaded_files(self, extensions: tuple = ()) -> list:
        """Get FileResult entries that were successfully downloaded.

        Args:
            extensions: If provided, filter to files matching these extensions.
                        e.g. ('.js', '.mjs', '.cjs')
        """
        results = []
        files = getattr(self._report, "files", None) or getattr(self._report, "downloaded_files", None) or []
        for f in files:
            if getattr(f, "error", "") or not getattr(f, "local_path", ""):
                continue
            if extensions:
                lower = f.local_path.lower()
                if not any(lower.endswith(ext) for ext in extensions):
                    continue
            results.append(f)
        return results

    def _build_headers(self) -> dict:
        """Build HTTP headers with auth cookies/tokens and custom headers.

        All scanners that make HTTP requests MUST use this method
        to ensure consistent authentication across the scanning pipeline.
        """
        headers = {"User-Agent": self._settings.user_agent}
        if self._settings.custom_headers:
            headers.update(self._settings.custom_headers)
        # Inject authentication
        cookie_parts = []
        for k in list(headers.keys()):
            if k.lower() == "cookie":
                val = headers.pop(k)
                if val:
                    cookie_parts.append(val)
        if getattr(self._settings, 'custom_cookies', ''):
            cookie_parts.append(self._settings.custom_cookies)
        if getattr(self._settings, 'auth_cookie', ''):
            cookie_parts.append(self._settings.auth_cookie)
        if cookie_parts:
            headers["Cookie"] = "; ".join(cookie_parts)
        if getattr(self._settings, 'auth_token', ''):
            headers["Authorization"] = f"Bearer {self._settings.auth_token}"
        return headers

    def _get_proxy(self) -> str | None:
        """Return proxy URL if configured, else None."""
        return self._settings.proxy or None

    def _get_target_url(self) -> str:
        """Return the target URL from settings."""
        return self._settings.url

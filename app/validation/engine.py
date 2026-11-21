"""
ValidationEngine — Central coordinator for proof-based validation in WebRipper Recon 5.0.

Orchestrates all specialized proof-based validators across all findings in a ReconReport.
Ensures that no scanner finding is marked VERIFIED without machine-checkable proof.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional

from ..models import EventType, Finding, ProgressEvent, ReconReport, RipperSettings
from .base import BaseValidator
from .canaries import CanaryValidator
from .cors import CORSValidator
from .exposed_files import ExposedFilesValidator
from .redirect import OpenRedirectValidator
from .secrets import SecretsValidator
from .sqli import SQLiValidator
from .xss import XSSValidator

logger = logging.getLogger("webripper.validation")


class ValidationEngine:
    """
    Coordinates specialized proof-based validators across all findings in a ReconReport.
    Updates findings in place with machine-checkable proof and 'VERIFIED' confidence.
    """

    def __init__(
        self,
        settings: Optional[RipperSettings] = None,
        progress_callback: Optional[Callable[[ProgressEvent], None]] = None,
    ):
        self.settings = settings or RipperSettings()
        self.progress_callback = progress_callback

        # Initialize validators in prioritized order
        self.validators: List[BaseValidator] = [
            XSSValidator(self.settings),
            SQLiValidator(self.settings),
            CORSValidator(self.settings),
            OpenRedirectValidator(self.settings),
            ExposedFilesValidator(self.settings),
            SecretsValidator(self.settings),
            CanaryValidator(self.settings),
        ]

    def _emit(self, event_type: EventType, message: str, phase: str = "Validating") -> None:
        """Emit progress event if callback is registered."""
        if self.progress_callback:
            try:
                self.progress_callback(ProgressEvent(
                    event_type=event_type,
                    message=message,
                    phase=phase,
                ))
            except Exception:
                pass

    def validate_report(self, recon: ReconReport) -> ReconReport:
        """
        Coordinate validators across all findings in a ReconReport.
        Updates findings in place and returns the validated ReconReport.
        """
        all_findings = recon.all_findings
        if not all_findings:
            self._emit(EventType.LOG, "No candidate findings to validate.")
            return recon

        self._emit(
            EventType.PHASE_CHANGE,
            f"Evaluating {len(all_findings)} candidate findings through proof-based validators...",
            phase="Validation",
        )

        candidates_evaluated = 0
        verified_count = 0

        for sr in recon.scan_results:
            for finding in sr.findings:
                # Find matching validator
                matching_validator = None
                for val in self.validators:
                    try:
                        if val.can_validate(finding):
                            matching_validator = val
                            break
                    except Exception as err:
                        logger.debug("Validator match error for %s: %s", val.name, err)

                if matching_validator:
                    candidates_evaluated += 1
                    try:
                        matching_validator.validate(finding)
                        if getattr(finding, "confidence", "") == "VERIFIED":
                            verified_count += 1
                            self._emit(
                                EventType.LOG,
                                f"✓ [VERIFIED] {finding.title} — machine-checkable proof attached by {matching_validator.name} validator.",
                            )
                    except Exception as exc:
                        logger.error("Validation error on finding '%s' with %s: %s", finding.title, matching_validator.name, exc)
                        finding.confidence = "POSSIBLE"
                        finding.metadata["validation_error"] = str(exc)

        self._emit(
            EventType.LOG,
            f"Validation complete: {candidates_evaluated} candidates evaluated, {verified_count} confirmed VERIFIED with machine-checkable proof.",
            phase="Validation",
        )

        return recon

    def validate_finding(self, finding: Finding) -> Finding:
        """Validate a single candidate finding."""
        for val in self.validators:
            if val.can_validate(finding):
                return val.validate(finding)
        return finding

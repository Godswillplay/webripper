"""
WebRipper Recon 5.0 — Proof-Based Validator Layer.

This package provides deterministic, non-destructive, proof-based verification
for candidate security findings discovered by upstream scanners.

In WebRipper Recon 5.0, scanners ONLY produce candidate findings (LIKELY or POSSIBLE).
Only a validator in this package may elevate a finding to VERIFIED by attaching
machine-checkable proof (request, response hash/snippet, and observed delta).
"""

from .base import BaseValidator, HTTPResponse, DifferentialDelta
from .xss import XSSValidator
from .sqli import SQLiValidator
from .cors import CORSValidator
from .redirect import OpenRedirectValidator
from .exposed_files import ExposedFilesValidator
from .secrets import SecretsValidator
from .canaries import CanaryValidator
from .engine import ValidationEngine

__all__ = [
    "BaseValidator",
    "HTTPResponse",
    "DifferentialDelta",
    "XSSValidator",
    "SQLiValidator",
    "CORSValidator",
    "OpenRedirectValidator",
    "ExposedFilesValidator",
    "SecretsValidator",
    "CanaryValidator",
    "ValidationEngine",
]

"""
Data models for the Scenario Intelligence Engine.
Represents deconstructed real-world bug bounty writeups and canary probe recipes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional


@dataclass
class ScenarioRecipe:
    """A structured, machine-executable vulnerability scenario recipe.

    Derived from real-world HackerOne/Bugcrowd disclosures, CVE write-ups,
    and verified attack patterns.
    """
    id: str
    title: str
    tech_stack: List[str]          # Technologies this scenario applies to (e.g. ["nextjs", "react"])
    category: str                  # Scanner category: paths, vulns, cors, endpoints, auth, secrets
    cwe: str                       # e.g. "CWE-284"
    cvss_vector: str               # e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    probe_method: str = "GET"      # HTTP method: GET, POST, OPTIONS, PUT
    probe_path: str = ""           # Path relative to target URL
    probe_headers: Dict[str, str] = field(default_factory=dict)
    probe_body: str = ""
    match_status: List[int] = field(default_factory=lambda: [200])
    match_regex: str = ""          # Pattern that indicates vulnerability
    negative_regex: str = ""       # Pattern that invalidates finding (avoids false positives)
    bounty_reference: str = ""     # e.g. "HackerOne #312154 ($5,000 Payout)"
    author_insight: str = ""       # Root cause explanation from the original disclosure
    remediation: str = ""          # Precise defensive patch code or configuration

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "ScenarioRecipe":
        # Handle match_status if single int or list
        if "match_status" in data and isinstance(data["match_status"], int):
            data["match_status"] = [data["match_status"]]
        return cls(**data)

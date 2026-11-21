"""
Historical Diffing & Briefing Engine for WebRipper Watch Mode.

Provides deterministic change-only diffing between scans:
  - Fingerprint computation based on category, title, endpoint shape, and parameters.
  - Endpoint shape normalization (dynamic IDs, UUIDs, hex hashes, query shapes).
  - Detection of:
      * New findings (regressions)
      * Resolved findings (remediated)
      * Changed findings (severity, confidence, or proof status shifts)
      * Attack chain mutations (new/resolved correlated paths)
  - Change-only executive and technical briefings:
      * Markdown briefing (briefing.md)
      * JSON delta payload (briefing.json)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import parse_qsl, urlparse

from ..models import AttackChain, Finding, ReconReport, Severity


# ---------------------------------------------------------------------------
# Endpoint Shape Normalization & Fingerprinting
# ---------------------------------------------------------------------------

def compute_endpoint_shape(url: str = "", file_path: str = "") -> str:
    """
    Computes a normalized endpoint shape string for matching findings across scans.
    Replaces dynamic path variables (IDs, UUIDs, hex hashes) with structural tokens
    and retains sorted query parameter keys without volatile values.
    """
    if not url and file_path:
        norm_fp = file_path.replace("\\", "/").strip().lower()
        return norm_fp

    if not url:
        return ""

    try:
        parsed = urlparse(url)
        path = parsed.path or "/"

        # Normalize standard UUIDs
        path = re.sub(
            r"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            "/{uuid}",
            path,
        )
        # Normalize long hex hashes (MD5, SHA1, SHA256)
        path = re.sub(r"/[0-9a-fA-F]{32,64}", "/{hash}", path)
        # Normalize integer IDs
        path = re.sub(r"/\d+(?=/|$)", "/{id}", path)

        # Normalize query params to sorted key names only
        q_keys = sorted([k.lower() for k, _ in parse_qsl(parsed.query, keep_blank_values=True)])
        q_shape = f"?keys={','.join(q_keys)}" if q_keys else ""

        netloc = parsed.netloc.lower()
        if netloc:
            return f"{netloc}{path}{q_shape}"
        return f"{path}{q_shape}"
    except Exception:
        return url.strip().lower()


def compute_finding_fingerprint(finding: Any) -> str:
    """
    Computes a deterministic, collision-resistant fingerprint for a security finding.
    Uses explicit metadata['fingerprint'] if present, otherwise computes
    SHA-256 digest of (category, title, endpoint_shape, parameter).
    """
    if isinstance(finding, dict):
        meta = finding.get("metadata", {})
        if not isinstance(meta, dict):
            meta = {}
        explicit_fp = meta.get("fingerprint") or finding.get("fingerprint")
        if explicit_fp:
            return str(explicit_fp)
        category = str(finding.get("category", "")).strip().lower()
        title = str(finding.get("title", "")).strip().lower()
        url = str(finding.get("url", ""))
        file_path = str(finding.get("file_path", ""))
        param = str(meta.get("parameter", "")).strip().lower()
    else:
        meta = getattr(finding, "metadata", {}) or {}
        if not isinstance(meta, dict):
            meta = {}
        explicit_fp = meta.get("fingerprint") or getattr(finding, "fingerprint", None)
        if explicit_fp:
            return str(explicit_fp)
        category = str(getattr(finding, "category", "")).strip().lower()
        title = str(getattr(finding, "title", "")).strip().lower()
        url = str(getattr(finding, "url", ""))
        file_path = str(getattr(finding, "file_path", ""))
        param = str(meta.get("parameter", "")).strip().lower()

    endpoint = compute_endpoint_shape(url, file_path)
    raw_ident = f"{category}|{title}|{endpoint}|{param}"
    digest = hashlib.sha256(raw_ident.encode("utf-8")).hexdigest()[:16]
    return f"{category}_{digest}"


def extract_proof_status(finding: Any) -> Tuple[bool, str]:
    """
    Extracts proof presence and proof signature from finding metadata.
    Recognizes machine-checkable proof from proof validators or PoC commands.
    """
    meta = getattr(finding, "metadata", {}) if not isinstance(finding, dict) else finding.get("metadata", {})
    if not isinstance(meta, dict):
        meta = {}

    has_proof = False
    proof_sig = ""

    if "proof" in meta and meta["proof"]:
        has_proof = True
        p = meta["proof"]
        if isinstance(p, dict):
            proof_sig = f"{p.get('validator', '')}:{p.get('observed_delta', '')}"
        else:
            proof_sig = str(p)
    elif meta.get("poc_verified") is True:
        has_proof = True
        proof_sig = "poc_verified"
    elif meta.get("proof_of_concept"):
        has_proof = True
        proof_sig = str(meta.get("proof_of_concept"))[:80]
    elif meta.get("poc_curl"):
        has_proof = True
        proof_sig = str(meta.get("poc_curl"))[:80]

    conf = getattr(finding, "confidence", "") if not isinstance(finding, dict) else finding.get("confidence", "")
    if hasattr(conf, "value"):
        conf = conf.value
    conf = str(conf).upper()
    if conf == "VERIFIED":
        has_proof = True
        if not proof_sig:
            proof_sig = "verified_confidence"

    return has_proof, proof_sig


def _normalize_severity_str(sev: Any) -> str:
    """Normalize severity to uppercase string value."""
    if hasattr(sev, "value"):
        return str(sev.value).upper()
    return str(sev).upper() if sev else "INFO"


def _normalize_confidence_str(conf: Any) -> str:
    """Normalize confidence to uppercase string value."""
    if hasattr(conf, "value"):
        return str(conf.value).upper()
    return str(conf).upper() if conf else "POSSIBLE"


def finding_to_dict(finding: Any) -> Dict[str, Any]:
    """Convert a Finding object or raw dictionary into standardized dictionary format."""
    if isinstance(finding, dict):
        d = dict(finding)
        d["severity"] = _normalize_severity_str(d.get("severity", "INFO"))
        d["confidence"] = _normalize_confidence_str(d.get("confidence", "POSSIBLE"))
        d["fingerprint"] = compute_finding_fingerprint(d)
        d["endpoint_shape"] = compute_endpoint_shape(str(d.get("url", "")), str(d.get("file_path", "")))
        return d

    sev_val = _normalize_severity_str(getattr(finding, "severity", "INFO"))
    conf_val = _normalize_confidence_str(getattr(finding, "confidence", "POSSIBLE"))
    url_val = str(getattr(finding, "url", ""))
    fp_val = str(getattr(finding, "file_path", ""))

    d = {
        "severity": sev_val,
        "category": str(getattr(finding, "category", "")),
        "title": str(getattr(finding, "title", "")),
        "description": str(getattr(finding, "description", "")),
        "evidence": str(getattr(finding, "evidence", "")),
        "url": url_val,
        "file_path": fp_val,
        "line_number": int(getattr(finding, "line_number", 0) or 0),
        "remediation": str(getattr(finding, "remediation", "")),
        "confidence": conf_val,
        "metadata": getattr(finding, "metadata", {}) or {},
        "fingerprint": compute_finding_fingerprint(finding),
        "endpoint_shape": compute_endpoint_shape(url_val, fp_val),
    }
    if hasattr(finding, "poc_curl") and finding.poc_curl:
        d["poc_curl"] = finding.poc_curl
    return d


# ---------------------------------------------------------------------------
# Change-only Diff Data Models
# ---------------------------------------------------------------------------

@dataclass
class ChangedFinding:
    """Represents a finding present in both scans whose state or severity has shifted."""
    fingerprint: str
    title: str
    category: str
    url: str
    endpoint_shape: str
    changes: Dict[str, Dict[str, Any]]
    previous: Dict[str, Any]
    current: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "title": self.title,
            "category": self.category,
            "url": self.url,
            "endpoint_shape": self.endpoint_shape,
            "changes": self.changes,
            "previous": self.previous,
            "current": self.current,
        }


@dataclass
class WatchDiffBriefing:
    """
    Change-only security diff briefing.
    Encapsulates new, resolved, and changed findings alongside attack chain shifts.
    """
    target: str = ""
    baseline_timestamp: str = ""
    current_timestamp: str = ""
    generated_at: str = ""
    new_findings: List[Dict[str, Any]] = field(default_factory=list)
    resolved_findings: List[Dict[str, Any]] = field(default_factory=list)
    changed_findings: List[Dict[str, Any]] = field(default_factory=list)
    unchanged_count: int = 0
    new_attack_chains: List[Dict[str, Any]] = field(default_factory=list)
    resolved_attack_chains: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def has_changes(self) -> bool:
        return bool(
            self.new_findings
            or self.resolved_findings
            or self.changed_findings
            or self.new_attack_chains
            or self.resolved_attack_chains
        )

    @property
    def has_critical_or_high_regressions(self) -> bool:
        """Check if any new findings are CRITICAL or HIGH severity."""
        for f in self.new_findings:
            if f.get("severity") in ("CRITICAL", "HIGH"):
                return True
        for c in self.new_attack_chains:
            if c.get("severity") in ("CRITICAL", "HIGH"):
                return True
        for ch in self.changed_findings:
            new_sev = ch.get("changes", {}).get("severity", {}).get("new")
            if new_sev in ("CRITICAL", "HIGH"):
                return True
        return False

    @property
    def summary(self) -> Dict[str, Any]:
        return {
            "new": len(self.new_findings),
            "resolved": len(self.resolved_findings),
            "changed": len(self.changed_findings),
            "unchanged": self.unchanged_count,
            "new_attack_chains": len(self.new_attack_chains),
            "resolved_attack_chains": len(self.resolved_attack_chains),
            "total_changes": (
                len(self.new_findings)
                + len(self.resolved_findings)
                + len(self.changed_findings)
                + len(self.new_attack_chains)
                + len(self.resolved_attack_chains)
            ),
            "has_changes": self.has_changes,
            "has_critical_or_high_regressions": self.has_critical_or_high_regressions,
        }

    def to_dict(self) -> Dict[str, Any]:
        """Produce change-only JSON delta payload."""
        return {
            "version": "1.0",
            "target": self.target,
            "baseline_timestamp": self.baseline_timestamp,
            "current_timestamp": self.current_timestamp,
            "generated_at": self.generated_at or datetime.now(timezone.utc).isoformat(),
            "summary": self.summary,
            "new_findings": self.new_findings,
            "resolved_findings": self.resolved_findings,
            "changed_findings": self.changed_findings,
            "new_attack_chains": self.new_attack_chains,
            "resolved_attack_chains": self.resolved_attack_chains,
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize change-only delta to formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def to_markdown(self) -> str:
        """
        Produce human-readable, executive and technical Markdown briefing.
        Strictly change-only: excludes unchanged finding noise.
        """
        lines = [
            "# 🛡️ WebRipper Watch Briefing — Security Delta",
            "",
            f"**Target:** `{self.target or 'N/A'}`  ",
            f"**Generated:** `{self.generated_at or datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}`  ",
        ]
        if self.baseline_timestamp:
            lines.append(f"**Baseline Timestamp:** `{self.baseline_timestamp}`  ")
        if self.current_timestamp:
            lines.append(f"**Current Timestamp:** `{self.current_timestamp}`  ")

        lines.extend([
            "",
            "---",
            "",
            "## 📊 Executive Delta Summary",
            "",
            "| Metric | Count | Assessment |",
            "|:---|:---:|:---|",
            f"| 🚨 **New Findings (Regressions)** | **{len(self.new_findings)}** | Introduced attack surface or emerging flaws |",
            f"| ✅ **Resolved Findings (Remediated)** | **{len(self.resolved_findings)}** | Previously active vulnerabilities confirmed fixed |",
            f"| ⚠️ **Changed Findings (Modified)** | **{len(self.changed_findings)}** | Severity, confidence, or verification shifts |",
            f"| 🔒 **Unchanged Findings (Baseline)** | **{self.unchanged_count}** | Persisting security posture (zero drift noise) |",
            f"| ⛓️ **Attack Chain Diffs** | **{len(self.new_attack_chains)} new, {len(self.resolved_attack_chains)} resolved** | Correlated multi-stage path mutations |",
            "",
            "---",
            "",
        ])

        if not self.has_changes:
            lines.extend([
                "## 🛡️ Zero Delta: No Security Drift Observed",
                "",
                "All security findings and attack surfaces remain identical to baseline.",
                "Zero new vulnerabilities or configuration regressions detected in this scan cycle.",
                "",
            ])
            return "\n".join(lines)

        # 1. New Findings
        if self.new_findings:
            lines.extend([
                "## 🚨 New Findings (Regressions)",
                "",
                "The following security issues were detected in the current audit but were absent in the baseline:",
                "",
            ])
            for i, f in enumerate(self.new_findings, 1):
                sev = f.get("severity", "INFO")
                title = f.get("title", "Untitled Finding")
                cat = f.get("category", "general")
                url = f.get("url") or f.get("file_path") or "Target root"
                conf = f.get("confidence", "POSSIBLE")
                desc = f.get("description", "").strip()
                evidence = f.get("evidence", "").strip()
                remediation = f.get("remediation", "").strip()

                lines.append(f"### {i}. [{sev}] {title}")
                lines.append(f"- **Category:** `{cat}`")
                lines.append(f"- **Endpoint / Resource:** `{url}`")
                lines.append(f"- **Confidence:** `{conf}`")
                if desc:
                    lines.append(f"- **Description:** {desc}")
                if evidence:
                    snippet = evidence[:300].replace("\n", " ")
                    lines.append(f"- **Evidence:** `{snippet}`")
                if remediation:
                    lines.append(f"- **Remediation:** {remediation}")
                lines.append("")

            lines.append("---")
            lines.append("")

        # 2. Resolved Findings
        if self.resolved_findings:
            lines.extend([
                "## ✅ Resolved Findings (Remediated)",
                "",
                "The following findings from the baseline were no longer observed in the current scan:",
                "",
            ])
            for i, f in enumerate(self.resolved_findings, 1):
                sev = f.get("severity", "INFO")
                title = f.get("title", "Untitled Finding")
                cat = f.get("category", "general")
                url = f.get("url") or f.get("file_path") or "Target root"

                lines.append(f"### {i}. [{sev}] {title}")
                lines.append(f"- **Category:** `{cat}`")
                lines.append(f"- **Endpoint / Resource:** `{url}`")
                lines.append(f"- **Status:** Fixed / Remediated (no longer detected)")
                lines.append("")

            lines.append("---")
            lines.append("")

        # 3. Changed Findings
        if self.changed_findings:
            lines.extend([
                "## ⚠️ Changed Findings (State & Severity Shifts)",
                "",
                "The following persisting findings experienced state, severity, or verification changes:",
                "",
            ])
            for i, ch in enumerate(self.changed_findings, 1):
                title = ch.get("title", "Finding")
                cat = ch.get("category", "")
                url = ch.get("url") or ch.get("endpoint_shape") or "Target root"
                changes = ch.get("changes", {})

                lines.append(f"### {i}. {title}")
                lines.append(f"- **Category:** `{cat}` | **Resource:** `{url}`")
                for change_key, delta in changes.items():
                    if change_key == "severity":
                        lines.append(f"  - **Severity Shift:** `{delta.get('old')}` ➔ `{delta.get('new')}`")
                    elif change_key == "confidence":
                        lines.append(f"  - **Confidence Shift:** `{delta.get('old')}` ➔ `{delta.get('new')}`")
                    elif change_key == "proof_status":
                        old_p = "Verified Proof Attached" if delta.get("old_has_proof") else "Unverified / Heuristic"
                        new_p = "Verified Proof Attached" if delta.get("new_has_proof") else "Unverified / Heuristic"
                        lines.append(f"  - **Proof Status:** `{old_p}` ➔ `{new_p}`")
                    else:
                        lines.append(f"  - **{change_key}:** `{delta.get('old')}` ➔ `{delta.get('new')}`")
                lines.append("")

            lines.append("---")
            lines.append("")

        # 4. Attack Chains
        if self.new_attack_chains or self.resolved_attack_chains:
            lines.extend([
                "## ⛓️ Attack Chain Diffs",
                "",
            ])
            if self.new_attack_chains:
                lines.append("### 🚨 New Correlated Attack Chains")
                for c in self.new_attack_chains:
                    name = c.get("name", "Unnamed Chain")
                    sev = c.get("severity", "HIGH")
                    impact = c.get("impact", "")
                    steps = c.get("steps", [])
                    lines.append(f"- **[{sev}] {name}**")
                    if impact:
                        lines.append(f"  - *Impact:* {impact}")
                    if steps:
                        lines.append(f"  - *Steps ({len(steps)}):*")
                        for s in steps:
                            desc = s.get("description", "") if isinstance(s, dict) else getattr(s, "description", "")
                            lines.append(f"    1. {desc}")
                lines.append("")

            if self.resolved_attack_chains:
                lines.append("### ✅ Resolved Attack Chains")
                for c in self.resolved_attack_chains:
                    name = c.get("name", "Unnamed Chain")
                    sev = c.get("severity", "HIGH")
                    lines.append(f"- **[{sev}] {name}** — Remediated (chain links broken)")
                lines.append("")

            lines.append("---")
            lines.append("")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Historical Diffing Engine
# ---------------------------------------------------------------------------

class HistoricalDiffEngine:
    """
    Engine for historical comparison of scans.
    Performs deterministic fingerprinting, detects state transitions,
    and produces change-only briefings.
    """

    def __init__(self) -> None:
        pass

    @staticmethod
    def _extract_findings(scan_input: Any) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], str, str]:
        """
        Extract standardized findings, attack chains, target URL, and timestamp
        from various input representations (ReconReport, ScanResult list, dict, JSON file).
        """
        target_url = ""
        timestamp = ""
        raw_findings: List[Any] = []
        raw_chains: List[Any] = []

        if scan_input is None:
            return [], [], "", ""

        # Case 1: String path to JSON file or raw JSON string
        if isinstance(scan_input, str):
            if os.path.isfile(scan_input):
                with open(scan_input, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return HistoricalDiffEngine._extract_findings(data)
            try:
                data = json.loads(scan_input)
                return HistoricalDiffEngine._extract_findings(data)
            except Exception:
                pass

        # Case 2: ReconReport instance
        if isinstance(scan_input, ReconReport):
            target_url = scan_input.url
            timestamp = scan_input.end_time or scan_input.start_time
            raw_findings = scan_input.all_findings
            raw_chains = [c.to_dict() if hasattr(c, "to_dict") else c for c in scan_input.attack_chains]

        # Case 3: Dictionary (deserialized JSON report)
        elif isinstance(scan_input, dict):
            target_url = scan_input.get("target_url") or scan_input.get("url") or scan_input.get("target") or ""
            timestamp = scan_input.get("timestamp") or scan_input.get("end_time") or scan_input.get("start_time") or ""
            raw_chains = scan_input.get("attack_chains", [])

            if "findings" in scan_input:
                raw_findings = scan_input["findings"]
            elif "scans" in scan_input:
                # Top-level recon report structure
                for sr in scan_input.get("scans", []):
                    raw_findings.extend(sr.get("findings", []))
            elif "scan_results" in scan_input:
                for sr in scan_input.get("scan_results", []):
                    raw_findings.extend(sr.get("findings", []))

        # Case 4: Flat list of Finding objects or dictionaries
        elif isinstance(scan_input, (list, tuple)):
            raw_findings = list(scan_input)

        standardized_findings = [finding_to_dict(f) for f in raw_findings]

        standardized_chains: List[Dict[str, Any]] = []
        for c in raw_chains:
            if hasattr(c, "to_dict"):
                standardized_chains.append(c.to_dict())
            elif isinstance(c, dict):
                standardized_chains.append(c)

        return standardized_findings, standardized_chains, target_url, timestamp

    def compare(
        self,
        previous_scan: Any,
        current_scan: Any,
        target: str = "",
    ) -> WatchDiffBriefing:
        """
        Compare previous scan against current scan.
        Generates a change-only WatchDiffBriefing.
        """
        prev_findings, prev_chains, prev_target, prev_ts = self._extract_findings(previous_scan)
        curr_findings, curr_chains, curr_target, curr_ts = self._extract_findings(current_scan)

        target_url = target or curr_target or prev_target or "unknown_target"

        # Index previous findings by fingerprint
        prev_map: Dict[str, Dict[str, Any]] = {}
        for pf in prev_findings:
            fp = pf["fingerprint"]
            prev_map[fp] = pf

        # Index current findings by fingerprint
        curr_map: Dict[str, Dict[str, Any]] = {}
        for cf in curr_findings:
            fp = cf["fingerprint"]
            curr_map[fp] = cf

        prev_keys: Set[str] = set(prev_map.keys())
        curr_keys: Set[str] = set(curr_map.keys())

        new_keys = curr_keys - prev_keys
        resolved_keys = prev_keys - curr_keys
        common_keys = curr_keys & prev_keys

        new_findings = [curr_map[k] for k in sorted(new_keys)]
        resolved_findings = [prev_map[k] for k in sorted(resolved_keys)]

        changed_findings: List[Dict[str, Any]] = []
        unchanged_count = 0

        for k in sorted(common_keys):
            old_f = prev_map[k]
            new_f = curr_map[k]

            changes: Dict[str, Dict[str, Any]] = {}

            # 1. Severity check
            old_sev = _normalize_severity_str(old_f.get("severity"))
            new_sev = _normalize_severity_str(new_f.get("severity"))
            if old_sev != new_sev:
                changes["severity"] = {"old": old_sev, "new": new_sev}

            # 2. Confidence check
            old_conf = _normalize_confidence_str(old_f.get("confidence"))
            new_conf = _normalize_confidence_str(new_f.get("confidence"))
            if old_conf != new_conf:
                changes["confidence"] = {"old": old_conf, "new": new_conf}

            # 3. Proof status check
            old_has_proof, old_proof_sig = extract_proof_status(old_f)
            new_has_proof, new_proof_sig = extract_proof_status(new_f)
            if old_has_proof != new_has_proof or (old_has_proof and new_has_proof and old_proof_sig != new_proof_sig):
                changes["proof_status"] = {
                    "old_has_proof": old_has_proof,
                    "new_has_proof": new_has_proof,
                    "old_sig": old_proof_sig,
                    "new_sig": new_proof_sig,
                }

            if changes:
                changed_obj = ChangedFinding(
                    fingerprint=k,
                    title=new_f.get("title", ""),
                    category=new_f.get("category", ""),
                    url=new_f.get("url", ""),
                    endpoint_shape=new_f.get("endpoint_shape", ""),
                    changes=changes,
                    previous=old_f,
                    current=new_f,
                )
                changed_findings.append(changed_obj.to_dict())
            else:
                unchanged_count += 1

        # Diff attack chains
        def _chain_key(c: Dict[str, Any]) -> str:
            name = str(c.get("name", "")).strip().lower()
            return f"chain_{hashlib.sha256(name.encode('utf-8')).hexdigest()[:16]}"

        prev_chain_map = {_chain_key(c): c for c in prev_chains}
        curr_chain_map = {_chain_key(c): c for c in curr_chains}

        new_chain_keys = set(curr_chain_map.keys()) - set(prev_chain_map.keys())
        resolved_chain_keys = set(prev_chain_map.keys()) - set(curr_chain_map.keys())

        new_chains = [curr_chain_map[k] for k in sorted(new_chain_keys)]
        resolved_chains = [prev_chain_map[k] for k in sorted(resolved_chain_keys)]

        briefing = WatchDiffBriefing(
            target=target_url,
            baseline_timestamp=prev_ts,
            current_timestamp=curr_ts,
            generated_at=datetime.now(timezone.utc).isoformat(),
            new_findings=new_findings,
            resolved_findings=resolved_findings,
            changed_findings=changed_findings,
            unchanged_count=unchanged_count,
            new_attack_chains=new_chains,
            resolved_attack_chains=resolved_chains,
            metadata={
                "previous_finding_count": len(prev_findings),
                "current_finding_count": len(curr_findings),
            },
        )
        return briefing

    def generate_briefing(
        self,
        previous_scan: Any,
        current_scan: Any,
        target: str = "",
    ) -> WatchDiffBriefing:
        """Alias for compare()."""
        return self.compare(previous_scan=previous_scan, current_scan=current_scan, target=target)

    def export_briefings(
        self,
        briefing: WatchDiffBriefing,
        output_dir: str,
    ) -> Tuple[str, str]:
        """
        Write briefing.md and briefing.json to the target output directory.
        Returns tuple of (markdown_file_path, json_file_path).
        """
        os.makedirs(output_dir, exist_ok=True)
        md_path = os.path.join(output_dir, "briefing.md")
        json_path = os.path.join(output_dir, "briefing.json")

        with open(md_path, "w", encoding="utf-8") as f:
            f.write(briefing.to_markdown())

        with open(json_path, "w", encoding="utf-8") as f:
            f.write(briefing.to_json(indent=2))

        return md_path, json_path

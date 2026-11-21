"""
WebRipper Recon 5.0 — Finding Clustering Engine.

Clusters findings with SimHash Hamming distance <= 4.
Groups near-duplicate findings into a single representative finding.
The representative finding retains its primary details and accumulates
metadata["grouped_locations"] with details of all clustered instances.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from .simhash import (
    compute_finding_simhash,
    extract_endpoint_shape,
    simhash_hamming_distance,
)


class _FindingCluster:
    """Internal cluster container."""

    def __init__(self, rep: Any, rep_hash: int, shape: str):
        self.rep = rep
        self.rep_hash = rep_hash
        self.shape = shape
        self.members: List[Any] = [rep]
        self.member_hashes: List[int] = [rep_hash]


def _extract_location(f: Any) -> Dict[str, Any]:
    """Extract location dictionary from finding."""
    url = getattr(f, "url", "")
    metadata = getattr(f, "metadata", {}) if isinstance(getattr(f, "metadata", None), dict) else {}
    method = metadata.get("method", "GET")

    # Try attribute, then metadata
    param = getattr(f, "parameter", None)
    if param is None:
        param = metadata.get("parameter", "")
    if param is None:
        param = ""

    evidence = getattr(f, "evidence", "")
    return {
        "url": url,
        "method": method,
        "parameter": param,
        "evidence": evidence,
    }


def cluster_findings(
    findings: List[Any],
    max_distance: int = 4,
) -> List[Any]:
    """
    Cluster findings using 64-bit SimHash locality-sensitive fingerprints.

    Findings with Hamming distance <= max_distance (default 4) are grouped
    into a single representative finding. The representative finding keeps
    its primary details and accumulates:
      metadata["grouped_locations"] = [
          {"url": f.url, "method": f.metadata.get("method", "GET"), "parameter": f.parameter, "evidence": f.evidence},
          ...
      ]

    Returns deduplicated list of representative findings.
    """
    if not findings:
        return []

    clusters: List[_FindingCluster] = []

    for f in findings:
        url = getattr(f, "url", "")
        category = getattr(f, "category", "")
        title = getattr(f, "title", "")
        evidence = getattr(f, "evidence", "")

        shape = extract_endpoint_shape(url)
        f_hash = compute_finding_simhash(
            category=category,
            title=title,
            endpoint_shape=shape,
            evidence=evidence,
        )

        # Store simhash in metadata if finding has metadata
        if hasattr(f, "metadata") and isinstance(f.metadata, dict):
            f.metadata["simhash"] = f_hash
            f.metadata["endpoint_shape"] = shape

        # Find best matching cluster within max_distance
        best_cluster: Optional[_FindingCluster] = None
        best_dist = max_distance + 1

        for c in clusters:
            # Check distance to representative
            dist = simhash_hamming_distance(f_hash, c.rep_hash)
            # Also check if matching any member
            if dist > max_distance:
                min_member_dist = min(simhash_hamming_distance(f_hash, mh) for mh in c.member_hashes)
                if min_member_dist <= max_distance:
                    dist = min_member_dist

            if dist <= max_distance and dist < best_dist:
                best_dist = dist
                best_cluster = c

        if best_cluster is not None:
            best_cluster.members.append(f)
            best_cluster.member_hashes.append(f_hash)
        else:
            clusters.append(_FindingCluster(rep=f, rep_hash=f_hash, shape=shape))

    # Assemble deduplicated findings
    deduplicated: List[Any] = []
    for c in clusters:
        rep = c.rep
        if not hasattr(rep, "metadata") or not isinstance(rep.metadata, dict):
            rep.metadata = {}

        # Collect all locations from cluster members
        locations: List[Dict[str, Any]] = []
        for m in c.members:
            m_meta = getattr(m, "metadata", {}) if isinstance(getattr(m, "metadata", None), dict) else {}
            if "grouped_locations" in m_meta and isinstance(m_meta["grouped_locations"], list):
                locations.extend(m_meta["grouped_locations"])
            else:
                locations.append(_extract_location(m))

        if len(c.members) > 1 or len(locations) > 1:
            rep.metadata["grouped_locations"] = locations
            rep.metadata["cluster_size"] = len(locations)

        # Ensure parameter attribute exists on rep if available
        if not hasattr(rep, "parameter") and locations:
            try:
                rep.parameter = locations[0]["parameter"]
            except Exception:
                pass

        deduplicated.append(rep)

    return deduplicated

"""
WebRipper Recon 5.0 — 64-bit SimHash Locality-Sensitive Hashing.

Computes 64-bit SimHash fingerprints over finding titles, normalized evidence,
and parameterized endpoint shapes for near-duplicate clustering.
"""

from __future__ import annotations

import hashlib
import re
from typing import List, Tuple
from urllib.parse import parse_qsl, urlparse

_RE_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_RE_HASH = re.compile(r"^[0-9a-f]{16,64}$", re.IGNORECASE)
_RE_INT = re.compile(r"^\d+$")


def extract_endpoint_shape(url: str) -> str:
    """
    Normalize a URL into its structural endpoint shape for clustering.

    Collapses:
      - integer IDs in path segments to {id}
      - UUIDs to {uuid}
      - hexadecimal hashes (16-64 chars) to {hash}
      - query parameters sorted deterministically by key name
    """
    if not url:
        return "root"

    parsed = urlparse(url)
    segments = [s for s in parsed.path.split("/") if s]
    shape_segments: List[str] = []
    for seg in segments:
        if _RE_INT.match(seg):
            shape_segments.append("{id}")
        elif _RE_UUID.match(seg):
            shape_segments.append("{uuid}")
        elif _RE_HASH.match(seg):
            shape_segments.append("{hash}")
        else:
            shape_segments.append(seg.lower())

    path_shape = "/" + "/".join(shape_segments) if shape_segments else "/"

    if parsed.query:
        query_keys = sorted(k.lower() for k, _ in parse_qsl(parsed.query, keep_blank_values=True))
        query_shape = ("?" + "&".join(query_keys)) if query_keys else ""
    else:
        query_shape = ""

    netloc = parsed.netloc.lower()
    return f"{netloc}{path_shape}{query_shape}"


def _fnv64(token: str) -> int:
    """Deterministic 64-bit unsigned integer hash derived from SHA-256."""
    digest = hashlib.sha256(token.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], byteorder="big", signed=False)


def compute_finding_simhash(
    category: str,
    title: str,
    endpoint_shape: str,
    evidence: str,
) -> int:
    """
    Compute a deterministic 64-bit SimHash locality-sensitive fingerprint.

    Weights:
      - title tokens: 3
      - endpoint shape: 3
      - category: 2
      - evidence 3-gram shingles (whitespace normalized, truncated to 200 chars): 1
    """
    v = [0] * 64
    features: List[Tuple[str, int]] = []

    # Category weight = 2
    if category:
        features.append((f"cat:{category.lower().strip()}", 2))
    else:
        features.append(("cat:general", 2))

    # Title tokens weight = 3
    for tok in re.findall(r"\w+", (title or "").lower()):
        features.append((f"title:{tok}", 3))

    # Endpoint shape weight = 3
    if endpoint_shape:
        features.append((f"shape:{endpoint_shape}", 3))

    # Evidence shingle features weight = 1 (whitespace normalized, truncated to 200 chars)
    clean_ev = re.sub(r"\s+", " ", (evidence or "").strip().lower())[:200]
    words = clean_ev.split()
    for i in range(len(words) - 2):
        shingle = f"ev:{words[i]}_{words[i+1]}_{words[i+2]}"
        features.append((shingle, 1))

    if not features:
        features.append(("empty", 1))

    for feat, weight in features:
        h = _fnv64(feat)
        for i in range(64):
            bit = (h >> i) & 1
            if bit:
                v[i] += weight
            else:
                v[i] -= weight

    fingerprint = 0
    for i in range(64):
        if v[i] > 0:
            fingerprint |= (1 << i)

    return fingerprint


def simhash_hamming_distance(hash1: int, hash2: int) -> int:
    """
    Calculate Hamming distance between two 64-bit fingerprints using bit_count().
    """
    return (hash1 ^ hash2).bit_count()


def simhash_similarity(hash1: int, hash2: int) -> float:
    """
    Calculate normalized similarity [0.0, 1.0] between two 64-bit SimHashes.
    """
    dist = simhash_hamming_distance(hash1, hash2)
    return round((64 - dist) / 64.0, 4)

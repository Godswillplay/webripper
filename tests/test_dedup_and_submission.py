"""
Tests for Phase 2: SimHash Deduplication & Submission-Quality Guard.
"""

from __future__ import annotations

import os
import sqlite3
import tempfile
import pytest

from app.models import Finding, Severity, Confidence
from app.dedup.simhash import (
    extract_endpoint_shape,
    compute_finding_simhash,
    simhash_hamming_distance,
    simhash_similarity,
)
from app.dedup.cluster import cluster_findings
from app.dedup.submission import (
    DuplicateRiskScorer,
    score_finding_submission_risk,
    evaluate_submission_quality,
)


# ---------------------------------------------------------------------------
# 1. Tests for extract_endpoint_shape
# ---------------------------------------------------------------------------

class TestExtractEndpointShape:
    """Test URL normalization into structural endpoint shapes."""

    def test_integer_id_collapsing(self):
        url1 = "https://example.com/api/v1/users/42/profile"
        url2 = "https://example.com/api/v1/users/9999/profile"
        shape1 = extract_endpoint_shape(url1)
        shape2 = extract_endpoint_shape(url2)
        assert shape1 == "example.com/api/v1/users/{id}/profile"
        assert shape1 == shape2

    def test_uuid_collapsing(self):
        url = "https://api.target.com/orders/550e8400-e29b-41d4-a716-446655440000/status"
        shape = extract_endpoint_shape(url)
        assert shape == "api.target.com/orders/{uuid}/status"

    def test_hex_hash_collapsing(self):
        # 32 hex chars (MD5) and 64 hex chars (SHA256)
        url_md5 = "https://cdn.target.com/files/0123456789abcdef0123456789abcdef/view"
        url_sha = "https://cdn.target.com/files/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855/view"
        assert extract_endpoint_shape(url_md5) == "cdn.target.com/files/{hash}/view"
        assert extract_endpoint_shape(url_sha) == "cdn.target.com/files/{hash}/view"

    def test_query_parameter_sorting(self):
        url1 = "https://example.com/search?q=test&page=2&sort=asc"
        url2 = "https://example.com/search?sort=desc&q=security&page=1"
        shape1 = extract_endpoint_shape(url1)
        shape2 = extract_endpoint_shape(url2)
        assert shape1 == "example.com/search?page&q&sort"
        assert shape2 == "example.com/search?page&q&sort"
        assert shape1 == shape2

    def test_relative_paths(self):
        url = "/api/v2/items/123/comments"
        shape = extract_endpoint_shape(url)
        assert shape == "/api/v2/items/{id}/comments"

    def test_empty_and_root(self):
        assert extract_endpoint_shape("") == "root"
        assert extract_endpoint_shape("https://example.com/") == "example.com/"
        assert extract_endpoint_shape("https://example.com") == "example.com/"


# ---------------------------------------------------------------------------
# 2. Tests for SimHash and Hamming Distance
# ---------------------------------------------------------------------------

class TestSimHashComputation:
    """Test 64-bit SimHash generation and Hamming distance calculation."""

    def test_deterministic_simhash(self):
        h1 = compute_finding_simhash("cors", "CORS Misconfiguration", "example.com/api/{id}", "Access-Control-Allow-Origin: *")
        h2 = compute_finding_simhash("cors", "CORS Misconfiguration", "example.com/api/{id}", "Access-Control-Allow-Origin: *")
        assert h1 == h2
        assert 0 <= h1 < (1 << 64)

    def test_hamming_distance_identical(self):
        h = compute_finding_simhash("cors", "CORS Misconfiguration", "example.com/api/{id}", "evidence")
        assert simhash_hamming_distance(h, h) == 0
        assert simhash_similarity(h, h) == 1.0

    def test_hamming_distance_near_duplicates(self):
        # Near duplicate findings differing only in evidence detail
        h1 = compute_finding_simhash(
            "headers",
            "Missing Security Header X-Frame-Options",
            "example.com/dashboard",
            "Header X-Frame-Options is missing on GET /dashboard request 1",
        )
        h2 = compute_finding_simhash(
            "headers",
            "Missing Security Header X-Frame-Options",
            "example.com/dashboard",
            "Header X-Frame-Options is missing on GET /dashboard request 2",
        )
        dist = simhash_hamming_distance(h1, h2)
        assert dist <= 4
        assert simhash_similarity(h1, h2) >= 0.9375

    def test_hamming_distance_dissimilar_findings(self):
        h1 = compute_finding_simhash(
            "vulns",
            "SQL Injection in login parameter username",
            "example.com/login",
            "syntax error at line 1 in postgres query",
        )
        h2 = compute_finding_simhash(
            "secrets",
            "AWS Access Key ID exposed in JavaScript bundle",
            "cdn.example.com/static/app.js",
            "AKIAIOSFODNN7EXAMPLE matched AWS key pattern",
        )
        dist = simhash_hamming_distance(h1, h2)
        assert dist > 4


# ---------------------------------------------------------------------------
# 3. Tests for Finding Clustering (20 Findings Collapse)
# ---------------------------------------------------------------------------

class TestFindingClustering:
    """Test clustering collapses near-duplicate findings into representative findings."""

    def test_twenty_findings_collapse_to_single_grouped_finding(self):
        """20 findings across different ID URLs collapse into 1 grouped finding with 20 grouped_locations."""
        findings = [
            Finding(
                severity=Severity.HIGH,
                category="auth",
                title="BOLA Broken Object Level Authorization on User Profile",
                description="User profile endpoints return unauthorized data.",
                evidence="HTTP/1.1 200 OK Content-Type: application/json sensitive user data exposed",
                url=f"https://target.com/api/v1/users/{i}/profile",
                confidence="POSSIBLE",
                metadata={"method": "GET", "parameter": f"id={i}"},
            )
            for i in range(1, 21)
        ]

        clustered = cluster_findings(findings, max_distance=4)

        assert len(clustered) == 1, f"Expected 1 grouped finding, got {len(clustered)}"
        rep = clustered[0]

        # Representative preserves primary details
        assert rep.title == "BOLA Broken Object Level Authorization on User Profile"
        assert rep.severity == Severity.HIGH
        assert rep.category == "auth"

        # Check grouped locations
        assert "grouped_locations" in rep.metadata
        grouped_locs = rep.metadata["grouped_locations"]
        assert len(grouped_locs) == 20

        # Verify each location entry contract
        for idx, loc in enumerate(grouped_locs, start=1):
            assert loc["url"] == f"https://target.com/api/v1/users/{idx}/profile"
            assert loc["method"] == "GET"
            assert loc["parameter"] == f"id={idx}"
            assert "sensitive user data exposed" in loc["evidence"]

    def test_distinct_vulnerabilities_remain_separate(self):
        f1 = Finding(
            severity=Severity.HIGH,
            category="vulns",
            title="SQL Injection in login",
            description="SQLi detected",
            evidence="syntax error",
            url="https://target.com/login",
            metadata={"parameter": "user"},
        )
        f2 = Finding(
            severity=Severity.LOW,
            category="headers",
            title="Missing Content-Security-Policy",
            description="CSP header missing",
            evidence="CSP absent",
            url="https://target.com/home",
            metadata={"parameter": ""},
        )
        clustered = cluster_findings([f1, f2], max_distance=4)
        assert len(clustered) == 2


# ---------------------------------------------------------------------------
# 4. Tests for Submission-Quality Guard & Duplicate Risk Scoring
# ---------------------------------------------------------------------------

class TestSubmissionQualityGuard:
    """Test DuplicateRiskScorer against intel.db and fixture DBs."""

    def test_scoring_against_bundled_intel_db(self):
        """Test scoring using real bundled intel.db if present."""
        scorer = DuplicateRiskScorer()
        if not os.path.exists(scorer.db_path):
            pytest.skip("Bundled intel.db not present at default path")

        # Test against known HackerOne disclosure pattern (CORS)
        risk = scorer.calculate_risk(
            title="CORS Misconfiguration on api endpoint",
            cwe="CWE-284",
            tech_stack=["cors"],
        )
        assert isinstance(risk["score"], float)
        assert risk["risk_level"] in {"MEDIUM", "HIGH"}
        assert risk["similar_disclosures_count"] > 0
        assert len(risk["top_disclosures"]) > 0
        assert "Matched" in risk["rationale"]

    def test_score_finding_attaches_metadata_and_flags_missing_proof(self):
        """Test that score_finding attaches duplicate_risk and flags proof absence."""
        scorer = DuplicateRiskScorer()
        finding = Finding(
            severity=Severity.HIGH,
            category="cors",
            title="CORS Misconfiguration on api endpoint",
            description="CORS vulnerability",
            evidence="Access-Control-Allow-Origin: *",
            url="https://target.com/api/data",
            metadata={"cwe": "CWE-284", "tech_stack": ["cors"]},
        )

        scorer.score_finding(finding)

        assert "duplicate_risk" in finding.metadata
        assert finding.metadata["duplicate_risk"]["score"] > 0.0
        # Proof was not attached -> should be flagged
        assert "NO_PROOF_ATTACHED" in finding.metadata["submission_flags"]
        assert finding.metadata["flagged"] is True
        assert finding.metadata["submission_ready"] is False

    def test_proof_attached_clears_proof_flag(self):
        """When proof_attached is True, NO_PROOF_ATTACHED flag is not raised."""
        scorer = DuplicateRiskScorer()
        finding = Finding(
            severity=Severity.LOW,
            category="headers",
            title="Obscure Custom Header Disclosed",
            description="Informational disclosure",
            url="https://target.com/custom",
            metadata={"proof_attached": True, "cwe": "CWE-200"},
        )

        scorer.score_finding(finding)
        assert "NO_PROOF_ATTACHED" not in finding.metadata["submission_flags"]

    def test_score_finding_with_tech_stack_kwarg(self):
        """Verify score_finding accepts explicit tech_stack keyword argument without TypeError."""
        scorer = DuplicateRiskScorer()
        finding = Finding(
            severity=Severity.HIGH,
            category="vulns",
            title="SQL Injection in Login Form",
            description="SQLi detected",
            url="https://target.com/login",
            metadata={"cwe": "CWE-89"},
        )
        # Should execute cleanly without raising TypeError: unexpected keyword argument 'tech_stack'
        scorer.score_finding(finding, tech_stack=["PostgreSQL", "Django", "Python"])
        assert "duplicate_risk" in finding.metadata

    def test_scoring_with_sqlite_fixture(self):
        """Test DuplicateRiskScorer with a temporary SQLite database fixture."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
            db_path = tf.name

        try:
            conn = sqlite3.connect(db_path)
            conn.execute("""
                CREATE TABLE h1_disclosures (
                    id TEXT PRIMARY KEY,
                    program TEXT NOT NULL,
                    title TEXT NOT NULL,
                    link TEXT NOT NULL,
                    upvotes INTEGER NOT NULL,
                    bounty REAL NOT NULL,
                    vuln_type TEXT NOT NULL,
                    cwe TEXT NOT NULL,
                    tech_stack TEXT NOT NULL
                )
            """)
            conn.execute("""
                INSERT INTO h1_disclosures VALUES (
                    'H1-1001', 'Acme Corp', 'SSRF via Webhook URL Parameter',
                    'hackerone.com/reports/1001', 50, 2500.0, 'SSRF', 'CWE-918', '["webhook", "redis"]'
                )
            """)
            conn.commit()
            conn.close()

            scorer = DuplicateRiskScorer(db_path=db_path)
            risk = scorer.calculate_risk(
                title="SSRF via Webhook URL Parameter",
                cwe="CWE-918",
                tech_stack=["webhook"],
                program="Acme Corp",
            )
            assert risk["score"] >= 0.70
            assert risk["risk_level"] == "HIGH"
            assert risk["similar_disclosures_count"] == 1
            assert risk["top_disclosures"][0]["id"] == "H1-1001"

            finding = Finding(
                severity=Severity.HIGH,
                category="vulns",
                title="SSRF via Webhook URL Parameter",
                description="SSRF in webhook processor",
                url="https://acme.com/webhook",
                metadata={"cwe": "CWE-918", "proof_attached": True},
            )
            scorer.score_finding(finding, program="Acme Corp")
            assert "HIGH_DUPLICATE_RISK" in finding.metadata["submission_flags"]
            assert finding.metadata["is_duplicate_risk"] is True
        finally:
            if os.path.exists(db_path):
                os.unlink(db_path)

    def test_missing_database_handled_gracefully(self):
        """Scorer handles nonexistent database path without raising exceptions."""
        non_existent_path = "non_existent_db_path_987654.db"
        scorer = DuplicateRiskScorer(db_path=non_existent_path)

        risk = scorer.calculate_risk("Any Vulnerability Title", cwe="CWE-79")
        assert risk["score"] == 0.0
        assert risk["risk_level"] == "LOW"
        assert risk["similar_disclosures_count"] == 0
        assert risk["top_disclosures"] == []

        finding = Finding(
            severity=Severity.MEDIUM,
            category="vulns",
            title="Reflected XSS in search",
            description="XSS finding",
            url="https://target.com/search?q=1",
            metadata={},
        )
        scorer.score_finding(finding)
        assert finding.metadata["duplicate_risk"]["score"] == 0.0
        assert "NO_PROOF_ATTACHED" in finding.metadata["submission_flags"]

    def test_evaluate_submission_quality_helper(self):
        finding = Finding(
            severity=Severity.MEDIUM,
            category="info",
            title="Informational header",
            description="Info",
            url="https://target.com/info",
            metadata={"proof_attached": True},
        )
        quality = evaluate_submission_quality(finding)
        assert "ready" in quality
        assert "flags" in quality
        assert "duplicate_risk" in quality

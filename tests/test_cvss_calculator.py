"""
Unit tests for the CVSS 3.1 mathematical calculator and vector parser.
"""

from app.cvss import calculate_cvss31, parse_vector, CVSSScore, score_finding
from app.models import Finding, Severity


def test_cvss_critical_rce_vector():
    # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> 9.8
    score, impact, exploit = calculate_cvss31(
        av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H"
    )
    assert score == 9.8
    assert impact == 5.9
    assert exploit == 3.9


def test_cvss_xss_scope_change_vector():
    # Stored/Reflected XSS with Scope Changed:
    # CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N -> 6.1
    score, impact, exploit = calculate_cvss31(
        av="N", ac="L", pr="N", ui="R", s="C", c="L", i="L", a="N"
    )
    assert score == 6.1
    assert exploit == 2.8


def test_cvss_parse_vector():
    vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    metrics = parse_vector(vec)
    assert metrics["AV"] == "N"
    assert metrics["AC"] == "L"
    assert metrics["PR"] == "N"
    assert metrics["UI"] == "N"
    assert metrics["S"] == "U"
    assert metrics["C"] == "H"
    assert metrics["I"] == "H"
    assert metrics["A"] == "H"


def test_cvss_score_from_vector():
    cs = CVSSScore.from_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert cs.score == 9.8
    assert cs.label == "Critical"
    assert cs.impact == 5.9
    assert cs.exploitability == 3.9


def test_score_finding_cwe():
    f = Finding(
        severity=Severity.HIGH,
        category="vulns",
        title="SQL Injection",
        description="SQL injection in id param",
        metadata={"cwe": "CWE-89"},
    )
    cs = score_finding(f)
    assert cs.score == 9.8
    assert cs.label == "Critical"
    assert "CVSS:3.1" in cs.vector

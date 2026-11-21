"""
Unit tests for WebRipper Recon 5.0 Scenario Intelligence Engine and Scanner (#21).

Tests:
- ScenarioRecipe validation, serialization, and deserialization
- Catalog integrity and seed recipe definitions
- SQLite FTS5 database initialization and search
- Technology-filtered queries
- ScenarioScanner targeted canary probing and finding generation
"""

from unittest.mock import MagicMock, patch
import pytest

from app.intelligence.models import ScenarioRecipe
from app.intelligence.catalog import get_seed_scenarios
from app.intelligence.engine import ScenarioEngine
from app.models import RipperSettings, RipReport, FileResult
from app.scanners.scenarios import ScenarioScanner


def test_scenario_recipe_model():
    """Verify ScenarioRecipe instantiates and serializes correctly."""
    recipe = ScenarioRecipe(
        id="test-001",
        title="Test GraphQL Introspection Enabled",
        tech_stack=["graphql", "api"],
        category="graphql",
        cwe="CWE-200",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        probe_method="POST",
        probe_path="/graphql",
        probe_headers={"Content-Type": "application/json"},
        probe_body='{"query": "{ __schema { types { name } } }"}',
        match_status=[200],
        match_regex=r'__schema',
        negative_regex="",
        bounty_reference="HackerOne #12345 ($1,500 Payout)",
        author_insight="GraphQL schema introspection exposes all database types.",
        remediation="Disable schema introspection in production.",
    )

    data = recipe.to_dict()
    assert data["id"] == "test-001"
    assert data["probe_method"] == "POST"

    loaded = ScenarioRecipe.from_dict(data)
    assert loaded.id == "test-001"
    assert loaded.probe_path == "/graphql"
    assert loaded.match_status == [200]


def test_seed_catalog_validity():
    """Verify seed scenario recipes in catalog are well-formed and non-empty."""
    scenarios = get_seed_scenarios()
    assert len(scenarios) >= 10

    ids = set()
    for sc in scenarios:
        assert sc.id not in ids, f"Duplicate scenario ID: {sc.id}"
        ids.add(sc.id)
        assert sc.title
        assert len(sc.tech_stack) > 0
        assert sc.probe_path
        assert sc.match_status
        assert sc.cvss_vector.startswith("CVSS:3.1")


def test_scenario_engine_sqlite_fts(tmp_path):
    """Verify ScenarioEngine initializes SQLite FTS5 database and executes search."""
    db_file = str(tmp_path / "test_intel.db")
    engine = ScenarioEngine(db_path=db_file)

    # Search by keyword
    results = engine.search("Next.js")
    assert len(results) > 0
    assert any("nextjs" in r.id or "Next.js" in r.title for r in results)

    # Search by technology tag
    tech_results = engine.find_scenarios_for_tech(["supabase"])
    assert len(tech_results) > 0
    assert any("supabase" in r.tech_stack for r in tech_results)

    # Empty search fallback
    empty_results = engine.search("xyznonexistentterm12345")
    assert len(empty_results) == 0


def test_scenario_engine_full_intel_datasets():
    """Verify ScenarioEngine queries bundled HackerOne, CISA KEV, and Takeover datasets."""
    from app.intelligence.engine import get_engine
    engine = get_engine()

    # 1. HackerOne reports search
    h1 = engine.search_hackerone("Shopify", limit=5)
    assert len(h1) > 0
    assert any("Shopify" in r["program"] or "Shopify" in r["title"] for r in h1)

    # 2. CISA KEV search
    cisa = engine.search_cisa_kev("Apache", limit=5)
    assert len(cisa) > 0
    assert any("Apache" in r["vendor"] or "Apache" in r["product"] for r in cisa)

    # 3. Subdomain Takeover fingerprints
    takeovers = engine.get_takeovers()
    assert len(takeovers) >= 50
    assert any("github.io" in to["cnames"] or "herokuapp.com" in to["cnames"] for to in takeovers)

    # 4. Unified FTS search
    unified = engine.search_unified("GraphQL", limit=5)
    assert len(unified) > 0


def test_scenario_scanner_detects_technologies():
    """Verify _detect_technologies extracts technologies from crawled assets."""
    rip_report = RipReport(url="https://target.local")
    rip_report.downloaded_files = [
        FileResult(url="https://target.local/_next/static/chunks/app.js", local_path="chunks/app.js", status=200, content_type="application/javascript"),
        FileResult(url="https://target.local/wp-content/themes/style.css", local_path="themes/style.css", status=200, content_type="text/css"),
        FileResult(url="https://target.local/api/graphql", local_path="api/graphql", status=200, content_type="application/json"),
    ]

    settings = RipperSettings(url="https://target.local", output_dir=".")
    scanner = ScenarioScanner(rip_report=rip_report, settings=settings)

    techs = scanner._detect_technologies()
    assert "nextjs" in techs
    assert "wordpress" in techs
    assert "graphql" in techs


def test_scenario_scanner_probe_execution(tmp_path):
    """Verify ScenarioScanner matches tech stack and fires targeted canary probes."""
    rip_report = RipReport(url="https://target.local")
    rip_report.downloaded_files = [
        FileResult(url="https://target.local/_next/static/chunks/main.js", local_path="chunks/main.js", status=200, content_type="application/javascript"),
    ]

    settings = RipperSettings(
        url="https://target.local",
        output_dir=str(tmp_path),
        scan_scenarios=True,
    )

    events = []
    scanner = ScenarioScanner(
        rip_report=rip_report,
        settings=settings,
        progress_callback=lambda ev: events.append(ev),
    )

    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.headers = {"content-type": "application/json"}
    mock_response.read.return_value = b'{"version":3,"sources":["src/index.tsx"]}'
    mock_response.__enter__.return_value = mock_response

    with patch("app.scanners.scenarios.urlopen", return_value=mock_response):
        scan_result = scanner.scan()

    assert scan_result.scanner_name == "scenarios"
    assert len(scan_result.findings) > 0
    finding = scan_result.findings[0]
    assert "Scenario:" in finding.title
    assert "cvss" in finding.metadata


def test_nuclei_templates_intelligence_queries():
    """Verify ScenarioEngine queries bundled Nuclei community templates catalog."""
    from app.intelligence.engine import get_engine
    engine = get_engine()

    # 1. Search Nuclei templates by keyword
    templates = engine.search_nuclei("Spring", limit=5)
    assert len(templates) > 0
    assert any("spring" in t["name"].lower() or "spring" in t["id"].lower() for t in templates)

    # 2. Search Nuclei templates by severity
    crit_templates = engine.search_nuclei("RCE", severity="critical", limit=5)
    assert len(crit_templates) > 0
    assert all(t["severity"] == "critical" for t in crit_templates)


def test_portswigger_research_intelligence_queries():
    """Verify ScenarioEngine queries PortSwigger web security research methodologies."""
    from app.intelligence.engine import get_engine
    engine = get_engine()

    # Search PortSwigger research
    research = engine.search_portswigger("Request Smuggling", limit=5)
    assert len(research) > 0
    assert any("smuggling" in r["title"].lower() or "smuggling" in r["category"].lower() for r in research)

    proto = engine.search_portswigger("Prototype Pollution", limit=2)
    assert len(proto) > 0
    assert any("prototype" in p["title"].lower() for p in proto)


def test_cli_intel_query_multi_source(capsys):
    """Verify CLI --intel-query surfaces all intelligence sources."""
    from app.cli import _handle_intel_query
    ret = _handle_intel_query("Spring")
    assert ret == 0
    captured = capsys.readouterr().out
    assert "Curated Scenario Canary Recipes" in captured
    assert "HackerOne Disclosed Reports" in captured
    assert "CISA Known Exploited Vulnerabilities" in captured


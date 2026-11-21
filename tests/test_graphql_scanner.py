"""
Unit and integration tests for GraphQL Schema & Authorization Auditor.

Tests local mock HTTP server on 127.0.0.1:0 with:
  a) A GraphQL mock endpoint exposing introspection and batching.
  b) A hardened GraphQL mock endpoint enforcing depth limit and rejecting introspection.
100% offline, deterministic tests.
"""

from __future__ import annotations

import http.server
import json
import threading
import urllib.parse
from typing import Any, Dict, List

import pytest

from app.models import Finding, RipReport, RipperSettings, Severity
from app.scanners.graphql import GraphQLScanner


def _calculate_query_depth(query_str: str) -> int:
    """Calculate maximum nesting depth of curly braces in a GraphQL query string."""
    max_d = 0
    cur_d = 0
    for char in query_str:
        if char == "{":
            cur_d += 1
            if cur_d > max_d:
                max_d = cur_d
        elif char == "}":
            if cur_d > 0:
                cur_d -= 1
    return max_d


class MockGraphQLHandler(http.server.BaseHTTPRequestHandler):
    """
    Mock HTTP server providing both:
      a) Unhardened GraphQL endpoint (/graphql, /api/graphql, /v1/graphql, /gql, /query):
         - Introspection enabled
         - Batching enabled
         - Depth limit missing
         - Object authorization broken (unauthenticated user leak)
      b) Hardened GraphQL endpoint (/hardened/graphql):
         - Introspection rejected
         - Field suggestions enabled for unrecognized fields
         - Depth limit enforced (depth > 5 rejected)
         - Batching rejected
         - Object authorization enforced (requires Authorization header)
    """

    def log_message(self, format: str, *args: Any) -> None:
        # Silence HTTP server logs during pytest runs
        pass

    def do_POST(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        content_length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(content_length)

        try:
            body_json = json.loads(body_bytes.decode("utf-8"))
        except Exception:
            body_json = None

        # Route to hardened endpoint
        if path.startswith("/hardened"):
            self._handle_hardened(body_json)
        elif path in ("/graphql", "/api/graphql", "/v1/graphql", "/gql", "/query", "/custom/gql"):
            self._handle_unhardened(body_json)
        else:
            self._respond_json(404, {"error": "Not Found"})

    def _handle_unhardened(self, body_json: Any) -> None:
        """Handle queries for the unhardened GraphQL endpoint."""
        # Audit 4: Batching support (JSON array)
        if isinstance(body_json, list):
            responses = []
            for item in body_json:
                responses.append({"data": {"__typename": "Query"}})
            self._respond_json(200, responses)
            return

        if not isinstance(body_json, dict):
            self._respond_json(400, {"errors": [{"message": "Invalid query payload"}]})
            return

        query_str = body_json.get("query", "")

        # Audit 1: Introspection query enabled
        if "__schema" in query_str:
            resp = {
                "data": {
                    "__schema": {
                        "queryType": {"name": "Query"},
                        "mutationType": {"name": "Mutation"},
                        "subscriptionType": None,
                        "types": [
                            {
                                "name": "Query",
                                "kind": "OBJECT",
                                "fields": [
                                    {"name": "user"},
                                    {"name": "orders"},
                                    {"name": "publicInfo"},
                                ],
                            },
                            {
                                "name": "User",
                                "kind": "OBJECT",
                                "fields": [
                                    {"name": "id"},
                                    {"name": "email"},
                                    {"name": "name"},
                                    {"name": "role"},
                                ],
                            },
                            {
                                "name": "Order",
                                "kind": "OBJECT",
                                "fields": [
                                    {"name": "id"},
                                    {"name": "total"},
                                    {"name": "userId"},
                                ],
                            },
                            {"name": "String", "kind": "SCALAR"},
                            {"name": "Int", "kind": "SCALAR"},
                            {"name": "Boolean", "kind": "SCALAR"},
                        ],
                    }
                }
            }
            self._respond_json(200, resp)
            return

        # Audit 5: Object-level authorization validation (leaks private record without auth)
        if "user" in query_str:
            resp = {
                "data": {
                    "user": {
                        "id": "1",
                        "email": "victim@domain.local",
                        "name": "Alice Admin",
                        "role": "admin",
                    }
                }
            }
            self._respond_json(200, resp)
            return

        # Audit 3: Deep nested query accepted without depth limit
        if "DeepAudit" in query_str or _calculate_query_depth(query_str) > 5:
            self._respond_json(200, {"data": {"depthTest": "unrestricted_success"}})
            return

        # Default __typename probe
        self._respond_json(200, {"data": {"__typename": "Query"}})

    def _handle_hardened(self, body_json: Any) -> None:
        """Handle queries for the hardened GraphQL endpoint."""
        # Audit 4: Batching rejected
        if isinstance(body_json, list):
            self._respond_json(
                400,
                {"errors": [{"message": "Batching is not supported: operation array rejected"}]},
            )
            return

        if not isinstance(body_json, dict):
            self._respond_json(400, {"errors": [{"message": "Invalid query payload"}]})
            return

        query_str = body_json.get("query", "")

        # Audit 3: Depth limiting enforced (depth > 5)
        depth = _calculate_query_depth(query_str)
        if depth > 5:
            self._respond_json(
                400,
                {
                    "errors": [
                        {
                            "message": f"Query depth limit of 5 exceeded (calculated depth was {depth})",
                            "extensions": {"code": "DEPTH_LIMIT_EXCEEDED"},
                        }
                    ]
                },
            )
            return

        # Audit 1: Introspection rejected
        if "__schema" in query_str:
            self._respond_json(
                400,
                {
                    "errors": [
                        {
                            "message": (
                                "GraphQL introspection is not allowed by Apollo Server, "
                                "but the query contained __schema"
                            )
                        }
                    ]
                },
            )
            return

        # Audit 2: Field suggestion heuristics active
        if "usr" in query_str:
            self._respond_json(
                400,
                {
                    "errors": [
                        {
                            "message": 'Cannot query field "usr" on type "Query". Did you mean "user" or "users"?'
                        }
                    ]
                },
            )
            return

        if "prof" in query_str:
            self._respond_json(
                400,
                {
                    "errors": [
                        {
                            "message": 'Cannot query field "prof" on type "Query". Did you mean "profile"?'
                        }
                    ]
                },
            )
            return

        if "__schem" in query_str:
            self._respond_json(
                400,
                {
                    "errors": [
                        {
                            "message": 'Cannot query field "__schem" on type "Query". Did you mean "__schema"?'
                        }
                    ]
                },
            )
            return

        # Audit 5: Object-level authorization enforced
        if "user" in query_str or "profile" in query_str:
            auth_header = self.headers.get("Authorization", "")
            if auth_header == "Bearer valid-token":
                self._respond_json(
                    200,
                    {"data": {"user": {"id": "1", "name": "Alice"}}},
                )
            else:
                self._respond_json(
                    401,
                    {
                        "errors": [
                            {"message": "Unauthorized: Authentication required to access user resource"}
                        ],
                        "data": None,
                    },
                )
            return

        # Default __typename probe
        self._respond_json(200, {"data": {"__typename": "Query"}})

    def _respond_json(self, status: int, data: Any) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def mock_graphql_server():
    """Start local mock GraphQL HTTP server on 127.0.0.1:0."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), MockGraphQLHandler)
    host, port = server.server_address[0], server.server_address[1]
    base_url = f"http://{host}:{port}"

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield base_url

    server.shutdown()
    server.server_close()
    thread.join(timeout=2.0)


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------

def test_endpoint_detection_candidate_paths(mock_graphql_server):
    """Scanner detects GraphQL service endpoints across candidate paths."""
    settings = RipperSettings(url=mock_graphql_server)
    report = RipReport(url=mock_graphql_server)
    scanner = GraphQLScanner(report, settings)

    result = scanner.scan()

    discovery_findings = [
        f for f in result.findings if "GraphQL Service Endpoint Discovered" in f.title
    ]
    assert len(discovery_findings) >= 1
    # Check that discovered endpoints are marked with verified confidence & proof
    first_disco = discovery_findings[0]
    assert first_disco.severity == Severity.INFO
    assert first_disco.confidence == "VERIFIED"
    assert first_disco.metadata.get("proof_attached") is True
    assert "proof" in first_disco.metadata
    assert first_disco.metadata["proof"]["request"]["method"] == "POST"


def test_audit1_schema_introspection_enabled(mock_graphql_server):
    """Audit 1: Schema introspection query (__schema) exposes types and produces VERIFIED finding."""
    endpoint_url = f"{mock_graphql_server}/graphql"
    settings = RipperSettings(url=endpoint_url)
    report = RipReport(url=endpoint_url)
    scanner = GraphQLScanner(report, settings)

    result = scanner.scan()

    intro_findings = [
        f for f in result.findings if f.title == "GraphQL Schema Introspection Enabled"
    ]
    assert len(intro_findings) == 1
    finding = intro_findings[0]
    assert finding.severity == Severity.MEDIUM
    assert finding.confidence == "VERIFIED"
    assert finding.metadata.get("proof_attached") is True

    proof = finding.metadata.get("proof", {})
    assert proof.get("validator") == "graphql"
    assert "request" in proof and "response" in proof and "observed_delta" in proof
    assert proof["request"]["method"] == "POST"

    types = finding.metadata.get("types", [])
    custom_types = finding.metadata.get("custom_types", [])
    assert "User" in types or "User" in custom_types
    assert "Order" in types or "Order" in custom_types


def test_audit2_field_suggestions_heuristic(mock_graphql_server):
    """Audit 2: Field suggestion heuristics map entity types when introspection is rejected."""
    hardened_url = f"{mock_graphql_server}/hardened/graphql"
    settings = RipperSettings(url=hardened_url)
    report = RipReport(url=hardened_url)
    scanner = GraphQLScanner(report, settings)

    result = scanner.scan()

    # Introspection should NOT be reported on hardened endpoint
    intro_findings = [
        f for f in result.findings if f.title == "GraphQL Schema Introspection Enabled"
    ]
    assert len(intro_findings) == 0

    # Field suggestions finding should be detected with VERIFIED confidence
    sugg_findings = [
        f for f in result.findings if f.title == "GraphQL Field Suggestions Enabled"
    ]
    assert len(sugg_findings) == 1
    finding = sugg_findings[0]
    assert finding.severity == Severity.LOW
    assert finding.confidence == "VERIFIED"
    assert finding.metadata.get("proof_attached") is True

    suggested = finding.metadata.get("suggested_fields", [])
    assert "user" in suggested or "users" in suggested
    assert "profile" in suggested

    proof = finding.metadata.get("proof", {})
    assert "observed_delta" in proof
    assert "suggested" in proof["observed_delta"] or "suggestions" in proof["observed_delta"]


def test_audit3_query_depth_limiting(mock_graphql_server):
    """Audit 3: Query depth limiting is verified on unhardened vs hardened endpoints."""
    # 1. Unhardened endpoint: Depth limit is missing -> Finding generated
    unhardened_url = f"{mock_graphql_server}/graphql"
    scanner_unhardened = GraphQLScanner(
        RipReport(url=unhardened_url),
        RipperSettings(url=unhardened_url),
    )
    res_unhardened = scanner_unhardened.scan()
    depth_missing = [
        f for f in res_unhardened.findings if f.title == "GraphQL Query Depth Limit Missing"
    ]
    assert len(depth_missing) == 1
    finding = depth_missing[0]
    assert finding.severity == Severity.MEDIUM
    assert finding.confidence == "VERIFIED"
    assert finding.metadata.get("proof_attached") is True
    assert finding.metadata.get("depth_enforced") is False

    # 2. Hardened endpoint: Depth limit of 5 is enforced -> No finding generated
    hardened_url = f"{mock_graphql_server}/hardened/graphql"
    scanner_hardened = GraphQLScanner(
        RipReport(url=hardened_url),
        RipperSettings(url=hardened_url),
    )
    res_hardened = scanner_hardened.scan()
    hardened_depth_missing = [
        f for f in res_hardened.findings if f.title == "GraphQL Query Depth Limit Missing"
    ]
    assert len(hardened_depth_missing) == 0


def test_audit4_query_batching_verification(mock_graphql_server):
    """Audit 4: Query batching verification on unhardened vs hardened endpoints."""
    # 1. Unhardened endpoint: Batching enabled -> Finding generated with VERIFIED confidence
    unhardened_url = f"{mock_graphql_server}/graphql"
    scanner_unhardened = GraphQLScanner(
        RipReport(url=unhardened_url),
        RipperSettings(url=unhardened_url),
    )
    res_unhardened = scanner_unhardened.scan()
    batch_findings = [
        f for f in res_unhardened.findings if f.title == "GraphQL Query Batching Enabled"
    ]
    assert len(batch_findings) == 1
    finding = batch_findings[0]
    assert finding.severity == Severity.LOW
    assert finding.confidence == "VERIFIED"
    assert finding.metadata.get("proof_attached") is True
    assert finding.metadata.get("batch_size") == 3

    # 2. Hardened endpoint: Batching rejected -> No batching finding generated
    hardened_url = f"{mock_graphql_server}/hardened/graphql"
    scanner_hardened = GraphQLScanner(
        RipReport(url=hardened_url),
        RipperSettings(url=hardened_url),
    )
    res_hardened = scanner_hardened.scan()
    hardened_batch = [
        f for f in res_hardened.findings if f.title == "GraphQL Query Batching Enabled"
    ]
    assert len(hardened_batch) == 0


def test_audit5_object_level_authorization(mock_graphql_server):
    """Audit 5: Object-level authorization validation (BOLA / IDOR)."""
    # 1. Unhardened endpoint: Unauthenticated request leaks private user record -> HIGH severity finding
    unhardened_url = f"{mock_graphql_server}/graphql"
    scanner_unhardened = GraphQLScanner(
        RipReport(url=unhardened_url),
        RipperSettings(url=unhardened_url),
    )
    res_unhardened = scanner_unhardened.scan()
    bola_findings = [
        f for f in res_unhardened.findings if "GraphQL Broken Object-Level Authorization" in f.title
    ]
    assert len(bola_findings) >= 1
    finding = bola_findings[0]
    assert finding.severity == Severity.HIGH
    assert finding.confidence == "VERIFIED"
    assert finding.metadata.get("proof_attached") is True

    proof = finding.metadata.get("proof", {})
    assert "observed_delta" in proof
    assert "private" in proof["observed_delta"].lower() or "victim@domain.local" in str(proof["response"])

    # 2. Hardened endpoint: Unauthenticated request rejected -> No unauthorized finding
    hardened_url = f"{mock_graphql_server}/hardened/graphql"
    scanner_hardened = GraphQLScanner(
        RipReport(url=hardened_url),
        RipperSettings(url=hardened_url),
    )
    res_hardened = scanner_hardened.scan()
    hardened_bola = [
        f for f in res_hardened.findings if "GraphQL Broken Object-Level Authorization" in f.title
    ]
    assert len(hardened_bola) == 0


def test_offline_deterministic_execution(mock_graphql_server):
    """End-to-end audit scan executes 100% offline and deterministically."""
    settings = RipperSettings(url=f"{mock_graphql_server}/graphql", timeout=5)
    report = RipReport(url=f"{mock_graphql_server}/graphql")
    scanner = GraphQLScanner(report, settings)

    result = scanner.scan()

    assert result.scanner_name == "graphql"
    assert result.scan_time >= 0.0
    assert len(result.findings) >= 4  # Endpoint discovered, Introspection, Depth limit, Batching, BOLA

    # Ensure all findings meet confidence and proof mandates
    for finding in result.findings:
        if finding.confidence == "VERIFIED":
            assert finding.metadata.get("proof_attached") is True
            proof = finding.metadata.get("proof")
            assert isinstance(proof, dict)
            assert "request" in proof
            assert "response" in proof
            assert "observed_delta" in proof


def test_unreachable_target_handled_gracefully():
    """Unreachable target host handles network failure gracefully without unhandled exceptions."""
    # Port 59997 on localhost is not running any listener
    url = "http://127.0.0.1:59997"
    settings = RipperSettings(url=url, timeout=1)
    report = RipReport(url=url)
    scanner = GraphQLScanner(report, settings)

    result = scanner.scan()
    assert result.scanner_name == "graphql"
    assert len(result.findings) == 0


def test_non_graphql_server_not_falsely_detected():
    """A web server with no GraphQL endpoints produces 0 GraphQL findings."""
    class PlainHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Hello World</h1></body></html>")

        def do_POST(self):
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Not Found")

    plain_server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), PlainHandler)
    host, port = plain_server.server_address[0], plain_server.server_address[1]
    url = f"http://{host}:{port}"

    thread = threading.Thread(target=plain_server.serve_forever, daemon=True)
    thread.start()

    try:
        settings = RipperSettings(url=url, timeout=2)
        report = RipReport(url=url)
        scanner = GraphQLScanner(report, settings)
        result = scanner.scan()
        assert result.scanner_name == "graphql"
        disco = [f for f in result.findings if "GraphQL Service Endpoint Discovered" in f.title]
        assert len(disco) == 0
        assert len(result.findings) == 0
    finally:
        plain_server.shutdown()
        plain_server.server_close()
        thread.join(timeout=2.0)


def test_crawler_captured_requests_integrated(mock_graphql_server):
    """Scanner detects GraphQL endpoints recorded in crawl report captured_requests."""
    custom_endpoint = f"{mock_graphql_server}/custom/gql"
    settings = RipperSettings(url=mock_graphql_server, timeout=2)
    report = RipReport(
        url=mock_graphql_server,
        captured_requests=[{"url": custom_endpoint, "method": "POST"}],
    )
    scanner = GraphQLScanner(report, settings)

    result = scanner.scan()
    discovered_urls = [f.url for f in result.findings]
    assert custom_endpoint in discovered_urls


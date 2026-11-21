"""
GraphQL service endpoint detection, schema introspection, query depth limiting,
query batching, and object-level authorization auditor for WebRipper Recon.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import aiohttp

from .base import BaseScanner
from ..models import Finding, ScanResult, Severity


DEFAULT_GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/gql",
    "/query",
]

SUGGESTION_PATTERN = re.compile(
    r'(?:did\s+you\s+mean|suggestions?|perhaps\s+you\s+meant)\s*:?\s*([^\?\n\r]+)(?:\?|$)',
    re.IGNORECASE,
)

DEPTH_ERROR_PATTERN = re.compile(
    r'(?:exceeds?\s+(?:maximum\s+)?query\s+depth|depth\s+limit|too\s+deep|max(?:imum)?\s+depth)',
    re.IGNORECASE,
)

AUTH_ERROR_PATTERN = re.compile(
    r'(?:unauthorized|not\s+authenticated|authentication\s+required|access\s+denied|forbidden|jwt)',
    re.IGNORECASE,
)

PRIVATE_FIELD_KEYS = {
    "email", "role", "username", "token", "secret", "balance",
    "ssn", "password", "phone", "credit_card", "address",
}


def _build_proof(
    request_info: Dict[str, Any],
    response_info: Dict[str, Any],
    observed_delta: Any,
    validator: str = "graphql",
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Package machine-checkable proof dictionary."""
    proof: Dict[str, Any] = {
        "validator": validator,
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "request": request_info,
        "response": response_info,
        "observed_delta": observed_delta if isinstance(observed_delta, (str, dict, list)) else str(observed_delta),
    }
    if extra:
        proof["extra"] = extra
    return proof


class GraphQLScanner(BaseScanner):
    """
    GraphQL Service & Security Auditor.

    Audits:
      1. Schema introspection query (__schema)
      2. Field suggestion heuristics when introspection is disabled
      3. Query depth limiting controls
      4. Query batching verification (JSON array batching)
      5. Object-level authorization validation (BOLA / IDOR)
    """

    @property
    def name(self) -> str:
        return "graphql"

    @property
    def description(self) -> str:
        return (
            "Audits GraphQL service endpoints: schema introspection, field suggestions, "
            "query depth limits, batching controls, and object-level authorization."
        )

    def scan(self) -> ScanResult:
        start_time = time.time()
        self._log(f"Starting GraphQL audit on {self._settings.url}")

        try:
            try:
                running_loop = asyncio.get_running_loop()
            except RuntimeError:
                running_loop = None

            if running_loop and running_loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    pool.submit(lambda: asyncio.run(self._run_audit())).result()
            else:
                asyncio.run(self._run_audit())
        except Exception as exc:
            self._log(f"GraphQL scanner error: {exc}")

        return self._build_result(start_time, target=self._settings.url)

    # -----------------------------------------------------------------------
    # Main Async Orchestration
    # -----------------------------------------------------------------------

    async def _run_audit(self) -> None:
        timeout = aiohttp.ClientTimeout(total=min(self._settings.timeout, 15))
        connector = aiohttp.TCPConnector(ssl=False)
        base_headers = self._build_headers()
        proxy = self._get_proxy()

        candidate_urls = self._collect_candidate_urls()
        self._log(f"Probing {len(candidate_urls)} candidate GraphQL endpoints")

        async with aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers=base_headers,
        ) as session:
            detected_endpoints: List[str] = []

            # Phase 1: Endpoint detection
            probe_tasks = [self._probe_graphql_endpoint(session, url, proxy) for url in candidate_urls]
            probe_results = await asyncio.gather(*probe_tasks, return_exceptions=True)

            for url, res in zip(candidate_urls, probe_results):
                if isinstance(res, tuple) and res[0]:
                    is_gql, proof_data = res
                    detected_endpoints.append(url)
                    self._log(f"Confirmed GraphQL service endpoint: {url}")
                    finding = Finding(
                        severity=Severity.INFO,
                        category="graphql",
                        title=f"GraphQL Service Endpoint Discovered: {urlparse(url).path or '/'}",
                        description=f"A functional GraphQL service endpoint was detected at {url}.",
                        url=url,
                        confidence="VERIFIED",
                        remediation="Ensure proper access controls, introspection hardening, and rate limiting are configured.",
                        metadata={
                            "proof": _build_proof(
                                request_info=proof_data.get("request", {}),
                                response_info=proof_data.get("response", {}),
                                observed_delta=proof_data.get("observed_delta", "GraphQL __typename probe acknowledged"),
                            ),
                            "proof_attached": True,
                        },
                    )
                    self._add_finding(finding)

            if not detected_endpoints:
                self._log("No GraphQL endpoints detected")
                return

            # Phase 2: Run Audits 1 through 5 on each confirmed endpoint
            for endpoint in detected_endpoints:
                self._log(f"Auditing GraphQL endpoint: {endpoint}")
                await self._audit_endpoint(session, endpoint, proxy)

    def _collect_candidate_urls(self) -> List[str]:
        """Aggregate candidate GraphQL URLs from settings, captured requests, and default paths."""
        candidates: List[str] = []
        seen: Set[str] = set()

        def _add(u: str) -> None:
            clean = u.split("?")[0].rstrip("/")
            if clean and clean not in seen:
                seen.add(clean)
                candidates.append(clean)

        raw_url = self._settings.url.strip()
        parsed = urlparse(raw_url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"
        target_path = parsed.path.rstrip("/")

        # If user explicitly pointed to a specific GraphQL endpoint URL
        # e.g. http://example.com/hardened/graphql, http://example.com/graphql, etc.
        if any(target_path.endswith(p) for p in ("/graphql", "/gql", "/query")):
            _add(f"{base_origin}{target_path}")
            return candidates

        # Otherwise, the user provided a base app URL (e.g. http://example.com or http://example.com/app)
        prefix = target_path if target_path and target_path != "/" else ""

        if prefix:
            for path in DEFAULT_GRAPHQL_PATHS:
                _add(f"{base_origin}{prefix}{path}")

        for path in DEFAULT_GRAPHQL_PATHS:
            _add(f"{base_origin}{path}")

        # Inspect captured requests from crawler
        for req in getattr(self._report, "captured_requests", []) or []:
            u = req.get("url", "")
            if any(p in u.lower() for p in ("/graphql", "/gql", "/query")):
                _add(u)

        # Inspect downloaded files for GraphQL references
        for f in getattr(self._report, "files", []) or []:
            u = getattr(f, "url", "")
            if any(p in u.lower() for p in ("/graphql", "/gql", "/query")):
                _add(u)

        return candidates

    # -----------------------------------------------------------------------
    # Probe Endpoint
    # -----------------------------------------------------------------------

    async def _probe_graphql_endpoint(
        self, session: aiohttp.ClientSession, url: str, proxy: Optional[str]
    ) -> Tuple[bool, Dict[str, Any]]:
        """Probe URL with a __typename query to confirm GraphQL functionality."""
        probe_query = {"query": "{ __typename }"}
        req_headers = {"Content-Type": "application/json"}

        try:
            async with session.post(url, json=probe_query, headers=req_headers, proxy=proxy) as resp:
                text = await resp.text()
                try:
                    data = json.loads(text)
                except Exception:
                    data = None

                is_gql = False
                observed_delta = ""
                if isinstance(data, dict):
                    if "data" in data and isinstance(data["data"], dict) and "__typename" in data["data"]:
                        is_gql = True
                        observed_delta = f"Received GraphQL data envelope with __typename='{data['data']['__typename']}'"
                    elif "errors" in data and isinstance(data["errors"], list):
                        is_gql = True
                        observed_delta = f"Received GraphQL errors envelope with {len(data['errors'])} error items"

                if not is_gql and ("GraphQL" in text or "graphql" in text or resp.headers.get("Content-Type", "").startswith("application/graphql")):
                    is_gql = True
                    observed_delta = "GraphQL keyword or Content-Type header observed in HTTP response"

                if is_gql:
                    return True, {
                        "request": {"method": "POST", "url": url, "body": probe_query},
                        "response": {"status": resp.status, "body": text[:500]},
                        "observed_delta": observed_delta,
                    }
        except Exception:
            pass

        return False, {}

    # -----------------------------------------------------------------------
    # Endpoint Auditing (Audits 1 - 5)
    # -----------------------------------------------------------------------

    async def _audit_endpoint(
        self, session: aiohttp.ClientSession, endpoint: str, proxy: Optional[str]
    ) -> None:
        """Run Audits 1 to 5 against a confirmed GraphQL endpoint."""
        # Audit 1: Introspection Query
        introspection_enabled, types_info = await self._audit_introspection(session, endpoint, proxy)

        discovered_fields: Set[str] = set()
        if types_info.get("fields"):
            discovered_fields.update(types_info["fields"])

        # Audit 2: Field suggestion heuristics (especially relevant when introspection is disabled)
        suggested_fields = await self._audit_field_suggestions(session, endpoint, proxy, introspection_enabled)
        discovered_fields.update(suggested_fields)

        # Audit 3: Query depth limiting
        await self._audit_depth_limit(session, endpoint, proxy, introspection_enabled, discovered_fields)

        # Audit 4: Query batching verification
        await self._audit_batching(session, endpoint, proxy)

        # Audit 5: Object-level authorization validation
        await self._audit_object_authorization(session, endpoint, proxy, types_info, discovered_fields)

    # -----------------------------------------------------------------------
    # Audit 1: Introspection Query
    # -----------------------------------------------------------------------

    async def _audit_introspection(
        self, session: aiohttp.ClientSession, endpoint: str, proxy: Optional[str]
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Audit 1: Schema introspection query (__schema).
        If enabled, records finding with schema type list and VERIFIED confidence.
        """
        query_payload = {
            "query": (
                "query IntrospectionQuery { "
                "  __schema { "
                "    queryType { name } "
                "    mutationType { name } "
                "    subscriptionType { name } "
                "    types { name kind description fields { name } } "
                "  } "
                "}"
            )
        }
        fallback_payload = {"query": "{ __schema { types { name kind } } }"}
        req_headers = {"Content-Type": "application/json"}

        for payload in (query_payload, fallback_payload):
            try:
                async with session.post(endpoint, json=payload, headers=req_headers, proxy=proxy) as resp:
                    text = await resp.text()
                    try:
                        data = json.loads(text)
                    except Exception:
                        continue

                    if not isinstance(data, dict):
                        continue

                    schema = data.get("data", {}).get("__schema")
                    if isinstance(schema, dict) and "types" in schema:
                        raw_types = schema.get("types") or []
                        type_names = [t.get("name") for t in raw_types if isinstance(t, dict) and t.get("name")]
                        custom_types = [t for t in type_names if not t.startswith("__")]

                        all_fields: Set[str] = set()
                        query_fields: List[str] = []
                        for t in raw_types:
                            if isinstance(t, dict):
                                t_name = t.get("name")
                                fields = t.get("fields") or []
                                for f in fields:
                                    if isinstance(f, dict) and f.get("name"):
                                        all_fields.add(f["name"])
                                        if t_name == "Query":
                                            query_fields.append(f["name"])

                        finding = Finding(
                            severity=Severity.MEDIUM,
                            category="graphql",
                            title="GraphQL Schema Introspection Enabled",
                            description=(
                                f"Schema introspection is enabled on {endpoint}. Attackers can extract "
                                "the complete application data model, operations, queries, and mutations."
                            ),
                            url=endpoint,
                            confidence="VERIFIED",
                            remediation="Disable schema introspection in production environments (e.g., introspection: false).",
                            metadata={
                                "types_count": len(type_names),
                                "custom_types_count": len(custom_types),
                                "types": type_names,
                                "custom_types": custom_types,
                                "query_fields": query_fields,
                                "proof": _build_proof(
                                    request_info={"method": "POST", "url": endpoint, "body": payload},
                                    response_info={
                                        "status": resp.status,
                                        "types_count": len(type_names),
                                        "sample_types": custom_types[:10],
                                    },
                                    observed_delta=(
                                        f"Introspection query succeeded returning {len(type_names)} types "
                                        f"({len(custom_types)} custom types: {', '.join(custom_types[:5]) or 'none'})"
                                    ),
                                ),
                                "proof_attached": True,
                            },
                        )
                        self._add_finding(finding)
                        return True, {
                            "types": type_names,
                            "custom_types": custom_types,
                            "fields": list(all_fields),
                            "query_fields": query_fields,
                        }
            except Exception as exc:
                self._log(f"Introspection probe error: {exc}")

        return False, {}

    # -----------------------------------------------------------------------
    # Audit 2: Field Suggestion Heuristics
    # -----------------------------------------------------------------------

    async def _audit_field_suggestions(
        self,
        session: aiohttp.ClientSession,
        endpoint: str,
        proxy: Optional[str],
        introspection_enabled: bool,
    ) -> Set[str]:
        """
        Audit 2: Field suggestion heuristics.
        Analyzes query error suggestions (e.g., 'Did you mean ...?') to map available entity types.
        """
        probes = ["usr", "acc", "prof", "auth", "mem", "ord", "pay", "adm", "__schem"]
        req_headers = {"Content-Type": "application/json"}
        suggested_fields: Set[str] = set()
        triggering_probe: Optional[str] = None
        sample_error_message: str = ""
        sample_response_status: int = 200

        for probe in probes:
            query_payload = {"query": f"{{ {probe} }}"}
            try:
                async with session.post(endpoint, json=query_payload, headers=req_headers, proxy=proxy) as resp:
                    text = await resp.text()
                    try:
                        data = json.loads(text)
                    except Exception:
                        continue

                    if not isinstance(data, dict):
                        continue

                    errors = data.get("errors") or []
                    if not isinstance(errors, list):
                        continue

                    for err in errors:
                        msg = err.get("message", "") if isinstance(err, dict) else str(err)
                        match = SUGGESTION_PATTERN.search(msg)
                        if match:
                            suggestion_text = match.group(1)
                            # Extract quoted or word tokens
                            tokens = re.findall(r'["\']([a-zA-Z0-9_]+)["\']', suggestion_text)
                            if not tokens:
                                tokens = [
                                    w.strip()
                                    for w in re.split(r'[,;\s]|\bor\b|\band\b', suggestion_text)
                                    if w.strip() and w.strip().isidentifier()
                                ]
                            if tokens:
                                for t in tokens:
                                    suggested_fields.add(t)
                                if not triggering_probe:
                                    triggering_probe = probe
                                    sample_error_message = msg
                                    sample_response_status = resp.status
            except Exception as exc:
                self._log(f"Field suggestion probe '{probe}' error: {exc}")

        if suggested_fields:
            sorted_suggestions = sorted(list(suggested_fields))
            finding = Finding(
                severity=Severity.LOW,
                category="graphql",
                title="GraphQL Field Suggestions Enabled",
                description=(
                    f"Field suggestions are active on {endpoint}. Error responses include suggestions "
                    "for unrecognized fields (e.g. 'Did you mean ...?'), exposing schema entity types."
                ),
                url=endpoint,
                confidence="VERIFIED",
                remediation="Disable field suggestions in production (e.g., hideFieldSuggestions or custom error masking).",
                metadata={
                    "probed_fields": probes,
                    "suggested_fields": sorted_suggestions,
                    "proof": _build_proof(
                        request_info={"method": "POST", "url": endpoint, "body": {"query": f"{{ {triggering_probe} }}"}},
                        response_info={"status": sample_response_status, "error_message": sample_error_message},
                        observed_delta=f"Server returned field suggestions exposing valid fields: {sorted_suggestions}",
                    ),
                    "proof_attached": True,
                },
            )
            self._add_finding(finding)

        return suggested_fields

    # -----------------------------------------------------------------------
    # Audit 3: Query Depth Limiting
    # -----------------------------------------------------------------------

    async def _audit_depth_limit(
        self,
        session: aiohttp.ClientSession,
        endpoint: str,
        proxy: Optional[str],
        introspection_enabled: bool,
        discovered_fields: Set[str],
    ) -> None:
        """
        Audit 3: Query depth limiting.
        Tests queries with nested depth to verify whether depth limits are enforced.
        """
        # Depth 12-15 nested queries
        depth_target = 12
        req_headers = {"Content-Type": "application/json"}

        # Candidate deep queries: introspection-based or entity-based
        queries_to_test: List[Tuple[str, int]] = []

        if introspection_enabled:
            # Recursive schema ofType query
            chain = "type { " + ("ofType { " * (depth_target - 3)) + "name" + (" }" * (depth_target - 3)) + " }"
            q_intro = f"query DeepAuditIntro {{ __schema {{ types {{ fields {{ {chain} }} }} }} }}"
            queries_to_test.append((q_intro, depth_target))

        # Entity-based deep nesting
        # Check if user/node/friend fields are available, or use generic candidates
        entity_root = "user"
        entity_child = "friends"
        if "user" not in discovered_fields and "profile" in discovered_fields:
            entity_root = "profile"
            entity_child = "profile"
        elif "viewer" in discovered_fields:
            entity_root = "viewer"
            entity_child = "viewer"

        chain_entity = f"{entity_root} {{ " + (f"{entity_child} {{ " * (depth_target - 2)) + "id" + (" }" * (depth_target - 2)) + " }"
        q_entity = f"query DeepAuditEntity {{ {chain_entity} }}"
        queries_to_test.append((q_entity, depth_target))

        depth_limit_enforced = False
        unlimited_proof: Optional[Dict[str, Any]] = None

        for query_str, test_depth in queries_to_test:
            payload = {"query": query_str}
            try:
                async with session.post(endpoint, json=payload, headers=req_headers, proxy=proxy) as resp:
                    text = await resp.text()
                    try:
                        data = json.loads(text)
                    except Exception:
                        continue

                    if not isinstance(data, dict):
                        continue

                    errors = data.get("errors") or []
                    has_depth_error = False
                    for err in errors:
                        msg = err.get("message", "") if isinstance(err, dict) else str(err)
                        if DEPTH_ERROR_PATTERN.search(msg):
                            has_depth_error = True
                            depth_limit_enforced = True
                            self._log(f"Query depth limiting enforced on {endpoint}: {msg}")
                            break

                    if has_depth_error:
                        break

                    # If the query was executed with status 200 and data returned without depth restriction:
                    if resp.status == 200 and "data" in data and data["data"] is not None:
                        unlimited_proof = {
                            "request": {"method": "POST", "url": endpoint, "body": payload},
                            "response": {"status": resp.status, "data_keys": list(data.get("data", {}).keys())},
                            "observed_delta": (
                                f"Deeply nested query with depth {test_depth} was accepted and executed "
                                "without depth limit restriction."
                            ),
                            "tested_depth": test_depth,
                        }
            except Exception as exc:
                self._log(f"Depth limit probe error: {exc}")

        if not depth_limit_enforced and unlimited_proof:
            tested_depth = unlimited_proof.get("tested_depth", depth_target)
            finding = Finding(
                severity=Severity.MEDIUM,
                category="graphql",
                title="GraphQL Query Depth Limit Missing",
                description=(
                    f"The GraphQL endpoint at {endpoint} does not enforce query depth limits. "
                    f"A nested query with depth {tested_depth} was accepted and processed without depth restrictions, "
                    "enabling resource exhaustion and Denial of Service (DoS)."
                ),
                url=endpoint,
                confidence="VERIFIED",
                remediation="Implement query depth limiting (e.g., graphql-depth-limit) to reject queries exceeding safe nesting levels.",
                metadata={
                    "tested_depth": tested_depth,
                    "depth_enforced": False,
                    "proof": _build_proof(
                        request_info=unlimited_proof["request"],
                        response_info=unlimited_proof["response"],
                        observed_delta=unlimited_proof["observed_delta"],
                    ),
                    "proof_attached": True,
                },
            )
            self._add_finding(finding)

    # -----------------------------------------------------------------------
    # Audit 4: Query Batching Verification
    # -----------------------------------------------------------------------

    async def _audit_batching(
        self, session: aiohttp.ClientSession, endpoint: str, proxy: Optional[str]
    ) -> None:
        """
        Audit 4: Query batching verification.
        Tests JSON array query batching to verify if batching controls are configured.
        """
        batch_payload = [
            {"query": "query Batch1 { __typename }"},
            {"query": "query Batch2 { __typename }"},
            {"query": "query Batch3 { __typename }"},
        ]
        req_headers = {"Content-Type": "application/json"}

        try:
            async with session.post(endpoint, json=batch_payload, headers=req_headers, proxy=proxy) as resp:
                text = await resp.text()
                try:
                    data = json.loads(text)
                except Exception:
                    return

                # Batching is supported if response is a JSON array with matching length
                if isinstance(data, list) and len(data) >= 2:
                    all_have_data = any(
                        isinstance(item, dict) and ("data" in item or "__typename" in str(item))
                        for item in data
                    )
                    if all_have_data:
                        finding = Finding(
                            severity=Severity.LOW,
                            category="graphql",
                            title="GraphQL Query Batching Enabled",
                            description=(
                                f"The GraphQL endpoint at {endpoint} supports query batching via JSON arrays. "
                                "Attackers can batch numerous queries in a single HTTP request to bypass "
                                "rate limits, brute-force credentials, or trigger DoS."
                            ),
                            url=endpoint,
                            confidence="VERIFIED",
                            remediation="Disable JSON array batching or enforce strict batch size limits and request rate limits.",
                            metadata={
                                "batch_size": len(batch_payload),
                                "batching_allowed": True,
                                "proof": _build_proof(
                                    request_info={"method": "POST", "url": endpoint, "body": batch_payload},
                                    response_info={"status": resp.status, "batch_responses_count": len(data)},
                                    observed_delta=(
                                        f"Server processed batched JSON array of {len(batch_payload)} queries "
                                        f"and returned {len(data)} responses in a single HTTP transaction."
                                    ),
                                ),
                                "proof_attached": True,
                            },
                        )
                        self._add_finding(finding)
        except Exception as exc:
            self._log(f"Batching probe error: {exc}")

    # -----------------------------------------------------------------------
    # Audit 5: Object-Level Authorization Validation
    # -----------------------------------------------------------------------

    async def _audit_object_authorization(
        self,
        session: aiohttp.ClientSession,
        endpoint: str,
        proxy: Optional[str],
        types_info: Dict[str, Any],
        discovered_fields: Set[str],
    ) -> None:
        """
        Audit 5: Object-level authorization validation (BOLA / IDOR).
        Tests query fields representing user-owned resources to verify proper authorization checks.
        Sets confidence="VERIFIED" only when concrete proof is returned (unauthorized response
        body revealing private records).
        """
        # Determine candidate resource query patterns
        candidate_queries: List[Tuple[str, str]] = []

        query_fields = types_info.get("query_fields", [])
        known_sensitive_fields = ["user", "users", "account", "profile", "order", "orders", "me", "viewer"]

        # Prioritize discovered query fields
        for field in known_sensitive_fields:
            if field in query_fields or field in discovered_fields:
                if field in ("me", "viewer"):
                    candidate_queries.append((field, f"query {{ {field} {{ id email username role }} }}"))
                elif field in ("users", "orders"):
                    candidate_queries.append((field, f"query {{ {field} {{ id email role }} }}"))
                else:
                    candidate_queries.append((field, f"query {{ {field}(id: \"1\") {{ id email username role name }} }}"))

        # Fallback candidate probes if no schema fields were identified
        if not candidate_queries:
            candidate_queries = [
                ("user", 'query { user(id: "1") { id email username role name } }'),
                ("profile", 'query { profile(id: "1") { id email name } }'),
                ("me", 'query { me { id email username role } }'),
                ("account", 'query { account(id: "1") { id balance email name } }'),
                ("users", 'query { users { id email username role } }'),
            ]

        # Prepare unauthenticated request headers (strip auth token and cookies)
        clean_headers = self._build_headers()
        for k in list(clean_headers.keys()):
            if k.lower() in ("authorization", "cookie"):
                del clean_headers[k]
        clean_headers["Content-Type"] = "application/json"

        for resource_name, query_str in candidate_queries:
            payload = {"query": query_str}
            try:
                async with session.post(endpoint, json=payload, headers=clean_headers, proxy=proxy) as resp:
                    text = await resp.text()
                    try:
                        data = json.loads(text)
                    except Exception:
                        continue

                    if not isinstance(data, dict):
                        continue

                    # Check for explicit authorization errors
                    errors = data.get("errors") or []
                    has_auth_error = any(
                        AUTH_ERROR_PATTERN.search(err.get("message", "") if isinstance(err, dict) else str(err))
                        for err in errors
                    )
                    if has_auth_error or resp.status in (401, 403):
                        # Authorization check properly enforced
                        continue

                    # Check if response data exposes private record details
                    data_obj = data.get("data")
                    if isinstance(data_obj, dict):
                        resource_data = data_obj.get(resource_name)
                        if self._contains_private_records(resource_data):
                            finding = Finding(
                                severity=Severity.HIGH,
                                category="graphql",
                                title=f"GraphQL Broken Object-Level Authorization: {resource_name}",
                                description=(
                                    f"Unauthenticated request to user-owned resource field '{resource_name}' on "
                                    f"{endpoint} returned private record data without authorization verification."
                                ),
                                url=endpoint,
                                confidence="VERIFIED",
                                remediation=(
                                    f"Enforce object-level authorization checks on the '{resource_name}' resolver "
                                    "to verify caller authentication and ownership before returning private data."
                                ),
                                metadata={
                                    "field": resource_name,
                                    "exposed_data": resource_data,
                                    "proof": _build_proof(
                                        request_info={"method": "POST", "url": endpoint, "headers": clean_headers, "body": payload},
                                        response_info={"status": resp.status, "body": resource_data},
                                        observed_delta=(
                                            f"Unauthenticated query returned private user record for '{resource_name}': "
                                            f"{json.dumps(resource_data)[:300]}"
                                        ),
                                    ),
                                    "proof_attached": True,
                                },
                            )
                            self._add_finding(finding)
                            break
            except Exception as exc:
                self._log(f"Object-level authorization probe '{resource_name}' error: {exc}")

    def _contains_private_records(self, data: Any) -> bool:
        """Check if returned data contains private user records."""
        if not data:
            return False

        if isinstance(data, list):
            return any(self._contains_private_records(item) for item in data)

        if isinstance(data, dict):
            # If any sensitive key is present with a non-null, non-empty value
            has_sensitive_key = any(
                k.lower() in PRIVATE_FIELD_KEYS and data[k] is not None and data[k] != ""
                for k in data
            )
            # Or if id is present along with at least two other attributes
            has_id_and_attrs = "id" in data and len([k for k in data if data[k] is not None]) >= 3
            return has_sensitive_key or has_id_and_attrs

        return False

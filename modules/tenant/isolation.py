"""
BugKit v4 — Tenant Isolation Engine

For SaaS targets, tests cross-tenant data access:
  • org_id / tenant_id header and param swaps
  • Workspace/project crossover
  • Cross-tenant invite abuse
  • Shared link leakage across orgs
  • Subdomain tenant confusion (e.g. attacker.app.com → victim.app.com)

This is one of the highest-value modules for SaaS bug bounty programs.
"""
from __future__ import annotations

import json
import re
from typing import List, Optional

from core.session import BugKitSession
from core.diff import compare
from core import logger
from db import queries
from engines.token_swapper import TokenSwapper


# Headers that often carry tenant context
TENANT_HEADERS = [
    "X-Org-Id", "X-Organization-Id", "X-Tenant-Id", "X-Tenant",
    "X-Workspace-Id", "X-Account-Id", "X-Customer-Id", "X-Team-Id",
    "X-Project-Id", "X-Company-Id", "X-Client-Id",
]

# Query params that often carry tenant context
TENANT_PARAMS = [
    "org_id", "organization_id", "tenant_id", "workspace_id",
    "account_id", "team_id", "project_id", "company_id",
    "customer_id", "client_id", "shop_id", "store_id",
]

# Invitation / share endpoint patterns
INVITE_PATTERNS = re.compile(
    r"(invite|join|signup|register|accept|share|link|token)",
    re.I,
)


class TenantIsolationEngine:
    """
    Systematically probes for cross-tenant isolation failures.

    Typical usage:
        engine = TenantIsolationEngine(session)
        findings = engine.sweep(
            target_id      = 1,
            base_url       = "https://api.example.com",
            tenant_a_id    = "org_111",   # attacker's tenant
            tenant_b_id    = "org_222",   # victim's tenant (from recon)
            identity_a     = "userA",
            identity_b     = "userB",
        )
    """

    def __init__(self, session: BugKitSession) -> None:
        self.session  = session
        self._findings: int = 0

    def sweep(
        self,
        target_id:   int,
        base_url:    str,
        tenant_a_id: str,
        tenant_b_id: str,
        identity_a:  str = None,
        identity_b:  str = None,
    ) -> int:
        """
        Run all tenant isolation checks.
        Returns number of findings saved.
        """
        logger.section(f"Tenant Isolation  {base_url}")
        logger.info(f"Tenant A (attacker): {tenant_a_id}")
        logger.info(f"Tenant B (victim):   {tenant_b_id}")

        self._findings = 0
        target_id_val  = target_id

        # 1. Header injection
        self._test_header_injection(
            base_url, tenant_a_id, tenant_b_id,
            identity_a, target_id_val,
        )

        # 2. Parameter injection
        self._test_param_injection(
            base_url, tenant_a_id, tenant_b_id,
            identity_a, target_id_val,
        )

        # 3. Cross-identity endpoint comparison
        if identity_a and identity_b:
            self._test_cross_identity(
                base_url, identity_a, identity_b, target_id_val,
            )

        # 4. Invite abuse
        self._test_invite_abuse(
            base_url, tenant_b_id, identity_a, target_id_val,
        )

        # 5. Known endpoints from DB
        self._test_db_endpoints(
            target_id_val, tenant_a_id, tenant_b_id, identity_a,
        )

        logger.section("Tenant Isolation Summary")
        logger.ok(f"Findings: {self._findings}")
        return self._findings

    # ── Test categories ────────────────────────────────────────────────

    def _test_header_injection(
        self,
        base_url:    str,
        tenant_a_id: str,
        tenant_b_id: str,
        identity:    Optional[str],
        target_id:   int,
    ) -> None:
        """Inject tenant B's ID in tenant-context headers while auth as A."""
        logger.info("Testing tenant header injection…")

        endpoints = self._common_api_endpoints(base_url)

        for header in TENANT_HEADERS:
            for ep in endpoints[:5]:   # limit to top 5 to avoid noise
                # Baseline: legitimate request with tenant_a headers
                baseline = self.session.request(
                    "GET", ep,
                    identity_name=identity,
                    headers={header: tenant_a_id},
                    capture=True,
                )
                if baseline is None:
                    continue

                # Attack: swap tenant ID in the header
                attack = self.session.request(
                    "GET", ep,
                    identity_name=identity,
                    headers={header: tenant_b_id},
                    capture=True,
                )
                if attack is None:
                    continue

                diff = compare(
                    identity_a = f"[{header}: {tenant_a_id}]",
                    response_a = baseline,
                    identity_b = f"[{header}: {tenant_b_id}]",
                    response_b = attack,
                    url        = ep,
                )

                if diff.is_anomaly and attack.status_code in (200, 201, 206):
                    self._save_tenant_finding(
                        target_id = target_id,
                        title     = f"Tenant Isolation — Header Override: {header}",
                        url       = ep,
                        detail    = (
                            f"Injecting `{header}: {tenant_b_id}` (victim tenant) "
                            f"while authenticated as tenant {tenant_a_id} returned "
                            f"HTTP {attack.status_code}. "
                            f"Signals: {diff.summary}"
                        ),
                        evidence  = (
                            f"Header: {header}\n"
                            f"Attacker tenant: {tenant_a_id}\n"
                            f"Victim tenant:   {tenant_b_id}\n"
                            f"Response size delta: {abs(len(baseline.content) - len(attack.content))}B"
                        ),
                        severity  = "CRITICAL",
                        confidence= diff.confidence,
                    )

    def _test_param_injection(
        self,
        base_url:    str,
        tenant_a_id: str,
        tenant_b_id: str,
        identity:    Optional[str],
        target_id:   int,
    ) -> None:
        """Inject tenant B's ID in query/body parameters."""
        logger.info("Testing tenant parameter injection…")
        endpoints = queries.get_endpoints(target_id)

        for ep in endpoints:
            params_raw = ep.params or "[]"
            try:
                param_list = json.loads(params_raw)
            except Exception:
                param_list = []

            for param in param_list:
                if not any(tp in param.lower() for tp in TENANT_PARAMS):
                    continue

                from core.utils import inject_param
                mut_url = inject_param(ep.url, param, tenant_b_id)

                baseline = self.session.request("GET", ep.url, identity_name=identity, capture=True)
                attack   = self.session.request("GET", mut_url,  identity_name=identity, capture=True)
                if baseline is None or attack is None:
                    continue

                diff = compare(
                    identity_a = f"[{param}={tenant_a_id}]",
                    response_a = baseline,
                    identity_b = f"[{param}={tenant_b_id}]",
                    response_b = attack,
                    url        = mut_url,
                )

                if diff.is_anomaly and attack.status_code < 400:
                    self._save_tenant_finding(
                        target_id = target_id,
                        title     = f"Tenant Isolation — Parameter Override: {param}",
                        url       = mut_url,
                        detail    = (
                            f"Setting `{param}={tenant_b_id}` in request produced a "
                            f"different response. Signals: {diff.summary}"
                        ),
                        evidence  = (
                            f"Param: {param}\n"
                            f"Attacker value: {tenant_a_id}\n"
                            f"Victim value:   {tenant_b_id}\n"
                        ),
                        severity  = "CRITICAL",
                        confidence= diff.confidence,
                    )

    def _test_cross_identity(
        self,
        base_url:   str,
        identity_a: str,
        identity_b: str,
        target_id:  int,
    ) -> None:
        """
        For all endpoints, compare responses from identity_a vs identity_b.
        Anomalies suggest broken tenant isolation or IDOR.
        """
        logger.info(f"Cross-identity comparison: {identity_a} vs {identity_b}…")
        endpoints = queries.get_endpoints(target_id)

        swapper = TokenSwapper(self.session)
        for ep in endpoints[:30]:   # cap at 30 to be reasonable
            result = swapper.swap(
                method            = ep.method or "GET",
                url               = ep.url,
                baseline_identity = identity_a,
            )
            if result.anomalous:
                finding_ids = swapper.save_findings(result, target_id, module="tenant")
                self._findings += len(finding_ids)

    def _test_invite_abuse(
        self,
        base_url:    str,
        tenant_b_id: str,
        identity:    Optional[str],
        target_id:   int,
    ) -> None:
        """Look for invite/join endpoints and test cross-tenant accept."""
        logger.info("Testing invite / cross-tenant join abuse…")
        endpoints = queries.get_endpoints(target_id)
        invite_eps = [
            ep for ep in endpoints
            if INVITE_PATTERNS.search(ep.url)
        ]

        for ep in invite_eps[:10]:
            logger.debug(f"  Probing invite endpoint: {ep.url}")
            resp = self.session.request(
                ep.method or "GET", ep.url,
                identity_name = identity,
                capture       = True,
            )
            if resp and resp.status_code < 400:
                # A 200 on an invite-like endpoint for a different tenant
                # is worth flagging for manual review
                self._save_tenant_finding(
                    target_id  = target_id,
                    title      = f"Potential Cross-Tenant Invite Endpoint: {ep.url}",
                    url        = ep.url,
                    detail     = (
                        f"Invite/join endpoint returned HTTP {resp.status_code}. "
                        "Verify whether this accepts cross-tenant invitations."
                    ),
                    evidence   = f"Status: {resp.status_code}\nBody: {resp.text[:300]}",
                    severity   = "MEDIUM",
                    confidence = "low",
                )

    def _test_db_endpoints(
        self,
        target_id:   int,
        tenant_a_id: str,
        tenant_b_id: str,
        identity:    Optional[str],
    ) -> None:
        """Apply header injection to all DB-known endpoints (broader sweep)."""
        logger.info("Broad header injection across known endpoints…")
        endpoints = queries.get_endpoints(target_id)

        for ep in endpoints[:50]:
            for header in TENANT_HEADERS[:3]:   # top 3 most common headers
                attack = self.session.request(
                    ep.method or "GET", ep.url,
                    identity_name = identity,
                    headers       = {header: tenant_b_id},
                    capture       = True,
                )
                if attack and attack.status_code in (200, 201, 206):
                    # Quick heuristic: 200 with victim tenant ID accepted
                    resp_text = attack.text[:500]
                    if (tenant_b_id.lower() in resp_text.lower() or
                            len(attack.content) > 100):
                        self._save_tenant_finding(
                            target_id  = target_id,
                            title      = f"Tenant Data in Response — {header} Override",
                            url        = ep.url,
                            detail     = (
                                f"Header `{header}: {tenant_b_id}` accepted by server "
                                f"at {ep.url}. Response size: {len(attack.content)}B."
                            ),
                            evidence   = f"Response snippet:\n{resp_text}",
                            severity   = "HIGH",
                            confidence = "medium",
                        )
                        break

    # ── Helpers ────────────────────────────────────────────────────────

    def _common_api_endpoints(self, base_url: str) -> List[str]:
        base = base_url.rstrip("/")
        return [
            f"{base}/api/me",
            f"{base}/api/user",
            f"{base}/api/account",
            f"{base}/api/profile",
            f"{base}/api/org",
            f"{base}/api/organizations",
            f"{base}/api/workspace",
            f"{base}/api/team",
            f"{base}/api/settings",
            f"{base}/api/billing",
        ]

    def _save_tenant_finding(
        self,
        target_id:  int,
        title:      str,
        url:        str,
        detail:     str,
        evidence:   str,
        severity:   str = "HIGH",
        confidence: str = "medium",
    ) -> None:
        cap = self.session.last_capture
        queries.save_finding(
            target_id    = target_id,
            module       = "tenant",
            title        = title,
            severity     = severity,
            confidence   = confidence,
            url          = url,
            evidence     = evidence,
            detail       = detail,
            raw_request  = cap.raw_request  if cap else "",
            raw_response = cap.raw_response[:2000] if cap else "",
            curl_poc     = cap.curl         if cap else "",
            impact       = (
                "Cross-tenant data access. In a SaaS application this could "
                "expose all customer data, allow account takeover, or permit "
                "one organisation to modify another's resources."
            ),
            remediation  = (
                "Enforce tenant context server-side on every request. "
                "Never trust client-supplied org_id/tenant_id. "
                "Bind the authenticated user's tenant to the session and "
                "verify all resource accesses against that binding."
            ),
            cwe  = "CWE-863",
            cvss = 9.1 if severity == "CRITICAL" else 7.5,
            tags = ["tenant-isolation", "saas", "multi-tenant", "access-control"],
        )
        self._findings += 1
        logger.finding(title=title, severity=severity, url=url, confidence=confidence)

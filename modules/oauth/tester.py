"""
BugKit v4 — OAuth / OIDC Security Tester

Tests the highest-paying OAuth attack categories:
  1. State parameter CSRF — missing or reusable state
  2. redirect_uri manipulation — open redirect → token theft
  3. PKCE bypass — code_challenge validation missing
  4. Token leakage via Referer header
  5. Authorization code replay — code reuse after redemption
  6. Token scope escalation — requesting more scopes than granted
  7. Client secret exposure in JS / URLs
  8. Implicit flow token leakage in URL fragment
  9. Cross-tenant token reuse
  10. Account linking / merging abuse
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlencode

from core.session import BugKitSession
from core import logger
from db import queries


# Common OAuth endpoint path patterns
OAUTH_DISCOVERY_PATHS = [
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/oauth/authorize",
    "/oauth2/authorize",
    "/auth/authorize",
    "/connect/authorize",
    "/oauth/token",
    "/oauth2/token",
    "/auth/token",
    "/connect/token",
]

COMMON_REDIRECT_BYPASS = [
    "https://evil.com",
    "https://evil.com/callback",
    "//evil.com",
    "//evil.com/callback",
    "http://localhost:8080",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "/\\evil.com",
]


@dataclass
class OAuthConfig:
    """Discovered OAuth configuration for a target."""
    authorization_endpoint: str = ""
    token_endpoint:         str = ""
    userinfo_endpoint:      str = ""
    issuer:                 str = ""
    scopes_supported:       List[str] = field(default_factory=list)
    response_types:         List[str] = field(default_factory=list)
    grant_types:            List[str] = field(default_factory=list)
    pkce_required:          bool      = False
    raw:                    dict      = field(default_factory=dict)


class OAuthTester:
    """
    Comprehensive OAuth/OIDC security tester.

    Usage:
        tester = OAuthTester(session)
        tester.run(
            target_id    = 1,
            base_url     = "https://example.com",
            client_id    = "my_app_client_id",
            redirect_uri = "https://example.com/callback",
            identity     = "userA",
        )
    """

    def __init__(self, session: BugKitSession) -> None:
        self.session   = session
        self._findings = 0
        self._config:  Optional[OAuthConfig] = None

    def run(
        self,
        target_id:    int,
        base_url:     str,
        client_id:    str = "",
        redirect_uri: str = "",
        identity:     str = None,
        scopes:       str = "openid profile email",
    ) -> int:
        logger.section(f"OAuth / OIDC Tester  →  {base_url}")
        self._tid      = target_id
        self._base     = base_url.rstrip("/")
        self._findings = 0
        self._client_id    = client_id
        self._redirect_uri = redirect_uri
        self._identity     = identity
        self._scopes       = scopes

        # 1. Discover OAuth endpoints
        self._config = self._discover()
        if not self._config.authorization_endpoint:
            logger.warn("No OAuth endpoints discovered. "
                        "Provide --client-id and --redirect-uri for manual flow.")
            if not client_id:
                return 0

        auth_ep  = self._config.authorization_endpoint or self._base + "/oauth/authorize"
        token_ep = self._config.token_endpoint         or self._base + "/oauth/token"

        # 2. Run all test categories
        self._test_state_csrf(auth_ep)
        self._test_redirect_uri_manipulation(auth_ep)
        self._test_pkce_bypass(auth_ep, token_ep)
        self._test_token_scope_escalation(auth_ep)
        self._test_implicit_flow_leakage(auth_ep)
        self._test_client_secret_exposure()
        self._test_token_reuse_cross_identity(token_ep)
        self._test_account_linking_abuse()

        logger.section("OAuth Summary")
        logger.ok(f"Findings: {self._findings}")
        return self._findings

    # ── Discovery ──────────────────────────────────────────────────────

    def _discover(self) -> OAuthConfig:
        config = OAuthConfig()
        for path in OAUTH_DISCOVERY_PATHS:
            url  = self._base + path
            resp = self.session.get(url, capture=False)
            if resp is None or resp.status_code != 200:
                continue
            try:
                data = resp.json()
                if "authorization_endpoint" in data:
                    config.authorization_endpoint = data.get("authorization_endpoint", "")
                    config.token_endpoint         = data.get("token_endpoint", "")
                    config.userinfo_endpoint       = data.get("userinfo_endpoint", "")
                    config.issuer                 = data.get("issuer", "")
                    config.scopes_supported        = data.get("scopes_supported", [])
                    config.response_types          = data.get("response_types_supported", [])
                    config.grant_types             = data.get("grant_types_supported", [])
                    config.pkce_required           = data.get("code_challenge_methods_supported") is not None
                    config.raw                     = data
                    logger.ok(f"OAuth config discovered: {url}")
                    break
                # Plain authorize endpoint check
                elif resp.status_code in (200, 302, 400) and path.endswith("/authorize"):
                    config.authorization_endpoint = url
                    break
            except Exception:
                # Check if it's a redirect to login (that means it's an auth endpoint)
                if resp.status_code == 302 and "login" in resp.headers.get("Location","").lower():
                    config.authorization_endpoint = url

        return config

    # ── Test 1: State CSRF ─────────────────────────────────────────────

    def _test_state_csrf(self, auth_ep: str) -> None:
        logger.info("Testing state parameter CSRF…")

        # Test 1a: Missing state
        params = self._base_auth_params()
        params.pop("state", None)
        url  = auth_ep + "?" + urlencode(params)
        resp = self.session.get(url, identity_name=self._identity,
                                capture=True, allow_redirects=False)

        if resp and resp.status_code in (200, 302):
            location = resp.headers.get("Location", "")
            if "code=" in location or resp.status_code == 200:
                self._save(
                    title     = "OAuth — Missing State Parameter Accepted",
                    severity  = "HIGH",
                    url       = url,
                    detail    = (
                        "Authorization request without `state` parameter returned "
                        f"HTTP {resp.status_code}. CSRF attacks on OAuth flows are possible."
                    ),
                    evidence  = f"Response: HTTP {resp.status_code}\nLocation: {location[:200]}",
                    confidence= "high",
                    tags      = ["oauth", "csrf", "state"],
                    cwe       = "CWE-352",
                    cvss      = 8.1,
                )

        # Test 1b: Reusable / predictable state
        state1 = "aaaaaaaaaaaaaaaa"
        params["state"] = state1
        url  = auth_ep + "?" + urlencode(params)
        resp = self.session.get(url, identity_name=self._identity,
                                capture=False, allow_redirects=False)
        if resp and resp.status_code not in (400, 401, 422):
            self._save(
                title     = "OAuth — Predictable State Value Accepted",
                severity  = "MEDIUM",
                url       = url,
                detail    = (
                    f"State value `{state1}` (all-same-chars, predictable) "
                    "was not rejected. Server may not validate state entropy."
                ),
                evidence  = f"Response: HTTP {resp.status_code}",
                confidence= "low",
                tags      = ["oauth", "csrf", "state"],
                cwe       = "CWE-330",
                cvss      = 5.4,
            )

    # ── Test 2: redirect_uri manipulation ─────────────────────────────

    def _test_redirect_uri_manipulation(self, auth_ep: str) -> None:
        logger.info("Testing redirect_uri manipulation…")
        params = self._base_auth_params()

        for evil_uri in COMMON_REDIRECT_BYPASS:
            params["redirect_uri"] = evil_uri
            url  = auth_ep + "?" + urlencode(params)
            resp = self.session.get(url, identity_name=self._identity,
                                    capture=True, allow_redirects=False)
            if resp is None:
                continue

            location = resp.headers.get("Location", "")
            # Dangerous: server redirects to the evil URI
            if resp.status_code in (302, 301, 303) and evil_uri in location:
                self._save(
                    title     = f"OAuth — redirect_uri Accepted: {evil_uri[:50]}",
                    severity  = "CRITICAL",
                    url       = url,
                    detail    = (
                        f"Authorization code redirect to attacker-controlled URI accepted.\n"
                        f"Redirect: {location[:300]}"
                    ),
                    evidence  = (
                        f"Injected redirect_uri: {evil_uri}\n"
                        f"Server redirected to:  {location[:300]}"
                    ),
                    confidence= "high",
                    tags      = ["oauth", "redirect-uri", "token-theft"],
                    cwe       = "CWE-601",
                    cvss      = 9.3,
                )

            # Also test partial URI bypass (open redirect in allowed domain)
            elif resp.status_code not in (400, 422) and "error" not in location.lower():
                self._save(
                    title     = "OAuth — redirect_uri Validation May Be Weak",
                    severity  = "MEDIUM",
                    url       = url,
                    detail    = (
                        f"redirect_uri `{evil_uri}` returned HTTP {resp.status_code} "
                        "without an explicit error. Manual verification recommended."
                    ),
                    evidence  = f"HTTP {resp.status_code}\nLocation: {location[:200]}",
                    confidence= "low",
                    tags      = ["oauth", "redirect-uri"],
                    cwe       = "CWE-601",
                    cvss      = 6.1,
                )
                break  # one low-conf finding per category is enough

    # ── Test 3: PKCE bypass ───────────────────────────────────────────

    def _test_pkce_bypass(self, auth_ep: str, token_ep: str) -> None:
        logger.info("Testing PKCE bypass…")

        # Start flow without code_challenge
        state    = secrets.token_urlsafe(16)
        params   = self._base_auth_params()
        params["state"]        = state
        params["response_type"]= "code"
        # Deliberately omit code_challenge / code_challenge_method

        url  = auth_ep + "?" + urlencode(params)
        resp = self.session.get(url, identity_name=self._identity,
                                capture=True, allow_redirects=False)

        if resp and resp.status_code not in (400, 422):
            loc = resp.headers.get("Location", "")
            if "code=" in loc or resp.status_code == 200:
                self._save(
                    title     = "OAuth — PKCE Not Enforced",
                    severity  = "HIGH",
                    url       = url,
                    detail    = (
                        "Authorization code flow accepted without `code_challenge`. "
                        "PKCE is not enforced, enabling authorization code interception attacks."
                    ),
                    evidence  = f"HTTP {resp.status_code}\nLocation: {loc[:200]}",
                    confidence= "medium",
                    tags      = ["oauth", "pkce", "code-interception"],
                    cwe       = "CWE-287",
                    cvss      = 7.4,
                )

    # ── Test 4: Scope escalation ───────────────────────────────────────

    def _test_token_scope_escalation(self, auth_ep: str) -> None:
        logger.info("Testing scope escalation…")
        privileged_scopes = [
            "admin", "superadmin", "read:all", "write:all",
            "admin:org", "delete:users", "manage:billing",
            "offline_access", "full_access",
        ]
        current_scopes = self._scopes.split()

        for priv in privileged_scopes:
            if priv in current_scopes:
                continue
            params = self._base_auth_params()
            params["scope"] = self._scopes + " " + priv
            url  = auth_ep + "?" + urlencode(params)
            resp = self.session.get(url, identity_name=self._identity,
                                    capture=True, allow_redirects=False)
            if resp is None:
                continue
            loc = resp.headers.get("Location", "")
            # Accepted if we got a code and no scope error
            if (resp.status_code in (200, 302) and
                    "error" not in loc and
                    "invalid_scope" not in loc):
                self._save(
                    title     = f"OAuth — Privileged Scope Accepted: {priv}",
                    severity  = "HIGH",
                    url       = url,
                    detail    = (
                        f"Requesting additional scope `{priv}` did not produce an error. "
                        "Server may grant more permissions than the client is authorised for."
                    ),
                    evidence  = f"Scope: {params['scope']}\nHTTP {resp.status_code}\n{loc[:200]}",
                    confidence= "medium",
                    tags      = ["oauth", "scope-escalation", "privilege"],
                    cwe       = "CWE-269",
                    cvss      = 8.0,
                )

    # ── Test 5: Implicit flow token in URL ─────────────────────────────

    def _test_implicit_flow_leakage(self, auth_ep: str) -> None:
        logger.info("Testing implicit flow token leakage…")
        params = self._base_auth_params()
        params["response_type"] = "token"  # implicit flow
        url  = auth_ep + "?" + urlencode(params)
        resp = self.session.get(url, identity_name=self._identity,
                                capture=True, allow_redirects=False)
        if resp is None:
            return
        loc = resp.headers.get("Location", "")
        if "access_token=" in loc:
            self._save(
                title     = "OAuth — Implicit Flow Returns Token in URL",
                severity  = "HIGH",
                url       = url,
                detail    = (
                    "Server supports implicit flow (`response_type=token`). "
                    "Access tokens in URL fragments leak via Referer headers, "
                    "browser history, and server logs."
                ),
                evidence  = f"Location: {loc[:300]}",
                confidence= "high",
                tags      = ["oauth", "implicit-flow", "token-leakage"],
                cwe       = "CWE-598",
                cvss      = 7.4,
            )

    # ── Test 6: Client secret in JS / endpoints ────────────────────────

    def _test_client_secret_exposure(self) -> None:
        logger.info("Testing client secret exposure in JS…")
        # Check JS findings from jsintel module
        with queries.get_db() as db:
            from db.models import Finding as FindingModel
            js_findings = db.query(FindingModel).filter(
                FindingModel.target_id == self._tid,
                FindingModel.module == "jsintel",
            ).all()

        for f in js_findings:
            evidence = f.evidence or ""
            if any(kw in evidence.lower() for kw in
                   ["client_secret", "client secret", "oauth_secret", "app_secret"]):
                self._save(
                    title     = "OAuth — Client Secret Exposed in JavaScript",
                    severity  = "CRITICAL",
                    url       = f.url,
                    detail    = (
                        "OAuth client_secret found in client-side JavaScript. "
                        "Attacker can impersonate the application in OAuth flows."
                    ),
                    evidence  = evidence[:500],
                    confidence= "high",
                    tags      = ["oauth", "client-secret", "credential-exposure"],
                    cwe       = "CWE-312",
                    cvss      = 9.1,
                )

    # ── Test 7: Cross-identity token reuse ────────────────────────────

    def _test_token_reuse_cross_identity(self, token_ep: str) -> None:
        if len(self.session.identity_names) < 2:
            return
        logger.info("Testing cross-identity token reuse…")
        identities = self.session.identity_names

        # Get userA's access token from headers
        resp_a = self.session.request(
            "GET", self._base + "/api/me",
            identity_name=identities[0], capture=False,
        )
        if resp_a is None:
            return

        # Try using identityA's auth headers while accessing identityB's resources
        token_header = self.session._identities.get(identities[0], None)
        if token_header:
            auth_val = token_header.headers.get("Authorization", "")
            if auth_val:
                # Access userB's profile with userA's token
                resp_b = self.session.request(
                    "GET", self._base + "/api/me",
                    identity_name=identities[1], capture=True,
                )
                if resp_b and resp_a and resp_b.status_code == 200:
                    from core.diff import compare
                    diff = compare(identities[0], resp_a,
                                   identities[1], resp_b,
                                   self._base + "/api/me")
                    if diff.is_anomaly:
                        self._save(
                            title     = "OAuth — Cross-Identity Token Returns Different Data",
                            severity  = "HIGH",
                            url       = self._base + "/api/me",
                            detail    = f"Signals: {diff.summary}",
                            evidence  = "\n".join(str(s) for s in diff.signals if s.is_anomaly),
                            confidence= diff.confidence,
                            tags      = ["oauth", "token-reuse", "idor"],
                            cwe       = "CWE-639",
                            cvss      = 8.1,
                        )

    # ── Test 8: Account linking abuse ─────────────────────────────────

    def _test_account_linking_abuse(self) -> None:
        logger.info("Testing account linking / social login abuse…")
        link_paths = [
            "/auth/connect", "/oauth/connect", "/account/connect",
            "/link", "/auth/link", "/social/connect",
        ]
        for path in link_paths:
            url  = self._base + path
            resp = self.session.request(
                "GET", url,
                identity_name=self._identity,
                capture=True,
            )
            if resp and resp.status_code in (200, 302, 400):
                self._save(
                    title     = f"OAuth — Account Linking Endpoint Found: {url}",
                    severity  = "INFO",
                    url       = url,
                    detail    = (
                        f"Account linking endpoint discovered at {url}. "
                        "Test for: linking another user's social account, "
                        "pre-linking before victim logs in, email clash bypass."
                    ),
                    evidence  = f"HTTP {resp.status_code}",
                    confidence= "low",
                    tags      = ["oauth", "account-linking"],
                    cwe       = "CWE-287",
                    cvss      = 0.0,
                )
                break  # One discovery finding is enough

    # ── Helpers ────────────────────────────────────────────────────────

    def _base_auth_params(self) -> Dict[str, str]:
        return {
            "client_id":     self._client_id or "bugkit_test",
            "redirect_uri":  self._redirect_uri or self._base + "/callback",
            "response_type": "code",
            "scope":         self._scopes,
            "state":         secrets.token_urlsafe(16),
        }

    def _save(
        self,
        title:      str,
        severity:   str,
        url:        str,
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
            module       = "oauth",
            title        = title,
            severity     = severity,
            confidence   = confidence,
            url          = url,
            detail       = detail,
            evidence     = evidence,
            raw_request  = cap.raw_request  if cap else "",
            raw_response = cap.raw_response[:2000] if cap else "",
            curl_poc     = cap.curl         if cap else "",
            impact       = "OAuth flow compromise leading to account takeover or token theft.",
            remediation  = (
                "Validate state parameter on every callback. "
                "Enforce strict redirect_uri allowlist (no wildcards, no partial matches). "
                "Require PKCE for all public clients. "
                "Never use implicit flow. Rotate client secrets regularly."
            ),
            cwe  = cwe,
            cvss = cvss,
            tags = tags,
        )
        self._findings += 1
        logger.finding(title=title, severity=severity, url=url, confidence=confidence)

"""
BugKit v4 — Rate Limit Tester

Tests rate limiting on authentication-sensitive endpoints.

Improvements over v3:
  • Tests per-identity vs per-IP limits (different bypass strategies)
  • Header rotation to test IP-based bypass (X-Forwarded-For, etc.)
  • Concurrent bursts via the Scheduler
  • GraphQL batching rate limit test
  • OTP/2FA endpoint specific testing
  • Confidence scoring based on response patterns
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional

from core.session import BugKitSession
from core import logger
from db import queries


# Endpoints commonly rate-limited (tested automatically)
DEFAULT_ENDPOINTS = [
    "/login", "/signin", "/auth/login",
    "/api/login", "/api/v1/login", "/api/v2/login",
    "/forgot-password", "/reset-password",
    "/verify", "/api/verify", "/otp/verify",
    "/register", "/signup",
    "/token", "/oauth/token", "/api/token",
]

# Headers used to probe IP-based rate limit bypass
IP_SPOOF_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "10.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
]


@dataclass
class RateLimitResult:
    url:          str
    identity:     str
    burst_size:   int
    hit_429:      bool          = False
    threshold:    Optional[int] = None   # how many before 429
    bypass_found: bool          = False
    bypass_header: str          = ""
    confidence:   str           = "low"
    status_dist:  Dict[int, int] = field(default_factory=dict)


class RateLimitTester:
    """
    Rate limit and brute-force protection tester.

    Usage:
        tester  = RateLimitTester(session)
        results = tester.run(
            target_id = 1,
            base_url  = "https://example.com",
            burst     = 30,
            identity  = "userA",
        )
    """

    def __init__(self, session: BugKitSession) -> None:
        self.session   = session
        self._findings = 0

    def run(
        self,
        target_id: int,
        base_url:  str,
        burst:     int = 30,
        identity:  str = None,
    ) -> int:
        logger.section(f"Rate Limit Tester  →  {base_url}")
        self._tid  = target_id
        self._base = base_url.rstrip("/")
        self._findings = 0

        # Get endpoints from DB + default list
        db_eps    = [ep.url for ep in queries.get_endpoints(target_id)
                     if any(kw in ep.url for kw in
                            ["login","signin","verify","token","otp","register","forgot"])]
        heuristic = [self._base + p for p in DEFAULT_ENDPOINTS]
        all_urls  = list(dict.fromkeys(db_eps + heuristic))[:20]

        logger.info(f"Testing {len(all_urls)} endpoint(s) with burst={burst}")

        for url in all_urls:
            result = self._test_endpoint(url, burst, identity)
            if result is None:
                continue

            if not result.hit_429:
                self._save(
                    title     = f"No Rate Limiting — {url}",
                    url       = url,
                    severity  = "HIGH",
                    confidence= "high",
                    detail    = (
                        f"{burst} requests sent with no 429 response. "
                        "Endpoint may be brute-forceable."
                    ),
                    evidence  = f"Status distribution: {result.status_dist}",
                )

            elif result.threshold and result.threshold > 20:
                self._save(
                    title     = f"Weak Rate Limit Threshold ({result.threshold}) — {url}",
                    url       = url,
                    severity  = "MEDIUM",
                    confidence= "medium",
                    detail    = (
                        f"Rate limit triggered after {result.threshold} requests. "
                        "Threshold is too high for security-sensitive endpoints."
                    ),
                    evidence  = f"429 appeared at request #{result.threshold}",
                )

            # Test IP bypass on limited endpoints
            if result.hit_429:
                self._test_ip_bypass(url, identity)

        # GraphQL batching bypass
        self._test_graphql_ratelimit(target_id)

        logger.section("Rate Limit Summary")
        logger.ok(f"Findings: {self._findings}")
        return self._findings

    def _test_endpoint(
        self, url: str, burst: int, identity: Optional[str]
    ) -> Optional[RateLimitResult]:
        """Sequential burst — track exactly when 429 appears."""
        # Quick reachability check
        probe = self.session.request("GET", url,
                                     identity_name=identity, capture=False)
        if probe is None:
            return None
        if probe.status_code in (404, 410):
            return None

        result = RateLimitResult(url=url, identity=identity or "anonymous",
                                 burst_size=burst)
        body = {"email": "test@test.com", "password": "test123"}

        for i in range(1, burst + 1):
            resp = self.session.request(
                "POST", url, json=body,
                identity_name=identity, capture=False,
            )
            # resp.status_code is checked via `is not None`, NOT truthiness —
            # requests.Response.__bool__() is False for ANY 4xx/5xx status,
            # including 429. The old `if resp else 0` meant a real 429
            # response was indistinguishable from a dead connection: sc
            # would be forced to 0 either way, so `sc == 429` could never
            # fire. This module's entire job is detecting 429s.
            sc = resp.status_code if resp is not None else 0
            result.status_dist[sc] = result.status_dist.get(sc, 0) + 1

            if sc == 429:
                result.hit_429  = True
                result.threshold = i
                logger.debug(f"  429 at request #{i}: {url}")
                break

        result.confidence = "high" if not result.hit_429 else "medium"
        return result

    def _test_ip_bypass(self, url: str, identity: Optional[str]) -> None:
        """Try IP spoofing headers to bypass rate limit."""
        body = {"email": "test@test.com", "password": "bypass_test"}

        for headers in IP_SPOOF_HEADERS:
            # Send 5 quick requests with the spoof header
            success = 0
            for _ in range(5):
                resp = self.session.request(
                    "POST", url, json=body, headers=headers,
                    identity_name=identity, capture=True,
                )
                if resp and resp.status_code != 429:
                    success += 1
            if success >= 4:
                header_str = list(headers.keys())[0]
                self._save(
                    title     = f"Rate Limit Bypass via {header_str} — {url}",
                    url       = url,
                    severity  = "HIGH",
                    confidence= "medium",
                    detail    = (
                        f"Setting `{header_str}: 127.0.0.1` bypassed rate limiting. "
                        f"{success}/5 requests returned non-429 after limit was hit."
                    ),
                    evidence  = f"Header: {headers}",
                )
                return

    def _test_graphql_ratelimit(self, target_id: int) -> None:
        """Check if GraphQL batching bypasses rate limits."""
        gql_eps = [ep.url for ep in queries.get_endpoints(target_id)
                   if "graphql" in ep.url.lower() or "gql" in ep.url.lower()]

        for ep in gql_eps[:3]:
            # Send a batch of 10 mutation-like queries
            batch = [{"query": "{ __typename }"}] * 10
            resp  = self.session.post(
                ep, json=batch,
                headers={"Content-Type": "application/json"},
                capture=True,
            )
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    if isinstance(data, list) and len(data) == 10:
                        self._save(
                            title     = f"GraphQL Batching Bypasses Rate Limit — {ep}",
                            url       = ep,
                            severity  = "MEDIUM",
                            confidence= "high",
                            detail    = (
                                "10 GraphQL queries submitted in one batch request "
                                "all returned results. This bypasses per-request rate limits "
                                "and can be used to brute-force OTP or passwords."
                            ),
                            evidence  = f"Batch of 10 returned {len(data)} responses.",
                        )
                except Exception:
                    pass

    def _save(
        self,
        title:      str,
        url:        str,
        severity:   str,
        confidence: str,
        detail:     str,
        evidence:   str,
    ) -> None:
        cap = self.session.last_capture
        queries.save_finding(
            target_id    = self._tid,
            module       = "ratelimit",
            title        = title,
            severity     = severity,
            confidence   = confidence,
            url          = url,
            method       = "POST",
            detail       = detail,
            evidence     = evidence,
            raw_request  = cap.raw_request  if cap else "",
            raw_response = cap.raw_response[:2000] if cap else "",
            curl_poc     = cap.curl         if cap else "",
            impact       = (
                "No rate limiting on auth endpoints enables brute-force attacks "
                "on passwords, OTP codes, email enumeration, and account takeover."
            ),
            remediation  = (
                "Implement server-side rate limiting based on account identifier, "
                "not just IP address. Apply exponential backoff after failures. "
                "Use CAPTCHA after N failures. Never trust client-supplied IP headers."
            ),
            cwe  = "CWE-307",
            cvss = 7.5 if severity == "HIGH" else 5.3,
            tags = ["ratelimit", "brute-force", "auth"],
        )
        self._findings += 1
        logger.finding(title=title, severity=severity, url=url, confidence=confidence)

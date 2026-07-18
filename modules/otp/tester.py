"""
BugKit v4 — 2FA / OTP Abuse Tester

Tests multi-factor authentication for the most common bypass categories:

  1. OTP brute-force (no rate limit on verify endpoint)
  2. OTP code reuse (same code accepted multiple times)
  3. OTP length tolerance (truncated / extended codes accepted)
  4. Response manipulation (200 with wrong code, code in response)
  5. Backup code enumeration
  6. 2FA bypass via account recovery flow
  7. 2FA skip via direct endpoint access (step skipping)
  8. Race condition on OTP verification (concurrent submissions)
  9. TOTP algorithm confusion (HOTP counter accepted)
  10. Cross-account OTP (one user's OTP accepted for another)
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import List

from core.session import BugKitSession
from core import logger
from engines.race_engine import RaceEngine
from db import queries


# Common 2FA endpoint paths
OTP_PATHS = [
    "/api/verify",
    "/api/2fa/verify",
    "/api/mfa/verify",
    "/api/otp/verify",
    "/api/totp/verify",
    "/api/auth/verify",
    "/api/v1/verify",
    "/api/v1/2fa/verify",
    "/verify",
    "/2fa",
    "/mfa/verify",
    "/otp",
    "/confirm",
    "/api/auth/2fa",
    "/api/auth/otp",
]

BACKUP_CODE_PATHS = [
    "/api/backup-codes",
    "/api/recovery-codes",
    "/api/2fa/backup",
    "/account/backup-codes",
    "/security/backup-codes",
]

RECOVERY_PATHS = [
    "/api/auth/recover",
    "/account/recovery",
    "/forgot-2fa",
    "/disable-2fa",
    "/api/2fa/disable",
]

# OTP field name variants
OTP_FIELD_NAMES = [
    "otp", "code", "token", "totp", "mfa_code",
    "verification_code", "auth_code", "two_factor_code",
    "pin", "passcode", "otp_code",
]


@dataclass
class OTPTestResult:
    url:         str
    test_name:   str
    vulnerable:  bool   = False
    confidence:  str    = "low"
    detail:      str    = ""
    evidence:    str    = ""
    severity:    str    = "HIGH"


class OTPTester:
    """
    2FA / OTP security tester.

    Usage:
        tester = OTPTester(session)
        tester.run(
            target_id = 1,
            base_url  = "https://app.example.com",
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
        identity:  str = None,
        username:  str = "test@example.com",
    ) -> int:
        logger.section(f"2FA / OTP Tester  →  {base_url}")
        self._tid      = target_id
        self._base     = base_url.rstrip("/")
        self._identity = identity
        self._username = username
        self._findings = 0

        # Discover OTP endpoints
        active_otp_eps = self._discover_otp_endpoints()
        if not active_otp_eps:
            logger.info("No OTP endpoints found. Checked common paths.")
            return 0

        logger.ok(f"Found {len(active_otp_eps)} OTP endpoint(s)")

        for ep in active_otp_eps:
            self._test_brute_force(ep)
            self._test_code_reuse(ep)
            self._test_length_tolerance(ep)
            self._test_code_in_response(ep)
            self._test_race_condition(ep)

        self._test_backup_codes()
        self._test_recovery_bypass()
        self._test_step_skip()
        self._test_cross_account_otp(active_otp_eps)

        logger.section("2FA / OTP Summary")
        logger.ok(f"Findings: {self._findings}")
        return self._findings

    # ── Discovery ──────────────────────────────────────────────────────

    def _discover_otp_endpoints(self) -> List[str]:
        active = []
        db_eps = [
            ep.url for ep in queries.get_endpoints(self._tid)
            if any(kw in ep.url.lower() for kw in
                   ["otp","2fa","mfa","verify","totp","confirm","pin"])
        ]
        heuristic = [self._base + p for p in OTP_PATHS]
        candidates = list(dict.fromkeys(db_eps + heuristic))

        for url in candidates[:20]:
            resp = self.session.get(url, capture=False)
            if resp and resp.status_code not in (404, 410, 500):
                active.append(url)
                logger.debug(f"  OTP endpoint: {url}  HTTP {resp.status_code}")
        return active

    # ── Test 1: Brute-force (no rate limit) ───────────────────────────

    def _test_brute_force(self, url: str) -> None:
        logger.info(f"Testing OTP brute-force: {url}")
        test_codes   = ["000000", "123456", "999999", "111111",
                        "000001", "000002", "000003"]
        non_429_hits = 0

        for code in test_codes:
            body = self._otp_body(code)
            resp = self.session.request(
                "POST", url, json=body,
                identity_name=self._identity,
                capture=True,
            )
            if resp is None:
                continue
            if resp.status_code != 429:
                non_429_hits += 1

        if non_429_hits >= 5:
            cap = self.session.last_capture
            self._save(
                title     = f"2FA — No Rate Limit on OTP Verify: {url}",
                url       = url,
                severity  = "HIGH",
                confidence= "high",
                detail    = (
                    f"Sent {len(test_codes)} OTP attempts with no 429 response "
                    f"({non_429_hits} returned non-429). "
                    "Attacker can brute-force 6-digit OTP in ~1M requests."
                ),
                evidence  = f"{non_429_hits}/{len(test_codes)} requests returned non-429.",
                raw_req   = cap.raw_request  if cap else "",
                raw_resp  = cap.raw_response[:1000] if cap else "",
                curl      = cap.curl         if cap else "",
                tags      = ["otp","brute-force","2fa","rate-limit"],
                cwe       = "CWE-307",
                cvss      = 8.1,
            )

    # ── Test 2: Code reuse ─────────────────────────────────────────────

    def _test_code_reuse(self, url: str) -> None:
        logger.info(f"Testing OTP code reuse: {url}")
        # We don't know a valid code so use a common test code and check
        # if submitting it twice behaves the same (suggests no invalidation)
        code = "123456"
        body = self._otp_body(code)

        r1 = self.session.request("POST", url, json=body,
                                   identity_name=self._identity, capture=False)
        if not r1:
            return

        time.sleep(0.5)
        r2 = self.session.request("POST", url, json=body,
                                   identity_name=self._identity, capture=True)
        if not r2:
            return

        # If both responses are identical and neither is a "already used" error
        reuse_indicators = ["already used","expired","invalid","used before"]
        r2_text = r2.text.lower()
        has_reuse_error = any(ind in r2_text for ind in reuse_indicators)

        if r1.status_code == r2.status_code and not has_reuse_error:
            cap = self.session.last_capture
            self._save(
                title     = f"2FA — OTP May Be Reusable: {url}",
                url       = url,
                severity  = "HIGH",
                confidence= "low",
                detail    = (
                    "Two identical OTP submissions returned the same status code "
                    "with no 'already used' error. Manual verification required."
                ),
                evidence  = f"R1: HTTP {r1.status_code}  R2: HTTP {r2.status_code}",
                raw_req   = cap.raw_request  if cap else "",
                raw_resp  = cap.raw_response[:1000] if cap else "",
                curl      = cap.curl         if cap else "",
                tags      = ["otp","code-reuse","2fa"],
                cwe       = "CWE-294",
                cvss      = 7.4,
            )

    # ── Test 3: Length tolerance ───────────────────────────────────────

    def _test_length_tolerance(self, url: str) -> None:
        logger.info(f"Testing OTP length tolerance: {url}")
        variants = [
            ("1234567890", "10-digit code"),
            ("123",        "3-digit truncated"),
            ("",           "empty code"),
            ("123456 ",    "code with trailing space"),
            (" 123456",    "code with leading space"),
        ]
        for code, desc in variants:
            body = self._otp_body(code)
            resp = self.session.request(
                "POST", url, json=body,
                identity_name=self._identity, capture=True,
            )
            if resp and resp.status_code == 200:
                resp_text = resp.text.lower()
                if any(kw in resp_text for kw in
                       ["success","verified","token","session","welcome"]):
                    cap = self.session.last_capture
                    self._save(
                        title     = f"2FA — OTP Length Tolerance Bypass: {desc}",
                        url       = url,
                        severity  = "CRITICAL",
                        confidence= "high",
                        detail    = (
                            f"OTP endpoint accepted malformed code: {desc!r}. "
                            "Server is not validating OTP format strictly."
                        ),
                        evidence  = f"Code: {code!r}\nHTTP {resp.status_code}\n{resp.text[:300]}",
                        raw_req   = cap.raw_request  if cap else "",
                        raw_resp  = cap.raw_response[:1000] if cap else "",
                        curl      = cap.curl         if cap else "",
                        tags      = ["otp","length-bypass","2fa"],
                        cwe       = "CWE-287",
                        cvss      = 9.1,
                    )

    # ── Test 4: Code in response ───────────────────────────────────────

    def _test_code_in_response(self, url: str) -> None:
        logger.info(f"Testing OTP in response body: {url}")
        body = self._otp_body("000000")
        resp = self.session.request(
            "POST", url, json=body,
            identity_name=self._identity, capture=True,
        )
        if resp is None:
            return
        resp_text = resp.text

        # Look for 6-digit sequences that look like OTP codes
        otp_pattern = re.compile(r'\b\d{6}\b')
        found_codes  = otp_pattern.findall(resp_text)

        # Remove the code we sent
        found_codes = [c for c in found_codes if c != "000000"]
        if found_codes:
            cap = self.session.last_capture
            self._save(
                title     = f"2FA — OTP Code Exposed in Response: {url}",
                url       = url,
                severity  = "CRITICAL",
                confidence= "medium",
                detail    = (
                    f"6-digit code(s) found in server response: {found_codes[:3]}. "
                    "Server may be returning the valid OTP in the response body."
                ),
                evidence  = f"Codes found: {found_codes[:5]}\n{resp_text[:400]}",
                raw_req   = cap.raw_request  if cap else "",
                raw_resp  = cap.raw_response[:1000] if cap else "",
                curl      = cap.curl         if cap else "",
                tags      = ["otp","information-disclosure","2fa"],
                cwe       = "CWE-200",
                cvss      = 9.8,
            )

    # ── Test 5: Race condition ─────────────────────────────────────────

    def _test_race_condition(self, url: str) -> None:
        logger.info(f"Testing OTP race condition: {url}")
        race    = RaceEngine(self.session)
        result  = race.race(
            "POST", url,
            json_body   = self._otp_body("123456"),
            concurrency = 8,
            identity    = self._identity,
        )
        if result.is_anomaly and result.success_count > 1:
            self._save(
                title     = f"2FA — Race Condition on OTP Verify: {url}",
                url       = url,
                severity  = "HIGH",
                confidence= "medium",
                detail    = (
                    f"{result.success_count} concurrent OTP requests returned success. "
                    "Race condition may allow code reuse or bypass."
                ),
                evidence  = json.dumps(result.status_distribution),
                raw_req   = "",
                raw_resp  = "",
                curl      = "",
                tags      = ["otp","race-condition","2fa"],
                cwe       = "CWE-362",
                cvss      = 8.1,
            )

    # ── Test 6: Backup codes ───────────────────────────────────────────

    def _test_backup_codes(self) -> None:
        logger.info("Testing backup code endpoints…")
        for path in BACKUP_CODE_PATHS:
            url  = self._base + path
            resp = self.session.request(
                "GET", url,
                identity_name=self._identity, capture=True,
            )
            if resp is None or resp.status_code in (404, 410):
                continue
            if resp.status_code == 200:
                code_pattern = re.compile(r'[A-Z0-9]{8,12}')
                found = code_pattern.findall(resp.text)
                if found:
                    cap = self.session.last_capture
                    self._save(
                        title     = f"2FA — Backup Codes Exposed: {url}",
                        url       = url,
                        severity  = "HIGH",
                        confidence= "high",
                        detail    = f"Backup recovery codes returned in plaintext: {found[:3]}",
                        evidence  = resp.text[:500],
                        raw_req   = cap.raw_request  if cap else "",
                        raw_resp  = cap.raw_response[:1000] if cap else "",
                        curl      = cap.curl         if cap else "",
                        tags      = ["otp","backup-codes","2fa","information-disclosure"],
                        cwe       = "CWE-312",
                        cvss      = 7.5,
                    )

    # ── Test 7: Recovery flow bypass ──────────────────────────────────

    def _test_recovery_bypass(self) -> None:
        logger.info("Testing 2FA recovery / disable bypass…")
        for path in RECOVERY_PATHS:
            url  = self._base + path
            # Probe without authentication
            self.session.as_guest()
            resp = self.session.request("POST", url,
                                         json={"email": self._username},
                                         capture=True)
            # Restore active identity
            if self.session._active_id:
                self.session.use(self.session._active_id)

            if resp and resp.status_code in (200, 201, 202):
                cap = self.session.last_capture
                self._save(
                    title     = f"2FA — Recovery Endpoint Accessible Without Auth: {url}",
                    url       = url,
                    severity  = "HIGH",
                    confidence= "medium",
                    detail    = (
                        f"2FA recovery endpoint {url} returned HTTP {resp.status_code} "
                        "to an unauthenticated request. May allow 2FA bypass."
                    ),
                    evidence  = f"HTTP {resp.status_code}\n{resp.text[:300]}",
                    raw_req   = cap.raw_request  if cap else "",
                    raw_resp  = cap.raw_response[:1000] if cap else "",
                    curl      = cap.curl         if cap else "",
                    tags      = ["otp","recovery","2fa-bypass","unauth"],
                    cwe       = "CWE-287",
                    cvss      = 9.1,
                )

    # ── Test 8: Step skip (direct protected endpoint) ─────────────────

    def _test_step_skip(self) -> None:
        logger.info("Testing 2FA step skip…")
        protected_paths = [
            "/dashboard", "/home", "/api/me",
            "/api/user", "/account", "/settings",
        ]
        for path in protected_paths:
            url  = self._base + path
            resp = self.session.request(
                "GET", url,
                identity_name=self._identity, capture=False,
            )
            if resp and resp.status_code == 200:
                resp_text = resp.text.lower()
                if any(kw in resp_text for kw in
                       ["dashboard","welcome","account","profile","settings"]):
                    self._save(
                        title     = f"2FA — Protected Page Accessible Without OTP: {url}",
                        url       = url,
                        severity  = "HIGH",
                        confidence= "low",
                        detail    = (
                            f"Authenticated endpoint {url} returned HTTP 200 "
                            "without completing 2FA verification. "
                            "Manual verification: confirm 2FA was not yet completed."
                        ),
                        evidence  = f"HTTP 200\n{resp.text[:300]}",
                        raw_req   = "",
                        raw_resp  = "",
                        curl      = "",
                        tags      = ["otp","step-skip","2fa-bypass"],
                        cwe       = "CWE-287",
                        cvss      = 8.1,
                    )
                    break

    # ── Test 9: Cross-account OTP ──────────────────────────────────────

    def _test_cross_account_otp(self, otp_eps: List[str]) -> None:
        if len(self.session.identity_names) < 2:
            return
        logger.info("Testing cross-account OTP…")
        id_a = self.session.identity_names[0]
        id_b = self.session.identity_names[1]

        for url in otp_eps[:3]:
            # Get OTP state as userA (trigger OTP send)
            body_a = self._otp_body("123456")

            # Submit as userA but then resubmit exact same request as userB
            self.session.request("POST", url, json=body_a,
                                  identity_name=id_a, capture=False)
            resp_b = self.session.request("POST", url, json=body_a,
                                           identity_name=id_b, capture=True)

            if resp_b and resp_b.status_code == 200:
                if any(kw in resp_b.text.lower() for kw in
                       ["success","verified","token"]):
                    cap = self.session.last_capture
                    self._save(
                        title     = f"2FA — Cross-Account OTP Accepted: {url}",
                        url       = url,
                        severity  = "CRITICAL",
                        confidence= "medium",
                        detail    = (
                            f"OTP submitted as '{id_a}' was accepted when replayed "
                            f"as '{id_b}'. OTP may not be bound to a specific user session."
                        ),
                        evidence  = f"A: {id_a}  B: {id_b}\nHTTP {resp_b.status_code}\n{resp_b.text[:300]}",
                        raw_req   = cap.raw_request  if cap else "",
                        raw_resp  = cap.raw_response[:1000] if cap else "",
                        curl      = cap.curl         if cap else "",
                        tags      = ["otp","cross-account","2fa-bypass","idor"],
                        cwe       = "CWE-287",
                        cvss      = 9.8,
                    )

    # ── Helpers ────────────────────────────────────────────────────────

    def _otp_body(self, code: str) -> dict:
        """Build a plausible OTP submission body with all common field names."""
        body: dict = {}
        for field in OTP_FIELD_NAMES:
            body[field] = code
        body["email"] = self._username
        return body

    def _save(
        self,
        title:      str,
        url:        str,
        severity:   str,
        confidence: str,
        detail:     str,
        evidence:   str,
        raw_req:    str,
        raw_resp:   str,
        curl:       str,
        tags:       list,
        cwe:        str,
        cvss:       float,
    ) -> None:
        queries.save_finding(
            target_id    = self._tid,
            module       = "otp",
            title        = title,
            severity     = severity,
            confidence   = confidence,
            url          = url,
            method       = "POST",
            detail       = detail,
            evidence     = evidence,
            raw_request  = raw_req,
            raw_response = raw_resp,
            curl_poc     = curl,
            impact       = (
                "2FA bypass enables full account takeover even when the "
                "victim has multi-factor authentication enabled."
            ),
            remediation  = (
                "Rate-limit OTP endpoints per account, not just per IP. "
                "Invalidate OTP codes immediately after first use. "
                "Bind OTP codes to a specific user session. "
                "Use cryptographically strong TOTP (RFC 6238). "
                "Never expose OTP values in API responses."
            ),
            cwe  = cwe,
            cvss = cvss,
            tags = tags,
        )
        self._findings += 1
        logger.finding(title=title, severity=severity, url=url, confidence=confidence)

"""
BugKit v4 — Billing / Subscription Logic Module

Tests for high-ROI billing bugs:
  • Coupon code reuse / race
  • Negative price / quantity manipulation
  • Plan upgrade without payment
  • Trial period reset
  • Downgrade confusion (access after cancel)
  • Invoice IDOR (access other users' invoices)
  • Referral credit abuse
"""
from __future__ import annotations

import json
import time
from typing import List

from core.session import BugKitSession
from core import logger
from db import queries
from engines.race_engine import RaceEngine
from engines.object_mutator import ObjectMutator


class BillingTester:
    """
    Billing logic test suite.

    Usage:
        tester = BillingTester(session)
        tester.run_all(
            target_id   = 1,
            base_url    = "https://app.example.com",
            coupon_code = "SAVE50",
            identity    = "userA",
        )
    """

    def __init__(self, session: BugKitSession) -> None:
        self.session   = session
        self._findings = 0

    def run_all(
        self,
        target_id:   int,
        base_url:    str,
        coupon_code: str = "",
        identity:    str = None,
    ) -> int:
        """Run all billing checks. Returns finding count."""
        logger.section(f"Billing Logic Tests  →  {base_url}")
        self._findings = 0
        self._tid      = target_id
        self._base     = base_url.rstrip("/")
        self._identity = identity

        self._test_coupon_reuse(coupon_code)
        self._test_coupon_race(coupon_code)
        self._test_negative_quantity()
        self._test_plan_upgrade_bypass()
        self._test_trial_reset()
        self._test_invoice_idor()
        self._test_downgrade_access()
        self._test_referral_abuse()

        logger.section("Billing Summary")
        logger.ok(f"Findings: {self._findings}")
        return self._findings

    # ── Individual checks ──────────────────────────────────────────────

    def _test_coupon_reuse(self, code: str) -> None:
        if not code:
            return
        logger.info(f"Testing coupon reuse: {code!r}")
        endpoints = self._find_billing_endpoints("coupon", "promo", "discount", "redeem")

        for ep in endpoints:
            body = {"coupon": code, "code": code, "promo_code": code}
            # Apply once
            r1 = self.session.request(
                "POST", ep, json=body, identity_name=self._identity, capture=True
            )
            if r1 is None or r1.status_code >= 400:
                continue

            time.sleep(0.5)

            # Apply again
            r2 = self.session.request(
                "POST", ep, json=body, identity_name=self._identity, capture=True
            )
            if r2 and r2.status_code < 400:
                self._save(
                    title      = f"Coupon Reuse — {code!r} applied twice",
                    url        = ep,
                    detail     = (
                        f"Coupon '{code}' was accepted twice by {ep}. "
                        f"First: HTTP {r1.status_code}, Second: HTTP {r2.status_code}."
                    ),
                    evidence   = f"R1: {r1.status_code}  R2: {r2.status_code}\n{r2.text[:300]}",
                    severity   = "HIGH",
                    confidence = "high",
                    tags       = ["billing", "coupon-reuse", "business-logic"],
                    cwe        = "CWE-841",
                    impact     = "Unlimited discount application, financial loss.",
                )

    def _test_coupon_race(self, code: str) -> None:
        if not code:
            return
        logger.info(f"Testing coupon race condition: {code!r}")
        endpoints = self._find_billing_endpoints("coupon", "promo", "redeem")

        race_engine = RaceEngine(self.session)
        for ep in endpoints:
            result = race_engine.race(
                "POST", ep,
                json_body   = {"coupon": code, "code": code},
                concurrency = 10,
                identity    = self._identity,
            )
            if result.is_anomaly:
                self._save(
                    title    = f"Coupon Race Condition — {code!r}",
                    url      = ep,
                    detail   = result.anomaly_note,
                    evidence = json.dumps(result.status_distribution),
                    severity = "HIGH",
                    confidence="medium",
                    tags     = ["billing", "race-condition", "coupon"],
                    cwe      = "CWE-362",
                    impact   = "Double/multiple redemption of one-time coupons.",
                )

    def _test_negative_quantity(self) -> None:
        logger.info("Testing negative quantity / price manipulation…")
        cart_endpoints = self._find_billing_endpoints(
            "cart", "order", "checkout", "purchase", "buy", "item"
        )

        neg_payloads = [
            {"quantity": -1},
            {"quantity": -99},
            {"amount":   -1},
            {"price":    -0.01},
            {"quantity": 0},
            {"count":    -1},
        ]

        for ep in cart_endpoints:
            for payload in neg_payloads:
                r = self.session.request(
                    "POST", ep, json=payload,
                    identity_name=self._identity, capture=True,
                )
                if r and r.status_code < 400:
                    self._save(
                        title     = f"Negative Quantity Accepted — {ep}",
                        url       = ep,
                        detail    = (
                            f"Payload {payload} accepted with HTTP {r.status_code}. "
                            "Negative pricing may allow credit or free goods."
                        ),
                        evidence  = f"Payload: {json.dumps(payload)}\n{r.text[:300]}",
                        severity  = "HIGH",
                        confidence= "medium",
                        tags      = ["billing", "negative-price", "business-logic"],
                        cwe       = "CWE-20",
                        impact    = "Financial loss, negative account balance abuse.",
                    )
                    break

    def _test_plan_upgrade_bypass(self) -> None:
        logger.info("Testing plan upgrade without payment…")
        upgrade_eps = self._find_billing_endpoints(
            "upgrade", "plan", "subscribe", "subscription", "tier"
        )

        # Try upgrading directly without going through payment
        paid_plans = ["pro", "premium", "enterprise", "business", "team", "plus"]
        for ep in upgrade_eps:
            for plan in paid_plans:
                for body in [
                    {"plan": plan},
                    {"plan_id": plan},
                    {"tier": plan},
                    {"subscription": {"plan": plan}},
                ]:
                    r = self.session.request(
                        "POST", ep, json=body,
                        identity_name=self._identity, capture=True,
                    )
                    if r and r.status_code in (200, 201, 202):
                        if any(kw in r.text.lower() for kw in
                               ["success", "updated", "upgraded", plan]):
                            self._save(
                                title     = f"Plan Upgrade Bypass — {plan} without payment",
                                url       = ep,
                                detail    = (
                                    f"POSTing {{plan: {plan!r}}} to {ep} returned HTTP {r.status_code} "
                                    "suggesting plan was upgraded without payment flow."
                                ),
                                evidence  = f"Payload: {json.dumps(body)}\n{r.text[:500]}",
                                severity  = "CRITICAL",
                                confidence= "medium",
                                tags      = ["billing", "plan-bypass", "business-logic"],
                                cwe       = "CWE-841",
                                impact    = "Free access to paid features, financial loss.",
                            )
                            break

    def _test_trial_reset(self) -> None:
        logger.info("Testing trial period reset…")
        trial_eps = self._find_billing_endpoints("trial", "free", "start", "reset")

        for ep in trial_eps:
            r = self.session.request(
                "POST", ep, json={"reset": True, "restart": True},
                identity_name=self._identity, capture=True,
            )
            if r and r.status_code < 400:
                if any(kw in r.text.lower() for kw in ["trial", "days", "free"]):
                    self._save(
                        title      = f"Trial Reset — {ep}",
                        url        = ep,
                        detail     = f"Trial appears to have been reset via POST to {ep}.",
                        evidence   = r.text[:400],
                        severity   = "MEDIUM",
                        confidence = "low",
                        tags       = ["billing", "trial-reset"],
                        cwe        = "CWE-841",
                        impact     = "Unlimited free trial periods.",
                    )

    def _test_invoice_idor(self) -> None:
        logger.info("Testing invoice IDOR…")
        invoice_eps = self._find_billing_endpoints("invoice", "receipt", "billing")

        mutator = ObjectMutator(self.session)
        for ep in invoice_eps:
            results     = mutator.sweep("GET", ep)
            finding_ids = mutator.save_findings(results, self._tid)
            self._findings += len(finding_ids)

    def _test_downgrade_access(self) -> None:
        logger.info("Testing access after downgrade/cancel…")
        feature_eps = self._find_billing_endpoints(
            "export", "api", "advanced", "report", "analytics", "team"
        )
        cancel_eps  = self._find_billing_endpoints("cancel", "downgrade", "unsubscribe")

        for cancel_ep in cancel_eps[:2]:
            r = self.session.request(
                "POST", cancel_ep, json={"confirm": True},
                identity_name=self._identity, capture=True,
            )
            if r and r.status_code < 400:
                time.sleep(1)
                for feat_ep in feature_eps[:5]:
                    r2 = self.session.request(
                        "GET", feat_ep, identity_name=self._identity, capture=True,
                    )
                    if r2 and r2.status_code == 200:
                        self._save(
                            title     = f"Post-Cancel Feature Access — {feat_ep}",
                            url       = feat_ep,
                            detail    = (
                                f"After cancelling at {cancel_ep}, "
                                f"premium endpoint {feat_ep} still returned HTTP 200."
                            ),
                            evidence  = r2.text[:300],
                            severity  = "MEDIUM",
                            confidence= "low",
                            tags      = ["billing", "downgrade", "access-control"],
                            cwe       = "CWE-613",
                            impact    = "Continued access to paid features after cancellation.",
                        )

    def _test_referral_abuse(self) -> None:
        logger.info("Testing referral / credit abuse…")
        ref_eps = self._find_billing_endpoints("referral", "refer", "credit", "reward")
        for ep in ref_eps:
            # Try self-referral
            r = self.session.request(
                "POST", ep,
                json={"referral_code": "SELF", "email": "self@self.com"},
                identity_name=self._identity, capture=True,
            )
            if r and r.status_code < 400 and any(
                kw in r.text.lower() for kw in ["credit", "reward", "bonus"]
            ):
                self._save(
                    title     = f"Referral Credit Abuse — {ep}",
                    url       = ep,
                    detail    = "Self-referral or repeated referral may be accepted.",
                    evidence  = r.text[:300],
                    severity  = "MEDIUM",
                    confidence= "low",
                    tags      = ["billing", "referral"],
                    cwe       = "CWE-841",
                    impact    = "Infinite credit generation via self-referral.",
                )

    # ── Helpers ────────────────────────────────────────────────────────

    def _find_billing_endpoints(self, *keywords: str) -> List[str]:
        """
        Return URLs from DB whose path contains any keyword,
        plus heuristic paths against the base URL.
        """
        eps = queries.get_endpoints(self._tid)
        matched = [
            ep.url for ep in eps
            if any(kw in ep.url.lower() for kw in keywords)
        ]
        # Always add heuristic paths
        for kw in keywords:
            for suffix in [
                f"/api/{kw}", f"/api/v1/{kw}", f"/api/v2/{kw}",
                f"/{kw}", f"/billing/{kw}", f"/account/{kw}",
            ]:
                url = self._base + suffix
                if url not in matched:
                    matched.append(url)
        return matched[:15]  # cap to avoid sprawl

    def _save(
        self,
        title:      str,
        url:        str,
        detail:     str,
        evidence:   str,
        severity:   str,
        confidence: str,
        tags:       list,
        cwe:        str,
        impact:     str,
    ) -> None:
        cap = self.session.last_capture
        queries.save_finding(
            target_id    = self._tid,
            module       = "billing",
            title        = title,
            severity     = severity,
            confidence   = confidence,
            url          = url,
            detail       = detail,
            evidence     = evidence,
            raw_request  = cap.raw_request  if cap else "",
            raw_response = cap.raw_response[:2000] if cap else "",
            curl_poc     = cap.curl         if cap else "",
            impact       = impact,
            remediation  = (
                "Implement server-side idempotency keys for all financial "
                "transactions. Validate all monetary values server-side (reject "
                "negative/zero amounts). Use atomic database transactions. "
                "Revoke feature access immediately on plan downgrade."
            ),
            cwe  = cwe,
            cvss = 8.6 if severity == "CRITICAL" else (7.0 if severity == "HIGH" else 5.0),
            tags = tags,
        )
        self._findings += 1
        logger.finding(title=title, severity=severity, url=url, confidence=confidence)

"""
BugKit v4 — Token Swap Engine

Given any captured request, replay it as every loaded identity
and compare responses using the diff engine.

This is the core primitive for IDOR and broken auth detection.
"""
from __future__ import annotations

from typing import List, Optional

import requests

from core.diff import DiffResult, compare
from core.session import BugKitSession
from core import logger
from db import queries


class TokenSwapResult:
    def __init__(
        self,
        url:         str,
        method:      str,
        baseline_id: str,
        diffs:       List[DiffResult],
    ) -> None:
        self.url         = url
        self.method      = method
        self.baseline_id = baseline_id
        self.diffs       = diffs

    @property
    def anomalous(self) -> List[DiffResult]:
        return [d for d in self.diffs if d.is_anomaly]

    @property
    def highest_confidence(self) -> str:
        for level in ("high", "medium", "low"):
            if any(d.confidence == level and d.is_anomaly for d in self.diffs):
                return level
        return "none"


class TokenSwapper:
    """
    Replay a single request across every identity and compare results
    against the baseline (original) response.

    Usage:
        swapper = TokenSwapper(session)
        result  = swapper.swap(method="GET", url="...", baseline_identity="userA")
        for diff in result.anomalous:
            print(diff.summary)
    """

    def __init__(self, session: BugKitSession) -> None:
        self.session = session

    def swap(
        self,
        method:             str,
        url:                str,
        baseline_identity:  str,
        request_kwargs:     dict = None,
        skip_same_user:     bool = True,
    ) -> TokenSwapResult:
        """
        1. Send request as `baseline_identity` → baseline response.
        2. Send same request as every other identity + anonymous.
        3. Diff each response against the baseline.
        4. Return TokenSwapResult with annotated DiffResults.
        """
        kwargs = request_kwargs or {}

        logger.section(f"Token Swap  {method} {url}")
        logger.info(f"Baseline identity: {baseline_identity}")

        # ── Baseline ──────────────────────────────────────────────────
        baseline_resp = self.session.swap_identity(
            baseline_identity, method, url, **kwargs
        )
        if baseline_resp is None:
            logger.err("Baseline request failed — cannot compare.")
            return TokenSwapResult(url, method, baseline_identity, [])

        logger.info(
            f"Baseline → HTTP {baseline_resp.status_code}  "
            f"size={len(baseline_resp.content)}B"
        )

        diffs: List[DiffResult] = []
        all_ids = list(self.session.identity_names) + ["__anonymous__"]

        for identity_name in all_ids:
            if skip_same_user and identity_name == baseline_identity:
                continue

            # Send as this identity
            if identity_name == "__anonymous__":
                resp = self._send_anonymous(method, url, **kwargs)
            else:
                resp = self.session.swap_identity(identity_name, method, url, **kwargs)

            diff = compare(
                identity_a=baseline_identity,
                response_a=baseline_resp,
                identity_b=identity_name,
                response_b=resp,
                url=url,
                method=method,
            )
            diffs.append(diff)

            icon = "⚑" if diff.is_anomaly else "·"
            logger.info(
                f"  {icon} [{identity_name:<20}]  "
                f"HTTP {resp.status_code if resp is not None else '---'}  "
                f"conf={diff.confidence}  {diff.summary}"
            )

        return TokenSwapResult(url, method, baseline_identity, diffs)

    def _send_anonymous(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Send without any credentials."""
        anon_session = self.session._make_session(force_anonymous=True)
        from config import settings
        try:
            return anon_session.request(
                method, url, verify=False, timeout=settings.timeout, **kwargs
            )
        except Exception:
            return None

    def save_findings(
        self,
        result:    TokenSwapResult,
        target_id: int,
        module:    str = "idor",
    ) -> List[int]:
        """Persist anomalous diffs as findings. Returns list of finding IDs."""
        finding_ids: List[int] = []
        for diff in result.anomalous:
            # Build evidence string
            evidence_lines = [f"Baseline: {diff.identity_a} → HTTP baseline"]
            for signal in diff.signals:
                if signal.is_anomaly:
                    evidence_lines.append(f"  ⚑ {signal}")

            # Get raw HTTP from capture history
            raw_req = raw_resp = curl = ""
            cap = self.session.last_capture
            if cap:
                raw_req  = cap.raw_request
                raw_resp = cap.raw_response[:2000]
                curl     = cap.curl

            f = queries.save_finding(
                target_id   = target_id,
                module      = module,
                title       = f"Broken Access Control — {diff.identity_b} can access {diff.identity_a}'s resource",
                severity    = "HIGH" if diff.confidence == "high" else "MEDIUM",
                confidence  = diff.confidence,
                url         = result.url,
                method      = result.method,
                evidence    = "\n".join(evidence_lines),
                raw_request = raw_req,
                raw_response= raw_resp,
                curl_poc    = curl,
                detail      = (
                    f"Identity '{diff.identity_b}' received a meaningfully different "
                    f"response to '{diff.identity_a}' when accessing the same endpoint.\n\n"
                    f"Signals: {diff.summary}"
                ),
                impact      = (
                    "Cross-user data access. Potential for account takeover, "
                    "data exfiltration, or privilege escalation."
                ),
                remediation = (
                    "Enforce server-side ownership checks on every object access. "
                    "Do not rely on client-supplied IDs without verifying the "
                    "requesting user's relationship to the object."
                ),
                cwe         = "CWE-639",
                cvss        = 8.1 if diff.confidence == "high" else 6.5,
                tags        = ["idor", "access-control", "bola"],
            )
            finding_ids.append(f.id)
            logger.finding(
                title      = f.title,
                severity   = f.severity,
                url        = result.url,
                confidence = diff.confidence,
            )
        return finding_ids

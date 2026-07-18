"""
BugKit v4 — Batch Comparator Engine

Runs a full cross-product comparison:
  • Every known endpoint  ×  Every loaded identity
  • Diffs each pair against the baseline identity's response
  • Uses the Scheduler for concurrent requests
  • Surfaces high-confidence anomalies as findings

This is the engine behind `bugkit idor batch` and `bugkit auth compare`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


from core.diff import DiffResult, compare
from core.scheduler import Scheduler, Task, TaskResult
from core.session import BugKitSession, CapturedPair
from core import logger
from db import queries


@dataclass
class CompareJob:
    """One (endpoint, identity) comparison unit."""
    url:           str
    method:        str
    identity_name: str
    request_kwargs: Dict = field(default_factory=dict)


@dataclass
class BatchResult:
    """Aggregated result of one full batch comparison run."""
    baseline_identity: str
    total_pairs:       int = 0
    anomalous:         int = 0
    findings_saved:    int = 0
    diffs:             List[DiffResult] = field(default_factory=list)

    @property
    def high_confidence(self) -> List[DiffResult]:
        return [d for d in self.diffs if d.confidence == "high" and d.is_anomaly]


class Comparator:
    """
    Batch multi-endpoint × multi-identity comparator.

    Usage:
        comp   = Comparator(session, workers=8)
        result = comp.run(
            target_id        = 1,
            baseline_identity= "userA",
            endpoints        = queries.get_endpoints(target_id),
        )
        print(f"Found {result.findings_saved} IDOR/broken-auth issues")
    """

    def __init__(self, session: BugKitSession, workers: int = 6) -> None:
        self.session   = session
        self.scheduler = Scheduler(workers=workers)

    def run(
        self,
        target_id:         int,
        baseline_identity: str,
        endpoints:         list,                # list of Endpoint ORM objects
        save_findings:     bool = True,
        min_confidence:    str  = "medium",
    ) -> BatchResult:
        """
        Full batch comparison.

        For each endpoint:
          1. Fetch as baseline_identity (sequential, one request per EP)
          2. Fetch concurrently as every other identity
          3. Diff each response against baseline
          4. Save high-confidence anomalies as findings
        """
        identities = [
            name for name in self.session.identity_names
            if name != baseline_identity
        ] + ["__anonymous__"]

        if not identities:
            logger.warn("No other identities loaded. Run: bugkit auth add")
            return BatchResult(baseline_identity=baseline_identity)

        result = BatchResult(baseline_identity=baseline_identity)

        logger.section(
            f"Batch Comparator  —  {len(endpoints)} endpoints  ×  "
            f"{len(identities)} identities"
        )
        logger.info(f"Baseline: {baseline_identity}")

        for ep in endpoints:
            url    = ep.url
            method = ep.method or "GET"

            # Step 1: baseline response
            baseline_resp = self.session.swap_identity(
                baseline_identity, method, url
            )
            if baseline_resp is None:
                logger.debug(f"  skip (no baseline response): {url}")
                continue

            baseline_status = baseline_resp.status_code
            if baseline_status in (404, 410, 500, 502, 503):
                logger.debug(f"  skip ({baseline_status}): {url}")
                continue

            # Step 2: concurrent requests as every other identity
            tasks = self._build_tasks(url, method, identities)
            task_results: List[TaskResult] = self.scheduler.run_tasks(tasks)

            # Step 3: diff each against baseline
            for tr in task_results:
                identity_name = tr.task.tag
                result.total_pairs += 1

                diff = compare(
                    identity_a = baseline_identity,
                    response_a = baseline_resp,
                    identity_b = identity_name,
                    response_b = tr.response,
                    url        = url,
                    method     = method,
                )
                result.diffs.append(diff)

                if diff.is_anomaly:
                    result.anomalous += 1
                    conf_ok = (
                        diff.confidence == "high" or
                        (min_confidence == "medium" and diff.confidence in ("medium","high")) or
                        min_confidence == "low"
                    )
                    if conf_ok:
                        sc = tr.response.status_code if tr.response else "???"
                        logger.warn(
                            f"  ⚑ [{identity_name:<20}]  {method} {url[:60]}  "
                            f"HTTP {sc}  conf={diff.confidence}"
                        )
                        if save_findings:
                            self._save(diff, target_id, url, method, task_result=tr)
                            result.findings_saved += 1

        logger.section("Batch Comparator Summary")
        logger.ok(
            f"Pairs tested: {result.total_pairs}  "
            f"Anomalies: {result.anomalous}  "
            f"Findings: {result.findings_saved}"
        )
        return result

    def run_urls(
        self,
        target_id:         int,
        baseline_identity: str,
        urls:              List[str],
        method:            str  = "GET",
        save_findings:     bool = True,
    ) -> BatchResult:
        """Convenience: compare a flat list of URLs (no ORM objects needed)."""

        class _FakeEP:
            def __init__(self, u: str, m: str) -> None:
                self.url    = u
                self.method = m

        eps = [_FakeEP(u, method) for u in urls]
        return self.run(
            target_id         = target_id,
            baseline_identity = baseline_identity,
            endpoints         = eps,
            save_findings     = save_findings,
        )

    # ── Helpers ────────────────────────────────────────────────────────

    def _build_tasks(
        self, url: str, method: str, identities: List[str]
    ) -> List[Task]:
        tasks = []
        for name in identities:
            if name == "__anonymous__":
                anon_sess = self.session._make_session(force_anonymous=True)
                tasks.append(Task(
                    fn     = anon_sess.request,
                    args   = (method, url),
                    kwargs = {"verify": False, "timeout": 15},
                    tag    = "__anonymous__",
                ))
            else:
                tasks.append(Task(
                    fn     = self.session.request,
                    args   = (method, url),
                    kwargs = {"identity_name": name, "capture": False},
                    tag    = name,
                ))
        return tasks

    def _save(
        self,
        diff:        DiffResult,
        target_id:   int,
        url:         str,
        method:      str,
        task_result: Optional[TaskResult] = None,
    ) -> None:
        signals = [s for s in diff.signals if s.is_anomaly]
        evidence = "\n".join([
            f"Baseline:  {diff.identity_a}",
            f"Compared:  {diff.identity_b}",
            "",
        ] + [f"  ⚑ {s}" for s in signals])

        # Build evidence from the actual comparison-identity response for
        # THIS finding, not the shared session.last_capture. Under the
        # Scheduler's concurrency, last_capture reflects whichever request
        # happened to run last across ALL worker threads — it does not
        # reliably correspond to diff.identity_b's request. requests.Response
        # already carries its own PreparedRequest on `.request`, so we can
        # rebuild a CapturedPair per-task with no shared mutable state.
        cap = None
        if task_result is not None and task_result.response is not None:
            prepared_req = getattr(task_result.response, "request", None)
            if prepared_req is not None:
                cap = CapturedPair(
                    identity = diff.identity_b,
                    request  = prepared_req,
                    response = task_result.response,
                    elapsed  = task_result.elapsed,
                )

        queries.save_finding(
            target_id    = target_id,
            module       = "idor",
            title        = (
                f"Broken Access Control — {diff.identity_b} receives "
                f"different response to {diff.identity_a}"
            ),
            severity     = "HIGH" if diff.confidence == "high" else "MEDIUM",
            confidence   = diff.confidence,
            url          = url,
            method       = method,
            evidence     = evidence,
            raw_request  = cap.raw_request  if cap else "",
            raw_response = cap.raw_response[:2000] if cap else "",
            curl_poc     = cap.curl         if cap else "",
            detail       = (
                f"Cross-identity response comparison detected a meaningful "
                f"difference between {diff.identity_a!r} and {diff.identity_b!r}.\n\n"
                f"Signals: {diff.summary}"
            ),
            impact       = (
                "Cross-user data access or privilege escalation. "
                "Attacker-controlled identity can access resources belonging to another user."
            ),
            remediation  = (
                "Enforce server-side ownership and role checks on every endpoint. "
                "Do not trust client-supplied identity claims. "
                "Use a centralised authorisation layer."
            ),
            cwe  = "CWE-639",
            cvss = 8.1 if diff.confidence == "high" else 6.5,
            tags = ["idor", "access-control", "bola", "batch-compare"],
        )

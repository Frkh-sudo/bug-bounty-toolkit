"""
BugKit v4 — Object Mutator / IDOR Sweep Engine

1. Parse a URL for object IDs (numeric, UUID) in path and query.
2. For each ID, generate mutations (±1, neighbours, another identity's known ID).
3. Send mutated requests as the active identity.
4. Compare responses using the diff engine.
5. Log anomalies as findings.

Safe by default: skips PUT/PATCH/DELETE unless --no-safe is set.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlparse, urlunparse

from core.diff import compare, DiffResult
from core.session import BugKitSession
from core.utils import (
    extract_ids_from_url, mutate_id, inject_param
)
from core import logger
from config import settings
from db import queries


@dataclass
class MutationResult:
    original_url: str
    mutated_url:  str
    location:     str           # e.g. "path:2" or "param:user_id"
    original_id:  str
    mutated_id:   str
    identity:     str
    diff:         Optional[DiffResult] = None
    is_anomaly:   bool = False


class ObjectMutator:
    """
    IDOR / BOLA sweep.

    Usage:
        mutator = ObjectMutator(session)
        results = mutator.sweep("GET", "https://api.example.com/users/1042/orders")
    """

    def __init__(self, session: BugKitSession) -> None:
        self.session = session

    def sweep(
        self,
        method:            str,
        url:               str,
        extra_ids:         List[str] = None,   # known IDs from other users
        request_kwargs:    dict = None,
    ) -> List[MutationResult]:
        """
        Main entry point. Finds IDs in URL, mutates each one, compares.
        Returns list of MutationResult (including anomaly flag).
        """
        if method.upper() in ("PUT", "PATCH", "DELETE") and settings.safe_mode:
            logger.warn(
                f"[SAFE MODE] Skipping {method} mutation. "
                "Use --no-safe to test write operations."
            )
            return []

        ids_found = extract_ids_from_url(url)
        if not ids_found:
            logger.info(f"No IDs detected in: {url}")
            return []

        logger.section(f"IDOR Sweep  {method} {url}")
        logger.info(f"Found {len(ids_found)} ID position(s): "
                    + ", ".join(f"{loc}={val}" for loc, val in ids_found))

        results: List[MutationResult] = []

        for location, original_id in ids_found:
            mutations = mutate_id(original_id)
            if extra_ids:
                mutations = list(extra_ids) + mutations   # prioritise real IDs

            # Baseline: the original URL as-is
            baseline_resp = self.session.request(method, url, **(request_kwargs or {}))
            if baseline_resp is None:
                logger.warn(f"Baseline failed for {url}")
                continue

            logger.info(
                f"  Baseline [{location}={original_id}] → "
                f"HTTP {baseline_resp.status_code}  "
                f"size={len(baseline_resp.content)}B"
            )

            for mut_id in mutations:
                mut_url = self._apply_mutation(url, location, mut_id)
                if mut_url == url:
                    continue

                resp = self.session.request(method, mut_url, **(request_kwargs or {}))
                diff = compare(
                    identity_a = "original",
                    response_a = baseline_resp,
                    identity_b = f"mutated[{location}={mut_id}]",
                    response_b = resp,
                    url        = mut_url,
                    method     = method,
                )

                mr = MutationResult(
                    original_url = url,
                    mutated_url  = mut_url,
                    location     = location,
                    original_id  = original_id,
                    mutated_id   = mut_id,
                    identity     = self.session._active_id or "unknown",
                    diff         = diff,
                    is_anomaly   = diff.is_anomaly,
                )
                results.append(mr)

                if diff.is_anomaly:
                    sc = resp.status_code if resp is not None else "???"
                    logger.warn(
                        f"  ⚑ [{location}] {original_id}→{mut_id}  "
                        f"HTTP {sc}  conf={diff.confidence}  {diff.summary}"
                    )
                else:
                    sc = resp.status_code if resp is not None else "???"
                    logger.debug(f"  · [{location}] {original_id}→{mut_id}  HTTP {sc}")

        return results

    def sweep_all_identities(
        self,
        method:         str,
        url:            str,
        request_kwargs: dict = None,
    ) -> List[MutationResult]:
        """
        For each identity, sweep the URL with their credentials.
        Cross-compares: can identity B access an ID that only identity A owns?
        """
        all_results: List[MutationResult] = []
        original_active = self.session._active_id

        for identity_name in self.session.identity_names:
            logger.info(f"Sweeping as: {identity_name}")
            self.session.use(identity_name)
            results = self.sweep(method, url, request_kwargs=request_kwargs)
            all_results.extend(results)

        # Restore original
        if original_active:
            self.session.use(original_active)

        return all_results

    def save_findings(
        self,
        results:   List[MutationResult],
        target_id: int,
    ) -> List[int]:
        """Persist anomalous mutation results as findings."""
        finding_ids: List[int] = []
        for mr in results:
            if not mr.is_anomaly or not mr.diff:
                continue
            signals = [s for s in mr.diff.signals if s.is_anomaly]
            evidence = "\n".join(
                [f"Original  : {mr.original_url}",
                 f"Mutated   : {mr.mutated_url}",
                 f"Location  : {mr.location}",
                 f"ID change : {mr.original_id} → {mr.mutated_id}",
                 ""]
                + [f"  ⚑ {s}" for s in signals]
            )
            cap = self.session.last_capture
            f = queries.save_finding(
                target_id   = target_id,
                module      = "idor",
                title       = (
                    f"IDOR — Accessing object {mr.mutated_id} via "
                    f"{mr.location} returns different data"
                ),
                severity    = "HIGH" if mr.diff.confidence == "high" else "MEDIUM",
                confidence  = mr.diff.confidence,
                url         = mr.mutated_url,
                method      = mr.diff.method,
                parameter   = mr.location,
                payload     = mr.mutated_id,
                evidence    = evidence,
                raw_request = cap.raw_request if cap else "",
                raw_response= cap.raw_response[:2000] if cap else "",
                curl_poc    = cap.curl if cap else "",
                detail      = (
                    f"Mutating [{mr.location}] from {mr.original_id!r} to "
                    f"{mr.mutated_id!r} produced a meaningfully different response.\n\n"
                    f"Signals: {mr.diff.summary}"
                ),
                impact      = (
                    "Insecure Direct Object Reference (IDOR/BOLA). "
                    "Attacker can access or modify resources belonging to other users "
                    "by enumerating or guessing IDs."
                ),
                remediation = (
                    "Implement server-side ownership verification for every "
                    "object access. Use opaque, non-sequential IDs (UUIDs). "
                    "Enforce access control at the data layer, not just the route."
                ),
                cwe  = "CWE-639",
                cvss = 8.1 if mr.diff.confidence == "high" else 6.5,
                tags = ["idor", "bola", "access-control"],
            )
            finding_ids.append(f.id)
        return finding_ids

    # ── Private helpers ────────────────────────────────────────────────

    def _apply_mutation(self, url: str, location: str, new_id: str) -> str:
        """Apply a single ID mutation to the URL."""
        parsed = urlparse(url)

        if location.startswith("path:"):
            idx      = int(location.split(":")[1])
            segments = parsed.path.split("/")
            # Account for leading empty string after split
            non_empty = [s for s in segments if s]
            if idx < len(non_empty):
                non_empty[idx] = new_id
                new_path = "/" + "/".join(non_empty)
                return urlunparse(parsed._replace(path=new_path))

        elif location.startswith("param:"):
            param = location.split(":", 1)[1]
            return inject_param(url, param, new_id)

        return url

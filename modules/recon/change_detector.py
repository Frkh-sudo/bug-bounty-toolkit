"""
BugKit v4 — Change Detection Engine

Compares current state against saved snapshots to find:
  • New endpoints that appeared
  • Auth removed from previously protected paths
  • Changed JS bundles (new routes, removed checks)
  • New parameters in API responses
  • Status code changes (404→200 = newly deployed)
  • Response size spikes (new data exposed)

Fresh changes = fresh attack surface = fresh bugs.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

from core.session import BugKitSession
from core.utils import sha256_of
from core import logger
from db import queries


@dataclass
class Change:
    kind:       str          # new_endpoint | auth_removed | content_change | status_change | size_spike
    url:        str
    old_value:  str = ""
    new_value:  str = ""
    severity:   str = "INFO"
    note:       str = ""


class ChangeDetector:
    """
    Compare a fresh crawl/snapshot against the DB baseline.

    Usage:
        detector = ChangeDetector(session)
        changes  = detector.run(target_id=1, base_url="https://example.com")
        detector.save_findings(changes, target_id=1)
    """

    def __init__(self, session: BugKitSession) -> None:
        self.session = session

    def run(self, target_id: int, base_url: str) -> List[Change]:
        logger.section(f"Change Detection  →  {base_url}")
        changes: List[Change] = []

        endpoints = queries.get_endpoints(target_id)
        if not endpoints:
            logger.warn("No baseline endpoints. Run recon first.")
            return []

        logger.info(f"Checking {len(endpoints)} known endpoint(s) for changes…")

        for ep in endpoints:
            snap = queries.get_latest_snapshot(target_id, ep.url)
            if snap is None:
                continue

            resp = self.session.get(ep.url, capture=False)
            if resp is None:
                continue

            current_hash = sha256_of(resp.content)
            current_size = len(resp.content)
            current_sc   = resp.status_code

            # ── Status code change ─────────────────────────────────────
            if snap.status != current_sc:
                sev  = "HIGH" if (snap.status in (401, 403) and current_sc == 200) else "MEDIUM"
                note = ""
                if snap.status in (401, 403) and current_sc == 200:
                    note = "Auth previously required — now public! High-priority review."
                elif snap.status == 404 and current_sc == 200:
                    note = "Endpoint newly deployed or restored."
                changes.append(Change(
                    kind      = "status_change",
                    url       = ep.url,
                    old_value = str(snap.status),
                    new_value = str(current_sc),
                    severity  = sev,
                    note      = note or f"Status changed {snap.status}→{current_sc}",
                ))

            # ── Auth removed ───────────────────────────────────────────
            if ep.auth_required and current_sc == 200:
                changes.append(Change(
                    kind      = "auth_removed",
                    url       = ep.url,
                    old_value = "auth_required=True",
                    new_value = f"HTTP {current_sc}",
                    severity  = "HIGH",
                    note      = "Endpoint previously required auth; now returns 200.",
                ))

            # ── Content changed ────────────────────────────────────────
            if snap.sha256 != current_hash and current_sc == 200:
                size_delta = abs(current_size - snap.body_size)
                pct        = size_delta / max(snap.body_size, 1) * 100
                sev        = "MEDIUM" if pct > 20 else "INFO"

                changes.append(Change(
                    kind      = "content_change",
                    url       = ep.url,
                    old_value = f"sha256={snap.sha256[:16]}…  size={snap.body_size}B",
                    new_value = f"sha256={current_hash[:16]}…  size={current_size}B",
                    severity  = sev,
                    note      = f"Content changed ({pct:.1f}% size delta). Review for new params / removed checks.",
                ))

            # ── Size spike (new data?) ─────────────────────────────────
            if current_size > snap.body_size * 2 and snap.body_size > 0:
                changes.append(Change(
                    kind      = "size_spike",
                    url       = ep.url,
                    old_value = f"{snap.body_size}B",
                    new_value = f"{current_size}B",
                    severity  = "MEDIUM",
                    note      = "Response size more than doubled — new data may be exposed.",
                ))

            # Save fresh snapshot
            queries.save_snapshot(
                target_id = target_id,
                url       = ep.url,
                sha256    = current_hash,
                body_size = current_size,
                status    = current_sc,
                headers   = dict(resp.headers),
            )

        # ── New endpoints (not in DB before) ───────────────────────────
        # Compare DB endpoints vs a fresh quick probe of common paths
        known_urls = {ep.url for ep in endpoints}
        from modules.recon.scanner import ADMIN_PATHS, API_DISCOVERY_PATHS
        base = base_url.rstrip("/")
        for path in ADMIN_PATHS + API_DISCOVERY_PATHS:
            url = base + path
            if url in known_urls:
                continue
            resp = self.session.get(url, capture=False)
            if resp and resp.status_code not in (404, 410, 400):
                changes.append(Change(
                    kind      = "new_endpoint",
                    url       = url,
                    old_value = "not in DB",
                    new_value = f"HTTP {resp.status_code}",
                    severity  = "HIGH" if resp.status_code == 200 else "MEDIUM",
                    note      = f"Previously unknown endpoint responded with HTTP {resp.status_code}.",
                ))
                queries.upsert_endpoint(
                    target_id   = target_id,
                    url         = url,
                    status_code = resp.status_code,
                    source      = "change_detector",
                )

        self._print_summary(changes)
        return changes

    def save_findings(self, changes: List[Change], target_id: int) -> int:
        count = 0
        important = [c for c in changes if c.severity in ("HIGH", "CRITICAL")]
        for c in important:
            queries.save_finding(
                target_id  = target_id,
                module     = "recon",
                title      = f"Change Detected — {c.kind.replace('_',' ').title()}: {c.url}",
                severity   = c.severity,
                confidence = "medium",
                url        = c.url,
                evidence   = f"Old: {c.old_value}\nNew: {c.new_value}",
                detail     = c.note,
                impact     = (
                    "Fresh changes to an application's attack surface often "
                    "introduce new vulnerabilities. Prioritise testing recently "
                    "changed or newly deployed endpoints."
                ),
                remediation= "Review the change. Verify access controls are correctly applied.",
                tags       = ["recon", "change-detection", c.kind],
            )
            count += 1
        return count

    def _print_summary(self, changes: List[Change]) -> None:
        if not changes:
            logger.ok("No changes detected.")
            return
        by_kind: dict = {}
        for c in changes:
            by_kind.setdefault(c.kind, []).append(c)
        logger.section("Change Detection Summary")
        for kind, items in by_kind.items():
            logger.info(f"  {kind:<22} {len(items)} change(s)")
        high = [c for c in changes if c.severity in ("HIGH","CRITICAL")]
        if high:
            logger.warn(f"\n  {len(high)} high-priority change(s):")
            for c in high:
                logger.warn(f"    ⚑ [{c.kind}] {c.url}")
                logger.warn(f"      {c.note}")

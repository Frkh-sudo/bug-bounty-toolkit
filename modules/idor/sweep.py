"""
BugKit v4 — IDOR / BOLA Sweep Module

High-level entry point for the IDOR engine.
Works in two modes:
  1. URL sweep: mutate IDs in a given URL across the active identity
  2. Cross-identity sweep: test each identity's access to other users' objects
"""
from __future__ import annotations

import json
from typing import List

from core.session import BugKitSession, Identity
from core import logger
from engines.object_mutator import ObjectMutator
from db import queries


def cmd_idor_sweep(
    target:     str,
    url:        str,
    method:     str,
    session:    BugKitSession,
    all_ids:    bool = False,    # also sweep with every identity
    extra_ids:  List[str] = None,
) -> int:
    """
    Sweep a URL for IDOR vulnerabilities.
    Returns number of findings saved.
    """
    t = queries.get_target(target)
    if not t:
        logger.err(f"Target '{target}' not found.")
        return 0

    # Load identities
    _load_identities(t.id, session)

    mutator = ObjectMutator(session)

    if all_ids:
        results = mutator.sweep_all_identities(method.upper(), url)
    else:
        results = mutator.sweep(method.upper(), url, extra_ids=extra_ids)

    finding_ids = mutator.save_findings(results, t.id)

    anomalous = [r for r in results if r.is_anomaly]
    logger.section("IDOR Sweep Summary")
    logger.ok(f"Mutations tested: {len(results)}  "
              f"Anomalies: {len(anomalous)}  "
              f"Findings: {len(finding_ids)}")
    return len(finding_ids)


def cmd_idor_batch(
    target:  str,
    session: BugKitSession,
) -> int:
    """
    Sweep ALL known endpoints in the DB for IDOR.
    Prioritises endpoints with detectable IDs.
    """
    t = queries.get_target(target)
    if not t:
        logger.err(f"Target '{target}' not found.")
        return 0

    _load_identities(t.id, session)

    endpoints = queries.get_endpoints(t.id)
    candidate_eps = []
    for ep in endpoints:
        from core.utils import extract_ids_from_url
        if extract_ids_from_url(ep.url):
            candidate_eps.append(ep)

    logger.section(f"IDOR Batch  —  {len(candidate_eps)} candidate endpoints")

    mutator  = ObjectMutator(session)
    total    = 0
    for ep in candidate_eps:
        results     = mutator.sweep(ep.method or "GET", ep.url)
        finding_ids = mutator.save_findings(results, t.id)
        total      += len(finding_ids)

    logger.ok(f"Batch complete. Total findings: {total}")
    return total


def _load_identities(target_id: int, session: BugKitSession) -> None:
    from core.session import decrypt
    for row in queries.get_identities(target_id):
        try:
            secrets = json.loads(decrypt(row.secrets))
            ident   = Identity(
                name    = row.name,
                role    = row.role,
                cookies = secrets.get("cookies", {}),
                headers = secrets.get("headers", {}),
                note    = row.note or "",
            )
            session.load_identity(ident)
        except Exception as e:
            logger.warn(f"Could not decrypt identity '{row.name}': {e}")

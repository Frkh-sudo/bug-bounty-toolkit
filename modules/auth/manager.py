"""
BugKit v4 — Auth / Identity Manager Module

Commands wired to CLI:
  bugkit auth add
  bugkit auth list
  bugkit auth test
  bugkit auth compare
"""
from __future__ import annotations

import json
from typing import Dict, List

from rich.table import Table

from core import logger
from core.session import BugKitSession, Identity, encrypt, decrypt
from db import queries


def cmd_auth_add(
    target:   str,
    name:     str,
    role:     str,
    cookies:  str = "",
    headers:  List[str] = None,
    note:     str = "",
) -> None:
    """
    Register a new identity for a target.
    cookies: "session=abc; csrf=xyz"
    headers: ["Authorization: Bearer ...", "X-API-Key: ..."]
    """
    t = queries.get_target(target)
    if not t:
        logger.err(f"Target '{target}' not found. Run: bugkit target add {target}")
        return

    # Parse cookies
    cookie_dict: Dict[str, str] = {}
    for pair in (cookies or "").split(";"):
        pair = pair.strip()
        if "=" in pair:
            k, v = pair.split("=", 1)
            cookie_dict[k.strip()] = v.strip()

    # Parse headers
    header_dict: Dict[str, str] = {}
    for hdr in (headers or []):
        if ":" in hdr:
            k, v = hdr.split(":", 1)
            header_dict[k.strip()] = v.strip()

    secrets_json = json.dumps({"cookies": cookie_dict, "headers": header_dict})
    secrets_enc  = encrypt(secrets_json)

    queries.save_identity(
        target_id = t.id,
        name      = name,
        role      = role,
        secrets   = secrets_enc,
        note      = note,
    )
    logger.ok(f"Identity '{name}' ({role}) saved for target '{target}'.")
    logger.info(
        f"  Cookies: {len(cookie_dict)} key(s)  "
        f"Headers: {len(header_dict)} key(s)"
    )


def cmd_auth_list(target: str) -> None:
    """List all registered identities for a target."""
    t = queries.get_target(target)
    if not t:
        logger.err(f"Target '{target}' not found.")
        return

    identities = queries.get_identities(t.id)
    if not identities:
        logger.warn("No identities registered. Run: bugkit auth add")
        return

    from rich.console import Console
    console = Console()
    table   = Table(title=f"Identities for {target}", show_lines=True)
    table.add_column("Name",     style="cyan bold")
    table.add_column("Role",     style="yellow")
    table.add_column("Verified", style="green")
    table.add_column("Note",     style="dim")

    for ident in identities:
        table.add_row(
            ident.name,
            ident.role,
            "✔" if ident.verified else "·",
            ident.note or "",
        )
    console.print(table)


def cmd_auth_test(
    target:  str,
    url:     str,
    session: BugKitSession,
) -> None:
    """
    Test that each identity can authenticate by fetching `url`
    and reporting the HTTP status received.
    """
    t = queries.get_target(target)
    if not t:
        logger.err(f"Target '{target}' not found.")
        return

    logger.section(f"Auth Test  →  {url}")

    identities = queries.get_identities(t.id)
    if not identities:
        logger.warn("No identities. Run: bugkit auth add")
        return

    # Load all identities into session
    for ident_row in identities:
        secrets = json.loads(decrypt(ident_row.secrets))
        ident   = Identity(
            name    = ident_row.name,
            role    = ident_row.role,
            cookies = secrets.get("cookies", {}),
            headers = secrets.get("headers", {}),
            note    = ident_row.note or "",
        )
        session.load_identity(ident)

    results = session.replay_all_identities("GET", url)

    for id_name, resp in results.items():
        sc  = resp.status_code if resp is not None else "---"
        sz  = len(resp.content) if resp is not None else 0
        icon = "✔" if resp and resp.status_code < 400 else "✖"
        col  = "green" if icon == "✔" else "red"
        logger.console.print(
            f"  [{col}]{icon}[/{col}]  [cyan]{id_name:<20}[/cyan]  "
            f"HTTP {sc}  {sz}B"
        )

        if resp and resp.status_code < 400:
            queries.mark_identity_verified(t.id, id_name)


def cmd_auth_compare(
    target:     str,
    url:        str,
    method:     str,
    baseline:   str,
    session:    BugKitSession,
    target_id:  int,
) -> None:
    """
    Compare responses to `url` across all identities vs the baseline.
    Saves findings for meaningful differences.
    """
    from engines.token_swapper import TokenSwapper

    t = queries.get_target(target)
    if not t:
        logger.err(f"Target '{target}' not found.")
        return

    # Load identities
    for ident_row in queries.get_identities(t.id):
        secrets = json.loads(decrypt(ident_row.secrets))
        ident   = Identity(
            name    = ident_row.name,
            role    = ident_row.role,
            cookies = secrets.get("cookies", {}),
            headers = secrets.get("headers", {}),
        )
        session.load_identity(ident)

    swapper = TokenSwapper(session)
    result  = swapper.swap(
        method            = method.upper(),
        url               = url,
        baseline_identity = baseline,
    )
    finding_ids = swapper.save_findings(result, t.id)

    logger.section("Auth Compare Summary")
    logger.ok(f"Anomalies: {len(result.anomalous)}  "
              f"Findings saved: {len(finding_ids)}")

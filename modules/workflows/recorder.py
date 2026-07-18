"""
BugKit v4 — Workflow Module CLI Commands

Thin wrappers that connect the CLI to the ReplayEngine.
"""
from __future__ import annotations

from typing import List

from core.session import BugKitSession
from core import logger
from engines.replay_engine import ReplayEngine
from db import queries


def cmd_workflow_record(
    target:   str,
    name:     str,
    session:  BugKitSession,
    steps:    List[dict],          # list of {method, url, body, note}
    description: str = "",
) -> None:
    t = queries.get_target(target)
    if not t:
        logger.err(f"Target '{target}' not found.")
        return

    engine = ReplayEngine(session)
    for step in steps:
        engine.record_step(
            name    = step.get("name", step["url"]),
            method  = step.get("method", "GET"),
            url     = step["url"],
            body    = step.get("body"),
            params  = step.get("params"),
            headers = step.get("headers"),
            note    = step.get("note", ""),
        )
    engine.save(name, t.id, description)


def cmd_workflow_replay(
    target:  str,
    name:    str,
    session: BugKitSession,
) -> int:
    t = queries.get_target(target)
    if not t:
        logger.err(f"Target '{target}' not found.")
        return 0

    logger.section(f"Workflow Replay  →  {name}")
    engine  = ReplayEngine.load(session, t.id, name)
    results = engine.run_all_scenarios()
    count   = engine.save_findings(results, t.id)

    anomalous = [r for r in results if r.is_anomaly]
    logger.ok(
        f"Scenarios run: {len(results)}  "
        f"Anomalies: {len(anomalous)}  "
        f"Findings: {count}"
    )
    return count


def cmd_workflow_list(target: str) -> None:
    t = queries.get_target(target)
    if not t:
        logger.err(f"Target '{target}' not found.")
        return
    wfs = queries.list_workflows(t.id)
    if not wfs:
        logger.warn("No workflows saved.")
        return
    from rich.table import Table
    from rich.console import Console
    table = Table(title=f"Workflows for {target}")
    table.add_column("Name",    style="cyan")
    table.add_column("Steps",   style="yellow")
    table.add_column("Description", style="dim")
    for wf in wfs:
        table.add_row(wf.name, str(len(wf.step_list)), wf.description or "")
    Console().print(table)

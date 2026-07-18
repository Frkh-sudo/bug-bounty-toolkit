"""
BugKit v4 — Structured logger using Rich.
Call log.* anywhere; findings get their own styled panel.
"""
from __future__ import annotations

from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console(highlight=False)
_debug_enabled = False


def enable_debug() -> None:
    global _debug_enabled
    _debug_enabled = True


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def info(msg: str) -> None:
    console.print(f"  [dim]{_ts()}[/dim]  [cyan]ℹ[/cyan]  {msg}")


def ok(msg: str) -> None:
    console.print(f"  [dim]{_ts()}[/dim]  [green]✔[/green]  {msg}")


def warn(msg: str) -> None:
    console.print(f"  [dim]{_ts()}[/dim]  [yellow]⚠[/yellow]  {msg}")


def err(msg: str) -> None:
    console.print(f"  [dim]{_ts()}[/dim]  [red]✖[/red]  {msg}")


def debug(msg: str) -> None:
    if _debug_enabled:
        console.print(f"  [dim]{_ts()}[/dim]  [magenta]⚙[/magenta]  [dim]{msg}[/dim]")


def section(title: str) -> None:
    console.rule(f"[bold cyan]{title}[/bold cyan]")


_SEV_STYLE = {
    "CRITICAL": ("red bold",   "🔴"),
    "HIGH":     ("red",        "🟠"),
    "MEDIUM":   ("yellow",     "🟡"),
    "LOW":      ("cyan",       "🔵"),
    "INFO":     ("white",      "⚪"),
}


def finding(
    title:    str,
    severity: str,
    url:      str,
    detail:   str = "",
    confidence: str = "medium",
) -> None:
    style, icon = _SEV_STYLE.get(severity.upper(), ("white", "⚪"))
    body = Text()
    body.append(f"{icon} [{severity}]  ", style=style + " bold")
    body.append(title + "\n", style="bold white")
    body.append(f"  URL: {url}\n", style="dim")
    if detail:
        body.append(f"  {detail}\n", style="dim")
    body.append(f"  Confidence: {confidence}", style="dim italic")
    console.print(Panel(body, border_style=style, box=box.ROUNDED, padding=(0, 1)))

"""
BugKit v4 — CLI  (Typer + Rich)

All commands are grouped by domain:
  target    add / list / remove
  auth      add / list / test / compare
  recon     run / changes
  idor      sweep / batch
  tenant    sweep
  billing   test
  workflow  record / replay / list
  graphql   test
  js        analyze
  oauth     test
  fuzz      run
  massassign test
  openapi   import / discover
  otp       test
  files     test
  websocket test
  ratelimit test
  report    md / html / json
  findings  list
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table

# ── Bootstrap ──────────────────────────────────────────────────────────
# Must happen before any local imports so config is available everywhere
from config import settings, VERSION
from core import logger
from core.scope import ScopeGuard
from core.session import BugKitSession
from db import queries

console = Console()
app     = typer.Typer(
    name            = "bugkit",
    help            = f"BugKit v{VERSION} — Intelligence-driven bug bounty platform",
    no_args_is_help = True,
    rich_markup_mode= "rich",
)

# Sub-apps
target_app   = typer.Typer(help="Manage targets",              no_args_is_help=True)
auth_app     = typer.Typer(help="Manage identities",           no_args_is_help=True)
recon_app    = typer.Typer(help="Reconnaissance",              no_args_is_help=True)
idor_app     = typer.Typer(help="IDOR / BOLA sweep",           no_args_is_help=True)
tenant_app   = typer.Typer(help="Tenant isolation testing",    no_args_is_help=True)
billing_app   = typer.Typer(help="Billing logic testing",       no_args_is_help=True)
workflow_app  = typer.Typer(help="Workflow record & replay",    no_args_is_help=True)
graphql_app   = typer.Typer(help="GraphQL security testing",    no_args_is_help=True)
js_app        = typer.Typer(help="JavaScript intelligence",     no_args_is_help=True)
report_app    = typer.Typer(help="Report generation",           no_args_is_help=True)
oauth_app     = typer.Typer(help="OAuth/OIDC security testing", no_args_is_help=True)
fuzz_app      = typer.Typer(help="Smart fuzzer (SQLi/XSS/blind/stored)", no_args_is_help=True)
massassign_app= typer.Typer(help="Mass assignment / over-posting", no_args_is_help=True)
openapi_app   = typer.Typer(help="OpenAPI/Swagger spec import", no_args_is_help=True)
otp_app       = typer.Typer(help="2FA/OTP abuse testing",       no_args_is_help=True)
files_app     = typer.Typer(help="File upload/download testing",no_args_is_help=True)
websocket_app = typer.Typer(help="WebSocket security testing",  no_args_is_help=True)
ratelimit_app = typer.Typer(help="Rate limit & brute-force",    no_args_is_help=True)

app.add_typer(target_app,    name="target")
app.add_typer(auth_app,      name="auth")
app.add_typer(recon_app,     name="recon")
app.add_typer(idor_app,      name="idor")
app.add_typer(tenant_app,    name="tenant")
app.add_typer(billing_app,   name="billing")
app.add_typer(workflow_app,  name="workflow")
app.add_typer(graphql_app,   name="graphql")
app.add_typer(js_app,        name="js")
app.add_typer(report_app,    name="report")
app.add_typer(oauth_app,     name="oauth")
app.add_typer(fuzz_app,      name="fuzz")
app.add_typer(massassign_app,name="massassign")
app.add_typer(openapi_app,   name="openapi")
app.add_typer(otp_app,       name="otp")
app.add_typer(files_app,     name="files")
app.add_typer(websocket_app, name="websocket")
app.add_typer(ratelimit_app, name="ratelimit")


# ── Global options callback ────────────────────────────────────────────

@app.callback()
def global_opts(
    proxy:    Optional[str]  = typer.Option(None,   "--proxy",    help="HTTP(S) proxy, e.g. http://127.0.0.1:8080"),
    delay:    float          = typer.Option(0.3,    "--delay",    help="Delay between requests (seconds)"),
    timeout:  int            = typer.Option(15,     "--timeout",  help="Per-request timeout (seconds)"),
    no_safe:  bool           = typer.Option(False,  "--no-safe",  help="Allow destructive requests (DELETE/PUT)"),
    dry_run:  bool           = typer.Option(False,  "--dry-run",  help="Print requests without sending"),
    debug:    bool           = typer.Option(False,  "--debug",    help="Verbose debug output"),
) -> None:
    if proxy:   settings.proxy    = proxy
    if delay:   settings.delay    = delay
    if timeout: settings.timeout  = timeout
    if no_safe: settings.safe_mode = False
    if dry_run: settings.dry_run  = True
    if debug:
        settings.debug = True
        logger.enable_debug()


# ── Session factory ────────────────────────────────────────────────────

def _make_session(
    target: str,
    cookie: str = "",
    header: List[str] = None,
) -> BugKitSession:
    t = queries.get_target(target)
    # ScopeGuard now fails CLOSED when given no patterns, so make sure we
    # never hand it an empty list here — fall back to the target name
    # itself (same as the "target not found" case) instead of silently
    # blocking every request for a target that was added without --scope.
    scope_patterns = (t.scope_list if t and t.scope_list else [target])
    scope   = ScopeGuard(scope_patterns)
    cookies = {}
    for pair in (cookie or "").split(";"):
        pair = pair.strip()
        if "=" in pair:
            k, v = pair.split("=", 1)
            cookies[k.strip()] = v.strip()
    headers = {}
    for h in (header or []):
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    return BugKitSession(
        scope,
        proxy          = settings.proxy,
        global_headers = headers or None,
    )


# ═══════════════════════════════════════════════════════════════════════
#  TARGET commands
# ═══════════════════════════════════════════════════════════════════════

@target_app.command("add")
def target_add(
    domain:   str          = typer.Argument(..., help="Target domain (e.g. example.com)"),
    base_url: str          = typer.Option("",  "--base-url", help="Base URL override"),
    scope:    List[str]    = typer.Option([],  "--scope",    help="Scope pattern (repeatable)"),
    notes:    str          = typer.Option("",  "--notes",    help="Free-text notes"),
) -> None:
    """Register a new target."""
    if not base_url:
        base_url = f"https://{domain}"
    if not scope:
        scope = [f"*.{domain}", domain]
    queries.upsert_target(domain=domain, base_url=base_url,
                          scope=list(scope), notes=notes)
    logger.ok(f"Target '{domain}' registered. Scope: {list(scope)}")


@target_app.command("list")
def target_list() -> None:
    """List all registered targets."""
    targets = queries.list_targets()
    if not targets:
        logger.warn("No targets. Run: bugkit target add <domain>")
        return
    table = Table(title="Registered Targets", show_lines=True)
    table.add_column("Domain",    style="cyan bold")
    table.add_column("Base URL",  style="dim")
    table.add_column("Tech",      style="yellow")
    table.add_column("Notes",     style="dim")
    for t in targets:
        table.add_row(t.domain, t.base_url or "", ", ".join(t.tech_list[:4]), t.notes or "")
    console.print(table)


@target_app.command("remove")
def target_remove(
    domain: str = typer.Argument(..., help="Target domain to remove"),
) -> None:
    """Remove a target and all its data."""
    if typer.confirm(f"Delete ALL data for '{domain}'?"):
        if queries.delete_target(domain):
            logger.ok(f"Target '{domain}' deleted.")
        else:
            logger.err(f"Target '{domain}' not found.")


# ═══════════════════════════════════════════════════════════════════════
#  AUTH commands
# ═══════════════════════════════════════════════════════════════════════

@auth_app.command("add")
def auth_add(
    target:  str        = typer.Argument(..., help="Target domain"),
    name:    str        = typer.Option(..., "--name", "-n", help="Identity name (e.g. userA)"),
    role:    str        = typer.Option("user", "--role", "-r", help="Role: guest|user|manager|admin"),
    cookie:  str        = typer.Option("", "--cookie", "-c", help="Cookies: 'session=abc; csrf=xyz'"),
    header:  List[str]  = typer.Option([], "--header", "-H", help="Header: 'Authorization: Bearer ...'"),
    note:    str        = typer.Option("", "--note",   help="Free-text note"),
) -> None:
    """Register an identity (session credentials) for a target."""
    from modules.auth.manager import cmd_auth_add
    cmd_auth_add(target=target, name=name, role=role,
                 cookies=cookie, headers=header, note=note)


@auth_app.command("list")
def auth_list(
    target: str = typer.Argument(..., help="Target domain"),
) -> None:
    """List all identities for a target."""
    from modules.auth.manager import cmd_auth_list
    cmd_auth_list(target)


@auth_app.command("test")
def auth_test(
    target:  str       = typer.Argument(..., help="Target domain"),
    url:     str       = typer.Option(..., "--url", "-u", help="Test URL"),
    cookie:  str       = typer.Option("", "--cookie"),
    header:  List[str] = typer.Option([], "--header", "-H"),
) -> None:
    """Test all registered identities against a URL."""
    from modules.auth.manager import cmd_auth_test
    session = _make_session(target, cookie, header)
    cmd_auth_test(target=target, url=url, session=session)


@auth_app.command("compare")
def auth_compare(
    target:   str       = typer.Argument(..., help="Target domain"),
    url:      str       = typer.Option(..., "--url", "-u",        help="URL to compare across identities"),
    method:   str       = typer.Option("GET", "--method", "-X",   help="HTTP method"),
    baseline: str       = typer.Option(...,   "--baseline", "-b", help="Baseline identity name"),
    cookie:   str       = typer.Option("", "--cookie"),
    header:   List[str] = typer.Option([], "--header", "-H"),
) -> None:
    """Compare responses across all identities vs a baseline (find IDOR/broken auth)."""
    from modules.auth.manager import cmd_auth_compare
    session = _make_session(target, cookie, header)
    t = queries.get_target(target)
    cmd_auth_compare(target=target, url=url, method=method,
                     baseline=baseline, session=session,
                     target_id=t.id if t else 0)


# ═══════════════════════════════════════════════════════════════════════
#  RECON commands
# ═══════════════════════════════════════════════════════════════════════

@recon_app.command("run")
def recon_run(
    target:  str       = typer.Argument(..., help="Target domain"),
    limit:   int       = typer.Option(100, "--limit", "-l", help="Max subdomains to fingerprint"),
    cookie:  str       = typer.Option("", "--cookie"),
    header:  List[str] = typer.Option([], "--header", "-H"),
) -> None:
    """Enumerate subdomains, fingerprint tech, snapshot endpoints."""
    from modules.recon.scanner import cmd_recon_run
    session = _make_session(target, cookie, header)
    cmd_recon_run(target=target, session=session, limit=limit)


@recon_app.command("changes")
def recon_changes(
    target:  str       = typer.Argument(..., help="Target domain"),
    cookie:  str       = typer.Option("", "--cookie"),
    header:  List[str] = typer.Option([], "--header", "-H"),
) -> None:
    """Detect changes vs last snapshot (new endpoints, auth removed, content changes)."""
    from modules.recon.change_detector import ChangeDetector
    t = queries.get_target(target)
    if not t:
        logger.err(f"Target '{target}' not found.")
        raise typer.Exit(1)
    session  = _make_session(target, cookie, header)
    detector = ChangeDetector(session)
    changes  = detector.run(target_id=t.id, base_url=t.base_url or f"https://{target}")
    detector.save_findings(changes, t.id)


# ═══════════════════════════════════════════════════════════════════════
#  IDOR commands
# ═══════════════════════════════════════════════════════════════════════

@idor_app.command("sweep")
def idor_sweep(
    target:  str       = typer.Argument(..., help="Target domain"),
    url:     str       = typer.Option(..., "--url", "-u", help="URL to sweep"),
    method:  str       = typer.Option("GET", "--method", "-X"),
    all_ids: bool      = typer.Option(False, "--all-ids", help="Sweep with every loaded identity"),
    extra:   List[str] = typer.Option([], "--extra-id", help="Known victim object ID to inject"),
    cookie:  str       = typer.Option("", "--cookie"),
    header:  List[str] = typer.Option([], "--header", "-H"),
) -> None:
    """Sweep a URL for IDOR by mutating detected object IDs."""
    from modules.idor.sweep import cmd_idor_sweep
    session = _make_session(target, cookie, header)
    cmd_idor_sweep(target=target, url=url, method=method,
                   session=session, all_ids=all_ids, extra_ids=extra or None)


@idor_app.command("batch")
def idor_batch(
    target:  str       = typer.Argument(..., help="Target domain"),
    cookie:  str       = typer.Option("", "--cookie"),
    header:  List[str] = typer.Option([], "--header", "-H"),
) -> None:
    """Sweep ALL known endpoints for IDOR (uses endpoints discovered by recon/crawl)."""
    from modules.idor.sweep import cmd_idor_batch
    session = _make_session(target, cookie, header)
    cmd_idor_batch(target=target, session=session)


# ═══════════════════════════════════════════════════════════════════════
#  TENANT commands
# ═══════════════════════════════════════════════════════════════════════

@tenant_app.command("sweep")
def tenant_sweep(
    target:      str       = typer.Argument(..., help="Target domain"),
    tenant_a:    str       = typer.Option(..., "--tenant-a", help="Your (attacker) tenant ID"),
    tenant_b:    str       = typer.Option(..., "--tenant-b", help="Victim tenant ID"),
    identity_a:  str       = typer.Option(None,"--identity-a", help="Your identity name"),
    identity_b:  str       = typer.Option(None,"--identity-b", help="Victim identity name"),
    cookie:      str       = typer.Option("", "--cookie"),
    header:      List[str] = typer.Option([], "--header", "-H"),
) -> None:
    """Test cross-tenant isolation (org_id/workspace_id header & param injection)."""
    from modules.tenant.isolation import TenantIsolationEngine
    t = queries.get_target(target)
    if not t:
        logger.err(f"Target '{target}' not found.")
        raise typer.Exit(1)
    session = _make_session(target, cookie, header)
    engine  = TenantIsolationEngine(session)
    engine.sweep(
        target_id   = t.id,
        base_url    = t.base_url or f"https://{target}",
        tenant_a_id = tenant_a,
        tenant_b_id = tenant_b,
        identity_a  = identity_a,
        identity_b  = identity_b,
    )


# ═══════════════════════════════════════════════════════════════════════
#  BILLING commands
# ═══════════════════════════════════════════════════════════════════════

@billing_app.command("test")
def billing_test(
    target:  str       = typer.Argument(..., help="Target domain"),
    coupon:  str       = typer.Option("", "--coupon", "-c", help="Coupon code to test for reuse/race"),
    identity:str       = typer.Option(None,"--identity", "-i", help="Identity to use"),
    cookie:  str       = typer.Option("", "--cookie"),
    header:  List[str] = typer.Option([], "--header", "-H"),
) -> None:
    """Run billing / subscription logic abuse tests."""
    from modules.billing.logic import BillingTester
    t = queries.get_target(target)
    if not t:
        logger.err(f"Target '{target}' not found.")
        raise typer.Exit(1)
    session = _make_session(target, cookie, header)
    tester  = BillingTester(session)
    tester.run_all(
        target_id   = t.id,
        base_url    = t.base_url or f"https://{target}",
        coupon_code = coupon,
        identity    = identity,
    )


# ═══════════════════════════════════════════════════════════════════════
#  WORKFLOW commands
# ═══════════════════════════════════════════════════════════════════════

@workflow_app.command("record")
def workflow_record(
    target:      str  = typer.Argument(..., help="Target domain"),
    name:        str  = typer.Option(..., "--name", "-n", help="Workflow name"),
    steps_file:  Path = typer.Option(..., "--steps", "-s",
                                     help="JSON file with step list [{name,method,url,body,...}]"),
    description: str  = typer.Option("", "--desc"),
    cookie:      str  = typer.Option("", "--cookie"),
    header:      List[str] = typer.Option([], "--header", "-H"),
) -> None:
    """Record a multi-step workflow from a JSON step file."""
    from modules.workflows.recorder import cmd_workflow_record
    steps   = json.loads(steps_file.read_text())
    session = _make_session(target, cookie, header)
    cmd_workflow_record(target=target, name=name, session=session,
                        steps=steps, description=description)


@workflow_app.command("replay")
def workflow_replay(
    target:  str       = typer.Argument(..., help="Target domain"),
    name:    str       = typer.Option(..., "--name", "-n", help="Workflow name"),
    cookie:  str       = typer.Option("", "--cookie"),
    header:  List[str] = typer.Option([], "--header", "-H"),
) -> None:
    """Replay a workflow in all mutation scenarios (skip, duplicate, reorder)."""
    from modules.workflows.recorder import cmd_workflow_replay
    session = _make_session(target, cookie, header)
    cmd_workflow_replay(target=target, name=name, session=session)


@workflow_app.command("list")
def workflow_list(
    target: str = typer.Argument(..., help="Target domain"),
) -> None:
    """List saved workflows for a target."""
    from modules.workflows.recorder import cmd_workflow_list
    cmd_workflow_list(target)


# ═══════════════════════════════════════════════════════════════════════
#  GRAPHQL commands
# ═══════════════════════════════════════════════════════════════════════

@graphql_app.command("test")
def graphql_test(
    target:  str       = typer.Argument(..., help="Target domain"),
    base_url:str       = typer.Option(None, "--url", "-u", help="Override base URL"),
    cookie:  str       = typer.Option("", "--cookie"),
    header:  List[str] = typer.Option([], "--header", "-H"),
) -> None:
    """Run full GraphQL security test suite."""
    from modules.graphql.tester import GraphQLTester
    t = queries.get_target(target)
    if not t:
        logger.err(f"Target '{target}' not found.")
        raise typer.Exit(1)
    session = _make_session(target, cookie, header)
    tester  = GraphQLTester(session)
    tester.run(
        target_id = t.id,
        base_url  = base_url or t.base_url or f"https://{target}",
    )


# ═══════════════════════════════════════════════════════════════════════
#  JS commands
# ═══════════════════════════════════════════════════════════════════════

@js_app.command("analyze")
def js_analyze(
    target:  str       = typer.Argument(..., help="Target domain"),
    url:     str       = typer.Option(None,  "--url", "-u", help="Override start URL"),
    deep:    bool      = typer.Option(True,  "--deep/--shallow",  help="Fetch all external JS"),
    cookie:  str       = typer.Option("", "--cookie"),
    header:  List[str] = typer.Option([], "--header", "-H"),
) -> None:
    """Extract secrets, endpoints, roles, feature flags from JavaScript."""
    from modules.jsintel.analyzer import JSAnalyzer
    t = queries.get_target(target)
    if not t:
        logger.err(f"Target '{target}' not found.")
        raise typer.Exit(1)
    session  = _make_session(target, cookie, header)
    analyzer = JSAnalyzer(session)
    start    = url or t.base_url or f"https://{target}"
    analyzer.analyze(url=start, target_id=t.id, deep=deep)


# ═══════════════════════════════════════════════════════════════════════
#  REPORT commands
# ═══════════════════════════════════════════════════════════════════════

@report_app.command("generate")
def report_generate(
    target:     str            = typer.Argument(..., help="Target domain"),
    fmt:        str            = typer.Option("md",  "--format", "-f",
                                             help="Output format: md | html | json"),
    output:     Optional[Path] = typer.Option(None,  "--output", "-o",
                                              help="Output file path (default: stdout)"),
    severity:   Optional[str]  = typer.Option(None,  "--severity",  help="Filter by severity"),
    module:     Optional[str]  = typer.Option(None,  "--module",    help="Filter by module"),
    finding_id: Optional[int]  = typer.Option(None,  "--id",        help="Report single finding"),
) -> None:
    """Generate a bug bounty report (md/html/json)."""
    from modules.reports.generator import ReportGenerator
    gen = ReportGenerator()
    gen.generate(
        target     = target,
        fmt        = fmt,
        output_path= output,
        severity   = severity,
        module     = module,
        finding_id = finding_id,
    )


# ── Alias: bugkit report html / md / json ─────────────────────────────

@report_app.command("html")
def report_html(
    target: str            = typer.Argument(...),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
) -> None:
    """Generate HTML report."""
    from modules.reports.generator import ReportGenerator
    ReportGenerator().generate(target=target, fmt="html", output_path=output)


@report_app.command("md")
def report_md(
    target: str            = typer.Argument(...),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
) -> None:
    """Generate Markdown report."""
    from modules.reports.generator import ReportGenerator
    ReportGenerator().generate(target=target, fmt="md", output_path=output)


# ═══════════════════════════════════════════════════════════════════════
#  FINDINGS command
# ═══════════════════════════════════════════════════════════════════════

@app.command("findings")
def findings_list(
    target:   Optional[str] = typer.Argument(None, help="Target domain"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s"),
    module:   Optional[str] = typer.Option(None, "--module",   "-m"),
    output:   Optional[Path]= typer.Option(None, "--output",   "-o", help="Export as JSON"),
) -> None:
    """List all findings (optionally filtered)."""
    t_id = None
    if target:
        t = queries.get_target(target)
        if not t:
            logger.err(f"Target '{target}' not found.")
            raise typer.Exit(1)
        t_id = t.id

    findings = queries.get_findings(target_id=t_id, module=module, severity=severity)
    if not findings:
        logger.warn("No findings.")
        return

    if output:
        data = [
            {k: getattr(f, k) for k in
             ("id","title","severity","confidence","module","url","parameter","cvss","created_at")}
            for f in findings
        ]
        output.write_text(json.dumps(data, indent=2, default=str))
        logger.ok(f"Exported {len(findings)} findings → {output}")
        return

    table = Table(title=f"Findings ({len(findings)})", show_lines=True)
    table.add_column("ID",         style="dim",       width=5)
    table.add_column("Severity",   style="bold",      width=10)
    table.add_column("Confidence", style="dim",       width=8)
    table.add_column("Module",     style="cyan",      width=12)
    table.add_column("Title",      style="white",     max_width=50)
    table.add_column("URL",        style="dim",       max_width=40)

    _SEV_COLOUR = {"CRITICAL":"red","HIGH":"yellow","MEDIUM":"bright_yellow",
                   "LOW":"cyan","INFO":"white"}
    for f in findings:
        col = _SEV_COLOUR.get(f.severity, "white")
        table.add_row(
            str(f.id),
            f"[{col}]{f.severity}[/{col}]",
            f.confidence or "",
            f.module,
            f.title[:50],
            f.url[:40],
        )
    console.print(table)


# ═══════════════════════════════════════════════════════════════════════
#  OAUTH commands
# ═══════════════════════════════════════════════════════════════════════

@oauth_app.command("test")
def oauth_test(
    target:       str       = typer.Argument(..., help="Target domain"),
    client_id:    str       = typer.Option("",   "--client-id",    help="OAuth client_id"),
    redirect_uri: str       = typer.Option("",   "--redirect-uri", help="Registered redirect_uri"),
    scopes:       str       = typer.Option("openid profile email", "--scopes"),
    identity:     str       = typer.Option(None, "--identity", "-i"),
    cookie:       str       = typer.Option("", "--cookie"),
    header:       List[str] = typer.Option([], "--header", "-H"),
) -> None:
    """Full OAuth/OIDC security test (state CSRF, redirect_uri, PKCE, scope escalation…)."""
    from modules.oauth.tester import OAuthTester
    t = queries.get_target(target)
    if not t:
        logger.err(f"Target '{target}' not found."); raise typer.Exit(1)
    session = _make_session(target, cookie, header)
    tester  = OAuthTester(session)
    tester.run(
        target_id    = t.id,
        base_url     = t.base_url or f"https://{target}",
        client_id    = client_id,
        redirect_uri = redirect_uri,
        identity     = identity,
        scopes       = scopes,
    )


# ═══════════════════════════════════════════════════════════════════════
#  FUZZ commands
# ═══════════════════════════════════════════════════════════════════════

@fuzz_app.command("run")
def fuzz_run(
    target:       str       = typer.Argument(..., help="Target domain"),
    url:          str       = typer.Option(..., "--url", "-u", help="Target URL"),
    checks:       str       = typer.Option(
                               "sqli,sqli_blind,xss,xss_stored,ssti,lfi,redirect",
                               "--checks", "-c", help="Comma-separated check list"),
    identity:     str       = typer.Option(None, "--identity", "-i"),
    waf_evasion:  bool      = typer.Option(False, "--waf-evasion", help="Enable WAF bypass variants"),
    payload_file: str       = typer.Option(None,  "--payload-file", help="Custom payload file"),
    store_url:    str       = typer.Option("",    "--store-url",
                                           help="URL to fetch after injection (stored XSS)"),
    cookie:       str       = typer.Option("", "--cookie"),
    header:       List[str] = typer.Option([], "--header", "-H"),
) -> None:
    """Smart fuzzer: SQLi (error+blind), XSS (reflected+stored), SSTI, LFI, redirect."""
    from modules.fuzz.tester import Fuzzer
    t = queries.get_target(target)
    if not t:
        logger.err(f"Target '{target}' not found."); raise typer.Exit(1)
    session = _make_session(target, cookie, header)
    fuzzer  = Fuzzer(session)
    fuzzer.run(
        target_id    = t.id,
        url          = url,
        checks       = [c.strip() for c in checks.split(",")],
        identity     = identity,
        waf_evasion  = waf_evasion,
        payload_file = payload_file,
        store_url    = store_url,
    )


# ═══════════════════════════════════════════════════════════════════════
#  MASS ASSIGNMENT commands
# ═══════════════════════════════════════════════════════════════════════

@massassign_app.command("test")
def massassign_test(
    target:   str       = typer.Argument(..., help="Target domain"),
    identity: str       = typer.Option(None, "--identity", "-i"),
    cookie:   str       = typer.Option("", "--cookie"),
    header:   List[str] = typer.Option([], "--header", "-H"),
) -> None:
    """Test all writable endpoints for mass assignment / over-posting vulnerabilities."""
    from modules.massassign.tester import MassAssignTester
    t = queries.get_target(target)
    if not t:
        logger.err(f"Target '{target}' not found."); raise typer.Exit(1)
    session = _make_session(target, cookie, header)
    tester  = MassAssignTester(session)
    tester.run(
        target_id = t.id,
        base_url  = t.base_url or f"https://{target}",
        identity  = identity,
    )


# ═══════════════════════════════════════════════════════════════════════
#  OPENAPI commands
# ═══════════════════════════════════════════════════════════════════════

@openapi_app.command("import")
def openapi_import(
    target:   str            = typer.Argument(..., help="Target domain"),
    spec_url: str            = typer.Option("", "--url", "-u",
                                            help="Direct URL to spec (auto-discovers if omitted)"),
    file:     Optional[Path] = typer.Option(None, "--file", "-f",
                                            help="Local spec file (JSON)"),
    cookie:   str            = typer.Option("", "--cookie"),
    header:   List[str]      = typer.Option([], "--header", "-H"),
) -> None:
    """Import OpenAPI/Swagger spec → auto-populate all endpoints into DB."""
    from modules.openapi.importer import OpenAPIImporter
    t = queries.get_target(target)
    if not t:
        logger.err(f"Target '{target}' not found."); raise typer.Exit(1)
    session  = _make_session(target, cookie, header)
    importer = OpenAPIImporter(session)
    base_url = t.base_url or f"https://{target}"
    if file:
        count = importer.import_from_file(t.id, file, base_url)
    else:
        count = importer.import_from_url(t.id, base_url, spec_url)
    logger.ok(f"Imported {count} endpoint(s) for '{target}'.")


@openapi_app.command("discover")
def openapi_discover(
    target:  str       = typer.Argument(..., help="Target domain"),
    cookie:  str       = typer.Option("", "--cookie"),
    header:  List[str] = typer.Option([], "--header", "-H"),
) -> None:
    """Probe common spec paths to find exposed OpenAPI/Swagger docs."""
    from modules.openapi.importer import SPEC_DISCOVERY_PATHS
    t = queries.get_target(target)
    if not t:
        logger.err(f"Target '{target}' not found."); raise typer.Exit(1)
    session  = _make_session(target, cookie, header)
    base_url = t.base_url or f"https://{target}"
    logger.section(f"OpenAPI Discovery  →  {base_url}")
    found = []
    for path in SPEC_DISCOVERY_PATHS:
        url  = base_url.rstrip("/") + path
        resp = session.get(url, capture=False)
        if resp and resp.status_code == 200:
            ct = resp.headers.get("Content-Type","")
            if "json" in ct or "yaml" in ct or url.endswith(".json"):
                logger.ok(f"Spec found: {url}  ({len(resp.content)}B)")
                found.append(url)
    if not found:
        logger.warn("No spec endpoints found.")
    else:
        logger.ok(f"Run: bugkit openapi import {target} --url {found[0]}")


# ═══════════════════════════════════════════════════════════════════════
#  OTP / 2FA commands
# ═══════════════════════════════════════════════════════════════════════

@otp_app.command("test")
def otp_test(
    target:   str       = typer.Argument(..., help="Target domain"),
    identity: str       = typer.Option(None, "--identity", "-i"),
    username: str       = typer.Option("test@example.com", "--username"),
    cookie:   str       = typer.Option("", "--cookie"),
    header:   List[str] = typer.Option([], "--header", "-H"),
) -> None:
    """Test 2FA/OTP for brute-force, reuse, race conditions, bypass, and more."""
    from modules.otp.tester import OTPTester
    t = queries.get_target(target)
    if not t:
        logger.err(f"Target '{target}' not found."); raise typer.Exit(1)
    session = _make_session(target, cookie, header)
    tester  = OTPTester(session)
    tester.run(
        target_id = t.id,
        base_url  = t.base_url or f"https://{target}",
        identity  = identity,
        username  = username,
    )


# ═══════════════════════════════════════════════════════════════════════
#  FILES commands
# ═══════════════════════════════════════════════════════════════════════

@files_app.command("test")
def files_test(
    target:   str       = typer.Argument(..., help="Target domain"),
    identity: str       = typer.Option(None, "--identity", "-i"),
    cookie:   str       = typer.Option("", "--cookie"),
    header:   List[str] = typer.Option([], "--header", "-H"),
) -> None:
    """Test file upload/download for IDOR, path traversal, content-type bypass, XSS."""
    from modules.files.tester import FileTester
    t = queries.get_target(target)
    if not t:
        logger.err(f"Target '{target}' not found."); raise typer.Exit(1)
    session = _make_session(target, cookie, header)
    tester  = FileTester(session)
    tester.run(
        target_id = t.id,
        base_url  = t.base_url or f"https://{target}",
        identity  = identity,
    )


# ═══════════════════════════════════════════════════════════════════════
#  WEBSOCKET commands
# ═══════════════════════════════════════════════════════════════════════

@websocket_app.command("test")
def websocket_test(
    target:   str       = typer.Argument(..., help="Target domain"),
    identity: str       = typer.Option(None, "--identity", "-i"),
    cookie:   str       = typer.Option("", "--cookie"),
    header:   List[str] = typer.Option([], "--header", "-H"),
) -> None:
    """Test WebSocket endpoints for auth bypass, CSWSH, subscription IDOR, injection."""
    from modules.websocket.tester import WebSocketTester
    t = queries.get_target(target)
    if not t:
        logger.err(f"Target '{target}' not found."); raise typer.Exit(1)
    session = _make_session(target, cookie, header)
    tester  = WebSocketTester(session)
    tester.run(
        target_id = t.id,
        base_url  = t.base_url or f"https://{target}",
        identity  = identity,
    )


# ═══════════════════════════════════════════════════════════════════════
#  RATELIMIT commands
# ═══════════════════════════════════════════════════════════════════════

@ratelimit_app.command("test")
def ratelimit_test(
    target:   str       = typer.Argument(..., help="Target domain"),
    burst:    int       = typer.Option(30,   "--burst", "-b", help="Requests per burst"),
    identity: str       = typer.Option(None, "--identity", "-i"),
    cookie:   str       = typer.Option("", "--cookie"),
    header:   List[str] = typer.Option([], "--header", "-H"),
) -> None:
    """Test rate limiting on auth endpoints; check IP-bypass headers and GraphQL batching."""
    from modules.ratelimit.tester import RateLimitTester
    t = queries.get_target(target)
    if not t:
        logger.err(f"Target '{target}' not found."); raise typer.Exit(1)
    session = _make_session(target, cookie, header)
    tester  = RateLimitTester(session)
    tester.run(
        target_id = t.id,
        base_url  = t.base_url or f"https://{target}",
        burst     = burst,
        identity  = identity,
    )


# ═══════════════════════════════════════════════════════════════════════
#  COMPARATOR (batch cross-identity sweep)
# ═══════════════════════════════════════════════════════════════════════

@idor_app.command("compare-all")
def idor_compare_all(
    target:    str       = typer.Argument(..., help="Target domain"),
    baseline:  str       = typer.Option(...,  "--baseline", "-b", help="Baseline identity name"),
    workers:   int       = typer.Option(6,    "--workers",  "-w", help="Concurrent threads"),
    min_conf:  str       = typer.Option("medium", "--min-confidence",
                                        help="Minimum confidence: low|medium|high"),
    cookie:    str       = typer.Option("", "--cookie"),
    header:    List[str] = typer.Option([], "--header", "-H"),
) -> None:
    """Batch-compare ALL known endpoints across ALL identities (finds IDOR at scale)."""
    from engines.comparator import Comparator
    from modules.idor.sweep import _load_identities
    t = queries.get_target(target)
    if not t:
        logger.err(f"Target '{target}' not found."); raise typer.Exit(1)
    session = _make_session(target, cookie, header)
    _load_identities(t.id, session)
    endpoints   = queries.get_endpoints(t.id)
    comparator  = Comparator(session, workers=workers)
    result      = comparator.run(
        target_id         = t.id,
        baseline_identity = baseline,
        endpoints         = endpoints,
        min_confidence    = min_conf,
    )
    logger.ok(
        f"Pairs: {result.total_pairs}  Anomalies: {result.anomalous}  "
        f"Findings: {result.findings_saved}"
    )


# ═══════════════════════════════════════════════════════════════════════
#  DATABASE utilities
# ═══════════════════════════════════════════════════════════════════════

@app.command("db-migrate")
def db_migrate() -> None:
    """Run pending database migrations (safe to run anytime)."""
    from db.migrations import migrate, current_version
    v_before = current_version(str(settings.db_path))
    migrate(str(settings.db_path))
    v_after  = current_version(str(settings.db_path))
    if v_after > v_before:
        logger.ok(f"Schema upgraded: v{v_before} → v{v_after}")
    else:
        logger.ok(f"Schema already current: v{v_after}")


@app.command("stats")
def stats_cmd() -> None:
    """Show finding counts and severity breakdown across all targets."""
    from rich.table import Table
    targets  = queries.list_targets()
    if not targets:
        logger.warn("No targets registered.")
        return
    table = Table(title="BugKit v4 — Stats", show_lines=True)
    table.add_column("Target",   style="cyan bold")
    table.add_column("CRITICAL", style="red",    justify="center")
    table.add_column("HIGH",     style="yellow",  justify="center")
    table.add_column("MEDIUM",   style="bright_yellow", justify="center")
    table.add_column("LOW",      style="cyan",    justify="center")
    table.add_column("Total",    style="white",   justify="center")
    for t in targets:
        findings = queries.get_findings(target_id=t.id)
        counts   = {s: 0 for s in ("CRITICAL","HIGH","MEDIUM","LOW")}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        table.add_row(
            t.domain,
            str(counts["CRITICAL"]) if counts["CRITICAL"] else "·",
            str(counts["HIGH"])     if counts["HIGH"]     else "·",
            str(counts["MEDIUM"])   if counts["MEDIUM"]   else "·",
            str(counts["LOW"])      if counts["LOW"]      else "·",
            str(len(findings)),
        )
    console.print(table)


# ═══════════════════════════════════════════════════════════════════════
#  BANNER
# ═══════════════════════════════════════════════════════════════════════

BANNER = f"""
[bold cyan]╔══════════════════════════════════════════════════════════════════════╗
║  BugKit v{VERSION}  —  Intelligence-Driven Bug Bounty Platform         ║
║                                                                      ║
║  recon · idor · tenant · billing · workflows · graphql · js         ║
║  oauth · fuzz · massassign · openapi · otp · files · websocket      ║
║  ratelimit · multi-identity · token-swap · smart-diff · reports     ║
╚══════════════════════════════════════════════════════════════════════╝[/bold cyan]
"""


def main() -> None:
    console.print(BANNER)
    app()


if __name__ == "__main__":
    main()

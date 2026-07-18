"""
BugKit v4 — JavaScript Intelligence Module

Goes far beyond secret scraping. Extracts:
  • Hidden API endpoints and routes
  • Role names and permission strings
  • Feature flags and debug parameters
  • GraphQL operations (queries/mutations)
  • Internal domain references
  • Hardcoded credentials and secrets
  • Admin/internal route hints
  • Client-side access control logic
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Set
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from core.session import BugKitSession
from core import logger
from db import queries


# ── Extraction patterns ────────────────────────────────────────────────

SECRETS = {
    "AWS Access Key":     re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret Key":     re.compile(r"(?i)aws.{0,10}secret.{0,10}['\"][0-9a-zA-Z/+]{40}"),
    "GitHub Token":       re.compile(r"gh[pousr]_[0-9a-zA-Z]{36,}"),
    "Google API Key":     re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Slack Token":        re.compile(r"xox[baprs]-[0-9a-zA-Z\-]{10,}"),
    "Stripe Secret Key":  re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    "Stripe Pub Key":     re.compile(r"pk_live_[0-9a-zA-Z]{24,}"),
    "Twilio SID":         re.compile(r"AC[0-9a-f]{32}"),
    "SendGrid Key":       re.compile(r"SG\.[0-9A-Za-z\-_]{22,}\.[0-9A-Za-z\-_]{43,}"),
    "Private Key PEM":    re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "JWT Bearer":         re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "Hardcoded Password": re.compile(r"""(?i)(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{6,}['"]"""),
    "Internal IP":        re.compile(r"(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)"),
    "Firebase URL":       re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"),
    "MongoDB URI":        re.compile(r"mongodb(?:\+srv)?://[^\s'\"]+"),
    "GCP Service Account":re.compile(r'"type"\s*:\s*"service_account"'),
    "NPM Token":          re.compile(r"npm_[0-9A-Za-z]{36}"),
    "Shopify Token":      re.compile(r"shpat_[0-9a-fA-F]{32}"),
    "Mailchimp Key":      re.compile(r"[0-9a-f]{32}-us[0-9]{2}"),
    "Twilio Auth Token":  re.compile(r"(?i)twilio.{0,10}auth.{0,10}['\"][0-9a-f]{32}"),
    "Generic API Key":    re.compile(r"""(?i)api[_-]?key\s*[:=]\s*['"][0-9a-zA-Z\-_]{16,}['"]"""),
}

API_ENDPOINTS = [
    re.compile(r"""(?:fetch|axios\.(?:get|post|put|patch|delete)|request)\s*\(\s*['"`]([^'"`\s]{4,200})['"`]"""),
    re.compile(r"""(?:url|baseURL|endpoint|path|route|href)\s*[:=]\s*['"`]([/][^'"`\s]{3,200})['"`]"""),
    re.compile(r"""['"`](\/api\/[^'"`\s]{3,200})['"`]"""),
    re.compile(r"""['"`](\/v\d+\/[^'"`\s]{3,200})['"`]"""),
    re.compile(r"""['"`](\/graphql[^'"`\s]*)['"`]"""),
    re.compile(r"""['"`](\/admin[^'"`\s]{2,200})['"`]"""),
    re.compile(r"""['"`](\/internal[^'"`\s]{2,200})['"`]"""),
]

ROLES = re.compile(
    r"""['"`](admin|superadmin|super_admin|moderator|manager|owner|"
    r"operator|staff|support|root|sysadmin|readonly|viewer|editor|"
    r"contributor|billing_admin|org_admin|tenant_admin)['"`]""",
    re.I,
)

FEATURE_FLAGS = re.compile(
    r"""(?:feature_?flag|featureFlag|isEnabled|isFeature|FEATURE_)\s*[:=]\s*\{([^}]{10,500})\}""",
    re.I,
)

DEBUG_PARAMS = re.compile(
    r"""['"`](debug|test|internal|dev|preview|beta|staging|admin_mode|"
    r"super|__debug|x_debug|force_admin|bypass)['"`]""",
    re.I,
)

GRAPHQL_OPS = re.compile(
    r"""(?:query|mutation)\s+(\w+)\s*[({]""",
    re.I,
)

INTERNAL_DOMAINS = re.compile(
    r"""(?:https?://)?([a-z0-9-]+\.(?:internal|corp|local|intranet|lan|"
    r"private|staging|dev|test|admin)\.[a-z]{2,10})""",
    re.I,
)

ACCESS_CONTROL_PATTERNS = re.compile(
    r"""(?:isAdmin|hasPermission|canAccess|isOwner|checkRole|requireAuth|"
    r"hasRole|userCan|allowedTo)\s*\(""",
    re.I,
)


@dataclass
class JSIntelResult:
    url:          str
    secrets:      List[dict]    = field(default_factory=list)
    endpoints:    Set[str]      = field(default_factory=set)
    roles:        Set[str]      = field(default_factory=set)
    feature_flags: List[str]   = field(default_factory=list)
    debug_params: Set[str]      = field(default_factory=set)
    graphql_ops:  Set[str]      = field(default_factory=set)
    internal_domains: Set[str]  = field(default_factory=set)
    access_ctrl:  List[str]     = field(default_factory=list)


class JSAnalyzer:
    """
    Fetch and deeply analyse JavaScript files attached to a target.

    Usage:
        analyzer = JSAnalyzer(session)
        results  = analyzer.analyze(
            "https://app.example.com",
            target_id=1,
            deep=True,
        )
    """

    def __init__(self, session: BugKitSession) -> None:
        self.session = session

    def analyze(
        self,
        url:       str,
        target_id: int,
        deep:      bool = True,
    ) -> List[JSIntelResult]:
        """
        Fetch the page, extract all JS sources, analyse each one.
        Returns list of JSIntelResult (one per JS file + inline).
        """
        logger.section(f"JS Intelligence  →  {url}")
        resp = self.session.get(url, capture=False)
        if resp is None:
            logger.err("Cannot reach target.")
            return []

        soup   = BeautifulSoup(resp.text, "html.parser")
        base   = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        results: List[JSIntelResult] = []

        # Inline scripts
        for script in soup.find_all("script"):
            if script.string and len(script.string.strip()) > 30:
                r = self._analyze_content(url + "#inline", script.string, base)
                results.append(r)

        if deep:
            # External script files
            for tag in soup.find_all("script", src=True):
                src = urljoin(url, tag["src"])
                if not self.session.scope.allows(src):
                    continue
                js_resp = self.session.get(src, capture=False)
                if js_resp and "javascript" in js_resp.headers.get("Content-Type",""):
                    r = self._analyze_content(src, js_resp.text, base)
                    results.append(r)
                    logger.debug(f"  Analysed: {src}")

        # Persist findings
        total_secrets   = 0
        total_endpoints = 0
        for r in results:
            total_secrets   += len(r.secrets)
            total_endpoints += len(r.endpoints)

            for secret in r.secrets:
                queries.save_finding(
                    target_id  = target_id,
                    module     = "jsintel",
                    title      = f"Secret in JS — {secret['type']}",
                    severity   = "HIGH",
                    confidence = "high",
                    url        = r.url,
                    evidence   = f"Type: {secret['type']}\nValue: {secret['value'][:80]}",
                    detail     = (
                        f"{secret['type']} found in JavaScript source at {r.url}. "
                        "Hardcoded credentials in client-side JS are world-readable."
                    ),
                    impact     = "Credential exposure to all users / attackers.",
                    remediation= (
                        "Never embed secrets in client-side code. "
                        "Use server-side environment variables and API proxies."
                    ),
                    cwe  = "CWE-312",
                    cvss = 7.5,
                    tags = ["jsintel", "secret", "credential"],
                )

            for ep in r.endpoints:
                queries.upsert_endpoint(
                    target_id = target_id,
                    url       = urljoin(url, ep) if ep.startswith("/") else ep,
                    source    = "js",
                )

        logger.ok(
            f"Analysed {len(results)} JS source(s).  "
            f"Secrets: {total_secrets}  Endpoints: {total_endpoints}"
        )
        self._print_summary(results)
        return results

    def _analyze_content(self, src_url: str, content: str, base: str) -> JSIntelResult:
        r = JSIntelResult(url=src_url)

        # Secrets
        for name, pattern in SECRETS.items():
            for match in pattern.findall(content):
                val = match if isinstance(match, str) else match[0]
                r.secrets.append({"type": name, "value": val[:200]})

        # API endpoints
        for pattern in API_ENDPOINTS:
            for ep in pattern.findall(content):
                if 2 < len(ep) < 200:
                    r.endpoints.add(ep)

        # Roles
        for m in ROLES.findall(content):
            r.roles.add(m.lower())

        # Feature flags
        for m in FEATURE_FLAGS.findall(content):
            r.feature_flags.append(m[:200])

        # Debug params
        for m in DEBUG_PARAMS.findall(content):
            r.debug_params.add(m.lower())

        # GraphQL operations
        for m in GRAPHQL_OPS.findall(content):
            r.graphql_ops.add(m)

        # Internal domains
        for m in INTERNAL_DOMAINS.findall(content):
            r.internal_domains.add(m.lower())

        # Client-side access control (worth flagging)
        for m in ACCESS_CONTROL_PATTERNS.findall(content):
            r.access_ctrl.append(m)

        return r

    def _print_summary(self, results: List[JSIntelResult]) -> None:
        all_roles    = set()
        all_ops      = set()
        all_internal = set()
        all_debug    = set()

        for r in results:
            all_roles    |= r.roles
            all_ops      |= r.graphql_ops
            all_internal |= r.internal_domains
            all_debug    |= r.debug_params

        if all_roles:
            logger.info(f"  Roles found:            {', '.join(sorted(all_roles))}")
        if all_ops:
            logger.info(f"  GraphQL operations:     {', '.join(sorted(all_ops)[:10])}")
        if all_internal:
            logger.warn(f"  Internal domains:       {', '.join(sorted(all_internal))}")
        if all_debug:
            logger.info(f"  Debug params:           {', '.join(sorted(all_debug))}")

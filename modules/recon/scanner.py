"""
BugKit v4 — Smart Recon Module

Focused on recon that LEADS to bugs, not just subdomain lists:
  • crt.sh + HackerTarget subdomain enumeration
  • DNS resolution + tech fingerprinting
  • Auth-required endpoint classification
  • Change detection snapshot (feeds change detector)
  • API base URL discovery
  • Admin panel detection
  • Known SaaS platform identification
"""
from __future__ import annotations

import json
import socket
from typing import List, Optional
from urllib.parse import urlparse
import urllib.request

import requests
try:
    import tldextract
except ImportError:
    tldextract = None  # optional: pip install tldextract

from core.session import BugKitSession
from core import logger
from db import queries
from core.utils import sha256_of


# ── Tech fingerprints — delegated to central registry ─────────────────
from core.fingerprints import fingerprint_response, detect_waf

# Paths that often indicate admin / sensitive surfaces
ADMIN_PATHS = [
    "/admin", "/admin/login", "/administrator", "/wp-admin",
    "/_admin", "/staff", "/internal", "/dashboard",
    "/manage", "/management", "/control", "/cp",
    "/api/admin", "/api/internal", "/api/v1/admin",
    "/superadmin", "/backoffice", "/console",
]

# Paths that reveal API structure
API_DISCOVERY_PATHS = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/graphql", "/graphiql",
    "/swagger", "/swagger.json", "/swagger/v1/swagger.json",
    "/openapi.json", "/openapi.yaml",
    "/docs", "/redoc",
    "/.well-known/openid-configuration",
    "/api-docs",
]


class ReconScanner:
    """
    Smart recon that builds an actionable target model.

    Usage:
        scanner = ReconScanner(session)
        scanner.run(domain="example.com", target_id=1, limit=200)
    """

    def __init__(self, session: BugKitSession) -> None:
        self.session = session

    def run(
        self,
        domain:    str,
        target_id: int,
        limit:     int = 100,
    ) -> dict:
        logger.section(f"Recon  →  {domain}")
        results = {
            "subdomains":    [],
            "admin_panels":  [],
            "api_surfaces":  [],
            "tech_stacks":   {},
        }

        # 1. Enumerate subdomains
        subs = self._enumerate_subdomains(domain, limit)
        logger.ok(f"Found {len(subs)} subdomain(s).")

        # 2. Fingerprint each
        base_url = queries.get_target(domain)
        base_url_str = (base_url.base_url if base_url else f"https://{domain}")

        for sub in subs:
            url = f"https://{sub}"
            info = self._fingerprint(url, target_id)
            if info:
                results["subdomains"].append(info)
                if info.get("tech"):
                    results["tech_stacks"][sub] = info["tech"]

        # 3. Admin panel detection on main domain
        logger.info("Probing admin surfaces…")
        for path in ADMIN_PATHS:
            url = base_url_str.rstrip("/") + path
            resp = self.session.get(url, capture=False)
            if resp and resp.status_code not in (404, 410):
                results["admin_panels"].append({
                    "url":    url,
                    "status": resp.status_code,
                })
                logger.warn(f"  Admin surface: {url}  →  HTTP {resp.status_code}")
                queries.upsert_endpoint(
                    target_id  = target_id,
                    url        = url,
                    status_code= resp.status_code,
                    auth_required = resp.status_code in (401, 403),
                    source     = "recon",
                )

        # 4. API surface discovery
        logger.info("Probing API surfaces…")
        for path in API_DISCOVERY_PATHS:
            url = base_url_str.rstrip("/") + path
            resp = self.session.get(url, capture=False)
            if resp and resp.status_code < 404:
                results["api_surfaces"].append({
                    "url":    url,
                    "status": resp.status_code,
                    "ct":     resp.headers.get("Content-Type", ""),
                })
                logger.info(f"  API surface: {url}  →  HTTP {resp.status_code}")
                queries.upsert_endpoint(
                    target_id   = target_id,
                    url         = url,
                    status_code = resp.status_code,
                    source      = "recon",
                )

                # Save snapshot for change detection
                self._snapshot(url, target_id, resp)

        logger.section("Recon Summary")
        logger.ok(
            f"Subdomains: {len(results['subdomains'])}  "
            f"Admin panels: {len(results['admin_panels'])}  "
            f"API surfaces: {len(results['api_surfaces'])}"
        )
        return results

    # ── Subdomain enumeration ──────────────────────────────────────────

    def _enumerate_subdomains(self, domain: str, limit: int) -> List[str]:
        found: set = set()

        # crt.sh
        try:
            req  = urllib.request.Request(
                f"https://crt.sh/?q=%.{domain}&output=json",
                headers={"User-Agent": "BugKit/4"},
            )
            with urllib.request.urlopen(req, timeout=15) as r:  # nosec B310 - scheme/host are fixed literals; domain is only a query param
                data = json.loads(r.read())
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if name.endswith(f".{domain}") or name == domain:
                        found.add(name)
            logger.info(f"  crt.sh: {len(found)} entries")
        except Exception as e:
            logger.debug(f"crt.sh error: {e}")

        # HackerTarget
        try:
            req  = urllib.request.Request(
                f"https://api.hackertarget.com/hostsearch/?q={domain}",
                headers={"User-Agent": "BugKit/4"},
            )
            with urllib.request.urlopen(req, timeout=10) as r:  # nosec B310 - scheme/host are fixed literals; domain is only a query param
                for line in r.read().decode().splitlines():
                    if "," in line:
                        sub = line.split(",")[0].strip()
                        if sub.endswith(f".{domain}"):
                            found.add(sub)
            logger.info(f"  HackerTarget: {len(found)} total")
        except Exception as e:
            logger.debug(f"HackerTarget error: {e}")

        # DNS common prefix bruteforce
        prefixes = [
            "www", "api", "app", "admin", "dashboard", "portal",
            "staging", "dev", "test", "beta", "cdn", "assets",
            "static", "media", "mail", "smtp", "ftp", "vpn",
            "auth", "login", "sso", "oauth", "id", "accounts",
            "billing", "pay", "shop", "store", "docs", "help",
            "support", "status", "monitor", "ops", "infra",
        ]
        for prefix in prefixes:
            sub = f"{prefix}.{domain}"
            try:
                socket.gethostbyname(sub)
                found.add(sub)
            except socket.gaierror:
                pass

        return sorted(found)[:limit]

    def _fingerprint(self, url: str, target_id: int) -> Optional[dict]:
        resp = self.session.get(url, capture=False)
        if resp is None:
            return None

        tech: List[str] = fingerprint_response(dict(resp.headers), resp.text)
        waf = detect_waf(dict(resp.headers), resp.text)
        if waf:
            tech.append(f"WAF:{waf}")

        domain = urlparse(url).hostname or url
        info = {
            "url":    url,
            "status": resp.status_code,
            "tech":   list(set(tech)),
            "size":   len(resp.content),
        }

        # Persist
        queries.upsert_endpoint(
            target_id    = target_id,
            url          = url,
            status_code  = resp.status_code,
            auth_required= resp.status_code in (401, 403),
            content_type = resp.headers.get("Content-Type", ""),
            source       = "recon",
        )

        # Update target tech
        t = queries.get_target(domain)
        if t and tech:
            existing = t.tech_list
            merged   = list(set(existing + tech))
            from db.models import Target as TargetModel
            with queries.get_db() as db:
                row = db.query(TargetModel).filter_by(id=t.id).first()
                if row:
                    row.tech = json.dumps(merged)

        self._snapshot(url, target_id, resp)
        return info

    def _snapshot(self, url: str, target_id: int,
                  resp: requests.Response) -> None:
        queries.save_snapshot(
            target_id = target_id,
            url       = url,
            sha256    = sha256_of(resp.content),
            body_size = len(resp.content),
            status    = resp.status_code,
            headers   = dict(resp.headers),
        )


def cmd_recon_run(
    target:  str,
    session: BugKitSession,
    limit:   int = 100,
) -> dict:
    t = queries.get_target(target)
    if not t:
        logger.err(f"Target '{target}' not found. Run: bugkit target add {target}")
        return {}
    scanner = ReconScanner(session)
    return scanner.run(domain=target, target_id=t.id, limit=limit)

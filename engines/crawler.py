"""
BugKit v4 — Smart Authenticated Crawler

Crawls a target respecting scope, using the active session identity.
Extracts:
  • All links (href, src, action)
  • API endpoint hints from JS inline and external
  • Forms with their methods and fields
  • Auth-required vs public endpoint classification
  • Object IDs in paths
"""
from __future__ import annotations

import re
from collections import deque
from typing import List, Set
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from core.session import BugKitSession
from core import logger
from db import queries


# Patterns to extract API routes from JS
_API_PATTERNS = [
    re.compile(r"""(?:fetch|axios\.(?:get|post|put|patch|delete))\s*\(\s*['"`]([^'"`\s]+)['"`]"""),
    re.compile(r"""(?:url|endpoint|path|route)\s*[:=]\s*['"`]([/][^'"`\s]+)['"`]"""),
    re.compile(r"""['"`](\/api\/[^'"`\s]{3,128})['"`]"""),
    re.compile(r"""['"`](\/v\d+\/[^'"`\s]{3,128})['"`]"""),
]


class Crawler:
    """
    Breadth-first crawler. Respects scope. Uses active session identity.
    Feeds discovered endpoints directly into the DB.
    """

    def __init__(
        self,
        session:    BugKitSession,
        target_id:  int,
        max_depth:  int = 3,
        max_pages:  int = 150,
    ) -> None:
        self.session   = session
        self.target_id = target_id
        self.max_depth = max_depth
        self.max_pages = max_pages
        self._visited:  Set[str] = set()
        self._endpoints: List[dict] = []

    def crawl(self, start_url: str) -> List[dict]:
        """
        BFS from start_url. Returns list of discovered endpoint dicts.
        """
        logger.section(f"Crawler  →  {start_url}")
        queue: deque = deque([(start_url, 0)])
        pages = 0

        while queue and pages < self.max_pages:
            url, depth = queue.popleft()
            if url in self._visited or depth > self.max_depth:
                continue
            if not self.session.scope.allows(url):
                continue
            self._visited.add(url)

            resp = self.session.get(url, capture=False)
            if resp is None:
                continue

            pages += 1
            ct      = resp.headers.get("Content-Type", "")
            auth_req = resp.status_code in (401, 403)

            # Store endpoint
            queries.upsert_endpoint(
                target_id    = self.target_id,
                url          = url,
                method       = "GET",
                status_code  = resp.status_code,
                auth_required= auth_req,
                content_type = ct,
                source       = "crawl",
            )
            self._endpoints.append({
                "url":    url,
                "status": resp.status_code,
                "auth":   auth_req,
            })

            logger.debug(f"  [{pages}] {resp.status_code} {url}")

            if "html" not in ct:
                continue

            soup   = BeautifulSoup(resp.text, "html.parser")
            base   = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

            # Extract links
            for tag, attr in [("a","href"),("form","action"),
                               ("link","href"),("script","src")]:
                for el in soup.find_all(tag):
                    href = el.get(attr, "")
                    if href:
                        abs_url = urljoin(url, href).split("#")[0]
                        if (self.session.scope.allows(abs_url)
                                and abs_url not in self._visited):
                            queue.append((abs_url, depth + 1))

            # Extract forms (store POST endpoints too)
            for form in soup.find_all("form"):
                action = urljoin(url, form.get("action") or url)
                method = (form.get("method") or "GET").upper()
                params = [
                    inp.get("name", "")
                    for inp in form.find_all(["input","textarea","select"])
                    if inp.get("name")
                ]
                if self.session.scope.allows(action):
                    queries.upsert_endpoint(
                        target_id = self.target_id,
                        url       = action,
                        method    = method,
                        params    = params,
                        source    = "crawl",
                    )

            # Extract API routes from inline JS
            for script in soup.find_all("script"):
                if not script.get("src") and script.string:
                    for pattern in _API_PATTERNS:
                        for m in pattern.findall(script.string):
                            api_url = urljoin(base, m)
                            if self.session.scope.allows(api_url):
                                queries.upsert_endpoint(
                                    target_id = self.target_id,
                                    url       = api_url,
                                    method    = "GET",
                                    source    = "js",
                                )

        logger.ok(f"Crawled {pages} pages. "
                  f"Discovered {len(self._endpoints)} endpoints.")
        return self._endpoints

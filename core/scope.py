"""
BugKit v4 — Scope Guard
Every outbound URL is checked against registered scope patterns before
the request is sent.  ScopeViolation is raised on out-of-scope URLs so
callers can catch or let it bubble.
"""
from __future__ import annotations

import fnmatch
import re
from typing import List
from urllib.parse import urlparse

try:
    import tldextract
except ImportError:
    tldextract = None  # optional: pip install tldextract


class ScopeViolation(Exception):
    pass


class ScopeGuard:
    """
    Allows URLs that match any pattern in `patterns`.
    Patterns support:
      - exact domain           example.com
      - wildcard subdomain     *.example.com
      - CIDR notation          10.0.0.0/8  (future)
      - regex                  ^api\\.example\\.com$
    """

    def __init__(self, patterns: List[str]) -> None:
        self._patterns = [p.strip().lower() for p in patterns if p.strip()]

    def allows(self, url: str) -> bool:
        if not self._patterns:
            # Fail CLOSED. This guard exists specifically to stop
            # accidental out-of-scope/unauthorized requests — a target
            # with no scope configured (e.g. `target add` without
            # --scope) must block everything, not allow everything.
            return False
        host = urlparse(url).hostname or ""
        host = host.lower()
        for pat in self._patterns:
            if pat.startswith("^"):
                if re.match(pat, host):
                    return True
            elif "*" in pat:
                if fnmatch.fnmatch(host, pat):
                    return True
            else:
                # exact or suffix match  (example.com also covers sub.example.com)
                if host == pat or host.endswith("." + pat):
                    return True
        return False

    def check(self, url: str) -> None:
        if not self.allows(url):
            raise ScopeViolation(f"Out of scope: {url}")

    def add(self, pattern: str) -> None:
        self._patterns.append(pattern.strip().lower())

    def __repr__(self) -> str:  # pragma: no cover
        return f"ScopeGuard({self._patterns})"

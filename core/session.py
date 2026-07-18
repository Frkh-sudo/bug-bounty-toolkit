"""
BugKit v4 — Multi-Identity Session Manager

This is the crown jewel of v4.  Every HTTP request is routed through
here so that:
  • Scope is enforced on every call
  • Rate limiting / throttling is applied
  • Proxy is configured once
  • Any registered identity can be swapped in instantly
  • All raw traffic is captured for evidence

Identities store:
  cookies, headers, tokens — encrypted at rest via Fernet.
"""
from __future__ import annotations

import json
import threading
import time
from typing import Dict, List, Optional

import requests
import urllib3
from cryptography.fernet import Fernet

from config import KEY_FILE, UA, settings
from core.scope import ScopeGuard, ScopeViolation
from core import logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ── Fernet key (auto-generated on first run) ───────────────────────────

def _load_or_create_key() -> bytes:
    if KEY_FILE.exists():
        return KEY_FILE.read_bytes()
    key = Fernet.generate_key()
    KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    KEY_FILE.write_bytes(key)
    KEY_FILE.chmod(0o600)
    return key


_fernet = Fernet(_load_or_create_key())


def encrypt(data: str) -> str:
    return _fernet.encrypt(data.encode()).decode()


def decrypt(data: str) -> str:
    return _fernet.decrypt(data.encode()).decode()


# ── Identity ────────────────────────────────────────────────────────────

class Identity:
    """
    Represents one account / session on a target.

    name:    human label (e.g. "userA", "admin_candidate", "guest")
    role:    semantic role (guest | user | manager | admin | superadmin)
    cookies: dict of cookie name → value
    headers: dict of header name → value  (Authorization, X-API-Key, etc.)
    note:    free-text (e.g. "created via /register with email a@a.com")
    """
    def __init__(
        self,
        name:    str,
        role:    str = "user",
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        note:    str = "",
    ) -> None:
        self.name    = name
        self.role    = role
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.note    = note

    # ── Serialisation (encrypted) ──────────────────────────────────────

    def to_encrypted_dict(self) -> dict:
        payload = json.dumps({
            "cookies": self.cookies,
            "headers": self.headers,
        })
        return {
            "name":    self.name,
            "role":    self.role,
            "note":    self.note,
            "secrets": encrypt(payload),
        }

    @classmethod
    def from_encrypted_dict(cls, d: dict) -> "Identity":
        secrets = json.loads(decrypt(d["secrets"]))
        return cls(
            name    = d["name"],
            role    = d.get("role", "user"),
            note    = d.get("note", ""),
            cookies = secrets.get("cookies", {}),
            headers = secrets.get("headers", {}),
        )

    def __repr__(self) -> str:
        return f"<Identity name={self.name!r} role={self.role!r}>"


# ── Captured request/response pair ─────────────────────────────────────

class CapturedPair:
    def __init__(
        self,
        identity:  str,
        request:   requests.PreparedRequest,
        response:  requests.Response,
        elapsed:   float,
    ) -> None:
        self.identity  = identity
        self.request   = request
        self.response  = response
        self.elapsed   = elapsed

    @property
    def raw_request(self) -> str:
        req = self.request
        lines = [f"{req.method} {req.path_url} HTTP/1.1"]
        for k, v in req.headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        if req.body:
            body = req.body if isinstance(req.body, str) else req.body.decode("utf-8", errors="replace")
            lines.append(body)
        return "\n".join(lines)

    @property
    def raw_response(self) -> str:
        r = self.response
        lines = [f"HTTP/1.1 {r.status_code} {r.reason}"]
        for k, v in r.headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        lines.append(r.text[:4096])
        return "\n".join(lines)

    @property
    def curl(self) -> str:
        req = self.request
        parts = [f"curl -sk -X {req.method} '{req.url}'"]
        for k, v in req.headers.items():
            if k.lower() not in ("content-length", "user-agent"):
                parts.append(f"  -H '{k}: {v}'")
        if req.body:
            body = req.body if isinstance(req.body, str) else req.body.decode("utf-8", errors="replace")
            parts.append(f"  -d '{body}'")
        return " \\\n".join(parts)


# ── BugKitSession ──────────────────────────────────────────────────────

class BugKitSession:
    """
    Thread-safe multi-identity HTTP session.

    Usage:
        session = BugKitSession(scope_guard)
        session.load_identity(identity)
        session.use("userA")           # switch active identity
        r = session.get("https://api.example.com/me")
        pair = session.last_capture    # CapturedPair

        # Swap: send same request as another identity
        r2 = session.swap_identity("userB", "GET", url)
    """

    def __init__(
        self,
        scope:         ScopeGuard,
        proxy:         Optional[str]         = None,
        global_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self.scope          = scope
        self._proxy         = proxy or settings.proxy
        self._global_headers = global_headers or {}
        self._identities:   Dict[str, Identity] = {}
        self._active_id:    Optional[str]        = None
        self._lock          = threading.Lock()
        self._last:         float                = 0.0
        self.last_capture:  Optional[CapturedPair] = None
        self.capture_history: List[CapturedPair]   = []

        # Internal requests.Session (recreated per identity switch)
        self._sess = self._make_session()

    # ── Identity management ────────────────────────────────────────────

    def load_identity(self, identity: Identity) -> None:
        self._identities[identity.name] = identity
        logger.debug(f"Loaded identity: {identity.name} ({identity.role})")

    def use(self, name: str) -> "BugKitSession":
        """Switch the active identity. Returns self for chaining."""
        if name not in self._identities:
            raise KeyError(f"Identity {name!r} not loaded. Run: bugkit auth add {name}")
        self._active_id = name
        self._sess = self._make_session()
        logger.debug(f"Active identity → {name}")
        return self

    def as_guest(self) -> "BugKitSession":
        """Drop all credentials — anonymous request."""
        self._active_id = None
        self._sess = self._make_session(override_identity=None, force_anonymous=True)
        return self

    @property
    def active_identity(self) -> Optional[Identity]:
        if self._active_id:
            return self._identities.get(self._active_id)
        return None

    @property
    def identity_names(self) -> List[str]:
        return list(self._identities.keys())

    # ── Session factory ────────────────────────────────────────────────

    def _make_session(
        self,
        override_identity: Optional[Identity] = None,
        force_anonymous:   bool               = False,
    ) -> requests.Session:
        sess = requests.Session()
        sess.verify = False
        sess.headers.update({"User-Agent": UA})
        sess.headers.update(self._global_headers)

        if self._proxy:
            sess.proxies = {"http": self._proxy, "https": self._proxy}

        if force_anonymous:
            return sess

        identity = override_identity or self.active_identity
        if identity:
            sess.headers.update(identity.headers)
            sess.cookies.update(identity.cookies)

        return sess

    # ── Throttle ───────────────────────────────────────────────────────

    def _throttle(self) -> None:
        with self._lock:
            elapsed = time.time() - self._last
            gap = settings.delay - elapsed
            if gap > 0:
                time.sleep(gap)
            self._last = time.time()

    # ── Core HTTP methods ──────────────────────────────────────────────

    def request(
        self,
        method:  str,
        url:     str,
        *,
        identity_name: Optional[str] = None,   # ad-hoc override
        capture: bool = True,
        throttle: bool = True,
        **kwargs,
    ) -> Optional[requests.Response]:
        """
        Send an HTTP request with scope checking, throttling, and capture.
        If `identity_name` is given the request is sent with that identity's
        credentials without changing the active identity.

        throttle=False skips the per-session delay gate. This exists for
        RaceEngine bursts specifically: those requests are already
        synchronized with a threading.Barrier so they land on the server
        at the same instant, deliberately bypassing normal pacing to
        expose race windows. Routing them through the shared throttle
        lock would serialize them right back into a sequential trickle
        with settings.delay between each one — defeating the entire
        technique before the request even leaves the client.
        """
        try:
            self.scope.check(url)
        except ScopeViolation as e:
            logger.warn(str(e))
            return None

        if settings.dry_run:
            logger.info(f"[DRY RUN] {method} {url}")
            return None

        # Build a session for the ad-hoc identity if specified
        if identity_name and identity_name in self._identities:
            sess = self._make_session(override_identity=self._identities[identity_name])
        else:
            sess = self._sess

        kwargs.setdefault("timeout", settings.timeout)
        kwargs.setdefault("allow_redirects", True)

        # timeout/allow_redirects belong to Session.send(), NOT to the
        # requests.Request() constructor — passing them into Request()
        # raises `TypeError: Request.__init__() got an unexpected keyword
        # argument 'timeout'` on every single call, every time, since
        # timeout is defaulted just above. The broad `except Exception`
        # below silently swallowed that TypeError and returned None,
        # which made every real request through this method fail
        # invisibly — callers just saw None back, as if the network
        # request itself had failed.
        timeout         = kwargs.pop("timeout")
        allow_redirects = kwargs.pop("allow_redirects")

        if throttle:
            self._throttle()

        for attempt in range(settings.retries + 1):
            try:
                prep = sess.prepare_request(requests.Request(method, url, **kwargs))
                t0   = time.time()
                resp = sess.send(prep, verify=False, timeout=timeout,
                                 allow_redirects=allow_redirects)
                elapsed = time.time() - t0

                if capture:
                    used_id = identity_name or self._active_id or "anonymous"
                    pair = CapturedPair(used_id, prep, resp, elapsed)
                    self.last_capture = pair
                    self.capture_history.append(pair)

                logger.debug(f"{method} {url}  →  {resp.status_code}  ({elapsed*1000:.0f}ms)  [{identity_name or self._active_id or 'anon'}]")
                return resp

            except requests.exceptions.Timeout:
                if attempt < settings.retries:
                    time.sleep(0.5 * (attempt + 1))
                else:
                    logger.warn(f"Timeout: {url}")
                    return None
            except Exception as e:
                logger.debug(f"Request error {url}: {e}")
                return None

    def get(self, url: str, **kw) -> Optional[requests.Response]:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw) -> Optional[requests.Response]:
        return self.request("POST", url, **kw)

    def put(self, url: str, **kw) -> Optional[requests.Response]:
        return self.request("PUT", url, **kw)

    def patch(self, url: str, **kw) -> Optional[requests.Response]:
        return self.request("PATCH", url, **kw)

    def delete(self, url: str, **kw) -> Optional[requests.Response]:
        if settings.safe_mode:
            logger.warn(f"[SAFE MODE] Blocking DELETE {url}. Use --no-safe to allow.")
            return None
        return self.request("DELETE", url, **kw)

    # ── Identity swap convenience ──────────────────────────────────────

    def swap_identity(
        self,
        identity_name: str,
        method: str,
        url: str,
        **kwargs,
    ) -> Optional[requests.Response]:
        """
        Replay a request with a different identity WITHOUT changing the
        active identity.  Used by the token swap engine and IDOR sweeper.
        """
        return self.request(method, url, identity_name=identity_name,
                            capture=True, **kwargs)

    def replay_all_identities(
        self,
        method: str,
        url: str,
        **kwargs,
    ) -> Dict[str, Optional[requests.Response]]:
        """
        Send the same request as every loaded identity (+ anonymous).
        Returns {identity_name: response}.
        """
        results: Dict[str, Optional[requests.Response]] = {}
        # Anonymous
        anon_sess = self._make_session(force_anonymous=True)
        try:
            self.scope.check(url)
            self._throttle()
            results["__anonymous__"] = anon_sess.request(
                method, url, verify=False, timeout=settings.timeout, **kwargs
            )
        except Exception:
            results["__anonymous__"] = None

        for name in self._identities:
            results[name] = self.swap_identity(name, method, url, **kwargs)

        return results

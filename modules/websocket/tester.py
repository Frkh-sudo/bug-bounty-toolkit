"""
BugKit v4 — WebSocket Security Tester

Tests WebSocket endpoints for:
  1. Auth bypass — does WS accept connections without credentials?
  2. Token reuse after logout
  3. Cross-user message injection
  4. Subscription channel auth (can userB subscribe to userA's channel?)
  5. CSWSH — Cross-Site WebSocket Hijacking
  6. SQL / command injection in WS messages
  7. Insecure direct object reference in WS subscribe payloads

Uses only stdlib (http.client + socket + ssl) — no websockets package.
Falls back gracefully if the target doesn't support WebSockets.
"""
from __future__ import annotations

import base64
import json
import socket
import ssl
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List
from urllib.parse import urlparse

from core.session import BugKitSession
from core import logger
from db import queries


@dataclass
class WSConnection:
    """Represents an open (or attempted) WebSocket connection."""
    url:       str
    connected: bool      = False
    messages:  List[str] = field(default_factory=list)
    error:     str       = ""
    sock:      Any       = None

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None


class WebSocketTester:
    """
    WebSocket security tester using raw stdlib sockets.

    Usage:
        tester = WebSocketTester(session)
        tester.run(target_id=1, base_url="https://app.example.com", identity="userA")
    """

    def __init__(self, session: BugKitSession) -> None:
        self.session   = session
        self._findings = 0

    def run(
        self,
        target_id: int,
        base_url:  str,
        identity:  str = None,
    ) -> int:
        logger.section(f"WebSocket Tester  →  {base_url}")
        self._tid      = target_id
        self._base     = base_url.rstrip("/")
        self._identity = identity
        self._findings = 0

        ws_endpoints = self._discover_ws_endpoints()
        if not ws_endpoints:
            logger.info("No WebSocket endpoints found.")
            return 0

        logger.ok(f"Found {len(ws_endpoints)} WebSocket endpoint(s)")

        for ws_url in ws_endpoints:
            self._test_unauth_access(ws_url)
            self._test_cswsh(ws_url)
            self._test_cross_user_subscription(ws_url)
            self._test_message_injection(ws_url)
            self._test_token_reuse(ws_url)

        logger.section("WebSocket Summary")
        logger.ok(f"Findings: {self._findings}")
        return self._findings

    # ── Discovery ──────────────────────────────────────────────────────

    def _discover_ws_endpoints(self) -> List[str]:
        """
        Find WebSocket endpoints from:
          1. DB endpoints with ws:// or wss:// or /ws/ /socket/ paths
          2. JS findings (look for ws:// references)
          3. Heuristic probe of common WS paths
        """
        ws_urls: List[str] = []

        # From DB
        for ep in queries.get_endpoints(self._tid):
            if any(kw in ep.url.lower() for kw in
                   ["ws://","wss://","/ws","/socket","/websocket","/realtime",
                    "/live","/events","/stream","/cable","/sockjs","/pusher"]):
                # Convert http → ws
                ws_url = self._to_ws_url(ep.url)
                if ws_url and ws_url not in ws_urls:
                    ws_urls.append(ws_url)

        # Heuristic paths
        heuristic_paths = [
            "/ws", "/wss", "/websocket", "/socket",
            "/socket.io/", "/sockjs/websocket",
            "/realtime", "/live", "/events",
            "/cable", "/api/ws", "/api/socket",
            "/api/v1/ws", "/api/v2/ws",
        ]
        base_http  = self._base
        base_ws    = self._to_ws_url(base_http) or base_http.replace("https://","wss://").replace("http://","ws://")

        for path in heuristic_paths:
            ws_url = base_ws.rstrip("/") + path
            if ws_url not in ws_urls:
                ws_urls.append(ws_url)

        # Quick filter — only keep endpoints that actually upgrade
        verified: List[str] = []
        for ws_url in ws_urls[:15]:
            conn = self._connect(ws_url, with_auth=True)
            if conn.connected:
                verified.append(ws_url)
                conn.close()
            elif "101" in conn.error:
                verified.append(ws_url)
        return verified

    # ── Test 1: Unauthenticated access ─────────────────────────────────

    def _test_unauth_access(self, ws_url: str) -> None:
        logger.info(f"Testing unauthenticated WS access: {ws_url}")
        conn = self._connect(ws_url, with_auth=False)
        if conn.connected:
            # Try to receive any data
            msg = self._recv(conn)
            conn.close()
            if msg:
                self._save(
                    title     = f"WebSocket — Unauthenticated Connection Accepted: {ws_url}",
                    url       = ws_url,
                    severity  = "HIGH",
                    confidence= "high",
                    detail    = (
                        "WebSocket connection accepted without authentication credentials. "
                        f"Server sent data: {msg[:200]}"
                    ),
                    evidence  = f"Connected without auth\nFirst message: {msg[:500]}",
                    tags      = ["websocket","unauth","access-control"],
                    cwe       = "CWE-306",
                    cvss      = 7.5,
                )
        else:
            logger.debug(f"  WS auth enforced (good): {conn.error[:60]}")

    # ── Test 2: CSWSH ──────────────────────────────────────────────────

    def _test_cswsh(self, ws_url: str) -> None:
        """
        Cross-Site WebSocket Hijacking.
        Connect with valid auth but wrong Origin header.
        If server accepts it, attacker page can hijack the WS.
        """
        logger.info(f"Testing CSWSH: {ws_url}")
        conn = self._connect(
            ws_url,
            with_auth   = True,
            extra_headers = {"Origin": "https://evil.com"},
        )
        if conn.connected:
            conn.close()
            self._save(
                title     = f"WebSocket — CSWSH: Evil Origin Accepted: {ws_url}",
                url       = ws_url,
                severity  = "HIGH",
                confidence= "high",
                detail    = (
                    "WebSocket connection from `Origin: https://evil.com` was accepted. "
                    "A malicious website can initiate a WebSocket connection on behalf "
                    "of a logged-in victim and read their real-time data."
                ),
                evidence  = "Connected with Origin: https://evil.com",
                tags      = ["websocket","cswsh","csrf","origin"],
                cwe       = "CWE-346",
                cvss      = 8.1,
            )

    # ── Test 3: Cross-user subscription ───────────────────────────────

    def _test_cross_user_subscription(self, ws_url: str) -> None:
        if len(self.session.identity_names) < 2:
            return
        logger.info(f"Testing cross-user WS subscription: {ws_url}")

        # Get userA's known object IDs for subscription
        objects = queries.get_objects(self._tid)
        if not objects:
            return

        for obj in objects[:3]:
            # Subscribe to userA's channel as userB
            sub_msg = json.dumps({
                "action":    "subscribe",
                "channel":   f"user:{obj.object_id}",
                "room":      obj.object_id,
                "user_id":   obj.object_id,
                "topic":     f"user/{obj.object_id}",
            })

            conn = self._connect(ws_url, with_auth=True,
                                  identity=self.session.identity_names[1])
            if not conn.connected:
                continue

            self._send(conn, sub_msg)
            time.sleep(0.5)
            msg = self._recv(conn)
            conn.close()

            if msg and "error" not in msg.lower() and "denied" not in msg.lower():
                self._save(
                    title     = f"WebSocket — Cross-User Channel Subscription: {ws_url}",
                    url       = ws_url,
                    severity  = "HIGH",
                    confidence= "medium",
                    detail    = (
                        f"Identity '{self.session.identity_names[1]}' subscribed to "
                        f"channel for object {obj.object_id} (owned by '{obj.owner}') "
                        "without error."
                    ),
                    evidence  = f"Subscribe payload: {sub_msg}\nResponse: {msg[:300]}",
                    tags      = ["websocket","idor","subscription","access-control"],
                    cwe       = "CWE-639",
                    cvss      = 7.5,
                )
                break

    # ── Test 4: Message injection ──────────────────────────────────────

    def _test_message_injection(self, ws_url: str) -> None:
        logger.info(f"Testing WS message injection: {ws_url}")
        conn = self._connect(ws_url, with_auth=True)
        if not conn.connected:
            return

        injection_payloads = [
            '{"action":"execute","cmd":"id"}',
            '{"type":"sql","query":"SELECT * FROM users--"}',
            '{"event":"admin_action","user_id":1}',
            '{"__proto__":{"admin":true}}',
        ]

        for payload in injection_payloads:
            self._send(conn, payload)
            time.sleep(0.3)
            msg = self._recv(conn)
            if msg:
                # Look for signs the injection was processed
                if any(kw in msg.lower() for kw in
                       ["uid=","root:","admin","execute","result","query"]):
                    conn.close()
                    self._save(
                        title     = f"WebSocket — Message Injection Accepted: {ws_url}",
                        url       = ws_url,
                        severity  = "CRITICAL",
                        confidence= "medium",
                        detail    = (
                            f"Injected WS message `{payload[:80]}` produced "
                            f"suspicious response: {msg[:200]}"
                        ),
                        evidence  = f"Payload: {payload}\nResponse: {msg[:500]}",
                        tags      = ["websocket","injection","rce"],
                        cwe       = "CWE-20",
                        cvss      = 9.1,
                    )
                    return
        conn.close()

    # ── Test 5: Token reuse after logout ──────────────────────────────

    def _test_token_reuse(self, ws_url: str) -> None:
        logger.info(f"Testing WS token reuse after logout: {ws_url}")
        # This test is informational — we check if WS uses the same
        # auth token as REST and flag it for manual testing
        identity = self.session.active_identity
        if identity and identity.headers.get("Authorization"):
            self._save(
                title     = f"WebSocket — Token Reuse Risk: {ws_url}",
                url       = ws_url,
                severity  = "INFO",
                confidence= "low",
                detail    = (
                    "WebSocket endpoint uses Bearer token authentication. "
                    "Verify: (1) token is invalidated on logout, "
                    "(2) WS connection is terminated on logout, "
                    "(3) token cannot be reused after session expiry."
                ),
                evidence  = (
                    "Authorization header detected in active identity. "
                    "Manual verification required for WS token lifecycle."
                ),
                tags      = ["websocket","token-reuse","session"],
                cwe       = "CWE-613",
                cvss      = 0.0,
            )

    # ── Raw WebSocket implementation ───────────────────────────────────

    def _to_ws_url(self, url: str) -> str:
        """Convert HTTP URL to WS URL."""
        if url.startswith("wss://") or url.startswith("ws://"):
            return url
        return url.replace("https://", "wss://").replace("http://", "ws://")

    def _connect(
        self,
        ws_url:        str,
        with_auth:     bool = True,
        identity:      str  = None,
        extra_headers: Dict[str, str] = None,
    ) -> WSConnection:
        """
        Perform a raw WebSocket handshake using stdlib sockets.
        Returns WSConnection with .connected=True on success.
        """
        conn = WSConnection(url=ws_url)
        try:
            parsed   = urlparse(ws_url)
            use_ssl  = parsed.scheme == "wss"
            host     = parsed.hostname
            port     = parsed.port or (443 if use_ssl else 80)
            path     = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query

            # Build handshake headers
            key      = base64.b64encode(b"BugKitV4ProbeKey!").decode()
            headers  = {
                "Host":                  f"{host}:{port}",
                "Upgrade":               "websocket",
                "Connection":            "Upgrade",
                "Sec-WebSocket-Key":     key,
                "Sec-WebSocket-Version": "13",
                "User-Agent":            "BugKit/4.0",
                "Origin":                f"{'https' if use_ssl else 'http'}://{host}",
            }

            if with_auth:
                ident = None
                if identity and identity in self.session._identities:
                    ident = self.session._identities[identity]
                elif self.session.active_identity:
                    ident = self.session.active_identity

                if ident:
                    headers.update(ident.headers)
                    if ident.cookies:
                        cookie_str = "; ".join(f"{k}={v}" for k, v in ident.cookies.items())
                        headers["Cookie"] = cookie_str

            if extra_headers:
                headers.update(extra_headers)

            # Build HTTP upgrade request
            req_lines = [f"GET {path} HTTP/1.1"]
            for k, v in headers.items():
                req_lines.append(f"{k}: {v}")
            req_lines.extend(["", ""])
            request = "\r\n".join(req_lines).encode()

            # Create socket
            raw_sock = socket.create_connection((host, port), timeout=8)
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                raw_sock = ctx.wrap_socket(raw_sock, server_hostname=host)

            raw_sock.sendall(request)

            # Read response
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = raw_sock.recv(4096)
                if not chunk:
                    break
                resp += chunk

            resp_str = resp.decode("utf-8", errors="replace")
            if "101" in resp_str and "Switching Protocols" in resp_str:
                conn.connected = True
                conn.sock      = raw_sock
            else:
                status_line = resp_str.split("\r\n")[0]
                conn.error  = status_line
                raw_sock.close()

        except Exception as e:
            conn.error = str(e)

        return conn

    def _send(self, conn: WSConnection, message: str) -> None:
        """Send a WebSocket text frame (no masking for simplicity)."""
        if not conn.sock:
            return
        try:
            data    = message.encode("utf-8")
            length  = len(data)
            header  = bytes([0x81])  # FIN + text frame
            if length < 126:
                header += bytes([length])
            elif length < 65536:
                header += bytes([126]) + struct.pack(">H", length)
            else:
                header += bytes([127]) + struct.pack(">Q", length)
            conn.sock.sendall(header + data)
        except Exception:
            pass

    def _recv(self, conn: WSConnection, timeout: float = 2.0) -> str:
        """Read one WebSocket frame."""
        if not conn.sock:
            return ""
        try:
            conn.sock.settimeout(timeout)
            header = conn.sock.recv(2)
            if len(header) < 2:
                return ""
            payload_len = header[1] & 0x7F
            if payload_len == 126:
                ext = conn.sock.recv(2)
                payload_len = struct.unpack(">H", ext)[0]
            elif payload_len == 127:
                ext = conn.sock.recv(8)
                payload_len = struct.unpack(">Q", ext)[0]
            if payload_len > 65536:
                return ""
            data = b""
            while len(data) < payload_len:
                chunk = conn.sock.recv(payload_len - len(data))
                if not chunk:
                    break
                data += chunk
            msg = data.decode("utf-8", errors="replace")
            conn.messages.append(msg)
            return msg
        except Exception:
            return ""

    def _save(
        self,
        title:      str,
        url:        str,
        severity:   str,
        confidence: str,
        detail:     str,
        evidence:   str,
        tags:       list,
        cwe:        str,
        cvss:       float,
    ) -> None:
        queries.save_finding(
            target_id    = self._tid,
            module       = "websocket",
            title        = title,
            severity     = severity,
            confidence   = confidence,
            url          = url,
            detail       = detail,
            evidence     = evidence,
            impact       = "WebSocket auth bypass enables real-time data interception and account takeover.",
            remediation  = (
                "Validate Origin header against a strict allowlist. "
                "Enforce authentication on WS upgrade request. "
                "Invalidate WS connections on logout. "
                "Bind subscriptions to the authenticated user's ID server-side."
            ),
            cwe  = cwe,
            cvss = cvss,
            tags = tags,
        )
        self._findings += 1
        logger.finding(title=title, severity=severity, url=url, confidence=confidence)

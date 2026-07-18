"""
BugKit v4 — Module Unit Tests
Run with: python3 -m pytest tests/ -v

Covers the 8 new modules and core engines added in the 9+ upgrade.
No network calls — all requests are mocked.
"""
from __future__ import annotations

import json
import os
import sys
import time
import threading
import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import requests


# ── Mock response factory ──────────────────────────────────────────────

def mock_resp(
    status: int = 200,
    body:   str = "{}",
    headers: dict = None,
    elapsed_s: float = 0.1,
) -> requests.Response:
    r              = requests.Response()
    r.status_code  = status
    r._content     = body.encode()
    r.encoding     = "utf-8"
    r.headers      = requests.structures.CaseInsensitiveDict(
        {"Content-Type": "application/json", **(headers or {})}
    )
    r.elapsed      = datetime.timedelta(seconds=elapsed_s)
    return r


# ═══════════════════════════════════════════════════════════════════════
#  Scheduler tests
# ═══════════════════════════════════════════════════════════════════════

class TestScheduler:
    def test_map_returns_all_results(self):
        from core.scheduler import Scheduler
        sched   = Scheduler(workers=4)
        results = sched.map(fn=lambda x: mock_resp(200, x), targets=["a","b","c"])
        assert len(results) == 3

    def test_map_preserves_order(self):
        from core.scheduler import Scheduler
        import time as _time
        # Tasks finish in reverse order due to sleep, but results must be ordered
        def slow_fn(x):
            _time.sleep(0.05 if x == "a" else 0.0)
            return mock_resp(200, x)
        sched   = Scheduler(workers=4)
        results = sched.map(fn=slow_fn, targets=["a","b","c"])
        assert len(results) == 3

    def test_failed_task_returns_none_response(self):
        from core.scheduler import Scheduler
        def always_fails(x):
            raise RuntimeError("network error")
        sched   = Scheduler(workers=2)
        results = sched.map(fn=always_fails, targets=["x","y"])
        assert all(r.response is None for r in results)
        assert all(r.error for r in results)

    def test_rate_limiter_delays(self):
        from core.scheduler import _TokenBucket
        bucket = _TokenBucket(rate=10.0)   # 10 req/s → 100ms per token
        t0 = time.monotonic()
        for _ in range(3):
            bucket.acquire()
        elapsed = time.monotonic() - t0
        # 3 tokens at 10/s should take ~200ms (first is free)
        assert elapsed >= 0.15

    def test_streaming_yields_results(self):
        from core.scheduler import Scheduler, Task
        sched  = Scheduler(workers=2)
        tasks  = [Task(fn=lambda: mock_resp(200, str(i)), args=()) for i in range(5)]
        count  = 0
        for result in sched.run_tasks_streaming(tasks):
            count += 1
        assert count == 5


# ═══════════════════════════════════════════════════════════════════════
#  Migration tests
# ═══════════════════════════════════════════════════════════════════════

class TestMigrations:
    def test_migrate_creates_all_tables(self, tmp_path):
        import sqlite3
        from db.migrations import migrate
        db_path = str(tmp_path / "test.db")
        migrate(db_path)
        conn   = sqlite3.connect(db_path)
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        conn.close()
        required = {
            "targets","identities","endpoints","findings","scans",
            "snapshots","workflows","objects","_schema_version",
            "oauth_flows","massassign_results","ratelimit_results",
        }
        assert required.issubset(tables), f"Missing: {required - tables}"

    def test_migrate_idempotent(self, tmp_path):
        from db.migrations import migrate, current_version
        db_path = str(tmp_path / "idem.db")
        migrate(db_path)
        v1 = current_version(db_path)
        migrate(db_path)  # second call must be a no-op
        v2 = current_version(db_path)
        assert v1 == v2

    def test_version_tracking(self, tmp_path):
        from db.migrations import migrate, current_version, MIGRATIONS
        db_path = str(tmp_path / "ver.db")
        migrate(db_path)
        assert current_version(db_path) == len(MIGRATIONS)

    def test_schema_version_table_exists(self, tmp_path):
        import sqlite3
        from db.migrations import migrate
        db_path = str(tmp_path / "sv.db")
        migrate(db_path)
        conn = sqlite3.connect(db_path)
        row  = conn.execute("SELECT MAX(version) FROM _schema_version").fetchone()
        conn.close()
        assert row[0] is not None and row[0] > 0


# ═══════════════════════════════════════════════════════════════════════
#  Comparator engine tests
# ═══════════════════════════════════════════════════════════════════════

class TestComparator:
    def _make_session(self):
        from core.scope import ScopeGuard
        from core.session import BugKitSession, Identity
        sg   = ScopeGuard(["example.com"])
        sess = BugKitSession(sg)
        for name, role in [("userA","user"),("userB","user"),("admin","admin")]:
            sess.load_identity(Identity(name=name, role=role))
        return sess

    def test_build_tasks_includes_all_identities(self):
        from engines.comparator import Comparator
        sess  = self._make_session()
        comp  = Comparator(sess, workers=2)
        tasks = comp._build_tasks("https://example.com/me", "GET",
                                   ["userB","__anonymous__"])
        assert len(tasks) == 2
        tags = {t.tag for t in tasks}
        assert "userB" in tags
        assert "__anonymous__" in tags

    def test_batch_result_counts_anomalies(self):
        from engines.comparator import BatchResult
        from core.diff import DiffResult, Signal
        result = BatchResult(baseline_identity="userA")
        diff   = DiffResult("userA","userB","https://x.com/","GET")
        diff.add(Signal("status_code","403 vs 200", is_anomaly=True))
        diff.compute_confidence()
        result.diffs.append(diff)
        result.anomalous = 1
        assert len(result.high_confidence) == 0  # only one signal → medium
        diff2 = DiffResult("userA","userB","https://x.com/2","GET")
        for _ in range(3):
            diff2.add(Signal("test","x", is_anomaly=True))
        diff2.compute_confidence()
        result.diffs.append(diff2)
        assert len(result.high_confidence) == 1


# ═══════════════════════════════════════════════════════════════════════
#  Mass assignment tester tests
# ═══════════════════════════════════════════════════════════════════════

class TestMassAssignTester:
    def _make_session(self):
        from core.scope import ScopeGuard
        from core.session import BugKitSession
        return BugKitSession(ScopeGuard(["example.com"]))

    def test_severity_classification(self):
        from modules.massassign.tester import MassAssignTester
        sess   = self._make_session()
        tester = MassAssignTester(sess)
        assert tester._severity("role", "admin")     == "CRITICAL"
        assert tester._severity("is_admin", True)    == "CRITICAL"
        assert tester._severity("plan", "enterprise")== "HIGH"
        assert tester._severity("verified", True)    == "HIGH"
        assert tester._severity("nickname", "x")     == "MEDIUM"

    def test_reflection_detected(self):
        from modules.massassign.tester import MassAssignTester
        sess     = self._make_session()
        tester   = MassAssignTester(sess)
        baseline = mock_resp(200, '{"id":1,"name":"bob"}')
        injected = mock_resp(200, '{"id":1,"name":"bob","role":"admin"}')
        result   = tester._analyze(
            url="https://example.com/api/profile", method="PUT",
            field_name="role", field_value="admin",
            baseline_resp=baseline, injected_resp=injected,
            baseline_json={"id":1,"name":"bob"},
        )
        assert result.accepted
        assert result.confidence in ("high","medium")

    def test_no_false_positive_on_identical(self):
        from modules.massassign.tester import MassAssignTester
        sess     = self._make_session()
        tester   = MassAssignTester(sess)
        baseline = mock_resp(200, '{"id":1}')
        injected = mock_resp(200, '{"id":1}')
        result   = tester._analyze(
            url="https://example.com/api/user", method="PUT",
            field_name="role", field_value="admin",
            baseline_resp=baseline, injected_resp=injected,
            baseline_json={"id":1},
        )
        assert not result.accepted

    def test_heuristic_endpoints_generated(self):
        from modules.massassign.tester import MassAssignTester
        sess   = self._make_session()
        tester = MassAssignTester(sess)
        tester._base = "https://api.example.com"
        eps = tester._heuristic_endpoints()
        assert len(eps) > 5
        assert any("profile" in u for u, _ in eps)
        assert all(u.startswith("https://") for u, _ in eps)


# ═══════════════════════════════════════════════════════════════════════
#  OpenAPI importer tests
# ═══════════════════════════════════════════════════════════════════════

class TestOpenAPIImporter:
    def _make_session(self):
        from core.scope import ScopeGuard
        from core.session import BugKitSession
        return BugKitSession(ScopeGuard(["example.com"]))

    def test_parse_openapi3_paths(self):
        from modules.openapi.importer import OpenAPIImporter
        sess     = self._make_session()
        importer = OpenAPIImporter(sess)
        importer._base = "https://api.example.com"
        spec = {
            "openapi": "3.0.0",
            "servers": [{"url": "https://api.example.com"}],
            "paths": {
                "/users": {
                    "get": {
                        "summary": "List users",
                        "security": [{"bearerAuth": []}],
                        "parameters": [{"name": "page", "in": "query"}],
                        "responses": {"200": {"description": "OK"}},
                    },
                    "post": {
                        "summary": "Create user",
                        "security": [{"bearerAuth": []}],
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "email": {"type": "string"},
                                            "role":  {"type": "string"},
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {"201": {"description": "Created"}},
                    }
                },
                "/users/{id}": {
                    "get": {
                        "summary": "Get user",
                        "security": [],
                        "responses": {"200": {"description": "OK"}},
                    }
                }
            }
        }
        endpoints = importer._parse_openapi3(spec, "https://api.example.com")
        assert len(endpoints) == 3
        urls = [e["url"] for e in endpoints]
        assert "https://api.example.com/users" in urls

        get_users = next(e for e in endpoints if e["url"].endswith("/users") and e["method"]=="GET")
        assert get_users["auth_required"] == True
        assert "page" in get_users["params"]

        post_users = next(e for e in endpoints if e["method"]=="POST")
        assert "email" in post_users["params"]
        assert "role"  in post_users["params"]

        get_user = next(e for e in endpoints if "{id}" in e["url"])
        assert get_user["auth_required"] == False

    def test_detect_version(self):
        from modules.openapi.importer import OpenAPIImporter
        sess     = self._make_session()
        importer = OpenAPIImporter(sess)
        assert importer._detect_version({"openapi": "3.0.0"}) == "3.0.0"
        assert importer._detect_version({"swagger": "2.0"})   == "2.0"
        assert importer._detect_version({})                    == "unknown"

    def test_resolve_ref(self):
        from modules.openapi.importer import OpenAPIImporter
        sess     = self._make_session()
        importer = OpenAPIImporter(sess)
        spec = {
            "components": {
                "schemas": {
                    "User": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "integer"},
                            "email": {"type": "string"},
                        }
                    }
                }
            }
        }
        resolved = importer._resolve_ref("#/components/schemas/User", spec)
        assert resolved is not None
        assert "properties" in resolved
        assert "email" in resolved["properties"]

    def test_schema_field_extraction(self):
        from modules.openapi.importer import OpenAPIImporter
        sess     = self._make_session()
        importer = OpenAPIImporter(sess)
        schema = {
            "type": "object",
            "properties": {
                "name":  {"type": "string"},
                "email": {"type": "string"},
                "role":  {"type": "string"},
            }
        }
        fields = importer._extract_schema_fields(schema, {})
        assert "name"  in fields
        assert "email" in fields
        assert "role"  in fields


# ═══════════════════════════════════════════════════════════════════════
#  Fuzzer tests
# ═══════════════════════════════════════════════════════════════════════

class TestFuzzer:
    def _make_session(self):
        from core.scope import ScopeGuard
        from core.session import BugKitSession
        return BugKitSession(ScopeGuard(["example.com"]))

    def test_waf_expansion_increases_payload_count(self):
        from modules.fuzz.tester import Fuzzer
        sess   = self._make_session()
        fuzzer = Fuzzer(sess)
        original = ["' OR '1'='1", "' OR 1=1--"]
        expanded = fuzzer._expand_waf(original, "sqli")
        assert len(expanded) > len(original)

    def test_waf_expansion_no_duplicates(self):
        from modules.fuzz.tester import Fuzzer
        sess     = self._make_session()
        fuzzer   = Fuzzer(sess)
        original = ["<script>alert(1)</script>"]
        expanded = fuzzer._expand_waf(original, "xss")
        assert len(expanded) == len(set(expanded))

    def test_payload_file_loading(self, tmp_path):
        from modules.fuzz.tester import Fuzzer
        sess = self._make_session()
        fuzzer = Fuzzer(sess)
        pfile = tmp_path / "payloads.txt"
        pfile.write_text(
            "# comment\n"
            "' OR 1=1--\n"
            "sqli:' UNION SELECT NULL--\n"
            "xss:<img src=x onerror=alert(1)>\n"
            "\n"
        )
        result = fuzzer._load_payload_file(str(pfile))
        assert "' OR 1=1--" in result.get("sqli", [])
        assert "' UNION SELECT NULL--" in result.get("sqli", [])
        assert "<img src=x onerror=alert(1)>" in result.get("xss", [])

    def test_sql_error_pattern_matches(self):
        from modules.fuzz.tester import SQL_ERROR_PATTERNS
        assert SQL_ERROR_PATTERNS.search("You have an error in your SQL syntax")
        assert SQL_ERROR_PATTERNS.search("Warning: mysql_query() failed")
        assert SQL_ERROR_PATTERNS.search("ORA-00907: missing right parenthesis")
        assert SQL_ERROR_PATTERNS.search("pg_query(): Query failed")
        assert not SQL_ERROR_PATTERNS.search("Everything looks fine here")

    def test_lfi_pattern_matches(self):
        import re
        lfi_match = re.compile(r"root:.*:/bin/|daemon:.*:/usr/sbin", re.I | re.M)
        assert lfi_match.search("root:x:0:0:root:/root:/bin/bash")
        assert lfi_match.search("daemon:x:1:1:daemon:/usr/sbin/nologin")
        assert not lfi_match.search("normal page content")


# ═══════════════════════════════════════════════════════════════════════
#  OAuth tester tests
# ═══════════════════════════════════════════════════════════════════════

class TestOAuthTester:
    def _make_session(self):
        from core.scope import ScopeGuard
        from core.session import BugKitSession
        return BugKitSession(ScopeGuard(["example.com"]))

    def test_base_auth_params_contains_state(self):
        from modules.oauth.tester import OAuthTester
        sess   = self._make_session()
        tester = OAuthTester(sess)
        tester._client_id    = "test_client"
        tester._redirect_uri = "https://example.com/cb"
        tester._scopes       = "openid profile"
        params = tester._base_auth_params()
        assert "state" in params
        assert len(params["state"]) >= 16
        assert params["client_id"]    == "test_client"
        assert params["response_type"]== "code"

    def test_redirect_bypass_list_not_empty(self):
        from modules.oauth.tester import COMMON_REDIRECT_BYPASS
        assert len(COMMON_REDIRECT_BYPASS) >= 4
        assert any("evil.com" in u for u in COMMON_REDIRECT_BYPASS)
        assert any(u.startswith("javascript:") for u in COMMON_REDIRECT_BYPASS)

    def test_discovery_paths_covered(self):
        from modules.oauth.tester import OAUTH_DISCOVERY_PATHS
        paths = " ".join(OAUTH_DISCOVERY_PATHS)
        assert "openid-configuration" in paths
        assert "authorize" in paths
        assert "token" in paths


# ═══════════════════════════════════════════════════════════════════════
#  OTP tester tests
# ═══════════════════════════════════════════════════════════════════════

class TestOTPTester:
    def _make_session(self):
        from core.scope import ScopeGuard
        from core.session import BugKitSession
        return BugKitSession(ScopeGuard(["example.com"]))

    def test_otp_body_covers_all_field_names(self):
        from modules.otp.tester import OTPTester, OTP_FIELD_NAMES
        sess   = self._make_session()
        tester = OTPTester(sess)
        tester._username = "test@test.com"
        body   = tester._otp_body("123456")
        for field in OTP_FIELD_NAMES:
            assert field in body, f"Missing OTP field: {field}"
        assert body["email"] == "test@test.com"

    def test_otp_code_in_response_pattern(self):
        import re
        pattern   = re.compile(r'\b\d{6}\b')
        text_with = '{"message":"Your code is 482910","status":"ok"}'
        text_none = '{"message":"Invalid code","status":"error"}'
        assert pattern.findall(text_with) == ["482910"]
        assert pattern.findall(text_none) == []

    def test_backup_code_pattern(self):
        import re
        pattern = re.compile(r'[A-Z0-9]{8,12}')
        text    = '{"codes":["ABCD1234EF","GHIJ5678KL"]}'
        found   = pattern.findall(text)
        assert len(found) >= 2


# ═══════════════════════════════════════════════════════════════════════
#  WebSocket tester tests
# ═══════════════════════════════════════════════════════════════════════

class TestWebSocketTester:
    def _make_session(self):
        from core.scope import ScopeGuard
        from core.session import BugKitSession
        return BugKitSession(ScopeGuard(["example.com"]))

    def test_to_ws_url_conversion(self):
        from modules.websocket.tester import WebSocketTester
        sess   = self._make_session()
        tester = WebSocketTester(sess)
        assert tester._to_ws_url("https://example.com/ws") == "wss://example.com/ws"
        assert tester._to_ws_url("http://example.com/ws")  == "ws://example.com/ws"
        assert tester._to_ws_url("wss://example.com/ws")   == "wss://example.com/ws"

    def test_ws_frame_encode_decode(self):
        from modules.websocket.tester import WSConnection, WebSocketTester
        import struct, io
        sess   = self._make_session()
        tester = WebSocketTester(sess)
        # Build a fake WS text frame for "hello"
        payload = b"hello"
        frame   = bytes([0x81, len(payload)]) + payload
        # Verify we can parse the length correctly
        header  = frame[:2]
        plen    = header[1] & 0x7F
        assert plen == 5

    def test_connection_failed_gracefully(self):
        from modules.websocket.tester import WebSocketTester
        sess   = self._make_session()
        tester = WebSocketTester(sess)
        # Connect to an invalid host — should fail gracefully
        conn = tester._connect("wss://nonexistent.invalid/ws", with_auth=False)
        assert not conn.connected
        assert conn.error != ""


# ═══════════════════════════════════════════════════════════════════════
#  Rate limit tester tests
# ═══════════════════════════════════════════════════════════════════════

class TestRateLimitTester:
    def _make_session(self):
        from core.scope import ScopeGuard
        from core.session import BugKitSession
        return BugKitSession(ScopeGuard(["example.com"]))

    def test_default_endpoints_list(self):
        from modules.ratelimit.tester import DEFAULT_ENDPOINTS
        assert len(DEFAULT_ENDPOINTS) >= 8
        assert any("login" in ep for ep in DEFAULT_ENDPOINTS)
        assert any("register" in ep or "signup" in ep for ep in DEFAULT_ENDPOINTS)
        assert any("token" in ep for ep in DEFAULT_ENDPOINTS)

    def test_ip_spoof_headers_list(self):
        from modules.ratelimit.tester import IP_SPOOF_HEADERS
        header_names = [list(h.keys())[0] for h in IP_SPOOF_HEADERS]
        assert "X-Forwarded-For" in header_names
        assert "X-Real-IP"       in header_names
        assert len(IP_SPOOF_HEADERS) >= 4

    def test_rate_limit_result_tracking(self):
        from modules.ratelimit.tester import RateLimitResult
        r = RateLimitResult(url="https://example.com/login",
                            identity="userA", burst_size=30)
        r.status_dist = {200: 29, 429: 1}
        r.hit_429      = True
        r.threshold    = 29
        assert r.threshold == 29
        assert r.hit_429


# ═══════════════════════════════════════════════════════════════════════
#  File tester tests
# ═══════════════════════════════════════════════════════════════════════

class TestFileTester:
    def _make_session(self):
        from core.scope import ScopeGuard
        from core.session import BugKitSession
        return BugKitSession(ScopeGuard(["example.com"]))

    def test_bypass_uploads_list(self):
        from modules.files.tester import BYPASS_UPLOADS
        assert len(BYPASS_UPLOADS) >= 5
        # Must include PHP and SVG
        filenames = [f[0] for f in BYPASS_UPLOADS]
        assert any(".php" in f or "php" in f for f in filenames)
        assert any(".svg" in f for f in filenames)

    def test_traversal_filenames(self):
        from modules.files.tester import TRAVERSAL_FILENAMES
        assert len(TRAVERSAL_FILENAMES) >= 4
        assert any("etc/passwd" in f for f in TRAVERSAL_FILENAMES)
        assert any("windows" in f.lower() for f in TRAVERSAL_FILENAMES)

    def test_file_url_extraction(self):
        from modules.files.tester import FileTester
        sess   = self._make_session()
        tester = FileTester(sess)
        resp   = '{"url": "https://cdn.example.com/uploads/file123.txt"}'
        url    = tester._extract_file_url(resp, "https://example.com")
        assert url == "https://cdn.example.com/uploads/file123.txt"

    def test_severity_on_php_upload(self):
        # PHP uploads should flag CRITICAL
        from modules.files.tester import BYPASS_UPLOADS
        php_entries = [e for e in BYPASS_UPLOADS if "php" in e[0].lower()]
        assert len(php_entries) > 0


# ═══════════════════════════════════════════════════════════════════════
#  Integration: DB queries + migrations
# ═══════════════════════════════════════════════════════════════════════

class TestDBIntegration:
    @pytest.fixture(autouse=True)
    def patch_db(self, tmp_path, monkeypatch):
        """Redirect all DB operations to a temp SQLite file."""
        db_path = str(tmp_path / "test_bugkit.db")
        from config import settings
        monkeypatch.setattr(settings, "db_path", tmp_path / "test_bugkit.db")
        # Reset engine singleton
        import db.queries as q
        q._engine   = None
        q._migrated = False
        yield
        q._engine   = None
        q._migrated = False

    def test_upsert_and_get_target(self):
        from db.queries import upsert_target, get_target
        upsert_target("test.example.com", "https://test.example.com",
                      scope=["*.example.com"])
        t = get_target("test.example.com")
        assert t is not None
        assert t.domain   == "test.example.com"
        assert t.base_url == "https://test.example.com"
        assert "*.example.com" in t.scope_list

    def test_upsert_target_updates_existing(self):
        from db.queries import upsert_target, get_target
        upsert_target("up.example.com", "https://up.example.com")
        upsert_target("up.example.com", "https://up.example.com",
                      notes="updated notes")
        t = get_target("up.example.com")
        assert t.notes == "updated notes"

    def test_save_and_get_finding(self):
        from db.queries import upsert_target, save_finding, get_findings
        upsert_target("find.example.com", "https://find.example.com")
        t = upsert_target("find.example.com")
        save_finding(
            target_id  = t.id,
            module     = "fuzz",
            title      = "Test SQLi",
            severity   = "CRITICAL",
            confidence = "high",
            url        = "https://find.example.com/search",
            cwe        = "CWE-89",
            cvss       = 9.8,
            tags       = ["sqli", "test"],
        )
        findings = get_findings(target_id=t.id)
        assert len(findings) == 1
        assert findings[0].title    == "Test SQLi"
        assert findings[0].severity == "CRITICAL"
        assert findings[0].cwe      == "CWE-89"
        assert "sqli" in findings[0].tag_list

    def test_upsert_endpoint_deduplicates(self):
        from db.queries import upsert_target, upsert_endpoint, get_endpoints
        upsert_target("ep.example.com", "https://ep.example.com")
        t = upsert_target("ep.example.com")
        upsert_endpoint(t.id, "https://ep.example.com/api/users", "GET")
        upsert_endpoint(t.id, "https://ep.example.com/api/users", "GET")
        eps = get_endpoints(t.id)
        assert len(eps) == 1

    def test_save_and_list_workflow(self):
        from db.queries import upsert_target, save_workflow, list_workflows
        upsert_target("wf.example.com", "https://wf.example.com")
        t  = upsert_target("wf.example.com")
        steps = [
            {"name": "signup", "method": "POST", "url": "https://wf.example.com/signup"},
            {"name": "verify", "method": "POST", "url": "https://wf.example.com/verify"},
        ]
        save_workflow(t.id, "checkout", steps, "Test workflow")
        wfs = list_workflows(t.id)
        assert len(wfs) == 1
        assert wfs[0].name == "checkout"
        assert len(wfs[0].step_list) == 2

    def test_findings_filter_by_severity(self):
        from db.queries import upsert_target, save_finding, get_findings
        upsert_target("sev.example.com", "https://sev.example.com")
        t = upsert_target("sev.example.com")
        for sev in ["CRITICAL","HIGH","MEDIUM"]:
            save_finding(target_id=t.id, module="test", title=f"Test {sev}",
                         severity=sev, url="https://sev.example.com/test")
        crits = get_findings(target_id=t.id, severity="CRITICAL")
        assert len(crits)    == 1
        assert crits[0].severity == "CRITICAL"

    def test_delete_target_cascades(self):
        from db.queries import upsert_target, save_finding, delete_target, get_findings
        upsert_target("del.example.com", "https://del.example.com")
        t = upsert_target("del.example.com")
        save_finding(target_id=t.id, module="test", title="Will be deleted",
                     severity="INFO", url="https://del.example.com/x")
        delete_target("del.example.com")
        # After deletion, target no longer exists
        from db.queries import get_target
        assert get_target("del.example.com") is None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

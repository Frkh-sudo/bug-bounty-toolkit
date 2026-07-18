"""
BugKit v4 — Core Unit Tests
Run with: pytest tests/ -v
"""
from __future__ import annotations

import json
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from unittest.mock import MagicMock, patch
import requests


# ── Scope tests ────────────────────────────────────────────────────────

from core.scope import ScopeGuard, ScopeViolation

def test_scope_exact_match():
    sg = ScopeGuard(["example.com"])
    assert sg.allows("https://example.com/foo")
    assert sg.allows("https://sub.example.com/bar")

def test_scope_wildcard():
    sg = ScopeGuard(["*.example.com"])
    assert sg.allows("https://api.example.com")
    assert not sg.allows("https://evil.com")

def test_scope_violation_raised():
    sg = ScopeGuard(["example.com"])
    with pytest.raises(ScopeViolation):
        sg.check("https://evil.com/steal")

def test_scope_empty_denies_all():
    # Fail closed: a scope guard with no configured patterns must block
    # everything rather than silently allowing all traffic. Allow-all was
    # the old (unsafe) behavior for a tool whose stated job is to prevent
    # accidental out-of-scope requests.
    sg = ScopeGuard([])
    assert not sg.allows("https://anything.com")


# ── Utils tests ────────────────────────────────────────────────────────

from core.utils import (
    extract_ids_from_url, mutate_id, looks_like_id, inject_param
)

def test_extract_numeric_id_from_path():
    ids = extract_ids_from_url("https://api.example.com/users/1042/orders")
    assert any(v == "1042" for _, v in ids)

def test_extract_uuid_from_path():
    url  = "https://api.example.com/docs/550e8400-e29b-41d4-a716-446655440000"
    ids  = extract_ids_from_url(url)
    assert any("550e8400" in v for _, v in ids)

def test_extract_param_id():
    ids = extract_ids_from_url("https://example.com/api?user_id=42")
    assert any(v == "42" for _, v in ids)

def test_mutate_numeric():
    mutations = mutate_id("100")
    assert "101" in mutations
    assert "99"  in mutations

def test_mutate_uuid():
    uid       = "550e8400-e29b-41d4-a716-446655440000"
    mutations = mutate_id(uid)
    assert len(mutations) > 0
    assert uid not in mutations

def test_looks_like_id_numeric():
    assert looks_like_id("12345")
    assert not looks_like_id("username")

def test_inject_param():
    url = inject_param("https://example.com/api?foo=1&bar=2", "foo", "99")
    assert "foo=99" in url
    assert "bar=2" in url


# ── Diff engine tests ──────────────────────────────────────────────────

from core.diff import compare, Signal, DiffResult

def _mock_response(status: int, body: str, headers: dict = None) -> requests.Response:
    r                  = requests.Response()
    r.status_code      = status
    r._content         = body.encode()
    r.headers          = requests.structures.CaseInsensitiveDict(headers or {})
    r.encoding         = "utf-8"
    import datetime
    r.elapsed          = datetime.timedelta(seconds=0.1)
    return r

def test_diff_identical_no_anomaly():
    ra = _mock_response(200, '{"id":1,"email":"a@a.com"}')
    rb = _mock_response(200, '{"id":1,"email":"a@a.com"}')
    d  = compare("userA", ra, "userB", rb, "https://x.com/me")
    assert not d.is_anomaly

def test_diff_status_code_anomaly():
    ra = _mock_response(403, "forbidden")
    rb = _mock_response(200, '{"id":2,"email":"b@b.com"}')
    d  = compare("userA", ra, "userB", rb, "https://x.com/me")
    assert d.is_anomaly
    assert any(s.name == "status_code" for s in d.signals)

def test_diff_json_extra_keys_anomaly():
    ra = _mock_response(200, '{"id":1}',
                         headers={"Content-Type":"application/json"})
    rb = _mock_response(200, '{"id":1,"admin":true,"permissions":["delete"]}',
                         headers={"Content-Type":"application/json"})
    d  = compare("userA", ra, "userB", rb, "https://x.com/me")
    assert d.is_anomaly

def test_diff_size_spike():
    ra = _mock_response(200, "x" * 100)
    rb = _mock_response(200, "x" * 5000)
    d  = compare("userA", ra, "userB", rb, "https://x.com/data")
    assert any(s.name == "body_size" and s.is_anomaly for s in d.signals)

def test_diff_redirect_anomaly():
    ra = _mock_response(302, "", headers={"Location": "/dashboard"})
    rb = _mock_response(302, "", headers={"Location": "/other-user/dashboard"})
    d  = compare("userA", ra, "userB", rb, "https://x.com/login")
    assert d.is_anomaly


# ── Object mutator tests ───────────────────────────────────────────────

from engines.object_mutator import ObjectMutator

def test_apply_mutation_path():
    from core.scope import ScopeGuard
    from core.session import BugKitSession
    scope   = ScopeGuard(["example.com"])
    session = BugKitSession(scope)
    mutator = ObjectMutator(session)
    result  = mutator._apply_mutation(
        "https://example.com/users/42/profile", "path:1", "99"
    )
    assert "/users/99/profile" in result

def test_apply_mutation_param():
    from core.scope import ScopeGuard
    from core.session import BugKitSession
    scope   = ScopeGuard(["example.com"])
    session = BugKitSession(scope)
    mutator = ObjectMutator(session)
    result  = mutator._apply_mutation(
        "https://example.com/api?user_id=42", "param:user_id", "99"
    )
    assert "user_id=99" in result


# ── Encryption tests ───────────────────────────────────────────────────

def test_encrypt_decrypt_roundtrip():
    from core.session import encrypt, decrypt
    original  = '{"cookies":{"session":"abc123"},"headers":{"Authorization":"Bearer xyz"}}'
    encrypted = encrypt(original)
    decrypted = decrypt(encrypted)
    assert decrypted == original
    assert encrypted != original

def test_identity_serialization():
    from core.session import Identity
    ident = Identity(
        name    = "userA",
        role    = "admin",
        cookies = {"session": "abc"},
        headers = {"Authorization": "Bearer xyz"},
        note    = "test user",
    )
    d         = ident.to_encrypted_dict()
    restored  = Identity.from_encrypted_dict(d)
    assert restored.name            == ident.name
    assert restored.role            == ident.role
    assert restored.cookies["session"] == "abc"
    assert restored.headers["Authorization"] == "Bearer xyz"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

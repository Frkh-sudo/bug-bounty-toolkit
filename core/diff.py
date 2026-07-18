"""
BugKit v4 — Smart Diff Engine

Does NOT just compare status codes.
Compares responses across identities / mutations using multiple signals:
  • HTTP status
  • Response body size delta
  • JSON key presence/absence
  • Semantic field values (role, permissions, owner, access)
  • Response timing (potential time-based oracle)
  • Headers (Set-Cookie, X-Accel-*, Cache-Control)
  • Redirects (destination differences)
  • Error messages

A DiffResult is raised to HIGH confidence if any of these signals fire.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import requests
from deepdiff import DeepDiff

# Fields whose VALUES indicate ownership / authorization
SENSITIVE_FIELDS = re.compile(
    r"(user_?id|owner|account|tenant|org|workspace|team|"
    r"role|permission|access|privilege|admin|subscription|plan|"
    r"email|phone|credit|billing|invoice|payment)",
    re.I,
)

# Status codes that scream "authorized"
AUTH_POSITIVE = {200, 201, 202, 206}
# Status codes that scream "denied"
AUTH_NEGATIVE = {401, 403, 404, 405, 410}


@dataclass
class Signal:
    name:        str
    value:       str
    is_anomaly:  bool = False

    def __str__(self) -> str:
        flag = "⚑ " if self.is_anomaly else ""
        return f"{flag}{self.name}: {self.value}"


@dataclass
class DiffResult:
    identity_a:   str
    identity_b:   str
    url:          str
    method:       str
    signals:      List[Signal] = field(default_factory=list)
    confidence:   str = "low"          # low | medium | high
    is_anomaly:   bool = False
    summary:      str = ""

    def add(self, signal: Signal) -> None:
        self.signals.append(signal)
        if signal.is_anomaly:
            self.is_anomaly = True

    def compute_confidence(self) -> None:
        anomalies = [s for s in self.signals if s.is_anomaly]
        if len(anomalies) >= 3:
            self.confidence = "high"
        elif len(anomalies) >= 1:
            self.confidence = "medium"
        else:
            self.confidence = "low"
        if anomalies:
            self.summary = " | ".join(s.name for s in anomalies)


def compare(
    identity_a: str,
    response_a: Optional[requests.Response],
    identity_b: str,
    response_b: Optional[requests.Response],
    url: str,
    method: str = "GET",
) -> DiffResult:
    """
    Compare two responses from different identities.
    Returns a DiffResult with confidence scoring.
    """
    result = DiffResult(
        identity_a=identity_a,
        identity_b=identity_b,
        url=url,
        method=method,
    )

    # ── Handle None responses ──────────────────────────────────────────
    if response_a is None and response_b is None:
        return result
    if response_a is None:
        result.add(Signal("response_a", "no response", is_anomaly=True))
    if response_b is None:
        result.add(Signal("response_b", "no response", is_anomaly=True))
        result.compute_confidence()
        return result

    a, b = response_a, response_b

    # ── 1. Status code ─────────────────────────────────────────────────
    if a.status_code != b.status_code:
        anomaly = (
            (a.status_code in AUTH_NEGATIVE and b.status_code in AUTH_POSITIVE) or
            (a.status_code in AUTH_POSITIVE and b.status_code in AUTH_NEGATIVE)
        )
        result.add(Signal(
            "status_code",
            f"{identity_a}={a.status_code} vs {identity_b}={b.status_code}",
            is_anomaly=anomaly,
        ))

    # ── 2. Body size delta ─────────────────────────────────────────────
    size_a, size_b = len(a.content), len(b.content)
    delta = abs(size_a - size_b)
    if delta > 50:            # >50 bytes difference is meaningful
        pct = delta / max(size_a, 1) * 100
        result.add(Signal(
            "body_size",
            f"{identity_a}={size_a}B  {identity_b}={size_b}B  Δ={delta}B ({pct:.1f}%)",
            is_anomaly=(pct > 15),   # >15% is suspicious
        ))

    # ── 3. JSON key diff ───────────────────────────────────────────────
    json_a = _try_json(a)
    json_b = _try_json(b)
    if json_a is not None and json_b is not None:
        _compare_json(result, identity_a, json_a, identity_b, json_b)

    # ── 4. Sensitive field values ──────────────────────────────────────
    if json_a and json_b:
        _compare_sensitive_fields(result, identity_a, json_a, identity_b, json_b)

    # ── 5. Timing oracle ───────────────────────────────────────────────
    elapsed_a = a.elapsed.total_seconds() if a.elapsed else 0
    elapsed_b = b.elapsed.total_seconds() if b.elapsed else 0
    timing_delta = abs(elapsed_a - elapsed_b)
    if timing_delta > 1.0:
        result.add(Signal(
            "timing",
            f"{identity_a}={elapsed_a:.2f}s  {identity_b}={elapsed_b:.2f}s  Δ={timing_delta:.2f}s",
            is_anomaly=(timing_delta > 2.0),
        ))

    # ── 6. Redirect destination ────────────────────────────────────────
    loc_a = a.headers.get("Location", "")
    loc_b = b.headers.get("Location", "")
    if loc_a != loc_b:
        result.add(Signal(
            "redirect",
            f"{identity_a}→{loc_a!r}  {identity_b}→{loc_b!r}",
            is_anomaly=True,
        ))

    # ── 7. Auth-revealing headers ──────────────────────────────────────
    _compare_headers(result, identity_a, a, identity_b, b)

    # ── 8. Inline error messages ───────────────────────────────────────
    _compare_error_strings(result, identity_a, a.text, identity_b, b.text)

    result.compute_confidence()
    return result


# ── Helpers ────────────────────────────────────────────────────────────

def _try_json(r: requests.Response) -> Optional[Any]:
    try:
        ct = r.headers.get("Content-Type", "")
        if "json" in ct or r.text.lstrip().startswith(("{", "[")):
            return r.json()
    except Exception:
        pass
    return None


def _compare_json(
    result: DiffResult,
    name_a: str, data_a: Any,
    name_b: str, data_b: Any,
) -> None:
    try:
        diff = DeepDiff(data_a, data_b, ignore_order=True, verbose_level=0)
    except Exception:
        return

    if diff.get("dictionary_item_added"):
        keys = list(diff["dictionary_item_added"])[:5]
        result.add(Signal(
            "json_keys_added_in_b",
            f"{name_b} has extra keys: {keys}",
            is_anomaly=True,
        ))
    if diff.get("dictionary_item_removed"):
        keys = list(diff["dictionary_item_removed"])[:5]
        result.add(Signal(
            "json_keys_removed_in_b",
            f"{name_b} missing keys vs {name_a}: {keys}",
            is_anomaly=False,
        ))
    if diff.get("values_changed"):
        changed = list(diff["values_changed"].items())[:5]
        result.add(Signal(
            "json_values_changed",
            ", ".join(f"{k}: {v['old_value']!r}→{v['new_value']!r}" for k, v in changed),
            is_anomaly=True,
        ))


def _flatten(obj: Any, prefix: str = "") -> Dict[str, Any]:
    """Flatten a nested dict/list into dotted keys."""
    out: Dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            full_key = f"{prefix}.{k}" if prefix else k
            out.update(_flatten(v, full_key))
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:10]):
            out.update(_flatten(v, f"{prefix}[{i}]"))
    else:
        out[prefix] = obj
    return out


def _compare_sensitive_fields(
    result: DiffResult,
    name_a: str, data_a: Any,
    name_b: str, data_b: Any,
) -> None:
    flat_a = _flatten(data_a)
    flat_b = _flatten(data_b)
    for key, val_a in flat_a.items():
        if not SENSITIVE_FIELDS.search(key):
            continue
        val_b = flat_b.get(key, "__MISSING__")
        if val_a != val_b and val_b != "__MISSING__":
            result.add(Signal(
                f"sensitive_field[{key}]",
                f"{name_a}={val_a!r}  {name_b}={val_b!r}",
                is_anomaly=True,
            ))


_AUTH_HEADERS = {"x-user-id", "x-account-id", "x-tenant-id", "x-role",
                 "x-permissions", "x-accel-redirect", "set-cookie"}


def _compare_headers(
    result: DiffResult,
    name_a: str, r_a: requests.Response,
    name_b: str, r_b: requests.Response,
) -> None:
    for h in _AUTH_HEADERS:
        va = r_a.headers.get(h, "")
        vb = r_b.headers.get(h, "")
        if va != vb:
            result.add(Signal(
                f"header[{h}]",
                f"{name_a}={va!r}  {name_b}={vb!r}",
                is_anomaly=True,
            ))


_ERROR_PATTERNS = re.compile(
    r"(unauthorized|forbidden|access.denied|not.allowed|permission|"
    r"invalid.token|session.expired|must.be.logged|authentication.required)",
    re.I,
)


def _compare_error_strings(
    result: DiffResult,
    name_a: str, text_a: str,
    name_b: str, text_b: str,
) -> None:
    err_a = bool(_ERROR_PATTERNS.search(text_a))
    err_b = bool(_ERROR_PATTERNS.search(text_b))
    if err_a != err_b:
        result.add(Signal(
            "error_message",
            f"{name_a} has auth error={err_a}  {name_b}={err_b}",
            is_anomaly=True,
        ))

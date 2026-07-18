"""
BugKit v4 — Shared Utilities
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, Generator, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup


# ── URL helpers ────────────────────────────────────────────────────────

def domain_of(url: str) -> str:
    return urlparse(url).hostname or url


def base_url(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def normalise_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def inject_param(url: str, param: str, value: str) -> str:
    """Return URL with `param` set to `value` (add or overwrite)."""
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(p._replace(query=new_query))


def all_param_variants(url: str, value: str) -> Generator[Tuple[str, str], None, None]:
    """Yield (mutated_url, param_name) for every query parameter in the URL."""
    p  = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    for param in qs:
        mutated = dict(qs)
        mutated[param] = [value]
        new_q = urlencode(mutated, doseq=True)
        yield urlunparse(p._replace(query=new_q)), param


# ── ID detection ───────────────────────────────────────────────────────

# Patterns that suggest an object ID in a URL path segment or query param
ID_PARAM_PATTERN = re.compile(
    r"(user_?id|owner_?id|account_?id|org_?id|tenant_?id|team_?id|"
    r"workspace_?id|project_?id|invoice_?id|order_?id|file_?id|"
    r"document_?id|resource_?id|record_?id|item_?id|object_?id|"
    r"uid|oid|pid|tid|wid|fid|bid|rid|cid)",
    re.I,
)

NUMERIC_ID = re.compile(r"^\d+$")
UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)


def looks_like_id(value: str) -> bool:
    return bool(NUMERIC_ID.match(value) or UUID_PATTERN.match(value))


def extract_ids_from_url(url: str) -> List[Tuple[str, str]]:
    """
    Return list of (location, value) for potential object IDs found in
    the URL path or query parameters.
    location is like 'path:3' or 'param:user_id'.
    """
    found: List[Tuple[str, str]] = []
    p = urlparse(url)

    # Path segments
    segments = [s for s in p.path.split("/") if s]
    for i, seg in enumerate(segments):
        if looks_like_id(seg):
            found.append((f"path:{i}", seg))

    # Query parameters
    for param, values in parse_qs(p.query, keep_blank_values=True).items():
        val = values[0] if values else ""
        if ID_PARAM_PATTERN.search(param) or looks_like_id(val):
            found.append((f"param:{param}", val))

    return found


def mutate_id(id_value: str, delta: int = 1) -> List[str]:
    """
    Generate plausible mutations of an ID value.
    For numeric IDs: +1, -1, neighbours, boundary values.
    For UUIDs: near-miss variants.
    """
    mutations: List[str] = []
    if NUMERIC_ID.match(id_value):
        n = int(id_value)
        # Always include direct neighbours first
        for candidate_n in [n + delta, n - delta, n - 10, n + 10, 0, 1, 2, 9999]:
            if candidate_n < 0:
                continue
            candidate = str(candidate_n)
            if candidate != id_value and candidate not in mutations:
                mutations.append(candidate)
    elif UUID_PATTERN.match(id_value):
        # Flip the last few characters
        prefix = id_value[:-4]
        for suffix in ["0000", "ffff", "1111", "aaaa"]:
            candidate = prefix + suffix
            if candidate != id_value:
                mutations.append(candidate)
    return mutations


# ── Forms ──────────────────────────────────────────────────────────────

def extract_forms(html: str, base: str) -> List[Dict]:
    from urllib.parse import urljoin
    soup  = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = urljoin(base, form.get("action") or "")
        method = (form.get("method") or "GET").upper()
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            inputs.append({
                "name":  inp.get("name", ""),
                "type":  inp.get("type", "text"),
                "value": inp.get("value", ""),
            })
        forms.append({"action": action, "method": method, "inputs": inputs})
    return forms


# ── Hashing ────────────────────────────────────────────────────────────

def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ── Response helpers ───────────────────────────────────────────────────

def is_json_response(r: requests.Response) -> bool:
    ct = r.headers.get("Content-Type", "")
    return "json" in ct or r.text.lstrip().startswith(("{", "["))


def safe_json(r: requests.Response) -> Optional[Any]:
    try:
        return r.json()
    except Exception:
        return None


def status_class(code: int) -> str:
    if code < 300:
        return "2xx"
    if code < 400:
        return "3xx"
    if code < 500:
        return "4xx"
    return "5xx"


# ── Chunking ───────────────────────────────────────────────────────────

def chunks(lst: List, n: int) -> Generator[List, None, None]:
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

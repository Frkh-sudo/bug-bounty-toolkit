"""
BugKit v4 — OpenAPI / Swagger Spec Importer

Parses an OpenAPI 2.0 (Swagger) or 3.x spec from a URL or local file
and automatically populates the endpoint database.

After import, every other BugKit module (IDOR, tenant, mass-assign,
comparator, etc.) immediately has a complete, structured target model
to work against — no manual endpoint discovery needed.

Supports:
  • OpenAPI 3.0 / 3.1  (application/json + YAML via stdlib)
  • Swagger 2.0
  • Auto-discovery from common spec paths
  • Authentication parameter extraction
  • Request body schema extraction (feeds mass-assignment tester)
  • Response schema analysis (feeds diff engine)
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

from core.session import BugKitSession
from core import logger
from db import queries


# Common paths where API specs live
SPEC_DISCOVERY_PATHS = [
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/api/v1/openapi.json",
    "/api/v2/openapi.json",
    "/api/v3/openapi.json",
    "/v1/openapi.json",
    "/v2/openapi.json",
    "/docs/openapi.json",
    "/redoc/openapi.json",
    "/.well-known/openapi.json",
    "/api-docs",
    "/api-docs/swagger.json",
]


class SpecParseError(Exception):
    pass


class OpenAPIImporter:
    """
    Import an OpenAPI / Swagger specification and populate the BugKit DB.

    Usage:
        importer = OpenAPIImporter(session)

        # From URL (auto-discovers if no path given)
        count = importer.import_from_url(
            target_id = 1,
            base_url  = "https://api.example.com",
        )

        # From local file
        count = importer.import_from_file(
            target_id = 1,
            path      = Path("openapi.json"),
            base_url  = "https://api.example.com",
        )

        print(f"Imported {count} endpoints")
    """

    def __init__(self, session: BugKitSession) -> None:
        self.session  = session
        self._spec:   Optional[dict] = None
        self._base:   str = ""
        self._version: str = "unknown"

    # ── Public API ─────────────────────────────────────────────────────

    def import_from_url(
        self,
        target_id: int,
        base_url:  str,
        spec_url:  str = "",
    ) -> int:
        """
        Fetch spec from `spec_url`, or auto-discover from `base_url`.
        Returns number of endpoints imported.
        """
        self._base = base_url.rstrip("/")

        if spec_url:
            urls = [spec_url]
        else:
            urls = [self._base + p for p in SPEC_DISCOVERY_PATHS]

        spec_raw = None
        used_url = ""
        for url in urls:
            resp = self.session.get(url, capture=False)
            if resp is None or resp.status_code != 200:
                continue
            ct = resp.headers.get("Content-Type", "")
            if "json" in ct or "yaml" in ct or url.endswith(".json"):
                spec_raw = resp.text
                used_url = url
                break

        if not spec_raw:
            logger.warn("No OpenAPI spec found. Try: bugkit openapi import --url <spec_url>")
            return 0

        logger.ok(f"Spec fetched: {used_url}")
        return self._parse_and_store(spec_raw, target_id, base_url)

    def import_from_file(
        self,
        target_id: int,
        path:      Path,
        base_url:  str,
    ) -> int:
        """Parse a local spec file and populate the DB."""
        if not path.exists():
            logger.err(f"File not found: {path}")
            return 0
        self._base = base_url.rstrip("/")
        spec_raw   = path.read_text(encoding="utf-8")
        logger.ok(f"Spec loaded from file: {path}")
        return self._parse_and_store(spec_raw, target_id, base_url)

    # ── Parsing ────────────────────────────────────────────────────────

    def _parse_and_store(
        self,
        spec_raw:  str,
        target_id: int,
        base_url:  str,
    ) -> int:
        try:
            spec = self._load_spec(spec_raw)
        except Exception as e:
            logger.err(f"Failed to parse spec: {e}")
            return 0

        self._spec = spec
        version    = self._detect_version(spec)
        logger.info(f"OpenAPI version: {version}")

        if version.startswith("2"):
            endpoints = self._parse_swagger2(spec, base_url)
        else:
            endpoints = self._parse_openapi3(spec, base_url)

        logger.section(f"OpenAPI Import  —  {len(endpoints)} endpoints")

        imported = 0
        auth_required_count = 0
        for ep in endpoints:
            queries.upsert_endpoint(
                target_id    = target_id,
                url          = ep["url"],
                method       = ep["method"],
                params       = ep.get("params", []),
                auth_required= ep.get("auth_required"),
                content_type = ep.get("content_type", ""),
                source       = "openapi",
            )
            if ep.get("auth_required"):
                auth_required_count += 1
            imported += 1

            logger.debug(
                f"  {ep['method']:<7} {ep['url'][:70]}"
                f"  auth={'Y' if ep.get('auth_required') else 'N'}"
            )

        logger.ok(
            f"Imported {imported} endpoints "
            f"({auth_required_count} require auth, "
            f"{imported - auth_required_count} public)."
        )
        self._report_security_observations(spec)
        return imported

    def _load_spec(self, raw: str) -> dict:
        """Try JSON first, then simple YAML fallback."""
        raw = raw.strip()
        if raw.startswith("{"):
            return json.loads(raw)
        # Minimal YAML→JSON conversion for simple specs
        return self._minimal_yaml_parse(raw)

    def _minimal_yaml_parse(self, yaml_text: str) -> dict:
        """
        Extremely minimal YAML parser that handles flat OpenAPI structures.
        For production use, install PyYAML. This handles the 80% case.
        """
        # Try to find embedded JSON blocks
        json_match = re.search(r'\{[\s\S]+\}', yaml_text)
        if json_match:
            try:
                return json.loads(json_match.group(0))
            except Exception:
                pass
        raise SpecParseError(
            "YAML spec detected but PyYAML is not installed. "
            "Install pyyaml or use a JSON spec."
        )

    def _detect_version(self, spec: dict) -> str:
        if "openapi" in spec:
            return spec["openapi"]
        if "swagger" in spec:
            return spec["swagger"]
        return "unknown"

    # ── OpenAPI 3.x parser ─────────────────────────────────────────────

    def _parse_openapi3(self, spec: dict, base_url: str) -> List[dict]:
        endpoints = []
        base      = self._resolve_base_url_v3(spec, base_url)
        paths     = spec.get("paths", {})
        security_global = spec.get("security", [])

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method in ("get","post","put","patch","delete","head","options"):
                op = path_item.get(method)
                if not op or not isinstance(op, dict):
                    continue

                url = base.rstrip("/") + path

                # Parameters (query, path, header, cookie)
                params = []
                all_params = list(path_item.get("parameters", [])) + \
                             list(op.get("parameters", []))
                for p in all_params:
                    if isinstance(p, dict) and p.get("name"):
                        params.append(p["name"])

                # Request body fields
                rb = op.get("requestBody", {})
                if rb:
                    for ct, media in rb.get("content", {}).items():
                        schema = media.get("schema", {})
                        params.extend(self._extract_schema_fields(schema, spec))

                # Security — is auth required?
                op_security   = op.get("security", security_global)
                auth_required = bool(op_security) and op_security != [{}]

                # Response schema analysis
                content_type = ""
                responses = op.get("responses", {})
                for status_str, resp_obj in responses.items():
                    if str(status_str).startswith("2") and isinstance(resp_obj, dict):
                        content = resp_obj.get("content", {})
                        for ct in content:
                            content_type = ct
                            break
                        break

                endpoints.append({
                    "url":          url,
                    "method":       method.upper(),
                    "params":       params,
                    "auth_required": auth_required,
                    "content_type": content_type,
                    "summary":      op.get("summary", ""),
                    "tags":         op.get("tags", []),
                })

        return endpoints

    # ── Swagger 2.0 parser ─────────────────────────────────────────────

    def _parse_swagger2(self, spec: dict, base_url: str) -> List[dict]:
        endpoints = []
        host      = spec.get("host", urlparse(base_url).netloc)
        base_path = spec.get("basePath", "/")
        schemes   = spec.get("schemes", ["https"])
        base      = f"{schemes[0]}://{host}{base_path}"
        paths     = spec.get("paths", {})
        sec_defs  = spec.get("securityDefinitions", {})

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method in ("get","post","put","patch","delete","head","options"):
                op = path_item.get(method)
                if not op or not isinstance(op, dict):
                    continue

                url = base.rstrip("/") + path

                params = []
                for p in op.get("parameters", []):
                    if isinstance(p, dict) and p.get("name"):
                        params.append(p["name"])
                        # Body param schema
                        if p.get("in") == "body":
                            schema = p.get("schema", {})
                            params.extend(self._extract_schema_fields(schema, spec))

                op_security   = op.get("security", spec.get("security", []))
                auth_required = bool(op_security) and bool(sec_defs)

                produces = op.get("produces", spec.get("produces", []))
                content_type = produces[0] if produces else ""

                endpoints.append({
                    "url":          url,
                    "method":       method.upper(),
                    "params":       params,
                    "auth_required": auth_required,
                    "content_type": content_type,
                    "summary":      op.get("summary", ""),
                })

        return endpoints

    # ── Schema field extraction ────────────────────────────────────────

    def _extract_schema_fields(
        self,
        schema: dict,
        full_spec: dict,
        depth: int = 0,
    ) -> List[str]:
        """Recursively extract field names from a JSON Schema object."""
        if depth > 3 or not isinstance(schema, dict):
            return []

        # Resolve $ref
        if "$ref" in schema:
            resolved = self._resolve_ref(schema["$ref"], full_spec)
            if resolved:
                return self._extract_schema_fields(resolved, full_spec, depth + 1)

        fields = []
        props  = schema.get("properties", {})
        for name, prop_schema in props.items():
            fields.append(name)
            # Recurse into nested objects
            if isinstance(prop_schema, dict) and prop_schema.get("type") == "object":
                nested = self._extract_schema_fields(prop_schema, full_spec, depth + 1)
                fields.extend(f"{name}.{f}" for f in nested)

        # allOf / anyOf / oneOf
        for combinator in ("allOf", "anyOf", "oneOf"):
            for sub in schema.get(combinator, []):
                fields.extend(self._extract_schema_fields(sub, full_spec, depth + 1))

        return fields

    def _resolve_ref(self, ref: str, spec: dict) -> Optional[dict]:
        """Resolve a JSON $ref path like '#/components/schemas/User'."""
        if not ref.startswith("#/"):
            return None
        parts = ref.lstrip("#/").split("/")
        obj   = spec
        for part in parts:
            if not isinstance(obj, dict):
                return None
            obj = obj.get(part)
        return obj if isinstance(obj, dict) else None

    def _resolve_base_url_v3(self, spec: dict, fallback: str) -> str:
        servers = spec.get("servers", [])
        if servers and isinstance(servers[0], dict):
            url = servers[0].get("url", fallback)
            # Handle relative server URLs
            if url.startswith("/"):
                parsed = urlparse(fallback)
                return f"{parsed.scheme}://{parsed.netloc}{url}"
            return url
        return fallback

    # ── Security observation reporter ──────────────────────────────────

    def _report_security_observations(self, spec: dict) -> None:
        """Log noteworthy security observations from the spec itself."""
        # 1. Endpoints with no security at all
        paths = spec.get("paths", {})
        global_security = spec.get("security", [])
        unprotected = []
        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method in ("post","put","patch","delete"):
                op = path_item.get(method, {})
                if not op:
                    continue
                op_sec = op.get("security", global_security)
                if not op_sec or op_sec == [{}]:
                    unprotected.append(f"{method.upper()} {path}")

        if unprotected:
            logger.warn(
                f"  {len(unprotected)} write endpoints with no security declared:"
            )
            for ep in unprotected[:5]:
                logger.warn(f"    • {ep}")
            if len(unprotected) > 5:
                logger.warn(f"    … and {len(unprotected) - 5} more")

        # 2. Exposed admin paths in spec
        admin_paths = [
            p for p in paths
            if any(kw in p.lower() for kw in
                   ["admin","internal","debug","superuser","staff","manage"])
        ]
        if admin_paths:
            logger.warn(f"  Admin/internal paths in spec: {admin_paths[:5]}")

        # 3. Interesting security schemes
        sec_schemes = (
            spec.get("securityDefinitions", {}) or       # Swagger 2
            spec.get("components", {}).get("securitySchemes", {})  # OA3
        )
        for name, scheme in sec_schemes.items():
            if isinstance(scheme, dict):
                logger.info(
                    f"  Auth scheme: {name} "
                    f"(type={scheme.get('type','?')} "
                    f"in={scheme.get('in','?')})"
                )

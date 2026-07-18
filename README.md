# BugKit v4 🎯

> **Intelligence-driven bug bounty hunting platform — built for authorized security research**

BugKit v4 is a modular, multi-identity, authenticated bug hunting platform. It moves beyond generic scanning into logic-aware, identity-comparative testing — the techniques that find real, high-payout vulnerabilities on modern SaaS targets.

> ⚠️ **For authorized testing only.** Use exclusively against targets covered by an active bug bounty program or with explicit written permission.

---

## What makes v4 different

| v3 approach | v4 approach |
|---|---|
| Single identity, one session | Multi-identity engine — swap tokens, compare responses |
| Status-code-only detection | 8-signal semantic diff (size, JSON keys, timing, headers…) |
| No business logic support | Workflow recorder + replay: skip steps, duplicate, reorder |
| No tenant isolation testing | Full SaaS tenant isolation engine (headers, params, invites) |
| Sequential requests only | Thread-pool scheduler with token-bucket rate limiting |
| One monolith file | 70-file modular package, SQLAlchemy ORM, schema migrations |
| No OAuth testing | Full OAuth/OIDC suite: state CSRF, redirect_uri, PKCE, scopes |
| No mass assignment | Over-posting detection across 30+ privileged fields |
| No 2FA testing | OTP brute-force, reuse, race, cross-account, bypass |
| Manual endpoint discovery | OpenAPI/Swagger importer auto-populates entire DB |

---

## Installation

```bash
git clone https://github.com/yourusername/bugkit.git
cd bugkit

# Install dependencies
pip install -r requirements.txt

# Optional: screenshots
pip install playwright && playwright install chromium

# Initialize database
python main.py db-migrate
```

Python 3.9+ required.

---

## Quick Start

```bash
# 1. Register target
python main.py target add api.example.com \
  --base-url https://api.example.com \
  --scope "*.example.com"

# 2. Add identities (authenticated sessions)
python main.py auth add api.example.com \
  --name userA --role user \
  --cookie "session=abc123; csrf=xyz"

python main.py auth add api.example.com \
  --name userB --role user \
  --cookie "session=def456; csrf=uvw"

# 3. Import API surface from spec (fastest path to full coverage)
python main.py openapi import api.example.com \
  --url https://api.example.com/openapi.json

# 4. Run IDOR sweep across all endpoints × all identities
python main.py idor compare-all api.example.com --baseline userA

# 5. Report
python main.py report html api.example.com -o report.html
```

---

## CLI Reference

All modules accept global flags placed before the command:

```
python main.py [GLOBAL] <module> <command> [OPTIONS]
```

### Global flags

| Flag | Default | Description |
|---|---|---|
| `--proxy <url>` | — | Route all traffic through Burp/ZAP |
| `--delay <s>` | `0.3` | Throttle between requests |
| `--timeout <s>` | `15` | Per-request timeout |
| `--no-safe` | off | Allow destructive requests (DELETE/PUT) |
| `--dry-run` | off | Print requests without sending |
| `--debug` | off | Verbose output |

---

## Modules

### `target` — Target Management

```bash
python main.py target add example.com --scope "*.example.com"
python main.py target list
python main.py target remove example.com
```

---

### `auth` — Identity Management

Store and test multiple authenticated sessions per target. Credentials are encrypted at rest with Fernet.

```bash
# Add identity with cookies
python main.py auth add example.com --name userA --role user \
  --cookie "session=abc123"

# Add identity with Bearer token
python main.py auth add example.com --name admin --role admin \
  --header "Authorization: Bearer eyJhbG..."

# Test all identities against a URL
python main.py auth test example.com --url https://api.example.com/me

# Compare responses across all identities
python main.py auth compare example.com \
  --url https://api.example.com/account \
  --baseline userA
```

**Roles:** `guest` | `user` | `manager` | `admin` | `superadmin`

---

### `recon` — Reconnaissance

```bash
# Enumerate subdomains, fingerprint tech, snapshot endpoints
python main.py recon run example.com --limit 200

# Detect changes since last scan
python main.py recon changes example.com
```

**What it finds:**
- Subdomains via crt.sh + HackerTarget + DNS bruteforce
- Admin panels, API surfaces, GraphQL endpoints
- Tech stack (30+ frameworks, WAF detection)
- New endpoints, auth removed, content changes

---

### `idor` — IDOR / BOLA Sweep

```bash
# Sweep a specific URL for IDOR
python main.py idor sweep example.com \
  --url https://api.example.com/users/1042/profile \
  --extra-id 9999

# Sweep with all identities
python main.py idor sweep example.com \
  --url https://api.example.com/orders/1042 \
  --all-ids

# Batch: compare ALL endpoints × ALL identities (most powerful)
python main.py idor compare-all example.com \
  --baseline userA \
  --workers 8 \
  --min-confidence medium

# Batch IDOR on all DB endpoints
python main.py idor batch example.com
```

**How it works:** Mutates numeric IDs and UUIDs in URL paths and query parameters (±1, neighbours, known victim IDs), then compares responses using the 8-signal diff engine. Cross-identity sweeps replay every endpoint as every identity and flag meaningful response differences.

---

### `tenant` — Tenant Isolation

High-priority for SaaS programs.

```bash
python main.py tenant sweep example.com \
  --tenant-a org_111 \
  --tenant-b org_222 \
  --identity-a userA \
  --identity-b userB
```

**What it tests:**
- `X-Org-Id`, `X-Tenant-Id`, `X-Workspace-Id` (11 headers) injection
- `org_id`, `tenant_id`, `workspace_id` (12 params) override
- Cross-identity endpoint comparison
- Invite/join cross-tenant abuse
- Broad header injection across all known endpoints

---

### `billing` — Billing Logic

```bash
python main.py billing test example.com \
  --coupon SAVE50 \
  --identity userA
```

**Tests:** Coupon reuse, coupon race condition (10 concurrent), negative quantity, plan upgrade without payment, trial reset, post-cancel feature access, referral abuse.

---

### `workflow` — Business Logic

Record a multi-step flow and test it for step-skip, duplicate, and reorder bugs.

```bash
# Record from JSON file
python main.py workflow record example.com \
  --name checkout \
  --steps steps.json

# steps.json format:
# [
#   {"name": "add_to_cart", "method": "POST", "url": "https://…/cart"},
#   {"name": "apply_coupon", "method": "POST", "url": "https://…/coupon",
#    "body": {"code": "SAVE50"}},
#   {"name": "checkout",     "method": "POST", "url": "https://…/checkout"}
# ]

# Replay with all mutation scenarios
python main.py workflow replay example.com --name checkout

python main.py workflow list example.com
```

---

### `graphql` — GraphQL Testing

```bash
python main.py graphql test example.com
```

**Tests:** Introspection (schema disclosure), unauthenticated queries, batching (rate-limit bypass), alias field bypass, cross-user mutations, IDOR via node IDs.

---

### `js` — JavaScript Intelligence

```bash
python main.py js analyze example.com --deep
```

**Extracts:** 20+ secret patterns (AWS, GitHub, Stripe…), API endpoints, role names, feature flags, GraphQL operations, internal domains, client-side access control logic.

---

### `oauth` — OAuth / OIDC Testing

```bash
python main.py oauth test example.com \
  --client-id my_app \
  --redirect-uri https://example.com/callback \
  --identity userA
```

**Tests:** State CSRF (missing + predictable), redirect_uri manipulation (evil.com, `//`, `javascript:`), PKCE enforcement, scope escalation (admin/write:all/full_access), implicit flow token leakage, client secret in JS, cross-identity token reuse, account linking discovery.

---

### `fuzz` — Smart Fuzzer

```bash
# Default: all checks
python main.py fuzz run example.com \
  --url "https://example.com/search?q=test"

# Specific checks + WAF evasion + custom payloads
python main.py fuzz run example.com \
  --url https://example.com/login \
  --checks sqli,sqli_blind,xss,xss_stored,ssti,lfi \
  --waf-evasion \
  --payload-file data/payloads/sqli.txt

# Stored XSS: inject at one URL, check reflection at another
python main.py fuzz run example.com \
  --url https://example.com/profile/edit \
  --checks xss_stored \
  --store-url https://example.com/profile/view
```

**Checks:**
| Check | What it detects | Method |
|---|---|---|
| `sqli` | Error-based SQL injection | SQL error pattern matching |
| `sqli_blind` | Blind SQLi | Timing oracle (MySQL/MSSQL/PG sleep) |
| `xss` | Reflected XSS | Payload verbatim in response |
| `xss_stored` | Stored XSS | Unique marker injection + re-fetch |
| `ssti` | Template injection | `{{7*7}}` → `49` evaluation |
| `lfi` | Local file inclusion | `/etc/passwd` in response |
| `redirect` | Open redirect | `evil.com` in Location header |
| `header_inject` | Header injection | CRLF in host headers |

**WAF evasion variants:** URL encoding, double encoding, unicode full-width, `/**/` comment injection, keyword case alternation, null-byte prefix, hex encoding.

---

### `massassign` — Mass Assignment

```bash
python main.py massassign test example.com --identity userA
```

Injects 30+ privileged fields (`role`, `is_admin`, `is_superuser`, `verified`, `plan`, `balance`, `owner_id`, `__proto__`…) into every POST/PUT/PATCH endpoint and detects when the server reflects or accepts them.

---

### `openapi` — OpenAPI / Swagger Import

```bash
# Auto-discover and import spec
python main.py openapi import example.com

# Import from specific URL
python main.py openapi import example.com \
  --url https://api.example.com/openapi.json

# Import from local file
python main.py openapi import example.com \
  --file ./openapi.json

# Probe for exposed specs
python main.py openapi discover example.com
```

Parses OpenAPI 3.x and Swagger 2.0. Populates all endpoints, methods, parameters, and auth requirements into the DB so every other module immediately has full coverage.

---

### `otp` — 2FA / OTP Testing

```bash
python main.py otp test example.com --identity userA
```

**Tests:** Brute-force (no rate limit), code reuse, length tolerance (truncated/empty codes), OTP in response body, race condition (8 concurrent), backup code exposure, recovery flow without auth, step-skip (direct endpoint access), cross-account OTP acceptance.

---

### `files` — File Upload / Download

```bash
python main.py files test example.com --identity userA
```

**Tests:** Content-type bypass (PHP/JSP/SVG/HTML upload), path traversal in filename, cross-user file access (IDOR), pre-signed URL abuse, sequential file ID enumeration.

---

### `websocket` — WebSocket Testing

```bash
python main.py websocket test example.com --identity userA
```

**Tests:** Unauthenticated connection, CSWSH (evil Origin accepted), cross-user subscription, message injection (SQL/command/prototype pollution), token reuse after logout.

Uses raw stdlib sockets — no external websockets package required.

---

### `ratelimit` — Rate Limit Testing

```bash
python main.py ratelimit test example.com --burst 30 --identity userA
```

**Tests:** Sequential burst on auth endpoints, IP bypass via X-Forwarded-For/X-Real-IP/CF-Connecting-IP, GraphQL batching bypass, threshold detection.

---

### `report` — Reporting

```bash
python main.py report html example.com -o report.html
python main.py report md   example.com -o report.md
python main.py report generate example.com \
  --format json \
  --severity HIGH \
  --module idor \
  -o findings.json
```

HTML report includes: executive summary with severity counts, table of contents with badges, per-finding sections with raw HTTP, curl PoC, evidence, impact, remediation, CWE, CVSS.

---

### `findings` — View Findings

```bash
python main.py findings example.com
python main.py findings example.com --severity CRITICAL
python main.py findings example.com --module oauth
python main.py findings example.com -o findings.json
```

---

## Full Hunting Workflow

```bash
# Phase 1: Surface mapping
python main.py target add api.example.com --scope "*.example.com"
python main.py openapi import api.example.com          # fastest if spec exists
python main.py recon run api.example.com --limit 200   # or manual recon
python main.py js analyze api.example.com --deep       # find hidden endpoints

# Phase 2: Add sessions
python main.py auth add api.example.com --name userA --role user \
  --cookie "session=abc"
python main.py auth add api.example.com --name userB --role user \
  --cookie "session=def"
python main.py auth test api.example.com \
  --url https://api.example.com/api/me

# Phase 3: Access control
python main.py idor compare-all api.example.com --baseline userA --workers 8
python main.py tenant sweep api.example.com \
  --tenant-a org_111 --tenant-b org_222 \
  --identity-a userA --identity-b userB
python main.py auth compare api.example.com \
  --url https://api.example.com/admin/users --baseline userA

# Phase 4: Auth protocol
python main.py oauth test api.example.com --client-id app_id
python main.py otp test api.example.com --identity userA
python main.py ratelimit test api.example.com --burst 30

# Phase 5: Application logic
python main.py billing test api.example.com --coupon SAVE50
python main.py workflow record api.example.com --name checkout --steps steps.json
python main.py workflow replay api.example.com --name checkout
python main.py massassign test api.example.com --identity userA

# Phase 6: Injection (targeted, not spray-and-pray)
python main.py fuzz run api.example.com \
  --url "https://api.example.com/search?q=test" \
  --checks sqli,sqli_blind,ssti --waf-evasion

# Phase 7: Specialised
python main.py graphql test api.example.com
python main.py files test api.example.com --identity userA
python main.py websocket test api.example.com --identity userA

# Phase 8: Change detection (run on return visits)
python main.py recon changes api.example.com

# Phase 9: Report
python main.py report html api.example.com -o report.html
```

---

## Database

SQLite at `~/.bugkit/bugkit.db`. Override with `--db <path>`.

```bash
# Run migrations (auto on startup, also manual)
python main.py db-migrate

# View stats
python main.py stats
```

**Tables:** `targets`, `identities`, `endpoints`, `findings`, `scans`, `snapshots`, `workflows`, `objects`, `oauth_flows`, `massassign_results`, `ratelimit_results`

---

## Bundled Payloads

Located in `data/payloads/`. Pass to fuzz with `--payload-file`:

```
data/payloads/sqli.txt   — Error-based + blind + union SQLi
data/payloads/xss.txt    — Reflected + stored + bypass variants
data/payloads/lfi.txt    — Path traversal + encoding variants
data/wordlists/params.txt      — 77 hidden parameter names
data/wordlists/subdomains.txt  — 87 common subdomain prefixes
```

---

## Architecture

```
bugkit/
├── main.py              Entry point
├── cli.py               Typer CLI — 34 commands across 18 modules
├── config.py            Settings (env + file override)
├── requirements.txt
├── Makefile
│
├── core/
│   ├── session.py       Multi-identity HTTP session + Fernet encryption
│   ├── scope.py         Scope guard enforced on every request
│   ├── diff.py          8-signal semantic response comparator
│   ├── fingerprints.py  Tech stack + WAF + takeover signatures
│   ├── scheduler.py     Thread-pool with token-bucket rate limiting
│   ├── logger.py        Rich terminal output
│   └── utils.py         Shared utilities (ID detection, mutations, hashing)
│
├── db/
│   ├── models.py        SQLAlchemy ORM models
│   ├── queries.py       Clean query layer (no raw SQL elsewhere)
│   └── migrations.py    Version-tracked schema migrations
│
├── engines/             Reusable cross-module logic
│   ├── token_swapper.py  Replay request as every identity → diff
│   ├── object_mutator.py ID mutation + ownership comparison
│   ├── comparator.py     Batch endpoint × identity sweep
│   ├── replay_engine.py  Workflow step recording + mutation replay
│   ├── race_engine.py    Concurrent burst (race condition detection)
│   └── crawler.py        Authenticated BFS crawler
│
├── modules/             One module per vulnerability class
│   ├── recon/           Subdomain enum, fingerprinting, change detection
│   ├── auth/            Identity management (add/list/test/compare)
│   ├── idor/            IDOR sweep, batch compare
│   ├── tenant/          SaaS tenant isolation (11 headers, 12 params)
│   ├── billing/         Coupon, plan, negative qty, post-cancel
│   ├── workflows/       Business logic step recording + replay
│   ├── graphql/         Introspection, batching, IDOR, mutations
│   ├── jsintel/         Secrets, endpoints, roles, feature flags
│   ├── oauth/           State CSRF, redirect_uri, PKCE, scopes
│   ├── fuzz/            SQLi (error+blind), XSS (reflected+stored), SSTI, LFI
│   ├── massassign/      Over-posting detection (30+ privileged fields)
│   ├── openapi/         Swagger/OpenAPI spec import
│   ├── otp/             2FA brute-force, reuse, race, bypass
│   ├── files/           Upload bypass, path traversal, IDOR
│   ├── websocket/       Auth bypass, CSWSH, subscription IDOR
│   ├── ratelimit/       Burst testing, IP bypass, GraphQL batching
│   └── reports/         HTML, Markdown, JSON report generation
│
├── data/
│   ├── payloads/        SQLi, XSS, LFI payload lists
│   └── wordlists/       Parameters, subdomains
│
└── tests/
    ├── run_tests.py     Standalone test runner (no pytest needed)
    ├── test_core.py     Core module tests
    └── test_modules.py  Module + integration tests
```

---

## Running Tests

```bash
# Standalone (no external deps needed)
python3 tests/run_tests.py

# With pytest (if installed)
pytest tests/ -v
```

17 test groups via the standalone runner (67 individual tests via pytest), 0 external network calls, 0 `bandit` security findings.

---

## Engineering Notes

A few things worth knowing if you're reading this as a reviewer rather than a user.

**Passing tests turned out not to mean the tool worked.** Before shipping this, I had 67/67 pytest and 17/17 custom tests passing, 0 bandit findings, 0 lint warnings — and the tool still couldn't successfully complete a single real HTTP request. I only found that by building a small deliberately-vulnerable test target and actually running BugKit against it end-to-end, rather than trusting a clean test suite. That gap is the most useful thing this project taught me, and it's why the fixes below exist.

- **Every real request was silently failing.** `requests.Request()` was being constructed with `timeout` and `allow_redirects` kwargs — both only valid on `Session.send()`, not on `Request()`. Every call raised a `TypeError` that a broad `except Exception: return None` swallowed without a trace. The unit tests never caught it because they mock around the real HTTP path; only firing an actual request against a real server surfaced it.
- **`requests.Response.__bool__()` is `False` for any 4xx/5xx status, not just when a request fails** — a well-known but easy-to-miss gotcha. Eleven call sites across the codebase used `if resp:` / `if not resp:` as a "did we get a response at all" check, which silently misfired on legitimate error responses. Concretely: the rate-limit detector could never recognize HTTP 429 (429 is itself a 4xx, so it always looked identical to "no response"), and the SQL-injection fuzzer skipped the most common real-world SQLi signal — a 500 with a database error in the body. Fixed by checking `is None` / `is not None` throughout instead of truthiness.
- **The race-condition engine's own synchronization was being undone by the session's throttle.** `RaceEngine` uses a `threading.Barrier` so concurrent requests hit the target at the same instant — but each request then serialized through a shared per-session rate-limit lock immediately afterward, turning a simultaneous burst back into a sequential trickle. Verified with a real check-then-act race bug: before the fix, a 10-way concurrent burst caught only 1/10 exploitable requests; after adding a `throttle=False` bypass for race bursts specifically, it caught 10/10.
- **Concurrency correctness was tested, not assumed, in the batch comparator too.** `engines/comparator.py` runs every endpoint × identity pair through a thread-pool scheduler, and evidence for each finding is built from that specific task's own response object rather than any shared session state — a subtlety that's easy to get wrong under concurrency and easy to miss in a happy-path test.
- **Know which IDOR technique you're reaching for.** `idor compare-all` diffs each identity's response against a baseline — it's blind to IDOR where *every* identity gets identical unauthorized access, since there's nothing to diff. `idor sweep --all-ids` mutates object IDs directly and catches exactly that case. I confirmed this by building an endpoint with zero ownership checks: `compare-all` missed it entirely, `sweep --all-ids` caught it on the first mutated ID.
- **The scope guard fails closed.** If a target somehow has no scope configured, `core/scope.py` blocks all requests rather than allowing them — the guard exists specifically to prevent accidentally hitting out-of-scope infrastructure, so an empty config should never mean "allow everything."
- **HTML reports escape their own findings.** Evidence fields often contain the exact payloads used during testing (e.g. `<script>` markers for stored XSS). The HTML report renderer runs those through an autoescaping Jinja environment; the Markdown/JSON renderer intentionally doesn't, since escaping would corrupt code blocks there.
- **Static analysis is part of the workflow, not an afterthought.** `bandit -r .` and `pyflakes .` both run clean. Any suppressed finding (`# nosec`) is commented with the specific reason it's a false positive at that call site, not a blanket suppression.

---

## Safety Controls

| Feature | Default | Flag to change |
|---|---|---|
| Scope guard | Enforced on every request | `--scope` to add patterns |
| Safe mode (blocks DELETE/PUT) | **ON** | `--no-safe` to disable |
| Dry run | OFF | `--dry-run` to enable |
| Request throttle | 0.3s | `--delay <s>` |
| Concurrent workers | 4 | `--workers <n>` |
| Request timeout | 15s | `--timeout <s>` |

Credentials (cookies, tokens) are encrypted at rest with Fernet symmetric encryption. The key is stored at `~/.bugkit/.identity_key` (chmod 600).

---

## Legal

This tool is for authorized security research and bug bounty programmes only. Only test targets covered by an active bug bounty programme or with explicit written permission. The authors are not responsible for misuse.

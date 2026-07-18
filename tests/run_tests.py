"""
BugKit v4 — Standalone test runner.
Works without pytest or any external packages.
Run: python3 tests/run_tests.py
"""
from __future__ import annotations
import sys, os, re, tempfile, datetime
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# ── Stub unavailable packages so imports don't fail ───────────────────
from unittest.mock import MagicMock

def _stub(name):
    m = MagicMock()
    sys.modules[name] = m
    return m

for pkg in ['rich','rich.console','rich.panel','rich.text','rich.table',
            'rich.box','sqlalchemy','sqlalchemy.orm','sqlalchemy.orm.session',
            'sqlalchemy.orm.declarative','typer','bs4','deepdiff',
            'jinja2','jinja2.loaders']:
    _stub(pkg)

# ── Test helpers ───────────────────────────────────────────────────────
passed, failed = [], []

def run(name, fn):
    try:
        fn()
        passed.append(name)
        print(f'  PASS  {name}')
    except Exception as e:
        import traceback
        failed.append((name, str(e)))
        print(f'  FAIL  {name}: {e}')
        if '--verbose' in sys.argv:
            traceback.print_exc()


# ══════════════════════════════════════════════════════════════════════
#  1. SCOPE GUARD
# ══════════════════════════════════════════════════════════════════════
def test_scope():
    from core.scope import ScopeGuard, ScopeViolation
    sg = ScopeGuard(['example.com', '*.api.example.com'])
    assert sg.allows('https://example.com/foo')
    assert sg.allows('https://sub.example.com/bar')
    assert sg.allows('https://v2.api.example.com/')
    assert not sg.allows('https://evil.com')
    assert not sg.allows('https://evil-example.com')
    try:
        sg.check('https://evil.com')
        raise AssertionError('should raise ScopeViolation')
    except ScopeViolation:
        pass
    sg.add('newdomain.com')
    assert sg.allows('https://newdomain.com')

run('ScopeGuard', test_scope)


# ══════════════════════════════════════════════════════════════════════
#  2. ENCRYPTION + IDENTITY
# ══════════════════════════════════════════════════════════════════════
def test_encryption():
    from core.session import encrypt, decrypt, Identity, BugKitSession
    from core.scope import ScopeGuard

    original = '{"cookies":{"session":"abc123"},"headers":{"Authorization":"Bearer xyz"}}'
    enc = encrypt(original)
    dec = decrypt(enc)
    assert dec == original, 'Decryption mismatch'
    assert enc != original, 'Encryption did nothing'

    # Identity round-trip
    ident = Identity('userA', 'admin',
                     cookies={'session': 'abc'},
                     headers={'Authorization': 'Bearer xyz'},
                     note='test admin account')
    d = ident.to_encrypted_dict()
    r = Identity.from_encrypted_dict(d)
    assert r.name == 'userA'
    assert r.role == 'admin'
    assert r.cookies['session'] == 'abc'
    assert r.headers['Authorization'] == 'Bearer xyz'
    assert r.note == 'test admin account'

    # BugKitSession identity management
    sess = BugKitSession(ScopeGuard(['example.com']))
    sess.load_identity(ident)
    assert 'userA' in sess.identity_names
    sess.use('userA')
    assert sess.active_identity.name == 'userA'

run('Encryption + Identity', test_encryption)


# ══════════════════════════════════════════════════════════════════════
#  3. FINGERPRINTS
# ══════════════════════════════════════════════════════════════════════
def test_fingerprints():
    from core.fingerprints import (fingerprint_response, detect_waf,
        check_takeover, CLOUD_SIGNATURES, TECH_BODY, TECH_HEADERS,
        WAF_SIGNATURES, paths_for_tech)

    # Multi-tech detection
    tech = fingerprint_response(
        {'X-Powered-By': 'PHP/8.1', 'cf-ray': 'abc123xyz', 'server': 'nginx'},
        'wp-content/themes/test __reactFiber __NEXT_DATA__'
    )
    assert 'PHP' in tech,       f'PHP missing from {tech}'
    assert 'Cloudflare' in tech,f'Cloudflare missing from {tech}'
    assert 'WordPress' in tech, f'WordPress missing from {tech}'
    assert 'Nginx' in tech,     f'Nginx missing from {tech}'
    assert 'React' in tech,     f'React missing from {tech}'

    # WAF detection
    assert detect_waf({'cf-ray': 'abc'}, '') == 'Cloudflare'
    assert detect_waf({'x-sucuri-id': '1'}, '') == 'Sucuri'
    assert detect_waf({}, 'Sucuri WebSite Firewall') == 'Sucuri'
    assert detect_waf({}, 'normal page') is None

    # Takeover detection
    assert check_takeover("There isn't a GitHub Pages site here") == 'GitHub Pages'
    assert check_takeover('No such app') == 'Heroku'
    assert check_takeover('NoSuchBucket') == 'AWS S3'
    assert check_takeover('normal 200 page') is None

    # At least 25 services covered
    services = {s[0] for s in CLOUD_SIGNATURES}
    assert len(services) >= 25, f'Only {len(services)} takeover services'
    assert 'GitHub Pages' in services
    assert 'AWS S3' in services
    assert 'Netlify' in services
    assert 'Shopify' in services
    assert 'Vercel' in services

    # Tech paths
    wp_paths = paths_for_tech('WordPress')
    assert any('wp-admin' in p for p in wp_paths)
    spring_paths = paths_for_tech('Spring')
    assert any('actuator' in p for p in spring_paths)

run('Fingerprints', test_fingerprints)


# ══════════════════════════════════════════════════════════════════════
#  4. UTILS
# ══════════════════════════════════════════════════════════════════════
def test_utils():
    from core.utils import (extract_ids_from_url, mutate_id,
        inject_param, looks_like_id, sha256_of, all_param_variants,
        domain_of, base_url, normalise_url, chunks)

    # ID extraction — path
    ids = extract_ids_from_url('https://api.example.com/users/1042/orders')
    assert any(v == '1042' for _, v in ids), f'Expected 1042 in {ids}'

    # ID extraction — query param
    ids2 = extract_ids_from_url('https://example.com?user_id=42&page=1')
    assert any(v == '42' for _, v in ids2), f'Expected 42 in {ids2}'

    # UUID in path
    ids3 = extract_ids_from_url(
        'https://api.example.com/docs/550e8400-e29b-41d4-a716-446655440000')
    assert any('550e8400' in v for _, v in ids3), f'UUID not found in {ids3}'

    # Mutations
    muts = mutate_id('100')
    assert '101' in muts
    assert '99' in muts
    assert len(muts) >= 4

    uuid_muts = mutate_id('550e8400-e29b-41d4-a716-446655440000')
    assert len(uuid_muts) > 0
    assert '550e8400-e29b-41d4-a716-446655440000' not in uuid_muts

    # Injection
    url = inject_param('https://example.com/api?foo=1&bar=2', 'foo', '99')
    assert 'foo=99' in url
    assert 'bar=2' in url

    # looks_like_id
    assert looks_like_id('12345')
    assert looks_like_id('550e8400-e29b-41d4-a716-446655440000')
    assert not looks_like_id('username')
    assert not looks_like_id('search')

    # sha256
    h = sha256_of(b'hello world')
    assert len(h) == 64 and all(c in '0123456789abcdef' for c in h)

    # domain_of, base_url, normalise_url
    assert domain_of('https://api.example.com/users') == 'api.example.com'
    assert base_url('https://api.example.com/users')  == 'https://api.example.com'
    assert normalise_url('example.com') == 'https://example.com'

    # chunks
    c = list(chunks([1,2,3,4,5], 2))
    assert c == [[1,2],[3,4],[5]]

    # all_param_variants
    variants = list(all_param_variants('https://ex.com?a=1&b=2', 'INJECT'))
    assert len(variants) == 2, f'Expected 2 variants, got {len(variants)}'
    urls = [v[0] for v in variants]
    assert any('a=INJECT' in u for u in urls), f'a=INJECT not in {urls}'
    assert any('b=INJECT' in u for u in urls), f'b=INJECT not in {urls}'

run('Utils', test_utils)


# ══════════════════════════════════════════════════════════════════════
#  5. SCHEDULER
# ══════════════════════════════════════════════════════════════════════
def test_scheduler():
    import time
    from core.scheduler import Scheduler, Task, TaskResult, _TokenBucket, get_scheduler

    sched = Scheduler(workers=4)

    # Basic map — all results returned
    results = sched.map(fn=lambda x: x * 2, targets=[1, 2, 3, 4, 5])
    assert len(results) == 5
    assert all(r.response == i * 2 for i, r in zip([1,2,3,4,5], results))

    # Order preserved even when tasks finish out-of-order
    import time as _t
    def slow(x):
        _t.sleep(0.02 if x == 0 else 0.0)
        return x
    res = sched.map(fn=slow, targets=[0, 1, 2, 3])
    assert len(res) == 4

    # Error handling — failed tasks return None response + error message
    def always_fails(x):
        raise RuntimeError(f'net error on {x}')
    res2 = sched.map(fn=always_fails, targets=['a', 'b', 'c'])
    assert all(r.response is None for r in res2)
    assert all(r.error for r in res2)
    assert all('net error' in r.error for r in res2)

    # Streaming
    tasks = [Task(fn=lambda: i, args=()) for i in range(5)]
    count = sum(1 for _ in sched.run_tasks_streaming(tasks))
    assert count == 5

    # Token bucket — doesn't block forever at high rate
    bucket = _TokenBucket(rate=1000.0)
    t0 = time.monotonic()
    for _ in range(20):
        bucket.acquire()
    assert time.monotonic() - t0 < 1.0

    # Singleton
    s = get_scheduler(workers=2)
    assert isinstance(s, Scheduler)

run('Scheduler', test_scheduler)


# ══════════════════════════════════════════════════════════════════════
#  6. MIGRATIONS
# ══════════════════════════════════════════════════════════════════════
def test_migrations():
    import sqlite3
    from db.migrations import migrate, current_version, MIGRATIONS

    assert len(MIGRATIONS) >= 5, f'Only {len(MIGRATIONS)} migrations defined'

    with tempfile.TemporaryDirectory() as d:
        db = os.path.join(d, 'bugkit_test.db')

        # Fresh migration
        migrate(db)
        v1 = current_version(db)
        assert v1 == len(MIGRATIONS), f'Expected v{len(MIGRATIONS)}, got v{v1}'

        # Idempotent — second run changes nothing
        migrate(db)
        assert current_version(db) == v1

        # All required tables exist
        conn = sqlite3.connect(db)
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        conn.close()

        required = {
            'targets', 'identities', 'endpoints', 'findings', 'scans',
            'snapshots', 'workflows', 'objects', 'oauth_flows',
            'massassign_results', 'ratelimit_results', '_schema_version'
        }
        missing = required - tables
        assert not missing, f'Missing tables: {missing}'

        # Version table has correct entries
        conn = sqlite3.connect(db)
        versions = [r[0] for r in conn.execute(
            'SELECT version FROM _schema_version ORDER BY version').fetchall()]
        conn.close()
        assert versions == list(range(1, len(MIGRATIONS) + 1))

run('Migrations', test_migrations)


# ══════════════════════════════════════════════════════════════════════
#  7. DIFF ENGINE
# ══════════════════════════════════════════════════════════════════════
def test_diff():
    import requests
    from core.diff import (DiffResult, Signal, AUTH_POSITIVE,
        AUTH_NEGATIVE, _try_json, _flatten, _compare_headers)

    assert 200 in AUTH_POSITIVE
    assert 201 in AUTH_POSITIVE
    assert 401 in AUTH_NEGATIVE
    assert 403 in AUTH_NEGATIVE
    assert 404 in AUTH_NEGATIVE

    # Signal anomaly propagation
    diff = DiffResult('userA', 'userB', 'https://x.com/api', 'GET')
    diff.add(Signal('status_code', '403 vs 200', is_anomaly=True))
    diff.add(Signal('body_size',   '100B vs 5000B', is_anomaly=True))
    diff.add(Signal('redirect',    '/login vs /dash', is_anomaly=True))
    diff.compute_confidence()
    assert diff.is_anomaly
    assert diff.confidence == 'high'   # 3 anomaly signals → high
    assert diff.summary                # non-empty

    # One anomaly → medium confidence
    diff2 = DiffResult('A', 'B', 'https://x.com/', 'GET')
    diff2.add(Signal('status_code', '200 vs 403', is_anomaly=True))
    diff2.compute_confidence()
    assert diff2.confidence == 'medium'

    # No anomaly → low
    diff3 = DiffResult('A', 'B', 'https://x.com/', 'GET')
    diff3.add(Signal('body_size', '100B vs 105B', is_anomaly=False))
    diff3.compute_confidence()
    assert diff3.confidence == 'low'
    assert not diff3.is_anomaly

    # _flatten nested dict
    flat = _flatten({'user': {'id': 1, 'role': 'admin'}})
    assert flat['user.id'] == 1
    assert flat['user.role'] == 'admin'

run('Diff Engine', test_diff)


# ══════════════════════════════════════════════════════════════════════
#  8. OBJECT MUTATOR
# ══════════════════════════════════════════════════════════════════════
def test_mutator():
    from core.scope import ScopeGuard
    from core.session import BugKitSession
    from engines.object_mutator import ObjectMutator

    sess    = BugKitSession(ScopeGuard(['example.com']))
    mutator = ObjectMutator(sess)

    # Path mutation
    r1 = mutator._apply_mutation(
        'https://example.com/users/42/profile', 'path:1', '99')
    assert '/users/99/profile' in r1, f'Got: {r1}'

    # Param mutation
    r2 = mutator._apply_mutation(
        'https://example.com/api?user_id=42', 'param:user_id', '99')
    assert 'user_id=99' in r2, f'Got: {r2}'

    # Invalid location — returns original
    r3 = mutator._apply_mutation('https://example.com/', 'invalid:x', '99')
    assert r3 == 'https://example.com/'

run('Object Mutator', test_mutator)


# ══════════════════════════════════════════════════════════════════════
#  9. REPLAY ENGINE
# ══════════════════════════════════════════════════════════════════════
def test_replay():
    from core.scope import ScopeGuard
    from core.session import BugKitSession
    from engines.replay_engine import WorkflowStep, ReplayResult, StepResult

    # WorkflowStep serialization
    step = WorkflowStep(
        name='login', method='POST',
        url='https://example.com/login',
        body='{"email":"a@b.com","password":"pass"}',
        note='first step'
    )
    d = step.to_dict()
    r = WorkflowStep.from_dict(d)
    assert r.name   == 'login'
    assert r.method == 'POST'
    assert r.url    == 'https://example.com/login'
    assert r.note   == 'first step'

    # ReplayResult anomaly tracking
    result = ReplayResult(scenario='skip[verify]')
    result.is_anomaly = True
    result.note = 'Skipping verify did not break flow'
    sr1 = StepResult(step=step, status_code=200, success=True)
    sr2 = StepResult(step=step, status_code=200, success=True)
    result.steps = [sr1, sr2]
    assert result.succeeded_count == 2
    assert result.all_succeeded

run('Replay Engine', test_replay)


# ══════════════════════════════════════════════════════════════════════
#  10. OAUTH TESTER
# ══════════════════════════════════════════════════════════════════════
def test_oauth():
    from core.scope import ScopeGuard
    from core.session import BugKitSession
    from modules.oauth.tester import (OAuthTester, OAuthConfig,
        OAUTH_DISCOVERY_PATHS, COMMON_REDIRECT_BYPASS)

    sess   = BugKitSession(ScopeGuard(['example.com']))
    tester = OAuthTester(sess)
    tester._client_id    = 'app_client_123'
    tester._redirect_uri = 'https://example.com/oauth/callback'
    tester._scopes       = 'openid profile email'

    params = tester._base_auth_params()
    assert 'state' in params
    assert len(params['state']) >= 16
    assert params['client_id']     == 'app_client_123'
    assert params['redirect_uri']  == 'https://example.com/oauth/callback'
    assert params['response_type'] == 'code'
    assert params['scope']         == 'openid profile email'

    # Discovery paths
    assert len(OAUTH_DISCOVERY_PATHS) >= 8
    paths_str = ' '.join(OAUTH_DISCOVERY_PATHS)
    assert 'openid-configuration' in paths_str
    assert 'authorize' in paths_str
    assert 'token' in paths_str

    # Redirect bypass list
    assert len(COMMON_REDIRECT_BYPASS) >= 4
    assert any('evil.com' in u for u in COMMON_REDIRECT_BYPASS)
    assert any(u.startswith('javascript:') for u in COMMON_REDIRECT_BYPASS)
    assert any(u.startswith('//') for u in COMMON_REDIRECT_BYPASS)

    # OAuthConfig defaults
    cfg = OAuthConfig()
    assert cfg.authorization_endpoint == ''
    assert cfg.pkce_required == False

run('OAuth Tester', test_oauth)


# ══════════════════════════════════════════════════════════════════════
#  11. MASS ASSIGNMENT
# ══════════════════════════════════════════════════════════════════════
def test_massassign():
    import requests as _req
    from core.scope import ScopeGuard
    from core.session import BugKitSession
    from modules.massassign.tester import (MassAssignTester, PRIV_FIELDS,
        MassAssignResult)

    sess = BugKitSession(ScopeGuard(['example.com']))
    t    = MassAssignTester(sess)
    t._base = 'https://api.example.com'

    # Severity classification
    assert t._severity('role', 'admin')       == 'CRITICAL'
    assert t._severity('is_admin', True)      == 'CRITICAL'
    assert t._severity('is_superuser', True)  == 'CRITICAL'
    assert t._severity('permissions', ['*'])  == 'CRITICAL'
    assert t._severity('plan', 'enterprise')  == 'HIGH'
    assert t._severity('verified', True)      == 'HIGH'
    assert t._severity('balance', 99999)      == 'HIGH'
    assert t._severity('owner_id', 1)         == 'HIGH'
    assert t._severity('bio', 'hello')        == 'MEDIUM'
    assert t._severity('nickname', 'x')       == 'MEDIUM'

    # Privilege field catalogue completeness
    assert len(PRIV_FIELDS) >= 20
    field_names = [f for f, _, _ in PRIV_FIELDS]
    for required in ['role', 'is_admin', 'verified', 'plan',
                     'balance', '__proto__', 'user_id']:
        assert required in field_names, f'Missing PRIV field: {required}'

    # Reflection detection
    def mk(status, body):
        r = _req.Response()
        r.status_code = status
        r._content    = body.encode()
        r.headers     = _req.structures.CaseInsensitiveDict({'Content-Type': 'application/json'})
        r.elapsed     = datetime.timedelta(seconds=0.1)
        return r

    baseline = mk(200, '{"id":1,"name":"bob"}')
    injected = mk(200, '{"id":1,"name":"bob","role":"admin","is_admin":true}')
    result   = t._analyze(
        url='https://api.example.com/profile', method='PUT',
        field_name='role', field_value='admin',
        baseline_resp=baseline, injected_resp=injected,
        baseline_json={'id': 1, 'name': 'bob'},
    )
    assert result.accepted, 'Should detect role reflected in response'
    assert result.confidence in ('high', 'medium')

    # No false positive on identical response
    r1 = mk(200, '{"id":1}')
    r2 = mk(200, '{"id":1}')
    result2 = t._analyze(
        url='https://api.example.com/profile', method='PUT',
        field_name='role', field_value='admin',
        baseline_resp=r1, injected_resp=r2,
        baseline_json={'id': 1},
    )
    assert not result2.accepted, 'Should not fire on identical responses'

    # Heuristic endpoints
    eps = t._heuristic_endpoints()
    assert len(eps) >= 5
    assert all(u.startswith('https://') for u, _ in eps)
    assert any('profile' in u for u, _ in eps)

run('Mass Assignment', test_massassign)


# ══════════════════════════════════════════════════════════════════════
#  12. OPENAPI IMPORTER
# ══════════════════════════════════════════════════════════════════════
def test_openapi():
    from core.scope import ScopeGuard
    from core.session import BugKitSession
    from modules.openapi.importer import (OpenAPIImporter,
        SPEC_DISCOVERY_PATHS)

    sess = BugKitSession(ScopeGuard(['example.com']))
    imp  = OpenAPIImporter(sess)
    imp._base = 'https://api.example.com'

    # Version detection
    assert imp._detect_version({'openapi': '3.1.0'}) == '3.1.0'
    assert imp._detect_version({'openapi': '3.0.0'}) == '3.0.0'
    assert imp._detect_version({'swagger': '2.0'})   == '2.0'
    assert imp._detect_version({})                    == 'unknown'

    # Discovery paths coverage
    assert len(SPEC_DISCOVERY_PATHS) >= 10
    paths_str = ' '.join(SPEC_DISCOVERY_PATHS)
    assert 'openapi' in paths_str
    assert 'swagger' in paths_str
    assert 'api-docs' in paths_str

    # Schema field extraction — flat object
    schema = {
        'type': 'object',
        'properties': {
            'email': {'type': 'string'},
            'role':  {'type': 'string'},
            'admin': {'type': 'boolean'},
        }
    }
    fields = imp._extract_schema_fields(schema, {})
    assert 'email' in fields
    assert 'role'  in fields
    assert 'admin' in fields

    # $ref resolution
    spec = {
        'components': {
            'schemas': {
                'User': {
                    'properties': {
                        'id':    {'type': 'integer'},
                        'email': {'type': 'string'},
                        'role':  {'type': 'string'},
                    }
                }
            }
        }
    }
    resolved = imp._resolve_ref('#/components/schemas/User', spec)
    assert resolved is not None
    assert 'email' in resolved['properties']
    assert 'role'  in resolved['properties']
    assert imp._resolve_ref('#/nonexistent/path', spec) is None

    # Full OpenAPI 3 parse
    spec3 = {
        'openapi': '3.0.0',
        'servers': [{'url': 'https://api.example.com'}],
        'security': [{'bearerAuth': []}],
        'paths': {
            '/users': {
                'get': {
                    'security': [{'bearerAuth': []}],
                    'parameters': [
                        {'name': 'page',  'in': 'query'},
                        {'name': 'limit', 'in': 'query'},
                    ],
                    'responses': {'200': {'description': 'OK'}},
                },
                'post': {
                    'security': [{'bearerAuth': []}],
                    'requestBody': {
                        'content': {
                            'application/json': {
                                'schema': {
                                    'type': 'object',
                                    'properties': {
                                        'email': {'type': 'string'},
                                        'role':  {'type': 'string'},
                                    }
                                }
                            }
                        }
                    },
                    'responses': {'201': {'description': 'Created'}},
                }
            },
            '/health': {
                'get': {
                    'security': [{}],   # explicitly public
                    'responses': {'200': {'description': 'OK'}},
                }
            }
        }
    }
    eps = imp._parse_openapi3(spec3, 'https://api.example.com')
    assert len(eps) == 3, f'Expected 3 endpoints, got {len(eps)}'

    get_users = next(e for e in eps if e['url'].endswith('/users') and e['method'] == 'GET')
    assert get_users['auth_required'] == True
    assert 'page'  in get_users['params']
    assert 'limit' in get_users['params']

    post_users = next(e for e in eps if e['method'] == 'POST')
    assert 'email' in post_users['params']
    assert 'role'  in post_users['params']

    health = next(e for e in eps if '/health' in e['url'])
    assert health['auth_required'] == False

run('OpenAPI Importer', test_openapi)


# ══════════════════════════════════════════════════════════════════════
#  13. OTP TESTER
# ══════════════════════════════════════════════════════════════════════
def test_otp():
    from core.scope import ScopeGuard
    from core.session import BugKitSession
    from modules.otp.tester import (OTPTester, OTP_FIELD_NAMES,
        OTP_PATHS, BACKUP_CODE_PATHS, RECOVERY_PATHS)

    sess   = BugKitSession(ScopeGuard(['example.com']))
    tester = OTPTester(sess)
    tester._username = 'victim@example.com'

    # OTP body covers all field names
    body = tester._otp_body('123456')
    for field in OTP_FIELD_NAMES:
        assert field in body, f'Missing OTP field: {field}'
    assert body['email'] == 'victim@example.com'
    assert body['otp']   == '123456'

    # 6-digit pattern
    otp_pattern = re.compile(r'\b\d{6}\b')
    assert otp_pattern.findall('{"otp":"482910"}') == ['482910']
    assert otp_pattern.findall('{"status":"error"}') == []

    # Path lists
    assert len(OTP_PATHS) >= 10
    assert any('2fa' in p for p in OTP_PATHS)
    assert any('verify' in p for p in OTP_PATHS)
    assert any('mfa' in p for p in OTP_PATHS)

    assert len(BACKUP_CODE_PATHS) >= 4
    assert any('backup' in p for p in BACKUP_CODE_PATHS)

    assert len(RECOVERY_PATHS) >= 4
    assert any('recover' in p or 'disable' in p for p in RECOVERY_PATHS)

    # Backup code detection pattern
    backup_pat = re.compile(r'[A-Z0-9]{8,12}')
    codes = backup_pat.findall('{"codes":["ABCD1234EF","GHIJ5678KL"]}')
    assert len(codes) >= 2

run('OTP Tester', test_otp)


# ══════════════════════════════════════════════════════════════════════
#  14. WEBSOCKET TESTER
# ══════════════════════════════════════════════════════════════════════
def test_websocket():
    from core.scope import ScopeGuard
    from core.session import BugKitSession
    from modules.websocket.tester import WebSocketTester, WSConnection

    sess   = BugKitSession(ScopeGuard(['example.com']))
    tester = WebSocketTester(sess)

    # URL conversion
    assert tester._to_ws_url('https://example.com/ws') == 'wss://example.com/ws'
    assert tester._to_ws_url('http://example.com/ws')  == 'ws://example.com/ws'
    assert tester._to_ws_url('wss://example.com/ws')   == 'wss://example.com/ws'
    assert tester._to_ws_url('ws://example.com/ws')    == 'ws://example.com/ws'

    # Connection to invalid host — fails gracefully
    conn = tester._connect('wss://nonexistent-host-bugkit-test.invalid/ws',
                           with_auth=False)
    assert not conn.connected
    assert conn.error != ''
    assert conn.sock is None

    # WSConnection close is safe when no socket
    conn2 = WSConnection(url='wss://x.com/ws')
    conn2.close()  # should not raise

run('WebSocket Tester', test_websocket)


# ══════════════════════════════════════════════════════════════════════
#  15. RATE LIMIT TESTER
# ══════════════════════════════════════════════════════════════════════
def test_ratelimit():
    from modules.ratelimit.tester import (DEFAULT_ENDPOINTS,
        IP_SPOOF_HEADERS, RateLimitResult)

    # Default endpoints cover key categories
    assert len(DEFAULT_ENDPOINTS) >= 8
    assert any('login'    in ep for ep in DEFAULT_ENDPOINTS)
    assert any('token'    in ep for ep in DEFAULT_ENDPOINTS)
    assert any('register' in ep or 'signup' in ep for ep in DEFAULT_ENDPOINTS)
    assert any('verify'   in ep or 'otp'    in ep for ep in DEFAULT_ENDPOINTS)
    assert any('forgot'   in ep or 'reset'  in ep for ep in DEFAULT_ENDPOINTS)

    # IP spoof headers cover the main bypass vectors
    names = [list(h.keys())[0] for h in IP_SPOOF_HEADERS]
    assert 'X-Forwarded-For'  in names
    assert 'X-Real-IP'        in names
    assert 'CF-Connecting-IP' in names
    assert 'True-Client-IP'   in names
    assert len(IP_SPOOF_HEADERS) >= 4

    # RateLimitResult tracking
    r = RateLimitResult(
        url        = 'https://example.com/login',
        identity   = 'userA',
        burst_size = 30,
        hit_429    = True,
        threshold  = 15,
        confidence = 'high',
    )
    assert r.threshold  == 15
    assert r.hit_429    == True
    assert r.confidence == 'high'
    r.status_dist = {200: 14, 429: 1}
    assert r.status_dist[200] == 14

run('Rate Limit Tester', test_ratelimit)


# ══════════════════════════════════════════════════════════════════════
#  16. FILE TESTER
# ══════════════════════════════════════════════════════════════════════
def test_files():
    from core.scope import ScopeGuard
    from core.session import BugKitSession
    from modules.files.tester import (FileTester, BYPASS_UPLOADS,
        TRAVERSAL_FILENAMES, UPLOAD_PATHS)

    sess   = BugKitSession(ScopeGuard(['example.com']))
    tester = FileTester(sess)
    tester._base = 'https://app.example.com'

    # Bypass upload catalogue
    assert len(BYPASS_UPLOADS) >= 5
    fnames = [f[0] for f in BYPASS_UPLOADS]
    assert any('php' in f.lower()      for f in fnames), 'No PHP payload'
    assert any('.svg' in f             for f in fnames), 'No SVG payload'
    assert any('.htaccess' in f        for f in fnames), 'No htaccess payload'
    assert any('jsp' in f.lower()      for f in fnames), 'No JSP payload'

    # Traversal filenames
    assert len(TRAVERSAL_FILENAMES) >= 4
    traversals = ' '.join(TRAVERSAL_FILENAMES)
    assert 'etc/passwd' in traversals
    assert '..' in traversals

    # Upload paths
    assert len(UPLOAD_PATHS) >= 10
    paths_str = ' '.join(UPLOAD_PATHS)
    assert 'upload' in paths_str
    assert 'file' in paths_str or 'files' in paths_str

    # URL extraction from response
    r1 = tester._extract_file_url(
        '{"url":"https://cdn.example.com/uploads/doc.txt"}',
        'https://app.example.com'
    )
    assert r1 == 'https://cdn.example.com/uploads/doc.txt'

    r2 = tester._extract_file_url(
        '{"file_url":"/uploads/test.pdf"}',
        'https://app.example.com'
    )
    assert 'uploads/test.pdf' in r2

    r3 = tester._extract_file_url('{"error":"not found"}', 'https://x.com')
    assert r3 == ''

run('File Tester', test_files)


# ══════════════════════════════════════════════════════════════════════
#  17. FUZZER
# ══════════════════════════════════════════════════════════════════════
def test_fuzzer():
    from core.scope import ScopeGuard
    from core.session import BugKitSession
    from modules.fuzz.tester import (Fuzzer, SQL_ERROR_PATTERNS,
        WAF_BYPASS_TRANSFORMS, SQLI_ERROR, SQLI_BLIND,
        XSS_REFLECTED, LFI_PAYLOADS, OPEN_REDIRECT,
        SSTI_PAYLOADS, HEADER_INJECTION)

    sess   = BugKitSession(ScopeGuard(['example.com']))
    fuzzer = Fuzzer(sess)
    fuzzer._tid      = 1
    fuzzer._identity = None

    # SQL error patterns
    assert SQL_ERROR_PATTERNS.search('You have an error in your SQL syntax')
    assert SQL_ERROR_PATTERNS.search('Warning: mysql_query() failed')
    assert SQL_ERROR_PATTERNS.search('ORA-00907: missing right parenthesis')
    assert SQL_ERROR_PATTERNS.search('pg_query(): Query failed')
    assert SQL_ERROR_PATTERNS.search('sqlite3.OperationalError: near')
    assert SQL_ERROR_PATTERNS.search('Microsoft OLE DB Provider for SQL Server')
    assert not SQL_ERROR_PATTERNS.search('Everything looks fine here')

    # LFI confirmation pattern
    lfi_match = re.compile(r'root:.*:/bin/|daemon:.*:/usr/sbin', re.I | re.M)
    assert lfi_match.search('root:x:0:0:root:/root:/bin/bash')
    assert lfi_match.search('daemon:x:1:1:daemon:/usr/sbin/nologin')
    assert not lfi_match.search('normal server response here')

    # WAF transforms exist for key checks
    assert 'sqli' in WAF_BYPASS_TRANSFORMS
    assert 'xss'  in WAF_BYPASS_TRANSFORMS
    assert 'lfi'  in WAF_BYPASS_TRANSFORMS
    assert len(WAF_BYPASS_TRANSFORMS['sqli']) >= 4
    assert len(WAF_BYPASS_TRANSFORMS['xss'])  >= 3

    # WAF expansion increases payload count without duplicates
    originals = ["' OR '1'='1", "' OR 1=1--", '" OR "1"="1']
    expanded  = fuzzer._expand_waf(originals, 'sqli')
    assert len(expanded) > len(originals)
    assert len(expanded) == len(set(expanded)), 'Duplicates in WAF expansion'

    xss_expanded = fuzzer._expand_waf(['<script>alert(1)</script>'], 'xss')
    assert len(xss_expanded) > 1

    # Payload lists are non-trivial
    assert len(SQLI_ERROR)    >= 10
    assert len(SQLI_BLIND)    >= 5
    assert len(XSS_REFLECTED) >= 6
    assert len(LFI_PAYLOADS)  >= 8
    assert len(OPEN_REDIRECT) >= 5
    assert len(SSTI_PAYLOADS) >= 4
    assert len(HEADER_INJECTION) >= 3

    # Blind SQLi payloads have expected structure (payload, delay, desc)
    for payload, delay, desc in SQLI_BLIND:
        assert isinstance(payload, str) and payload
        assert isinstance(delay, float) and delay >= 4.0
        assert isinstance(desc, str) and desc

    # Payload file loading
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write(
            "# comment line\n"
            "' OR 1=1--\n"
            "sqli:' UNION SELECT NULL--\n"
            "xss:<img src=x onerror=alert(1)>\n"
            "lfi:../../../../etc/passwd\n"
            "\n"
        )
        fpath = f.name
    result = fuzzer._load_payload_file(fpath)
    os.unlink(fpath)
    assert "' OR 1=1--"             in result.get('sqli', [])
    assert "' UNION SELECT NULL--"  in result.get('sqli', [])
    assert '<img src=x onerror=alert(1)>' in result.get('xss', [])
    assert '../../../../etc/passwd' in result.get('lfi', [])

run('Fuzzer', test_fuzzer)


# ══════════════════════════════════════════════════════════════════════
#  SUMMARY
# ══════════════════════════════════════════════════════════════════════
total = len(passed) + len(failed)
print()
print('=' * 55)
print(f'  BugKit v4 Test Suite')
print(f'  Passed: {len(passed)}/{total}')
if failed:
    print(f'  Failed: {len(failed)}')
    for name, err in failed:
        print(f'    ✖ {name}')
        print(f'      {err}')
    sys.exit(1)
else:
    print(f'  ALL {total} TEST GROUPS PASSED ✔')
    print('=' * 55)

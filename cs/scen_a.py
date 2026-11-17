# -*- coding: utf-8 -*-
"""Scenario A: multi-tenant SaaS on Keycloak realms t1 / t2 with Postgres row-level security. Behaviour follows the element set."""
import statistics
import time

import psycopg

from . import infra
from .common import Case, RealClock, RemoteIssuer
from .jwtlib import NS, STS, Issuer, get_path, size, Reject
from .verify import Verifier

CLOCK = RealClock()
PARTNER = Issuer('unused', 'partner-t2', kid='partner-t2')  # a signing key handed to t2's integration partner


def setup_db():
    with psycopg.connect(infra.PG_DSN, autocommit=True) as c:
        c.execute("""
        DROP TABLE IF EXISTS invoices; DROP TABLE IF EXISTS grants;
        DO $$ BEGIN
          IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='app_rls') THEN CREATE ROLE app_rls LOGIN PASSWORD 'p' NOBYPASSRLS; END IF;
          IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='app_norls') THEN CREATE ROLE app_norls LOGIN PASSWORD 'p' BYPASSRLS; END IF;
        END $$;
        CREATE TABLE invoices (id int PRIMARY KEY, tenant_id text NOT NULL, owner text NOT NULL, amount int NOT NULL);
        INSERT INTO invoices SELECT g, CASE WHEN g % 2 = 0 THEN 't1' ELSE 't2' END, 'user' || (g % 7), g * 1000 FROM generate_series(1, 40) g;
        ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
        CREATE POLICY tenant_isolation ON invoices USING (tenant_id = current_setting('app.tenant', true));
        GRANT SELECT ON invoices TO app_rls, app_norls;
        CREATE TABLE grants (subject text, invoice_id int, PRIMARY KEY (subject, invoice_id));
        INSERT INTO grants SELECT 'alice', g FROM generate_series(2, 40, 2) g;
        GRANT SELECT ON grants TO app_rls, app_norls;
        """)


def conn(role):
    return psycopg.connect(infra.PG_DSN.replace('user=app password=app', f'user={role} password=p'), autocommit=True)


class Api:
    """One instance per configuration; each keeps ONE pooled connection reused across requests."""

    def __init__(self, f, t1, t2):
        self.f = f
        self.realm_of = {t1.iss: 't1', t2.iss: 't2'}
        reg = {t1.iss: [t1], t2.iss: [t2, PARTNER]} if 'per_tenant_keys' in f else {t1.iss: [t1, t2, PARTNER], t2.iss: [t1, t2, PARTNER]}
        self.v = Verifier(f, reg, audience='saas-api', typ=('at+jwt',), required={'sub': str, NS + '|tenant_id': str}, clock=CLOCK)
        self.mode = 'local' if 'rls_local' in f else 'session' if 'rls_session' in f else 'none'
        self.db = conn('app_norls' if self.mode == 'none' else 'app_rls')

    def _auth(self, token, path_tenant, headers):
        c = self.v.verify(token)
        f = self.f
        t = get_path(c, NS + '|tenant_id') if 'namespace' in f else None
        if t is None:  # without the namespace rule, or when the claim is missing and not required: fall back to the request
            t = headers.get('X-Tenant') or path_tenant
        elif t != path_tenant and not isinstance(t, list):
            raise Reject('tenant mismatch with path')
        if 'tenant_iss_bind' in f and self.realm_of.get(c.get('iss')) != t:
            raise Reject('tenant claim does not match issuer')
        return c, t

    def _run(self, tenant, sql, args, set_ctx=True):
        if self.mode == 'session' and set_ctx:
            self.db.execute('SELECT set_config(%s, %s, false)', ('app.tenant', tenant if isinstance(tenant, str) else tenant[0]))
        if self.mode == 'local':
            with self.db.transaction():
                self.db.execute('SELECT set_config(%s, %s, true)', ('app.tenant', tenant if isinstance(tenant, str) else ''))
                return self.db.execute(sql, args).fetchall()
        return self.db.execute(sql, args).fetchall()

    def _where(self, tenant):
        if isinstance(tenant, list):  # an array claim slips into SQL as ANY(...)
            return 'tenant_id = ANY(%s)', (tenant,)
        return 'tenant_id = %s', (tenant,)

    def list(self, token, path_tenant, headers=None):
        c, t = self._auth(token, path_tenant, headers or {})
        w, a = self._where(t)
        return self._run(t, f'SELECT id, tenant_id FROM invoices WHERE {w}', a)

    def get(self, token, path_tenant, inv, headers=None):
        c, t = self._auth(token, path_tenant, headers or {})
        if 'data_tenant_check' in self.f:
            w, a = self._where(t)
            return self._run(t, f'SELECT id, tenant_id FROM invoices WHERE id = %s AND {w}', (inv,) + a)
        return self._run(t, 'SELECT id, tenant_id FROM invoices WHERE id = %s', (inv,))

    def report(self, token, path_tenant, headers=None):
        c, t = self._auth(token, path_tenant, headers or {})
        if 'data_tenant_check' in self.f:
            w, a = self._where(t)
            return self._run(t, f'SELECT id, tenant_id FROM invoices WHERE {w}', a, set_ctx=False)
        return self._run(t, 'SELECT id, tenant_id FROM invoices', (), set_ctx=False)


def leaked(rows, own):
    return any(r[1] != own for r in rows)


def cases(t1, t2):
    apis = {}

    def api(f):
        if f not in apis:
            apis[f] = Api(f, t1, t2)
        return apis[f]

    tok = {}

    def T(name):
        if name not in tok:
            spec = {'alice': ('t1', 'saas-web', 'alice'), 'bob': ('t2', 'saas-web', 'bob'), 'rogue': ('t2', 'rogue-web', 'bob'),
                    'light': ('t1', 'saas-light', 'alice'), 'multi': ('t1', 'saas-multi', 'alice')}[name]
            r = infra.token(*spec)
            tok[name], tok[name + '_id'] = r['access_token'], r.get('id_token')
        return tok[name]

    def partner(iss, tenant):
        p = Issuer(iss, 'partner-t2', kid='partner-t2')
        return p.mint({'sub': 'svc-partner', 'aud': 'saas-api', NS: {'tenant_id': tenant}}, now=CLOCK.now())

    def legit_list(user, t):
        return lambda f: (lambda rows: bool(rows) and not leaked(rows, t))(api(f).list(T(user), t))

    def report_after_bob(f):
        api(f).list(T('bob'), 't2')
        return leaked(api(f).report(T('alice'), 't1'), 't1')

    def expired(f):
        CLOCK.offset = 400
        try:
            return api(f).list(T('alice'), 't1')
        finally:
            CLOCK.offset = 0

    return [
        Case('A1', 'legit', 'テナント', 'Part 5 マルチテナント', 't1 の利用者が自分のテナントの請求書を一覧する', legit_list('alice', 't1')),
        Case('A2', 'legit', 'テナント', 'Part 5 マルチテナント', 't2 の利用者が自分のテナントの請求書を一覧する', legit_list('bob', 't2')),
        Case('A3', 'legit', 'BOLA', 'Part 5 BOLA', 't1 の利用者が自分の請求書を ID で読む', lambda f: bool(api(f).get(T('alice'), 't1', 2))),
        Case('A4', 'legit', '集計', 'Part 7 データ層', 't1 の利用者が集計 API で自分のテナントだけを得る',
             lambda f: (lambda rows: bool(rows) and not leaked(rows, 't1'))(api(f).report(T('alice'), 't1'))),
        Case('A5', 'attack', 'テナントの出どころ', 'Part 5 マルチテナント', 't2 のトークンで、パスとヘッダー X-Tenant を t1 にして一覧する',
             lambda f: leaked(api(f).list(T('bob'), 't1', {'X-Tenant': 't1'}), 't2')),
        Case('A6', 'attack', 'BOLA', 'Part 5 BOLA', 't1 の利用者が、t2 の請求書の ID を直接指定する', lambda f: leaked(api(f).get(T('alice'), 't1', 1), 't1')),
        Case('A7', 'attack', '接続プール', 'Part 7 接続プール', '直前の t2 の要求の文脈が残った接続で、条件を書き忘れた集計 API を t1 が呼ぶ', report_after_bob),
        Case('A8', 'attack', 'テナントと発行者', 'Part 5 マルチテナント', 't2 の管理者が自分のレルムのマッパーで tenant_id=t1 を出させ、t1 を読む（実際の Keycloak）',
             lambda f: leaked(api(f).list(T('rogue'), 't1'), 't2')),
        Case('A9', 'attack', 'テナント単位の鍵', 'Part 5（IR 8587 §5.2.1.2）', 't2 の連携先に渡した署名鍵で、iss=t1・tenant=t1 のトークンを作る',
             lambda f: leaked(api(f).list(partner(t1.iss, 't1'), 't1'), 't2')),
        Case('A10', 'attack', 'テナント単位の鍵', 'Part 5 マルチテナント', '同じ鍵で、iss=t2 のまま tenant=t1 を名乗る',
             lambda f: leaked(api(f).list(partner(t2.iss, 't1'), 't1'), 't2')),
        Case('A11', 'attack', '必須クレーム', 'Part 3 Keycloak（軽量アクセストークン）', '軽量アクセストークンで tenant が落ち、ヘッダー X-Tenant: t2 で既定を上書きする',
             lambda f: leaked(api(f).list(T('light'), 't2', {'X-Tenant': 't2'}), 't1')),
        Case('A12', 'attack', '型', 'Part 4 型', 'マッパーの設定誤りで tenant が配列 ["t1","t2"] になったトークンで一覧する',
             lambda f: leaked(api(f).list(T('multi'), 't1'), 't1')),
        Case('A13', 'attack', 'typ・aud', 'Part 1 ID トークンとアクセストークン', 'ログインで得た ID トークンを API に送る',
             lambda f: (T('alice'), bool(api(f).list(tok['alice_id'], 't1')))[1]),
        Case('A14', 'attack', 'exp', 'Part 1 検証の順序', '期限切れのトークン（発行から 400 秒後）で一覧する', lambda f: bool(expired(f))),
    ]


def defer_fine_grained(reps=2000):
    out = {'token_bytes': {}, 'check_us': {}}
    for n in (0, 20, 200, 1000):
        out['token_bytes'][n] = size(STS.mint({'sub': 'alice', 'aud': 'saas-api', NS: {'tenant_id': 't1', 'invoice_ids': list(range(2, 2 + 2 * n, 2))}}))
    ids = set(range(2, 2002, 2))
    lat = []
    for i in range(reps):
        t = time.perf_counter()
        _ = (i * 2) in ids
        lat.append((time.perf_counter() - t) * 1e6)
    out['check_us']['in_token_p50'] = statistics.median(lat)
    lat = []
    with conn('app_norls') as db:
        for i in range(reps):
            t = time.perf_counter()
            db.execute('SELECT 1 FROM grants WHERE subject = %s AND invoice_id = %s', ('alice', 2 + 2 * (i % 20))).fetchone()
            lat.append((time.perf_counter() - t) * 1e6)
    lat.sort()
    out['check_us']['pdp_db_p50'] = statistics.median(lat)
    out['check_us']['pdp_db_p95'] = lat[int(len(lat) * 0.95)]
    out['revoke_stale_s'] = {'in_token_max': 300, 'in_token_mean': 150, 'pdp': 0}
    return out


def run():
    setup_db()
    t1, t2 = RemoteIssuer('t1'), RemoteIssuer('t2')
    sizes = {k: size(infra.token(*v)['access_token']) for k, v in
             {'alice': ('t1', 'saas-web', 'alice'), 'light': ('t1', 'saas-light', 'alice')}.items()}
    return cases(t1, t2), {'keycloak_token_bytes': sizes, 'defer_fine_grained': defer_fine_grained()}

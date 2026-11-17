# -*- coding: utf-8 -*-
"""Scenario A: multi-tenant SaaS (Keycloak realms t1 / t2, Postgres row-level security).

N  : naive verifier, tenant from the X-Tenant header (falls back to the path), session-level SET on a pooled connection
B  : common baseline (iss allow-list t1+t2, aud saas-api, typ at+jwt, tenant claim required as a string); tenant taken from the
     token and compared with the path; queries add WHERE tenant_id by hand, no row-level security
BE : baseline + emphasis "tenant isolation": tenant bound to the issuer realm (per-tenant keys), SET LOCAL per transaction,
     row-level security on every query
"""
import statistics
import time

import psycopg

from . import infra
from .common import Case, RemoteIssuer
from .jwtlib import NS, STS, Baseline, CLOCK, Reject, get_path, naive_verify, size

TENANTS = ('t1', 't2')


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
    """One service instance per configuration; each keeps ONE pooled connection that is reused across requests."""

    def __init__(self, cfg, t1, t2):
        self.cfg, self.realms = cfg, {t1.iss: 't1', t2.iss: 't2'}
        self.keys = {t1.kid: t1.pub_pem, t2.kid: t2.pub_pem}
        self.base = Baseline([t1, t2], 'saas-api', typ=('at+jwt',), required={NS + '|tenant_id': str}, clock=_REAL)
        self.db = conn('app_norls' if cfg == 'B' else 'app_rls')

    def _auth(self, token, path_tenant, headers):
        if self.cfg == 'N':
            c = naive_verify(token, self.keys)
            return c, headers.get('X-Tenant') or path_tenant
        c = self.base.verify(token)
        tenant = get_path(c, NS + '|tenant_id')
        if tenant != path_tenant:
            raise Reject('tenant mismatch with path')
        if self.cfg == 'BE' and self.realms.get(c['iss']) != tenant:  # emphasis: the tenant must match the issuer realm (per-tenant keys)
            raise Reject('tenant claim does not match issuer')
        return c, tenant

    def _query(self, tenant, sql, args=(), set_context=True):
        if self.cfg == 'N':
            if set_context:
                self.db.execute('SELECT set_config(%s, %s, false)', ('app.tenant', tenant))  # session level: survives in the pool
            return [r for r in self.db.execute(sql, args).fetchall()]
        if self.cfg == 'B':
            return [r for r in self.db.execute(sql, args).fetchall()]
        with self.db.transaction():  # BE: the middleware always sets the tenant for this transaction only
            self.db.execute('SELECT set_config(%s, %s, true)', ('app.tenant', tenant))
            return [r for r in self.db.execute(sql, args).fetchall()]

    def list(self, token, path_tenant, headers=None):
        c, t = self._auth(token, path_tenant, headers or {})
        sql = 'SELECT id, tenant_id FROM invoices WHERE tenant_id = %s' if self.cfg == 'B' else 'SELECT id, tenant_id FROM invoices'
        return self._query(t, sql, (t,) if self.cfg == 'B' else ())

    def get(self, token, path_tenant, invoice_id, headers=None):
        c, t = self._auth(token, path_tenant, headers or {})
        sql = 'SELECT id, tenant_id FROM invoices WHERE id = %s'  # the developer forgot the tenant condition (BOLA)
        return self._query(t, sql, (invoice_id,))

    def report(self, token, path_tenant, headers=None):
        """A newer endpoint whose author forgot both the WHERE clause and the context call."""
        c, t = self._auth(token, path_tenant, headers or {})
        return self._query(t, 'SELECT id, tenant_id FROM invoices', (), set_context=False)


class _Real:
    def now(self):
        return int(time.time())


_REAL = _Real()


def leaked(rows, own):
    return any(r[1] != own for r in rows)


def cases(apis, tok):
    def legit_list(user_tenant):
        def f(cfg):
            rows = apis[cfg].list(tok[user_tenant], user_tenant)
            return rows and not leaked(rows, user_tenant)
        return f

    def report_after_other(cfg):
        apis[cfg].list(tok['t2'], 't2')  # bob's request leaves t2 in the pooled session (N)
        return leaked(apis[cfg].report(tok['t1'], 't1'), 't1')

    return [
        Case('A1', 'legit', 'tenant', 'Part 5 マルチテナント', 't1 の利用者が自分のテナントの請求書を一覧する', legit_list('t1')),
        Case('A2', 'legit', 'tenant', 'Part 5 マルチテナント', 't2 の利用者が自分のテナントの請求書を一覧する', legit_list('t2')),
        Case('A3', 'attack', 'tenant の出どころ', 'Part 5 マルチテナント', 't2 のトークンで、パスとヘッダー X-Tenant を t1 にして一覧する',
             lambda cfg: leaked(apis[cfg].list(tok['t2'], 't1', {'X-Tenant': 't1'}), 't2')),
        Case('A4', 'attack', 'BOLA', 'Part 5 BOLA', 't1 の利用者が、t2 の請求書の ID を直接指定する（WHERE にテナントが無い）',
             lambda cfg: leaked(apis[cfg].get(tok['t1'], 't1', 1), 't1')),
        Case('A5', 'attack', '接続プール', 'Part 7 接続プール', '直前の t2 の要求の文脈が残った接続で、条件を書き忘れた集計 API を t1 が呼ぶ', report_after_other),
        Case('A6', 'attack', 'テナント単位の鍵', 'Part 5 マルチテナント', 't2 の管理者が自分のレルムのマッパーで tenant_id=t1 を出させ、t1 を読む',
             lambda cfg: leaked(apis[cfg].list(tok['rogue'], 't1'), 't2') or bool(apis[cfg].list(tok['rogue'], 't1'))),
    ]


# ------------------------------------------------------------------ 見送り: fine-grained permissions in the token vs PDP lookup
def defer_fine_grained(reps=300):
    out = {'token_bytes': {}, 'check_us': {}}
    for n in (0, 20, 200, 1000):
        claims = {'sub': 'alice', 'aud': 'saas-api', NS: {'tenant_id': 't1', 'invoice_ids': list(range(2, 2 + 2 * n, 2))}}
        out['token_bytes'][n] = size(STS.mint(claims))
    ids = set(range(2, 2002, 2))
    t0 = time.perf_counter()
    for i in range(reps):
        _ = (i * 2) in ids
    out['check_us']['in_token'] = (time.perf_counter() - t0) / reps * 1e6
    lat = []
    with conn('app_norls') as db:
        for i in range(reps):
            t = time.perf_counter()
            db.execute('SELECT 1 FROM grants WHERE subject = %s AND invoice_id = %s', ('alice', 2 + 2 * (i % 20))).fetchone()
            lat.append((time.perf_counter() - t) * 1e6)
    lat.sort()
    out['check_us']['pdp_db_p50'] = statistics.median(lat)
    out['check_us']['pdp_db_p95'] = lat[int(len(lat) * 0.95)]
    # stale window after revoking one invoice permission: in-token lasts until exp; the PDP sees the change on the next request
    out['revoke_stale_s'] = {'in_token_max': 300, 'in_token_mean': 150, 'pdp': 0}
    return out


def run():
    setup_db()
    t1, t2 = RemoteIssuer('t1'), RemoteIssuer('t2')
    tok = {'t1': infra.token('t1', 'saas-web', 'alice')['access_token'], 't2': infra.token('t2', 'saas-web', 'bob')['access_token'],
           'rogue': infra.token('t2', 'rogue-web', 'bob')['access_token']}
    apis = {cfg: Api(cfg, t1, t2) for cfg in ('N', 'B', 'BE')}
    sizes = {k: size(v) for k, v in tok.items()}
    return cases(apis, tok), {'keycloak_token_bytes': sizes, 'defer_fine_grained': defer_fine_grained()}


EMPHASIS_CODE = ['Api._auth (tenant bound to issuer)', 'Api._query (SET LOCAL + RLS)', 'setup_db policy']
_ = CLOCK

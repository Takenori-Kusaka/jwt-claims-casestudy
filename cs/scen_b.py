# -*- coding: utf-8 -*-
"""Scenario B: internal business systems behind a gateway (Keycloak realm corp + mock Entra ID / Okta / Cognito).

N  : naive verifier at the services; the gateway copies claims into headers without removing what the client sent; services
     trust headers; a missing groups claim means "no restriction"; each service keys users by sub
B  : common baseline at every service (iss, aud, typ at+jwt, exp, required claims, immutable IDs, fail closed); the gateway
     removes the exact header names it writes
BE : baseline + emphasis "aud narrowing, no ID-token reuse, attribute freshness": the gateway validates each IdP's token in its
     own way and exchanges it for an internal token in the org namespace; services read only that token; sensitive decisions
     look up current attributes / session state (directory, introspection); groups overage resolved by a directory lookup
"""
import statistics
import time

import jwt
from jwcrypto import jwe, jwk

from . import infra
from .common import Case, RemoteIssuer
from .jwtlib import COGNITO, ENTRA, NS, OKTA, STS, Baseline, CLOCK, Reject, cognito_token, entra_token, get_path, naive_verify, okta_token, size

TID = '11111111-aaaa-4bbb-8ccc-000000000001'
DIRECTORY = {'oid-admin-0001': {'admins'}, 'oid-staff-0002': set()}  # what Graph would return for the overage pointer
OKTA_DATA = {'sato@example.com': 'payroll of the FORMER sato (uid 00uA)', '00uA': 'payroll of the FORMER sato', '00uB': 'payroll of the NEW sato'}


class _Real:
    def now(self):
        return int(time.time())


REAL = _Real()


def norm_headers(pairs):
    """The service framework lower-cases names and turns '_' into '-'; for duplicates the FIRST value wins."""
    out = {}
    for k, v in pairs:
        out.setdefault(k.lower().replace('_', '-'), v)
    return out


class Gateway:
    def __init__(self, cfg, corp):
        self.cfg, self.corp = cfg, corp
        self.kc = Baseline([corp], None, typ=('at+jwt',), clock=REAL)
        self.ext = {ENTRA.iss: Baseline([ENTRA], 'api://orders', typ=('JWT',), clock=CLOCK),
                    OKTA.iss: Baseline([OKTA], 'api://default', typ=('application/okta-internal-at+jwt',), clock=CLOCK),
                    COGNITO.iss: Baseline([COGNITO], None, typ=None, clock=CLOCK)}

    def forward(self, token, client_headers, audience):
        """Returns (token for the service, header pairs the service receives)."""
        if self.cfg == 'N':
            c = jwt.decode(token, options={'verify_signature': False})
            roles = ','.join(c.get('realm_access', {}).get('roles', []))
            pairs = list(client_headers) + ([('X-User-Role', roles)] if roles else [])  # appended after whatever the client sent
            return token, pairs
        if self.cfg == 'B':
            c = jwt.decode(token, options={'verify_signature': False})
            roles = ','.join(c.get('realm_access', {}).get('roles', []))
            pairs = [(k, v) for k, v in client_headers if k != 'X-User-Role'] + ([('X-User-Role', roles)] if roles else [])  # exact name only
            return token, pairs
        return self.exchange(token, audience), [(k, v) for k, v in client_headers if not k.lower().replace('_', '-').startswith('x-user-')]

    def exchange(self, token, audience):
        """BE: validate per IdP, normalise into the org namespace, mint a short internal token for one audience."""
        iss = jwt.decode(token, options={'verify_signature': False}).get('iss')
        if iss == self.corp.iss:
            self.kc.audience = None
            c = self.kc.verify(token)
            if audience not in (c['aud'] if isinstance(c['aud'], list) else [c['aud']]):
                raise Reject('external token not issued for this API')
            org = {'tenant_id': 'corp', 'user_id': 'kc:' + c['sub'], 'roles': sorted(c.get('realm_access', {}).get('roles', [])),
                   'department': get_path(c, NS + '|department'), 'sid': c.get('sid')}
        elif iss == ENTRA.iss:
            c = self.ext[iss].verify(token)
            groups = c.get('groups')
            if groups is None and '_claim_names' in c:  # overage: resolve through the directory instead of guessing
                groups = sorted(DIRECTORY.get(c['oid'], set()))
            if groups is None:
                raise Reject('groups unknown')
            org = {'tenant_id': c['tid'], 'user_id': f"entra:{c['tid']}:{c['oid']}", 'roles': sorted(groups)}
        elif iss == OKTA.iss:
            c = self.ext[iss].verify(token)
            org = {'tenant_id': 'corp', 'user_id': 'okta:' + c['uid'], 'roles': sorted(c.get('groups', []))}
        elif iss == COGNITO.iss:
            c = self.ext[iss].verify(token)
            if c.get('token_use') != 'access' or c.get('client_id') != 'client-app':  # Cognito: no aud unless resource; check client_id
                raise Reject('not a Cognito access token for this client')
            org = {'tenant_id': 'corp', 'user_id': 'cognito:' + c['sub'], 'roles': sorted(c.get('cognito:groups', []))}
        else:
            raise Reject('unknown issuer')
        return STS.mint({'sub': org['user_id'], 'aud': audience, NS: {k: v for k, v in org.items() if v is not None}}, lifetime=300)


class Service:
    """orders: read (any employee), admin action (role admins / approver), finance ledger (department finance)."""

    def __init__(self, cfg, name, corp):
        self.cfg, self.name = cfg, name
        self.keys = {corp.kid: corp.pub_pem, ENTRA.kid: ENTRA.pub_pem, OKTA.kid: OKTA.pub_pem, COGNITO.kid: COGNITO.pub_pem}
        self.base = {corp.iss: Baseline([corp], name, typ=('at+jwt',), required={'sub': str}, clock=REAL),
                     ENTRA.iss: Baseline([ENTRA], 'api://orders', typ=('JWT',), required={'oid': str, 'tid': str}, clock=CLOCK),
                     OKTA.iss: Baseline([OKTA], 'api://default', typ=('application/okta-internal-at+jwt',), required={'uid': str}, clock=CLOCK),
                     COGNITO.iss: Baseline([COGNITO], 'api://orders', typ=None, clock=CLOCK)}
        self.internal = Baseline([STS], name, typ=('at+jwt',), required={NS + '|user_id': str, NS + '|roles': list}, clock=CLOCK)

    def claims(self, token):
        if self.cfg == 'N':
            return naive_verify(token, self.keys)
        if self.cfg == 'B':
            iss = jwt.decode(token, options={'verify_signature': False}).get('iss')
            if iss not in self.base:
                raise Reject('unknown issuer')
            return self.base[iss].verify(token)
        return self.internal.verify(token)

    def user_key(self, c):
        if self.cfg == 'N':
            return c.get('sub')
        if self.cfg == 'B':
            return c.get('uid') or (f"{c.get('tid')}:{c.get('oid')}" if c.get('oid') else c.get('sub'))
        return get_path(c, NS + '|user_id')

    def roles(self, c, headers):
        if self.cfg in ('N', 'B') and 'x-user-role' in headers:
            return set(filter(None, headers['x-user-role'].split(',')))
        if self.cfg == 'BE':
            return set(get_path(c, NS + '|roles') or [])
        if 'groups' in c:
            return set(c['groups'])
        if '_claim_names' in c:
            if self.cfg == 'N':
                return {'*'}  # missing groups read as "no restriction"
            raise Reject('groups missing (overage) – fail closed')
        return set(c.get('realm_access', {}).get('roles', []))

    def read(self, token, headers=()):
        return self.user_key(self.claims(token))

    def admin(self, token, headers=()):
        c = self.claims(token)
        r = self.roles(c, norm_headers(headers))
        if not (r & {'admins', 'admin', '*'}):
            raise Reject('not admin')
        return True

    def ledger(self, token, headers=(), check_fresh=None):
        c = self.claims(token)
        dept = get_path(c, NS + '|department')
        if self.cfg == 'BE' and check_fresh:
            dept, active = check_fresh(c)
            if not active:
                raise Reject('session revoked')
        if dept != 'finance':
            raise Reject('not finance')
        return True


def cases(corp):
    gw = {cfg: Gateway(cfg, corp) for cfg in ('N', 'B', 'BE')}
    svc = {cfg: Service(cfg, 'orders', corp) for cfg in ('N', 'B', 'BE')}

    def kc(user, scope='openid aud-orders'):
        return infra.token('corp', 'portal', user, scope)

    def through(cfg, token, call, headers=(), aud='orders', **kw):
        t, pairs = gw[cfg].forward(token, list(headers), aud)
        return getattr(svc[cfg], call)(t, pairs, **kw)

    def fresh(c):  # BE: sensitive decision looks up the current attribute and the session state
        uid = get_path(c, NS + '|user_id').split(':', 1)[1]
        u = infra.admin('GET', f'corp/users/{uid}')
        sessions = infra.admin('GET', f'corp/users/{uid}/sessions')
        return (u.get('attributes', {}).get('department') or [None])[0], any(s['id'] == get_path(c, NS + '|sid') for s in sessions)

    dave = kc('dave')['access_token']
    infra.set_attr('corp', 'dave', 'department', 'sales')  # dave moved from finance to sales after his token was issued
    erin_tokens = {}

    def revoked(cfg):
        if 'tok' not in erin_tokens:
            infra.set_attr('corp', 'carol', 'department', 'finance')
            erin_tokens['tok'] = kc('carol')['access_token']
            infra.logout_user('corp', 'carol')  # the session is revoked; the JWT stays valid until exp
        return through(cfg, erin_tokens['tok'], 'ledger', check_fresh=fresh)

    over_admin = entra_token('oid-admin-0001', TID, groups=[f'g{i}' for i in range(250)])
    over_staff = entra_token('oid-staff-0002', TID, groups=[f'g{i}' for i in range(250)])
    okta_new = okta_token('00uB', 'sato@example.com', groups=['staff'])

    def okta_reuse(cfg):  # the new sato must not see the former sato's data
        key = through(cfg, okta_new, 'read')
        return OKTA_DATA.get(key, '').startswith('payroll of the FORMER')

    return [
        Case('B1', 'legit', 'aud', 'Part 1 検証の順序', '社員が orders 宛てのアクセストークンで注文を読む', lambda cfg: through(cfg, kc('carol')['access_token'], 'read')),
        Case('B2', 'attack', 'typ・aud', 'Part 1 ID トークンとアクセストークン', 'ログインで得た ID トークンを API に送る', lambda cfg: through(cfg, kc('carol')['id_token'], 'read')),
        Case('B3', 'attack', 'aud', 'Part 6 下流ほど絞る', 'invoices 宛てのトークンを orders に送る（宛先の差し替え）',
             lambda cfg: through(cfg, kc('carol', 'openid aud-invoices')['access_token'], 'read')),
        Case('B4', 'attack', 'ヘッダーへの転記', 'Part 6 ヘッダーへの転記', 'クライアントが X-User-Role: admin を付けて送る',
             lambda cfg: through(cfg, kc('carol')['access_token'], 'admin', [('X-User-Role', 'admin')])),
        Case('B5', 'attack', 'ヘッダーへの転記', 'Part 6 ヘッダーへの転記', 'アンダースコア版 X_User_Role: admin を送る（CVE-2025-64484 と同じ型）',
             lambda cfg: through(cfg, kc('carol')['access_token'], 'admin', [('X_User_Role', 'admin')])),
        Case('B6', 'attack', 'groups の超過', 'Part 3 Entra ID', '250 グループに属し groups が消えた一般社員が、管理操作を呼ぶ',
             lambda cfg: through(cfg, over_staff, 'admin')),
        Case('B7', 'legit', 'groups の超過', 'Part 3 Entra ID', '250 グループに属し groups が消えた管理者が、管理操作を呼ぶ',
             lambda cfg: through(cfg, over_admin, 'admin')),
        Case('B8', 'attack', '属性の鮮度', 'Part 8 寿命の間のクレーム', 'finance から sales に異動した直後に、古いトークンで経理台帳を読む',
             lambda cfg: through(cfg, dave, 'ledger', check_fresh=fresh)),
        Case('B9', 'attack', '失効', 'Part 8 失効の伝播', 'ログアウト（セッション失効）後に、残ったトークンで経理台帳を読む', revoked),
        Case('B10', 'attack', '不変の ID', 'Part 3 Okta', 'Okta の AT の sub（ログイン名）を再利用した新しい社員が、前任者のデータを読む', okta_reuse),
        Case('B12', 'attack', '送信者制約', 'Part 9 JWE と SD-JWT／Part 6', '漏れたトークンを別の端末からそのまま再送する（DPoP・mTLS を見送った場合）',
             lambda cfg: through(cfg, kc('dave')['access_token'], 'read')),
        Case('B11', 'legit', '正規化', 'Part 3 Cognito', 'Cognito のアクセストークン（aud なし、client_id あり）で注文を読む',
             lambda cfg: through(cfg, cognito_token('cog-sub-1'), 'read')),
    ]


# ------------------------------------------------------------------ 見送り: JWE and DPoP overhead
def defer_crypto(reps=300):
    inner = STS.mint({'sub': 'u-7f3a', 'aud': 'orders', NS: {'tenant_id': 'corp', 'user_id': 'kc:u-7f3a', 'roles': ['approver']}})
    enc_key = jwk.JWK.generate(kty='RSA', size=2048)
    t_enc, t_dec = [], []
    for _ in range(reps):
        t = time.perf_counter()
        e = jwe.JWE(inner.encode(), protected={'alg': 'RSA-OAEP-256', 'enc': 'A256GCM', 'cty': 'JWT'})
        e.add_recipient(enc_key)
        s = e.serialize(compact=True)
        t_enc.append(time.perf_counter() - t)
        t = time.perf_counter()
        d = jwe.JWE()
        d.deserialize(s, key=enc_key)
        t_dec.append(time.perf_counter() - t)
    ec = jwk.JWK.generate(kty='EC', crv='P-256')
    pem = ec.export_to_pem(private_key=True, password=None)
    pub = ec.export_public(as_dict=True)
    t_proof, t_vproof, proof = [], [], ''
    for i in range(reps):
        t = time.perf_counter()
        proof = jwt.encode({'htm': 'GET', 'htu': 'https://orders.internal.example.com/x', 'iat': CLOCK.now(), 'jti': f'p{i}', 'ath': 'x' * 43},
                           pem, algorithm='ES256', headers={'typ': 'dpop+jwt', 'jwk': pub})
        t_proof.append(time.perf_counter() - t)
        t = time.perf_counter()
        jwt.decode(proof, jwt.algorithms.ECAlgorithm.from_jwk(jwk.JWK(**pub).export()), algorithms=['ES256'], options={'verify_iat': False})
        t_vproof.append(time.perf_counter() - t)
    base_v = []
    b = Baseline([STS], 'orders', clock=CLOCK)
    for _ in range(reps):
        t = time.perf_counter()
        b.verify(inner)
        base_v.append(time.perf_counter() - t)
    med = lambda xs: statistics.median(xs) * 1e6  # noqa: E731
    return {'bytes': {'jws': size(inner), 'jwe_nested': len(s), 'dpop_proof': len(proof)},
            'us_p50': {'verify_jws': med(base_v), 'jwe_encrypt': med(t_enc), 'jwe_decrypt': med(t_dec), 'dpop_create': med(t_proof), 'dpop_verify': med(t_vproof)}}


def freshness_cost(reps=30):
    """Latency of the two freshness checks used by BE for sensitive decisions."""
    tok = infra.token('corp', 'portal', 'dave', 'openid aud-orders')['access_token']
    uid = jwt.decode(tok, options={'verify_signature': False})['sub']
    a, b = [], []
    for _ in range(reps):
        t = time.perf_counter()
        infra.introspect('corp', 'portal', tok)
        a.append((time.perf_counter() - t) * 1000)
        t = time.perf_counter()
        infra.admin('GET', f'corp/users/{uid}')
        b.append((time.perf_counter() - t) * 1000)
    return {'introspection_ms_p50': statistics.median(a), 'directory_lookup_ms_p50': statistics.median(b),
            'stale_window_s': {'self_contained_lifetime_300': {'max': 300, 'mean': 150}, 'self_contained_lifetime_3600': {'max': 3600, 'mean': 1800},
                               'lookup_or_introspection': 0}}


def run():
    corp = RemoteIssuer('corp')
    infra.set_attr('corp', 'dave', 'department', 'finance')
    infra.set_attr('corp', 'carol', 'department', 'sales')
    cs_ = cases(corp)
    return cs_, {'defer_crypto': defer_crypto(), 'freshness': freshness_cost(),
                 'token_bytes': {'keycloak_at': size(infra.token('corp', 'portal', 'carol', 'openid aud-orders')['access_token']),
                                 'internal_at': size(Gateway('BE', corp).exchange(infra.token('corp', 'portal', 'carol', 'openid aud-orders')['access_token'], 'orders')),
                                 'entra_overage': size(entra_token('oid-admin-0001', TID, groups=[f'g{i}' for i in range(250)])),
                                 'entra_150_groups': size(entra_token('oid-x', TID, groups=[f'{i:08d}-0000-0000-0000-000000000000' for i in range(150)]))}}

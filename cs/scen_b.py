# -*- coding: utf-8 -*-
"""Scenario B: internal business systems behind a gateway. Keycloak realm corp (real) and mock Entra ID / Okta / Cognito / Auth0.

Operations: read (any employee), admin (role admins), ledger (department finance, critical), docs (department sales or finance),
edit (role editor), payslip (by employee_id).
The service framework lower-cases header names, turns '_' into '-' and JOINS duplicate values with ',' (CVE-2026-26308 type).
"""
import statistics
import time

import jwt
from jwcrypto import jwe, jwk

from . import infra
from .common import Case, RealClock, RemoteIssuer
from .jwtlib import AUTH0, CLOCK as VCLOCK, COGNITO, ENTRA, NS, OKTA, STS, Reject, cognito_token, entra_token, get_path, okta_token, size
from .verify import Verifier

RCLOCK = RealClock()
TID = '11111111-aaaa-4bbb-8ccc-000000000001'
OTHER_TID = '99999999-ffff-4fff-8fff-000000000009'
ENTRA_ISS = f'https://login.microsoftonline.com/{TID}/v2.0'
DIRECTORY = {f'{TID}:oid-admin-0001': ['admins'], f'{TID}:oid-staff-0002': ['staff']}
PAYSLIPS = {'9007199254740993': 'payslip of the requester', '9007199254740992': "ANOTHER employee's payslip"}
OKTA_DATA = {'sato@example.com': 'FORMER sato', 'okta:00uA': 'FORMER sato', 'okta:00uB': 'new sato'}


def headers_seen(pairs):
    out = {}
    for k, v in pairs:
        n = k.lower().replace('_', '-')
        out[n] = out[n] + ',' + v if n in out else v
    return out


def idp_of(iss):
    if '/realms/corp' in (iss or ''):
        return 'kc'
    if (iss or '').startswith('https://login.microsoftonline.com/'):
        return 'entra'
    return {OKTA.iss: 'okta', COGNITO.iss: 'cognito', AUTH0.iss: 'auth0', STS.iss: 'internal'}.get(iss, 'unknown')


class Env:
    def __init__(self, corp):
        self.corp = corp

    def verifier(self, f, idp, audience):
        ns_roles = NS + '|roles'
        cfg = {
            'kc': ({self.corp.iss: [self.corp]}, ('at+jwt',), {'sub': str}),
            'entra': ({ENTRA_ISS: [ENTRA]}, ('JWT',), {'oid': str, 'tid': str}),
            'okta': ({OKTA.iss: [OKTA]}, ('application/okta-internal-at+jwt',), {'uid': str}),
            'cognito': ({COGNITO.iss: [COGNITO]}, lambda h, p: p.get('token_use') == 'access', {'sub': str}),
            'auth0': ({AUTH0.iss: [AUTH0]}, ('at+jwt',), {'sub': str}),
            'internal': ({STS.iss: [STS]}, ('at+jwt',), {NS + '|user_id': str, ns_roles: list, NS + '|tenant_id': str}),
        }[idp]
        reg, typ, req = cfg
        if idp == 'entra' and 'iss' not in f:  # multi-tenant {tenantid} placeholder accepted for any tenant
            reg = dict(reg)
            reg[f'https://login.microsoftonline.com/{OTHER_TID}/v2.0'] = [ENTRA]
        clock = RCLOCK if idp == 'kc' else VCLOCK
        return Verifier(f, reg, audience=audience, typ=typ, required=req, clock=clock)

    def ext_audience(self, idp, service):
        return {'kc': service, 'entra': 'api://orders', 'okta': 'api://default', 'cognito': 'api://orders', 'auth0': 'https://api.example.com'}[idp]

    def normalize(self, f, idp, c):
        """IdP claims → organisation attributes. Missing values: reject if 'required', otherwise the legacy defaults."""
        ns = (lambda k: get_path(c, NS + '|' + k)) if 'namespace' in f else (lambda k: c.get(k))
        imm = 'immutable_id' in f
        o = {'tenant': 'corp', 'sid': None, 'kc_sub': None}
        if idp == 'kc':
            o.update(user=('kc:' + c['sub']) if imm else c.get('preferred_username'), roles=c.get('realm_access', {}).get('roles'),
                     department=get_path(c, NS + '|department'), sid=c.get('sid'), kc_sub=c.get('sub'))
        elif idp == 'entra':
            roles = c.get('groups')
            if roles is None and '_claim_names' in c and 'overage_resolve' in f:
                roles = DIRECTORY.get(f"{c['tid']}:{c['oid']}", [])
            o.update(user=f"entra:{c['tid']}:{c['oid']}" if imm else c.get('upn'), roles=roles, tenant=c.get('tid'), department='sales')
        elif idp == 'okta':
            o.update(user=('okta:' + c['uid']) if imm else c.get('sub'), roles=c.get('groups'), department=get_path(c, NS + '|department'))
        elif idp == 'cognito':
            roles = c.get('cognito:groups') if 'namespace' in f else ([c['custom:role']] if c.get('custom:role') else c.get('cognito:groups'))
            o.update(user=('cognito:' + c['sub']) if imm else c.get('username'), roles=roles, department='sales')
        elif idp == 'auth0':
            emp = get_path(c, NS + '|employee_id')
            o.update(user=c['sub'], roles=ns('roles'), department='sales', employee_id=emp)
        defaults = {'roles': {'entra': ['*'], 'cognito': ['*'], 'auth0': ['editor']}.get(idp, []), 'department': 'sales'}
        for k in ('roles', 'department'):
            if o.get(k) is None:
                if 'required' in f:
                    raise Reject(f'{k} missing')
                o[k] = defaults[k]
        if 'employee_id' in o and o['employee_id'] is not None and not isinstance(o['employee_id'], str):
            if 'types' in f:
                raise Reject('employee_id must be a string')
            o['employee_id'] = str(int(float(o['employee_id'])))  # what a JavaScript consumer does with a JSON number
        return o


class Gateway:
    def __init__(self, f, env):
        self.f, self.env = f, env

    def forward(self, token, client_headers, service):
        f = self.f
        pairs = list(client_headers)
        if 'header_strip' in f:
            pairs = [(k, v) for k, v in pairs if not k.lower().replace('_', '-').startswith('x-user-')]
        c = jwt.decode(token, options={'verify_signature': False})
        idp = idp_of(c.get('iss'))
        if 'normalize_gw' in f:
            v = self.env.verifier(f, idp, None if idp == 'cognito' else self.env.ext_audience(idp, service))
            ext = v.verify(token)
            if idp == 'cognito' and ext.get('client_id') != 'client-app':  # Cognito access tokens carry no aud: check client_id instead
                raise Reject('Cognito token for another client')
            o = self.env.normalize(f, idp, ext)
            token = STS.mint({'sub': o['user'] or 'unknown', 'aud': service, NS: {'tenant_id': o['tenant'], 'user_id': o['user'] or 'unknown', 'roles': list(o['roles']),
                                                                               'department': o['department'], 'sid': o['sid'], 'kc_sub': o['kc_sub'],
                                                                               **({'employee_id': o['employee_id']} if o.get('employee_id') else {})}})
            roles = o['roles']
        else:  # the gateway was built for Keycloak: it copies realm roles into a header for the services' convenience
            roles = c.get('realm_access', {}).get('roles') or []
        if roles:
            pairs.append(('X-User-Role', ','.join(roles)))
        return token, pairs


class Service:
    def __init__(self, f, env, name='orders'):
        self.f, self.env, self.name = f, env, name

    def org(self, token, pairs):
        f = self.f
        if 'normalize_gw' in f:
            c = self.env.verifier(f, 'internal', self.name).verify(token)
            if idp_of(c.get('iss')) != 'internal':
                raise Reject('services accept only internal tokens')
            o = {k: get_path(c, NS + '|' + k) for k in ('roles', 'department', 'sid', 'kc_sub', 'employee_id')}
            o.update(user=get_path(c, NS + '|user_id'), roles=set(o['roles'] or []))
            return o
        c = jwt.decode(token, options={'verify_signature': False})
        idp = idp_of(c.get('iss'))
        if idp == 'unknown' and 'iss' in f:
            raise Reject('unknown issuer')
        v = self.env.verifier(f, idp if idp != 'unknown' else 'kc', self.env.ext_audience(idp if idp != 'unknown' else 'kc', self.name))
        o = self.env.normalize(f, idp, v.verify(token))
        h = headers_seen(pairs)
        o['roles'] = set(filter(None, h['x-user-role'].split(','))) if 'x-user-role' in h else set(o['roles'])
        return o

    def fresh(self, o):
        """Critical operations: look up the current department and whether the session still exists (Keycloak users)."""
        if 'freshness' not in self.f or not o.get('kc_sub'):
            return o
        u = infra.admin('GET', f"corp/users/{o['kc_sub']}")
        sessions = infra.admin('GET', f"corp/users/{o['kc_sub']}/sessions")
        if not any(s['id'] == o.get('sid') for s in sessions):
            raise Reject('session revoked')
        o['department'] = (u.get('attributes', {}).get('department') or [None])[0]
        return o

    def call(self, op, token, pairs):
        o = self.org(token, pairs)
        if op == 'read':
            return o['user']
        if op == 'admin':
            o = self.fresh(o)
            if not (o['roles'] & {'admins', '*'}):
                raise Reject('not admin')
            return True
        if op == 'ledger':
            o = self.fresh(o)
            if o['department'] != 'finance':
                raise Reject('not finance')
            return True
        if op == 'docs':
            if o['department'] not in ('sales', 'finance'):
                raise Reject('department not allowed')
            return True
        if op == 'edit':
            if not (o['roles'] & {'editor', '*'}):
                raise Reject('not editor')
            return True
        if op == 'payslip':
            return PAYSLIPS.get(str(o.get('employee_id')))
        raise ValueError(op)


def cases(corp):
    env = Env(corp)

    def call(f, token, op, headers=(), via='gw'):
        f = set(f)
        if via == 'gw':
            token, pairs = Gateway(f, env).forward(token, headers, 'orders')
        else:
            pairs = list(headers)
        return Service(f, env).call(op, token, pairs)

    def kc(user, scope='openid aud-orders'):
        return infra.token('corp', 'portal', user, scope)

    def stale(f):
        infra.set_attr('corp', 'dave', 'department', 'finance')
        tok = kc('dave')['access_token']
        infra.set_attr('corp', 'dave', 'department', 'sales')  # dave moved to sales after his token was issued
        try:
            return call(f, tok, 'ledger')
        finally:
            infra.set_attr('corp', 'dave', 'department', 'finance')

    def revoked(f):
        infra.set_attr('corp', 'carol', 'department', 'finance')
        tok = kc('carol')['access_token']
        infra.logout_user('corp', 'carol')
        try:
            return call(f, tok, 'ledger')
        finally:
            infra.set_attr('corp', 'carol', 'department', 'sales')

    over = lambda oid: entra_token(oid, TID, groups=[f'g{i}' for i in range(250)], iss=ENTRA_ISS)  # noqa: E731
    auth0 = lambda ns, **c: AUTH0.mint(dict({'sub': 'auth0|u-55', 'aud': ['https://api.example.com'], 'azp': 'client-app', 'scope': 'openid'}, **c),  # noqa: E731
                                       typ='at+jwt')

    def auth0_viewer(f):  # the Action writes roles under the org namespace (kept) or as a bare 'roles' (Auth0 drops it silently)
        return auth0(True, **{NS: {'roles': ['viewer'], 'employee_id': '1001'}}) if 'namespace' in f else auth0(False, **{NS: {'employee_id': '1001'}})

    def okta_reuse(f):
        key = call(f, okta_token('00uB', 'sato@example.com', groups=['staff'], **{NS: {'department': 'sales'}}), 'read')
        return OKTA_DATA.get(key) == 'FORMER sato'

    def okta_hook_timeout(f):  # the inline hook timed out after 3 s: the token is issued without the department claim
        return call(f, okta_token('00uC', 'tanaka@example.com', groups=['contractors']), 'docs')

    def cognito_writable(f):  # the user set custom:role=admin through UpdateUserAttributes
        return call(f, cognito_token('cog-sub-2', groups=['staff'], **{'custom:role': 'admins'}), 'admin')

    def cognito_suppressed(f):  # the pre-token-generation trigger suppressed cognito:groups to keep the token small
        tok = cognito_token('cog-sub-3')
        c = jwt.decode(tok, options={'verify_signature': False})
        c.pop('cognito:groups')
        return call(f, COGNITO.mint({k: v for k, v in c.items() if k not in ('iss', 'iat', 'exp')}, typ=None), 'admin')

    def big_id(f):
        tok = AUTH0.mint({'sub': 'auth0|u-55', 'aud': ['https://api.example.com'], 'scope': 'openid',
                          NS: {'roles': ['viewer'], 'employee_id': 9007199254740993}}, typ='at+jwt')
        return call(f, tok, 'payslip') == "ANOTHER employee's payslip"

    return [
        Case('B1', 'legit', 'aud', 'Part 1 検証の順序', '社員が orders 宛ての Keycloak のアクセストークンで注文を読む', lambda f: call(f, kc('carol')['access_token'], 'read')),
        Case('B2', 'attack', 'typ・aud', 'Part 1 ID トークンとアクセストークン', 'ログインで得た ID トークンを API に送る', lambda f: call(f, kc('carol')['id_token'], 'read')),
        Case('B3', 'attack', 'aud', 'Part 6 下流ほど絞る', 'invoices 宛てのトークンを orders に送る（宛先の差し替え）',
             lambda f: call(f, kc('carol', 'openid aud-invoices')['access_token'], 'read')),
        Case('B4', 'attack', 'ヘッダーへの転記', 'Part 6 ヘッダーへの転記', 'クライアントが X-User-Role: admins を付けて送る',
             lambda f: call(f, kc('carol')['access_token'], 'admin', [('X-User-Role', 'admins')])),
        Case('B5', 'attack', 'ヘッダーへの転記', 'Part 6 ヘッダーへの転記', 'アンダースコア版 X_User_Role: admins（CVE-2025-64484 の型）',
             lambda f: call(f, kc('carol')['access_token'], 'admin', [('X_User_Role', 'admins')])),
        Case('B6', 'attack', 'ヘッダーの重複', 'Part 6 ヘッダーへの転記', '小文字の x-user-role を足して重複させ、値を連結させる（CVE-2026-26308 の型）',
             lambda f: call(f, kc('carol')['access_token'], 'admin', [('x-user-role', 'admins')])),
        Case('B7', 'attack', '入口の迂回', 'Part 6 検証の分担', '入口を通らずサービスに直接、正しいトークンと偽のヘッダーを送る',
             lambda f: call(f, kc('carol')['access_token'], 'admin', [('X-User-Role', 'admins')], via='direct')),
        Case('B8', 'attack', 'groups の超過', 'Part 3 Entra ID', '250 グループで groups が消えた一般社員が、管理操作を呼ぶ', lambda f: call(f, over('oid-staff-0002'), 'admin')),
        Case('B9', 'legit', 'groups の超過', 'Part 3 Entra ID', '250 グループで groups が消えた管理者が、管理操作を呼ぶ', lambda f: call(f, over('oid-admin-0001'), 'admin')),
        Case('B10', 'attack', 'マルチテナントの iss', 'Part 3 Entra ID', '別の顧客テナントで発行された Entra のトークン（{tenantid} を何でも受ける実装）',
             lambda f: call(f, entra_token('oid-x', OTHER_TID, groups=['admins'], iss=f'https://login.microsoftonline.com/{OTHER_TID}/v2.0'), 'admin')),
        Case('B11', 'attack', '属性の鮮度', 'Part 8 寿命の間のクレーム', 'finance から sales に異動した直後に、古いトークンで経理台帳を読む', stale),
        Case('B12', 'attack', '失効', 'Part 8 失効の伝播', 'ログアウト（セッション失効）後に、残ったトークンで経理台帳を読む', revoked),
        Case('B13', 'attack', '不変の ID', 'Part 3 Okta', 'Okta の AT の sub（ログイン名）を再利用した新しい社員が、前任者のデータを読む', okta_reuse),
        Case('B14', 'legit', '不変の ID', 'Part 3 Okta', 'Okta の利用者が自分のデータを読む（uid で照合）',
             lambda f: call(f, okta_token('00uB', 'sato@example.com', groups=['staff'], **{NS: {'department': 'sales'}}), 'read') is not None),
        Case('B15', 'attack', '必須クレーム', 'Part 6 発行時フック', 'Okta のインラインフックが 3 秒で打ち切られ、部署のクレームなしで出たトークンで社内文書を読む（契約社員）',
             okta_hook_timeout),
        Case('B16', 'legit', '正規化', 'Part 3 Cognito', 'Cognito のアクセストークン（aud なし、client_id あり）で注文を読む', lambda f: call(f, cognito_token('cog-sub-1'), 'read')),
        Case('B17', 'attack', '種類（token_use）', 'Part 3 Cognito', 'Cognito の ID トークン（token_use=id）を API に送る',
             lambda f: call(f, cognito_token('cog-sub-1', token_use='id', aud='client-app'), 'read')),
        Case('B18', 'attack', '書き手', 'Part 4 書き手で分ける', '利用者本人が書き換えられる custom:role=admins で管理操作を呼ぶ（Cognito）', cognito_writable),
        Case('B19', 'attack', '必須クレーム', 'Part 3 Cognito', '発行前フックが cognito:groups を外したトークンで管理操作を呼ぶ', cognito_suppressed),
        Case('B20', 'attack', '名前空間', 'Part 3 Auth0', '予約名 roles として足したクレームを Auth0 が黙って外し、既定の editor で編集する',
             lambda f: call(f, auth0_viewer(f), 'edit')),
        Case('B21', 'legit', '名前空間', 'Part 3 Auth0', 'Auth0 の閲覧者が注文を読む', lambda f: call(f, auth0_viewer(f), 'read')),
        Case('B22', 'attack', '型（大きな数値）', 'Part 4 型', '2^53 を超える数値の社員番号を JavaScript 流に読み、別の社員の給与明細を得る', big_id),
        Case('B23', 'attack', '送信者制約', 'Part 9・6（見送りの代償）', '漏れたトークンを別の端末からそのまま再送する（DPoP・mTLS を見送った場合）',
             lambda f: call(f, kc('dave')['access_token'], 'read')),
    ]


def defer_crypto(reps=2000):
    inner = STS.mint({'sub': 'u-7f3a', 'aud': 'orders', NS: {'tenant_id': 'corp', 'user_id': 'kc:u-7f3a', 'roles': ['approver']}})
    enc_key = jwk.JWK.generate(kty='RSA', size=2048)
    t_enc, t_dec = [], []
    s = ''
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
    pubkey = jwt.algorithms.ECAlgorithm.from_jwk(jwk.JWK(**pub).export())
    t_proof, t_vproof, proof = [], [], ''
    for i in range(reps):
        t = time.perf_counter()
        proof = jwt.encode({'htm': 'GET', 'htu': 'https://orders.internal.example.com/x', 'iat': VCLOCK.now(), 'jti': f'p{i}', 'ath': 'x' * 43},
                           pem, algorithm='ES256', headers={'typ': 'dpop+jwt', 'jwk': pub})
        t_proof.append(time.perf_counter() - t)
        t = time.perf_counter()
        jwt.decode(proof, pubkey, algorithms=['ES256'], options={'verify_iat': False})
        t_vproof.append(time.perf_counter() - t)
    base = []
    v = Verifier({'alg', 'iss', 'aud', 'exp', 'typ'}, {STS.iss: [STS]}, audience='orders', clock=VCLOCK)
    for _ in range(reps):
        t = time.perf_counter()
        v.verify(inner)
        base.append(time.perf_counter() - t)
    q = lambda xs, p: sorted(xs)[int(len(xs) * p)] * 1e6  # noqa: E731
    return {'reps': reps, 'bytes': {'jws': size(inner), 'jwe_nested': len(s), 'dpop_proof': len(proof)},
            'us': {k: {'p50': q(v_, 0.5), 'p95': q(v_, 0.95)} for k, v_ in
                   {'verify_jws': base, 'jwe_encrypt': t_enc, 'jwe_decrypt': t_dec, 'dpop_create': t_proof, 'dpop_verify': t_vproof}.items()}}


def freshness_cost(reps=200):
    tok = infra.token('corp', 'portal', 'dave', 'openid aud-orders')['access_token']
    uid = jwt.decode(tok, options={'verify_signature': False})['sub']
    a, b = [], []
    for _ in range(reps):
        t = time.perf_counter()
        infra.introspect('corp', 'orders', tok)
        a.append((time.perf_counter() - t) * 1000)
        t = time.perf_counter()
        infra.admin('GET', f'corp/users/{uid}')
        b.append((time.perf_counter() - t) * 1000)
    q = lambda xs, p: sorted(xs)[int(len(xs) * p)]  # noqa: E731
    return {'reps': reps, 'introspection_ms': {'p50': q(a, 0.5), 'p95': q(a, 0.95)}, 'directory_lookup_ms': {'p50': q(b, 0.5), 'p95': q(b, 0.95)},
            'note': 'directory lookup includes fetching an admin token per call'}


def run():
    corp = RemoteIssuer('corp')
    infra.set_attr('corp', 'dave', 'department', 'finance')
    infra.set_attr('corp', 'carol', 'department', 'sales')
    env = Env(corp)
    kc_at = infra.token('corp', 'portal', 'carol', 'openid aud-orders')['access_token']
    internal = Gateway({'alg', 'iss', 'aud', 'exp', 'typ', 'required', 'types', 'immutable_id', 'namespace', 'normalize_gw'}, env).forward(kc_at, [], 'orders')[0]
    sizes = {'keycloak_at': size(kc_at), 'internal_at': size(internal),
             'entra_150_groups': size(entra_token('oid-x', TID, groups=[f'{i:08d}-0000-0000-0000-000000000000' for i in range(150)], iss=ENTRA_ISS)),
             'entra_overage': size(entra_token('oid-admin-0001', TID, groups=[f'g{i}' for i in range(250)], iss=ENTRA_ISS))}
    return cases(corp), {'defer_crypto': defer_crypto(), 'freshness': freshness_cost(), 'token_bytes': sizes}


__all__ = ['run', 'statistics']

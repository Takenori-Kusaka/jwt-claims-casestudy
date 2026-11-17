# -*- coding: utf-8 -*-
"""Issuers (mock IdPs and internal STS), a deliberately naive verifier and the baseline verifier.

All times come from an injectable clock so that every stale-window measurement is reproducible.
The naive verifier reproduces mistakes that real libraries and applications have made (alg taken from the header,
kid used as a file path, jku/jwk trusted, no aud/exp/typ checks). It is written by hand on purpose: current libraries
refuse several of these (e.g. PyJWT will not use a PEM key as an HMAC secret).
"""
import base64
import hashlib
import hmac
import json
import os

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEYDIR = os.path.join(ROOT, 'keys')
NS = 'https://claims.example.com/'


class Clock:
    def __init__(self, t=1_800_000_000):
        self.t = t

    def now(self):
        return self.t

    def advance(self, s):
        self.t += s


CLOCK = Clock()


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


def ub64(s):
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


def rsa_key(name):
    """Test-only keys, generated once and kept under keys/ so that re-runs use the same keys."""
    os.makedirs(KEYDIR, exist_ok=True)
    p = os.path.join(KEYDIR, name + '.pem')
    if not os.path.exists(p):
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        open(p, 'wb').write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return serialization.load_pem_private_key(open(p, 'rb').read(), password=None)


class Issuer:
    def __init__(self, iss, name, kid=None):
        self.iss, self.name = iss, name
        self.key = rsa_key(name)
        self.kid = kid or name + '-1'
        self.pub_pem = self.key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    def jwks(self):
        j = json.loads(RSAAlgorithm.to_jwk(self.key.public_key()))
        j.update(kid=self.kid, use='sig', alg='RS256')
        return {'keys': [j]}

    def mint(self, claims, typ='at+jwt', lifetime=300, extra_headers=None, now=None):
        now = CLOCK.now() if now is None else now
        body = {'iss': self.iss, 'iat': now, 'exp': now + (lifetime or 0)}
        body.update(claims)
        if lifetime is None:
            body.pop('exp')
        h = {'kid': self.kid}
        if typ:
            h['typ'] = typ
        h.update(extra_headers or {})
        h['alg'] = 'RS256'
        # signed by hand so that unusual claim types (numeric sub, huge integers) are kept exactly as given
        hs = b64(json.dumps(h, separators=(',', ':')).encode())
        ps = b64(json.dumps(body, separators=(',', ':'), ensure_ascii=False).encode())
        sig = jwt.algorithms.RSAAlgorithm(jwt.algorithms.RSAAlgorithm.SHA256).sign(f'{hs}.{ps}'.encode(), self.key)
        return f'{hs}.{ps}.{b64(sig)}'


# ------------------------------------------------------------------ mock IdPs in their documented shapes (notes 02)
ENTRA = Issuer('https://login.microsoftonline.com/11111111-aaaa-4bbb-8ccc-000000000001/v2.0', 'entra')
AUTH0 = Issuer('https://example-tenant.auth0.com/', 'auth0')
OKTA = Issuer('https://example.okta.com/oauth2/default', 'okta')
COGNITO = Issuer('https://cognito-idp.ap-northeast-1.amazonaws.com/ap-northeast-1_EXAMPLE', 'cognito')
STS = Issuer('https://sts.internal.example.com', 'sts')  # internal token service (edge exchange, agent delegation)
STS_OLD = Issuer('https://sts.internal.example.com', 'sts-old', kid='sts-0')


def entra_token(oid, tid, groups=(), roles=(), scp='Orders.Read', aud='api://orders', overage_limit=200, **kw):
    c = {'aud': aud, 'tid': tid, 'oid': oid, 'sub': 'pairwise-' + hashlib.sha256((oid + aud).encode()).hexdigest()[:20], 'ver': '2.0',
         'scp': scp, 'roles': list(roles), 'azp': 'client-app', 'upn': f'{oid[:6]}@example.com'}
    if len(groups) > overage_limit:  # groups overage: the claim disappears and a pointer replaces it
        c['_claim_names'] = {'groups': 'src1'}
        c['_claim_sources'] = {'src1': {'endpoint': f'https://graph.microsoft.com/v1.0/users/{oid}/getMemberObjects'}}
    else:
        c['groups'] = list(groups)
    c.update(kw)
    return ENTRA.mint(c, typ='JWT')


def auth0_token(user_id, org_id, permissions=(), aud='https://api.example.com', **kw):
    c = {'sub': 'auth0|' + user_id, 'aud': [aud, 'https://example-tenant.auth0.com/userinfo'], 'azp': 'client-app', 'scope': 'openid profile',
         'org_id': org_id, 'permissions': list(permissions), NS + 'tenant': org_id}
    c.update(kw)
    return AUTH0.mint(c, typ='at+jwt')


def okta_token(uid, login, groups=(), scp=('orders.read',), aud='api://default', **kw):
    c = {'sub': login, 'uid': uid, 'cid': 'client-app', 'aud': aud, 'scp': list(scp), 'groups': list(groups)}
    c.update(kw)
    return OKTA.mint(c, typ='application/okta-internal-at+jwt')


def cognito_token(sub, client_id='client-app', groups=(), scope='orders/read', resource=None, **kw):
    c = {'sub': sub, 'token_use': 'access', 'client_id': client_id, 'scope': scope, 'cognito:groups': list(groups), 'username': sub[:8]}
    if resource:
        c['aud'] = resource
    c.update(kw)
    return COGNITO.mint(c, typ=None)


# ------------------------------------------------------------------ verifiers
class Reject(Exception):
    pass


def parts(token):
    try:
        h, p, s = token.split('.')
        return json.loads(ub64(h)), json.loads(ub64(p)), h, p, s
    except Exception as e:  # noqa: BLE001
        raise Reject('malformed') from e


def naive_verify(token, keys, keydir=KEYDIR):
    """Mistakes on purpose: algorithm from the header, kid as a path, jku/jwk trusted, no iss/aud/exp/typ checks."""
    h, p, hs, ps, sig = parts(token)
    alg = h.get('alg', '')
    if alg.lower() == 'none':
        return p
    if 'jwk' in h:  # key embedded in the header is trusted
        key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(h['jwk']))
        return jwt.decode(token, key, algorithms=['RS256'], options={'verify_aud': False, 'verify_exp': False, 'verify_iat': False})
    if 'jku' in h:  # key set fetched from the URL in the header (here: a local "attacker" set)
        js = keys.get('jku:' + h['jku'])
        key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(js['keys'][0]))
        return jwt.decode(token, key, algorithms=['RS256'], options={'verify_aud': False, 'verify_exp': False, 'verify_iat': False})
    kid = h.get('kid', '')
    if '/' in kid or kid.startswith('.'):  # kid concatenated into a path: '../../dev/null' yields an empty key
        path = os.path.normpath(os.path.join(keydir, kid))
        secret = open(path, 'rb').read() if os.path.isfile(path) else b''
        good = hmac.new(secret, f'{hs}.{ps}'.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(b64(good), sig):
            raise Reject('bad signature')
        return p
    pem = keys.get(kid) or next(iter(v for k, v in keys.items() if not k.startswith('jku:')))
    if alg == 'HS256':  # RS→HS confusion: the public key bytes are used as the HMAC secret
        good = hmac.new(pem, f'{hs}.{ps}'.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(b64(good), sig):
            raise Reject('bad signature')
        return p
    try:
        return jwt.decode(token, pem, algorithms=['RS256'], options={'verify_aud': False, 'verify_exp': False, 'verify_iat': False})
    except jwt.PyJWTError as e:
        raise Reject(str(e)) from e


class Baseline:
    """The guide's common baseline: alg allow-list, keys only from the configured issuer by kid, exact iss, aud must include me,
    exp required (leeway 30 s), typ checked, required org claims with fixed types, fail closed."""

    def __init__(self, issuers, audience, typ=('at+jwt',), required=None, leeway=30, clock=CLOCK):
        self.issuers = {i.iss: i for i in issuers}
        self.audience, self.typ, self.leeway, self.clock = audience, typ, leeway, clock
        self.required = required or {}

    def verify(self, token):
        h, p, *_ = parts(token)
        if h.get('alg') != 'RS256':
            raise Reject('alg not allowed')
        if any(k in h for k in ('jku', 'jwk', 'x5u', 'x5c')):
            raise Reject('key reference in header')
        iss = p.get('iss')
        cands = [i for i in ([self.issuers[iss]] if iss in self.issuers else [])]
        cands += [i for i in getattr(self, 'old', []) if i.iss == iss]
        key = next((i for i in cands if i.kid == h.get('kid')), None)
        if key is None:
            raise Reject('unknown issuer or kid')
        if self.typ and h.get('typ') not in self.typ:
            raise Reject('wrong typ')
        try:
            c = jwt.decode(token, key.pub_pem, algorithms=['RS256'], audience=self.audience, issuer=iss,
                           options={'require': ['exp', 'iat', 'iss'], 'verify_exp': False, 'verify_iat': False, 'verify_aud': self.audience is not None})
        except jwt.PyJWTError as e:
            raise Reject(type(e).__name__) from e
        now = self.clock.now()
        if c['exp'] + self.leeway <= now:
            raise Reject('expired')
        if 'nbf' in c and c['nbf'] - self.leeway > now:
            raise Reject('not yet valid')
        for path, typ in self.required.items():
            v = get_path(c, path)
            if v is None:
                raise Reject('missing required claim ' + path)
            if not isinstance(v, typ):
                raise Reject('wrong type ' + path)
        return c


def get_path(c, path):
    cur = c
    for k in path.split('|'):  # '|' separates nesting so that URI names with dots stay intact
        if not isinstance(cur, dict) or k not in cur:
            return None
        cur = cur[k]
    return cur


def size(token):
    return len(token.encode())

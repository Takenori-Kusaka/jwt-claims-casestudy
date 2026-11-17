# -*- coding: utf-8 -*-
"""A token verifier whose checks are switched on by the baseline elements (flags.BASE).

Without 'alg' it behaves like the mistakes real code has made: the algorithm comes from the header (none, HS256 with the public
key as the secret), keys come from jku / jwk headers, kid is used as a file path.
"""
import hashlib
import hmac
import json
import os

import jwt

from .jwtlib import KEYDIR, Reject, b64, get_path, parts


class Verifier:
    def __init__(self, flags, registry, audience=None, typ=('at+jwt',), required=None, clock=None, leeway=30, jku_sets=None, allowed=None):
        """registry: {iss: [issuer objects with .kid and .pub_pem]}; required: {path: type}; typ: tuple or callable(header, payload)."""
        self.f, self.registry, self.audience, self.typ = set(flags), registry, audience, typ
        self.required, self.clock, self.leeway, self.jku = required or {}, clock, leeway, jku_sets or {}
        self.allowed = set(allowed) if allowed else set(registry)  # issuers accepted; the key set may hold more (aggregated JWKS)

    def _all_keys(self):
        return {k.kid: k.pub_pem for ks in self.registry.values() for k in ks}

    def _naive_sig(self, token, h, hs, ps, sig):
        alg = str(h.get('alg', ''))
        if alg.lower() == 'none':
            return
        if 'jwk' in h:
            key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(h['jwk']))
            jwt.decode(token, key, algorithms=['RS256'], options={'verify_signature': True, 'verify_aud': False, 'verify_exp': False, 'verify_iat': False})
            return
        if 'jku' in h:
            js = self.jku.get(h['jku'])
            if not js:
                raise Reject('jku unreachable')
            key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(js['keys'][0]))
            jwt.decode(token, key, algorithms=['RS256'], options={'verify_aud': False, 'verify_exp': False, 'verify_iat': False})
            return
        kid = str(h.get('kid', ''))
        if '/' in kid or kid.startswith('.'):
            path = os.path.normpath(os.path.join(KEYDIR, kid))
            secret = open(path, 'rb').read() if os.path.isfile(path) else b''
            if not hmac.compare_digest(b64(hmac.new(secret, f'{hs}.{ps}'.encode(), hashlib.sha256).digest()), sig):
                raise Reject('bad signature')
            return
        keys = self._all_keys()
        pem = keys.get(kid) or next(iter(keys.values()))
        if alg == 'HS256':
            if not hmac.compare_digest(b64(hmac.new(pem, f'{hs}.{ps}'.encode(), hashlib.sha256).digest()), sig):
                raise Reject('bad signature')
            return
        try:
            jwt.decode(token, pem, algorithms=['RS256'], options={'verify_aud': False, 'verify_exp': False, 'verify_iat': False})
        except jwt.PyJWTError as e:
            raise Reject(str(e)) from e

    def verify(self, token):
        h, p, hs, ps, sig = parts(token)
        f = self.f
        if 'alg' not in f:
            self._naive_sig(token, h, hs, ps, sig)
        else:
            if h.get('alg') != 'RS256':
                raise Reject('alg not allowed')
            if any(k in h for k in ('jku', 'jwk', 'x5u', 'x5c')):
                raise Reject('key reference in header')
            pool = self.registry.get(p.get('iss'), []) if 'iss' in f else [k for ks in self.registry.values() for k in ks]
            key = next((k for k in pool if k.kid == h.get('kid')), None)
            if key is None:
                raise Reject('unknown key for this issuer')
            try:
                jwt.decode(token, key.pub_pem, algorithms=['RS256'], options={'verify_aud': False, 'verify_exp': False, 'verify_iat': False, 'verify_nbf': False})
            except jwt.PyJWTError as e:
                raise Reject(type(e).__name__) from e
        if 'iss' in f and p.get('iss') not in self.allowed:
            raise Reject('issuer not allowed')
        if 'aud' in f and self.audience is not None:
            a = p.get('aud')
            if self.audience not in (a if isinstance(a, list) else [a]):
                raise Reject('aud')
        if 'exp' in f:
            if not isinstance(p.get('exp'), (int, float)):
                raise Reject('exp missing')
            if p['exp'] + self.leeway <= self.clock.now():
                raise Reject('expired')
        if 'typ' in f and self.typ:
            ok = self.typ(h, p) if callable(self.typ) else h.get('typ') in self.typ
            if not ok:
                raise Reject('wrong token type')
        for path, typ in self.required.items():
            v = get_path(p, path)
            if v is None:
                if 'required' in f:
                    raise Reject('missing required claim ' + path)
                continue
            if 'types' in f and not isinstance(v, typ) or 'types' in f and isinstance(v, bool) and typ is not bool:
                raise Reject('wrong type ' + path)
        return p

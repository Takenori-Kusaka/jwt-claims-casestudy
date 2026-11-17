# -*- coding: utf-8 -*-
"""Case registry, real-time clock for Keycloak tokens, remote issuers built from Keycloak JWKS."""
import json
import time

from jwt.algorithms import RSAAlgorithm
from cryptography.hazmat.primitives import serialization

from . import infra
from .jwtlib import Reject

CONFIGS = ('N', 'B', 'BE')
CONFIG_JA = {'N': '素朴（よくある誤り）', 'B': '共通の基準', 'BE': '共通の基準＋重点'}


class RealClock:
    def now(self):
        return int(time.time())


REAL = RealClock()


class RemoteIssuer:
    """A Keycloak realm as an issuer: iss and the signing key taken from its JWKS."""

    def __init__(self, realm):
        self.realm = realm
        self.iss = f'{infra.KC}/realms/{realm}'
        js = [k for k in infra.jwks(realm)['keys'] if k.get('use') == 'sig' and k['kty'] == 'RSA'][0]
        self.kid = js['kid']
        self.pub_pem = RSAAlgorithm.from_jwk(json.dumps(js)).public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


class Case:
    def __init__(self, cid, kind, target, part, desc, fn):
        self.cid, self.kind, self.target, self.part, self.desc, self.fn = cid, kind, target, part, desc, fn

    def run(self, cfg):
        """Returns True when the request was ACCEPTED (attack succeeded / legitimate request served)."""
        try:
            return bool(self.fn(cfg))
        except Reject:
            return False


def matrix(cases):
    rows = []
    for c in cases:
        r = {cfg: c.run(cfg) for cfg in CONFIGS}
        rows.append(dict(id=c.cid, kind=c.kind, target=c.target, part=c.part, desc=c.desc, **r))
    return rows


def score(rows):
    out = {}
    for cfg in CONFIGS:
        att = [r for r in rows if r['kind'] == 'attack']
        leg = [r for r in rows if r['kind'] == 'legit']
        out[cfg] = dict(attacks=len(att), attacks_succeeded=sum(r[cfg] for r in att), legit=len(leg), false_rejects=sum(not r[cfg] for r in leg))
    return out

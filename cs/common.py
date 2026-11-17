# -*- coding: utf-8 -*-
"""Case registry, configurations as element sets, ablation analysis, remote issuers from Keycloak JWKS."""
import json
import time

from cryptography.hazmat.primitives import serialization
from jwt.algorithms import RSAAlgorithm

from . import infra
from .jwtlib import Reject

CONFIG_JA = {'N': '素朴（よくある誤り）', 'B': '共通の基準', 'BE': '共通の基準＋重点'}


class RealClock:
    def __init__(self):
        self.offset = 0

    def now(self):
        return int(time.time()) + self.offset


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

    def run(self, flags):
        """True when the request was ACCEPTED (attack succeeded / legitimate request served)."""
        try:
            return bool(self.fn(frozenset(flags)))
        except Reject:
            return False
        except (KeyError, TypeError, ValueError):  # a consumer crashing on an unexpected claim shape = request not served
            return False


def matrix(cases, cfgs):
    rows = []
    for c in cases:
        r = dict(id=c.cid, kind=c.kind, target=c.target, part=c.part, desc=c.desc)
        for name, fl in cfgs.items():
            r[name] = c.run(fl)
        rows.append(r)
    return rows


def score(rows, names):
    out = {}
    att = [r for r in rows if r['kind'] == 'attack']
    leg = [r for r in rows if r['kind'] == 'legit']
    for n in names:
        out[n] = dict(attacks=len(att), attacks_succeeded=sum(r[n] for r in att), legit=len(leg), false_rejects=sum(not r[n] for r in leg))
    return out


def blockers(rows, full, prefix):
    """For each attack blocked in the full config: which single-element removals reopen it. Empty = blocked by several elements."""
    cols = [k for k in rows[0] if k.startswith(prefix + '-') and k.count('-') == 1]
    return {r['id']: [c[len(prefix) + 1:] for c in cols if r[c]] for r in rows if r['kind'] == 'attack' and not r[full]}


def ablation(rows, full, prefix):
    """For each element: attacks reopened (blocked in the full config, accepted without the element), legit requests newly
    rejected, and legit requests that only work without the element (the element's false-reject cost)."""
    out = {}
    for name in [k for k in rows[0] if k.startswith(prefix + '-') and k.count('-') == 1]:
        e = name[len(prefix) + 1:]
        out[e] = {
            'reopened': [r['id'] for r in rows if r['kind'] == 'attack' and not r[full] and r[name]],
            'newly_rejected_legit': [r['id'] for r in rows if r['kind'] == 'legit' and r[full] and not r[name]],
            'legit_only_without': [r['id'] for r in rows if r['kind'] == 'legit' and not r[full] and r[name]],
        }
    return out

# -*- coding: utf-8 -*-
"""Generic JWT attacks (guide Part 1) against the naive verifier (N) and the common baseline (B, BE = same here)."""
import hashlib
import hmac
import json

import jwt
from jwt.algorithms import RSAAlgorithm

from .common import Case
from .jwtlib import CLOCK, NS, STS, Baseline, Issuer, b64, naive_verify

AUD = 'https://orders.internal.example.com'
ATTACKER = Issuer('https://evil.example.net', 'attacker')
OTHER = Issuer('https://idp-other.example.com', 'other-idp')  # a second issuer whose keys a careless service also loaded
KEYS_N = {STS.kid: STS.pub_pem, OTHER.kid: OTHER.pub_pem, 'jku:https://evil.example.net/jwks': ATTACKER.jwks()}
BASE = Baseline([STS], AUD, typ=('at+jwt',), required={NS + '|tenant_id': str})


def claims(**kw):
    c = {'sub': 'u-7f3a', 'aud': AUD, NS: {'tenant_id': 't-042'}, 'scope': 'orders.read'}
    c.update(kw)
    return c


def raw(header, payload, sign):
    hs = b64(json.dumps(header, separators=(',', ':')).encode())
    ps = b64(json.dumps(payload, separators=(',', ':')).encode())
    return f'{hs}.{ps}.{sign(f"{hs}.{ps}".encode())}'


def body(**kw):
    p = {'iss': STS.iss, 'iat': CLOCK.now(), 'exp': CLOCK.now() + 300}
    p.update(claims(**kw))
    return p


def verify(cfg, tok):
    if cfg == 'N':
        return naive_verify(tok, KEYS_N)
    return BASE.verify(tok)


def cases():
    hs_with_pub = lambda m: b64(hmac.new(STS.pub_pem, m, hashlib.sha256).digest())  # noqa: E731
    out = [
        Case('G0', 'legit', '正規のトークン', 'Part 1', '発行者が署名した正しいトークン', lambda c: verify(c, STS.mint(claims()))),
        Case('G1', 'attack', 'alg', 'Part 1 危険なヘッダー', 'alg を none にして署名なしで送る',
             lambda c: verify(c, raw({'alg': 'none', 'typ': 'at+jwt'}, body(scope='orders.admin'), lambda m: ''))),
        Case('G2', 'attack', 'alg', 'Part 1 危険なヘッダー', 'RS256 を HS256 に変え、公開鍵を HMAC の秘密として署名する',
             lambda c: verify(c, raw({'alg': 'HS256', 'kid': STS.kid, 'typ': 'at+jwt'}, body(scope='orders.admin'), hs_with_pub))),
        Case('G3', 'attack', 'kid', 'Part 1 危険なヘッダー', 'kid にパスを入れて空の鍵を読ませ、空の秘密で署名する',
             lambda c: verify(c, raw({'alg': 'HS256', 'kid': '../no/such/file', 'typ': 'at+jwt'}, body(scope='orders.admin'),
                                     lambda m: b64(hmac.new(b'', m, hashlib.sha256).digest())))),
        Case('G4', 'attack', 'jku', 'Part 1 危険なヘッダー', 'jku で攻撃者の鍵の場所を指し、自分の鍵で署名する',
             lambda c: verify(c, ATTACKER.mint(dict(claims(scope='orders.admin'), iss=STS.iss), extra_headers={'jku': 'https://evil.example.net/jwks'}))),
        Case('G5', 'attack', 'jwk', 'Part 1 危険なヘッダー', 'ヘッダーに自分の公開鍵を埋め込み、自分で署名する',
             lambda c: verify(c, ATTACKER.mint(dict(claims(scope='orders.admin'), iss=STS.iss),
                                               extra_headers={'jwk': json.loads(RSAAlgorithm.to_jwk(ATTACKER.key.public_key()))}))),
        Case('G6', 'attack', 'exp', 'Part 1 検証の順序', 'exp の無いトークン（期限のない合鍵）', lambda c: verify(c, STS.mint(claims(), lifetime=None))),
        Case('G7', 'attack', 'exp', 'Part 1 検証の順序', '1 日前に期限が切れたトークン',
             lambda c: verify(c, STS.mint(claims(), now=CLOCK.now() - 90000))),
        Case('G8', 'attack', 'aud', 'Part 1 ID トークンとアクセストークン', '別のサービス宛て（invoices）のトークンを orders に送る',
             lambda c: verify(c, STS.mint(claims(aud='https://invoices.internal.example.com')))),
        Case('G9', 'attack', 'iss', 'Part 1 攻撃の型', '鍵を読み込んであった別の発行者が、正しい署名で発行したトークン',
             lambda c: verify(c, OTHER.mint(claims(scope='orders.admin')))),
        Case('G10', 'attack', 'typ', 'Part 1 ID トークンとアクセストークン', '同じ発行者の ID トークン（typ JWT）を API に送る',
             lambda c: verify(c, STS.mint(claims(), typ='JWT'))),
        Case('G11', 'attack', '必須クレーム', 'Part 4 前方互換', 'テナントのクレームが無いトークン（発行時フックの失敗など）',
             lambda c: verify(c, STS.mint({'sub': 'u-7f3a', 'aud': AUD, 'scope': 'orders.read'}))),
        Case('G12', 'attack', '型', 'Part 4 型', 'テナントのクレームが配列（型の揺れ）',
             lambda c: verify(c, STS.mint(claims(**{NS: {'tenant_id': ['t-042', 't-043']}})))),
    ]
    return out


__all__ = ['cases', 'jwt']

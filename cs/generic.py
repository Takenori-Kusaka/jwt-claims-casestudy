# -*- coding: utf-8 -*-
"""Generic JWT attacks (guide Part 1) against configurations built from the baseline elements."""
import hashlib
import hmac
import json

from jwt.algorithms import RSAAlgorithm

from .common import Case
from .jwtlib import CLOCK, NS, STS, Issuer, b64
from .verify import Verifier

AUD = 'https://orders.internal.example.com'
ATTACKER = Issuer('https://evil.example.net', 'attacker')
OTHER = Issuer('https://idp-other.example.com', 'other-idp')  # its keys sit in the same aggregated key set (Storm-0558 pattern)
REGISTRY = {STS.iss: [STS], OTHER.iss: [OTHER]}
JKU = {'https://evil.example.net/jwks': ATTACKER.jwks()}
REQ = {'sub': str, NS + '|tenant_id': str}


def verifier(flags):
    return Verifier(flags, REGISTRY, audience=AUD, typ=('at+jwt',), required=REQ, clock=CLOCK, jku_sets=JKU, allowed={STS.iss})


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


def cases():
    v = verifier
    hs_pub = lambda m: b64(hmac.new(STS.pub_pem, m, hashlib.sha256).digest())  # noqa: E731
    return [
        Case('G0', 'legit', '正規のトークン', 'Part 1 検証の順序', '発行者が署名した正しいトークン', lambda f: v(f).verify(STS.mint(claims()))),
        Case('G1', 'attack', 'alg', 'Part 1 危険なヘッダー', 'alg を none にして署名なしで送る',
             lambda f: v(f).verify(raw({'alg': 'none', 'typ': 'at+jwt'}, body(scope='orders.admin'), lambda m: ''))),
        Case('G2', 'attack', 'alg', 'Part 1 危険なヘッダー', 'RS256 を HS256 に変え、公開鍵を HMAC の秘密として署名する',
             lambda f: v(f).verify(raw({'alg': 'HS256', 'kid': STS.kid, 'typ': 'at+jwt'}, body(scope='orders.admin'), hs_pub))),
        Case('G3', 'attack', 'kid', 'Part 1 危険なヘッダー', 'kid にパスを入れて空の鍵を読ませ、空の秘密で署名する',
             lambda f: v(f).verify(raw({'alg': 'HS256', 'kid': '../no/such/file', 'typ': 'at+jwt'}, body(scope='orders.admin'),
                                       lambda m: b64(hmac.new(b'', m, hashlib.sha256).digest())))),
        Case('G4', 'attack', 'jku', 'Part 1 危険なヘッダー', 'jku で攻撃者の鍵の場所を指し、自分の鍵で署名する',
             lambda f: v(f).verify(ATTACKER.mint(dict(claims(scope='orders.admin'), iss=STS.iss), extra_headers={'jku': 'https://evil.example.net/jwks'}))),
        Case('G5', 'attack', 'jwk', 'Part 1 危険なヘッダー', 'ヘッダーに自分の公開鍵を埋め込み、自分で署名する',
             lambda f: v(f).verify(ATTACKER.mint(dict(claims(scope='orders.admin'), iss=STS.iss),
                                                 extra_headers={'jwk': json.loads(RSAAlgorithm.to_jwk(ATTACKER.key.public_key()))}))),
        Case('G6', 'attack', 'exp', 'Part 1 検証の順序', 'exp の無いトークン（期限のない合鍵）', lambda f: v(f).verify(STS.mint(claims(), lifetime=None))),
        Case('G7', 'attack', 'exp', 'Part 1 検証の順序', '1 日前に期限が切れたトークン', lambda f: v(f).verify(STS.mint(claims(), now=CLOCK.now() - 90000))),
        Case('G8', 'attack', 'aud', 'Part 1 ID トークンとアクセストークン', '別のサービス宛て（invoices）のトークンを orders に送る',
             lambda f: v(f).verify(STS.mint(claims(aud='https://invoices.internal.example.com')))),
        Case('G9', 'attack', 'iss', 'Part 1 攻撃の型', '同じ鍵の集合に載っている別の発行者が、自分の iss で発行したトークン',
             lambda f: v(f).verify(OTHER.mint(claims(scope='orders.admin')))),
        Case('G10', 'attack', 'iss と鍵の対応', 'Part 0 事故の例（Storm-0558）', '別の発行者の鍵で、iss を自分の発行者と偽って署名したトークン',
             lambda f: v(f).verify(OTHER.mint(dict(claims(scope='orders.admin'), iss=STS.iss)))),
        Case('G11', 'attack', 'typ', 'Part 1 ID トークンとアクセストークン', '同じ発行者の ID トークン（typ JWT）を API に送る',
             lambda f: v(f).verify(STS.mint(claims(), typ='JWT'))),
        Case('G12', 'attack', '必須クレーム', 'Part 4 前方互換', 'テナントのクレームが無いトークン（発行時フックの失敗など）を、既定のテナントで処理させる',
             lambda f: v(f).verify(STS.mint({'sub': 'u-7f3a', 'aud': AUD, 'scope': 'orders.read'}))),
        Case('G13', 'attack', '型', 'Part 4 型', 'テナントのクレームが配列（2 テナント分）', lambda f: v(f).verify(STS.mint(claims(**{NS: {'tenant_id': ['t-042', 't-043']}})))),
        Case('G14', 'attack', '型', 'Part 4 型', 'sub が数値（文字列と比べる受け手で別人と一致しうる）', lambda f: v(f).verify(STS.mint(claims(sub=7)))),
    ]

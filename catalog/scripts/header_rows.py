# -*- coding: utf-8 -*-
"""JOSE header parameters (not claims, but every consumer must decide how to treat them; the common baseline
depends on typ and alg). Rows HDR-01.. and their per-case decisions. Imported by merge.py and build_xlsx.py."""

IDPS = ['Entra', 'Keycloak', 'Auth0', 'Okta', 'Cognito']
B = 'https://www.rfc-editor.org/rfc/rfc7515#section-4.1'

# id, name, purpose, source, url, decision kind, use_or_loss, revisit
HDR = [
    ('HDR-01', 'typ（ヘッダー）', 'JWS 全体の種類。アクセストークンは at+jwt（RFC 9068 §2.1）。ID トークンなど別の目的のトークンを受け入れないために照合する。', 'RFC 7515 §4.1.9・RFC 9068 §2.1・RFC 8725 §3.11', 'https://www.rfc-editor.org/rfc/rfc9068#section-2.1',
     '必須（共通基準）', '内部トークンは at+jwt だけを受ける。入口は IdP ごとに決めた値で照合する（Entra＝JWT、Okta＝application/okta-internal-at+jwt、Cognito＝token_use、Keycloak＝クライアント設定 access.token.header.type.rfc9068 を有効にして at+jwt）。ID トークンの流用（G11・B2）を防ぐ。', '見直さない（共通の基準。IdP が typ の値を変えたら、入口の照合値だけを更新する）'),
    ('HDR-02', 'alg（ヘッダー）', '署名のアルゴリズム。受け手は値を信用せず、自分の許可リストと照合するだけ。', 'RFC 7515 §4.1.1・RFC 8725 §3.1', B,
     '必須（共通基準）', '許可リスト（RS256）と照合し、鍵ごとにアルゴリズムを 1 つに固定する。none とアルゴリズム混同（G1・G2）を防ぐ。', '署名アルゴリズムを移行するとき（例：RS256 → ES256）、許可リストを並行期間だけ 2 つにする'),
    ('HDR-03', 'kid（ヘッダー）', '署名に使った鍵のヒント。事前に取得した発行者の鍵の一覧の中だけで探す。', 'RFC 7515 §4.1.4・RFC 8725 §3.10', B,
     '採用', '鍵の入れ替え（ローテーション）中に正しい鍵を選ぶために使う。パスや SQL には使わない（G3）。', '発行者が kid を出さなくなったら、x5t#S256（HDR-08）での鍵の選択を検討する'),
    ('HDR-04', 'jku（ヘッダー）', '鍵の一覧の URL。たどると攻撃者の鍵で検証することになる。', 'RFC 7515 §4.1.2・RFC 8725 §3.10', B,
     '不採用・禁止', '受け手は無視し、鍵は発行者のメタデータの jwks_uri からだけ取る（G4）。失うものはない。', '発行者ごとの鍵の場所を動的に変える要件が出ても、許可リストの URL に限る'),
    ('HDR-05', 'jwk（ヘッダー）', 'ヘッダーに埋め込まれた公開鍵。信頼すると誰でも自分で署名できる。', 'RFC 7515 §4.1.3・RFC 8725 §3.10', B,
     '不採用・禁止', '受け手は無視する（G5）。DPoP の証明（別の種類の JWT）では使うが、アクセストークンの検証には使わない。', 'DPoP を導入したら、DPoP 証明の検証でだけ扱う'),
    ('HDR-06', 'x5u（ヘッダー）', '証明書の URL。jku と同じく、たどらない。', 'RFC 7515 §4.1.5', B,
     '不採用・禁止', '受け手は無視する。失うものはない。', '証明書ベースの発行者を受け入れる要件が出たら、許可リストに限る'),
    ('HDR-07', 'x5c（ヘッダー）', '証明書チェーン。受け手が検証規則を持たない限り信頼しない。', 'RFC 7515 §4.1.6', B,
     '不採用・禁止', '受け手は無視する。失うものはない。', 'mTLS や証明書で発行者を識別する設計にしたら、チェーン検証つきで扱う'),
    ('HDR-08', 'x5t#S256（ヘッダー）', '証明書のサムプリント。鍵の選択のヒント。', 'RFC 7515 §4.1.8', B,
     '不採用・不要', 'kid で鍵を選ぶので使わない。失うものはない。', '発行者が kid を出さず x5t#S256 だけを出す場合'),
    ('HDR-09', 'cty（ヘッダー）', '入れ子の JWT（署名してから暗号化）のときだけ JWT を入れる。', 'RFC 7519 §5.2', 'https://www.rfc-editor.org/rfc/rfc7519#section-5.2',
     '不採用・不要', 'JWE（入れ子の JWT）は見送ったので使わない。JWE を使わないことで、中継者から中身を隠せない。', 'JWE を導入したら（ケース B の見送りの見直し条件）'),
    ('HDR-10', 'crit（ヘッダー）', '理解必須の拡張ヘッダーの一覧。理解できなければ拒否する。', 'RFC 7515 §4.1.11', B,
     '不採用・不要', '拡張ヘッダーを使わないので出さない。受け手は crit があり理解できなければ拒否する（ライブラリの既定）。', '拡張ヘッダーを使う仕様（例：特定のプロファイル）を採用したら'),
]


def rows():
    out = []
    for hid, name, purpose, src, url, *_ in HDR:
        out.append(dict(id=hid, name=name, category='トークン種別・メタ', purpose=purpose, source_kind='標準（IETF RFC）', source=src, url=url,
                        value_type='string' if hid not in ('HDR-05', 'HDR-07') else ('object (JWK)' if hid == 'HDR-05' else 'array of string'),
                        token='JOSE ヘッダー（クレームではない）', support={k: '既定' if hid in ('HDR-01', 'HDR-02', 'HDR-03') else '不明' for k in IDPS},
                        is_custom='標準', notes='クレームではなく JOSE ヘッダーのパラメータ。共通の基準が依存するため参考として収録。', verified=True, status='最終',
                        change_controller='IESG', writer='発行者（権威ある情報源）', mutability='該当なし', freshness='該当なし',
                        authz_use='不可（表示・監査用）', pii='非該当', log_policy='平文で可', multiplicity='単一', limit='記載なし',
                        comparison='大小区別の完全一致', uniqueness='該当なし', vocabulary='標準で列挙' if hid in ('HDR-01', 'HDR-02') else '自由な文字列',
                        synonym_group='G-jose-header', checked_on='2026-11-17', _src='header'))
    return out


# --- review1 overrides (written by fix_review1.py) ---
# per-case overrides of the HDR decisions: {id: {case: {field: value}}}
CASE_OVERRIDE = {
    'HDR-05': {c: {'use_or_loss': 'アクセストークンの検証では無視する（G5）。DPoP の証明では、typ が dpop+jwt であることと一緒に jwk ヘッダーを検証し、その鍵で証明の署名を確かめ、鍵のサムプリントをアクセストークンの cnf.jkt と照合する。',
                   'revisit': 'DPoP の対象（cnf.jkt の判断）を変えたら一緒に見直す。アクセストークンの検証では見直さない。'} for c in 'AC'},
}
# --- end review1 overrides ---

def decisions():
    out = []
    for hid, name, purpose, src, url, kind, use, revisit in HDR:
        d = {'judgement': kind, 'condition': '', 'alt': [], 'use_or_loss': use, 'revisit': revisit,
             'checks': {'HDR-01': ['G11', 'B2'], 'HDR-02': ['G1', 'G2'], 'HDR-03': ['G3'], 'HDR-04': ['G4'], 'HDR-05': ['G5']}.get(hid, [])}
        out.append({'id': hid, 'guide_part': 'Part 1', **{c: dict(d, **CASE_OVERRIDE.get(hid, {}).get(c, {})) for c in 'ABC'}})
    return out

# -*- coding: utf-8 -*-
"""Merge raw/g1_standards.json, raw/g2_idps.json, raw/g3_platforms.json into catalog.json with stable IDs.
Adds the organisation's own claims (ORG rows, defined by this case study) and fills IdP support for standard
rows from raw/g2_support.json where the standards agent left 不明.
  python catalog/scripts/merge.py"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
CAT = os.path.dirname(HERE)
RAW = os.path.join(CAT, 'raw')
CATS = ['識別子', '発行者・宛先', '時刻・寿命', 'トークン種別・メタ', '認証の強さ・セッション', '権限・認可', '組織・テナント', '委任・行為者',
        'クライアント・ワークロード', '鍵・送信者制約', '監査・相関・イベント', '同意・目的・取引', 'プロフィール・連絡先', '本人確認・保証',
        '端末・ネットワーク・場所', '開示・暗号・検証補助', 'CI・ワークロード属性', 'その他']
KINDS = ['標準（IETF RFC）', '標準（OpenID Foundation 最終版）', '草案（IETF・OIDF）', 'IANA 登録（その他の標準化団体）', '公的機関・研究',
         'ベンダー独自', 'プラットフォーム独自', '業界の属性語彙', '本ケーススタディで定義']
IDPS = ['Entra', 'Keycloak', 'Auth0', 'Okta', 'Cognito']

NS = 'https://claims.example.com/'
ORG = [
    ('ORG-01', 'tenant_id', '組織・テナント', '主体が今回の操作で属するテナントの不変 ID。テナント名・表示名ではない。', 'string', '単一', 'G-tenant'),
    ('ORG-02', 'user_id', '識別子', '組織内の利用者の不変 ID（IdP をまたいで同じ人を指す）。メールやログイン名ではない。', 'string', '単一', 'G-user-id'),
    ('ORG-03', 'roles', '権限・認可', '組織の語彙で正規化した粗いロール。オブジェクトごとの許可は表さない。', 'array of string', '配列', 'G-roles'),
    ('ORG-04', 'department', '組織・テナント', '所属部門の ID。異動で変わるため、重要な操作では都度引き直す。', 'string', '単一', 'G-department'),
    ('ORG-05', 'employee_id', '識別子', '社員番号。数値に見えても文字列で運ぶ（JavaScript の精度の問題を避ける）。', 'string', '単一', 'G-employee-id'),
    ('ORG-06', 'idp', '監査・相関・イベント', '入口で受け取った元の IdP の種類（entra / keycloak / auth0 / okta / cognito）。監査と正規化の追跡用。', 'string', '単一', 'G-idp'),
    ('ORG-07', 'v', 'トークン種別・メタ', '名前空間オブジェクトの版。受け手は知っている版だけを読む。', 'string', '単一', 'G-schema-version'),
    ('ORG-08', 'authorization_details[type=https://claims.example.com/rar/payment]', '同意・目的・取引', '人が承認した支払いの内容（金額・通貨・相手先・対象）。RFC 9396 の type として定義。', 'object', '配列', 'G-authz-details'),
    ('ORG-09', 'task_id', '監査・相関・イベント', 'エージェントのタスクの ID。タスク単位の短命トークンと監査ログの相関に使う。', 'string', '単一', 'G-task'),
    ('ORG-11', 'sid', '認証の強さ・セッション', '入口が IdP のセッション ID（sid）を写したもの。経理・管理などの重要な操作の前に、セッションが生きているかを照合するためだけに使う。', 'string', '単一', 'G-sid'),
    ('ORG-10', 'approval_id', '同意・目的・取引', '人の承認の記録の ID。承認の内容は ORG-08 と照合する。', 'string', '単一', 'G-approval'),
]


def org_rows():
    out = []
    for oid, name, cat, purpose, vt, mult, sg in ORG:
        full = name if name.startswith('authorization_details') else NS + '.' + name
        out.append(dict(id=oid, name=full, category=cat, purpose=purpose, source_kind='本ケーススタディで定義',
                        source='本ケーススタディ（DECISION_POLICY.md）。名前空間の作り方は RFC 7519 §4.2（衝突しない名前）', url='https://github.com/Takenori-Kusaka/jwt-claims-casestudy',
                        value_type=vt, token='内部 AT（入口で発行）', support={k: 'フック・式で可' for k in IDPS}, is_custom='独自（どの標準にもない）',
                        notes='書き手は入口のトークン発行サービスだけ。IdP の独自クレームから入口で写す。', verified=True, status='本ケーススタディで定義',
                        change_controller='自組織（ID 基盤チーム）', writer='発行者（権威ある情報源）' if oid != 'ORG-04' else '発行者（取得元から転記）',
                        mutability='再割り当てなし' if oid in ('ORG-01', 'ORG-02', 'ORG-05') else '随時変わる',
                        freshness='発行時点で固定（寿命内は古いまま）', authz_use='iss・aud などと組で可' if oid in ('ORG-01', 'ORG-03', 'ORG-08') else '補助のみ',
                        pii='仮名の識別子' if oid in ('ORG-02', 'ORG-05', 'ORG-11') else '非該当', log_policy='ハッシュ・マスク' if oid in ('ORG-02', 'ORG-05', 'ORG-11') else '平文で可',
                        multiplicity=mult, limit='roles は 20 件まで（本ケーススタディの規則）' if oid == 'ORG-03' else '記載なし', comparison='大小区別の完全一致',
                        uniqueness='全体で一意' if oid in ('ORG-01', 'ORG-02', 'ORG-05', 'ORG-09', 'ORG-10') else 'なし', vocabulary='自由な文字列' if oid != 'ORG-03' else '発行者ごと（組織の語彙）',
                        synonym_group=sg, checked_on='2026-11-17', _src='org'))
    return out


def main():
    rows = []
    for f in ('g1_standards', 'g2_idps', 'g3_platforms'):
        for r in json.load(open(os.path.join(RAW, f + '.json'), encoding='utf-8')):
            r['_src'] = f
            rows.append(r)
    sup = json.load(open(os.path.join(RAW, 'g2_support.json'), encoding='utf-8'))
    filled = 0
    for r in rows:
        tok = r.get('token') or ''
        if r['_src'] == 'g1_standards' and r['name'] in sup and any(t in tok for t in ('ID', 'AT', '両方')) and not any(t in tok for t in ('その他', 'DPoP', 'SET', 'ログアウト', 'Txn')):
            s = sup[r['name']]
            for k in IDPS:
                if r['support'].get(k, '不明') == '不明' and s.get(k) and s.get(k) != '不明':
                    r['support'][k] = s[k]
                    filled += 1
            if s.get('note'):
                r['support_note'] = s['note']
    # vendor-specific rows: the other IdPs are not applicable (the row defines that vendor's own claim)
    VEN = {'Entra': ('Entra', 'Microsoft'), 'Keycloak': ('Keycloak',), 'Auth0': ('Auth0',), 'Okta': ('Okta',), 'Cognito': ('Cognito',)}
    for r in rows:
        if r['source_kind'] == 'ベンダー独自':
            own = [k for k, keys in VEN.items() if any(x in r['source'] for x in keys)]
            if len(own) == 1:
                for k in IDPS:
                    if k != own[0] and r['support'].get(k, '不明') == '不明':
                        r['support'][k] = '対象外（他社の独自クレーム）'
    ALIAS = {'G-auth_time': 'G-auth-time', 'G-authorization-details': 'G-authz-details'}
    for r in rows:
        r['synonym_group'] = ALIAS.get(r.get('synonym_group'), r.get('synonym_group'))
    ci = {c: i for i, c in enumerate(CATS)}
    ki = {k: i for i, k in enumerate(KINDS)}
    rows.sort(key=lambda r: (ci.get(r['category'], 99), r.get('synonym_group') or '', ki.get(r['source_kind'], 99), r['name']))
    for i, r in enumerate(rows, 1):
        r['id'] = 'CLM-%04d' % i
    import header_rows
    allrows = rows + header_rows.rows() + org_rows()
    json.dump(allrows, open(os.path.join(CAT, 'catalog.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print(len(rows), 'rows +', len(ORG), 'ORG rows; support filled from g2_support:', filled)


if __name__ == '__main__':
    main()

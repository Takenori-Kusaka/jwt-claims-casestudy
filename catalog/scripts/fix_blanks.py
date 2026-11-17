# -*- coding: utf-8 -*-
"""Fill every per-case cell that was left empty, so that no cell of the catalogue reads as "not done".
Idempotent: only empty fields are written.
  - condition: explicit "always" / "not applicable" text for judgements other than 条件付き採用
  - revisit: concrete text for 必須・採用 rows; for 対象外 rows the domain change that would bring the claim into scope
  - related: for 不採用・不要／不採用・禁止／対象外, the claims adopted in the same case that cover the same concept
             (same synonym group); shown in the 代替クレーム column
  - checks_note: why the 検証 ID column is empty
  python catalog/scripts/fix_blanks.py"""
import glob
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
CAT = os.path.dirname(HERE)
ADOPT = ('必須（共通基準）', '採用', '条件付き採用')

COND = {
    '必須（共通基準）': '常に（すべての内部トークンに必須。欠けたら拒否）',
    '採用': '常に（このケースの対象のトークンで使う）',
    '不採用・代替あり': '該当なし（採用しない。代わりに右の代替クレームを使う）',
    '不採用・不要': '該当なし（採用しない）',
    '不採用・禁止': '該当なし（載せない。受け取っても使わない）',
    '対象外': '該当なし（このケースの範囲外）',
}

# 必須・採用 rows: what would make us change the decision
REVISIT_ADOPTED = {
    'sub': '見直さない（共通の基準。利用者のキーは不変の ID に限る。外すと利用者を特定できない）',
    'aud': '見直さない（共通の基準。外すと別の宛先向けのトークンが通る）',
    'iss': '見直さない（共通の基準。外すと別の発行者のトークンが通る）',
    'exp': '見直さない（共通の基準。寿命の長さは「寿命の試算」の結果で調整する）',
    'iat': '見直さない（共通の基準。鮮度の確認と監査の時刻に使う）',
    'jti': '見直さない（共通の基準。取り消しと再送の検出、監査の相関に使う）',
    'typ（ヘッダー）': '見直さない（共通の基準。IdP が typ の値を変えたら、入口の照合値だけを更新する）',
    'alg（ヘッダー）': '署名アルゴリズムを移行するとき（例：RS256 → ES256）、許可リストを並行期間だけ 2 つにする',
    'kid（ヘッダー）': '発行者が kid を出さなくなったら、x5t#S256（HDR-08）での鍵の選択を検討する',
    'authorization_details': '承認の内容を表す業界標準の type（例：FAPI の決済の型）が決まったら、組織の type から移す',
    'authorization_details.actions': '承認の内容を表す業界標準の type が決まったら、その定義に合わせる',
    'authorization_details.locations': '承認の内容を表す業界標準の type が決まったら、その定義に合わせる',
    'authorization_details.type': '業界標準の type が決まったら、組織の type（ORG-08）から移す',
    'scope': '操作ごとの判定をすべて PDP に寄せたら、scope は入口での粗い判定だけに使う',
    'act': 'Transaction Tokens・ID-JAG など委任の標準が RFC になり、act の代わりの形が定まったら',
    'act.sub': 'Transaction Tokens・ID-JAG など委任の標準が RFC になり、行為者の表し方が定まったら',
    'client_id': '見直さない（RFC 9068 で必須。利用者とクライアントの区別に使う）',
    'https://claims.example.com/.tenant_id': '見直さない（共通の基準。テナントの境界の根拠）',
    'https://claims.example.com/.user_id': '見直さない（共通の基準。IdP をまたいで同じ人を指す ID）',
    'https://claims.example.com/.roles': 'ロールの数がトークンの上限に近づいたら、PDP で都度引く方式に移す',
    'https://claims.example.com/.department': '異動の反映の遅れが許されない操作が増えたら、トークンから外して都度引く',
    'https://claims.example.com/.idp': '受け入れる IdP を 1 つに統合したら外す',
    'https://claims.example.com/.v': '見直さない（名前空間オブジェクトの版の互換を判定するため）',
    'https://claims.example.com/.task_id': 'Transaction Tokens（草案）が RFC になり、txn で同じ相関を表せるようになったら',
    'https://claims.example.com/.approval_id': 'Transaction Tokens（草案）の rctx などで承認の記録を表す標準の形が定まったら',
    'https://claims.example.com/.sid': 'IdP のログアウトをイントロスペクションや CAEP のイベントで受け取れるようになったら',
}
REVISIT_ADOPTED_PREFIX = [('authorization_details[type=', '業界標準の type（例：FAPI の決済の型）が決まったら、組織の type から移す')]

# 対象外 rows: the scope change that would bring the claim into play
DOMAIN = [
    (r'SVT|電子署名の検証結果', '電子署名の検証結果（SVT）を扱う文書の仕組みと連携するようになったら'),
    (r'NIST IR 8112|属性メタデータ', '見直さない（台帳の列として使う）。ただし、属性の出どころや鮮度を受け手に送る必要が出たら、トークンでの伝え方を検討する'),
    (r'SPIFFE', 'サービス間の認証を SPIFFE のワークロード ID（JWT-SVID）で行うようになったら'),
    (r'ETSI NFV|ネットワーク機能仮想化', 'ネットワーク機能仮想化（ETSI NFV）の API を扱うようになったら'),
    (r'ACME|証明書発行', '証明書の自動発行（ACME）の仕組みを自前で運用するようになったら'),
    (r'Apple|学校向け', 'Apple School／Business Manager の管理アカウントを IdP として受け入れるようになったら'),
    (r'RDAP|ドメイン登録', 'ドメイン登録データの照会（RDAP）サービスを提供するようになったら'),
    (r'OpenID Federation|トラストマーク|エンティティステートメント', 'OpenID Federation に参加し、信頼チェーンを検証するようになったら'),
    (r'検証可能な資格情報|VC|SD-JWT|Verifiable', '検証可能な資格情報（VC）を発行または受け入れるようになったら'),
    (r'CI/CD|CI の|CI のワークロード|GitHub Actions|GitLab|パイプライン', 'CI/CD のワークロード ID（OIDC のフェデレーション）でデプロイ基盤を扱うようになったら'),
    (r'Kubernetes|ServiceAccount', 'Kubernetes の ServiceAccount トークンでサービスやワークロードを認証するようになったら'),
    (r'AWS|STS|セッションタグ', '外部 IdP のトークンで AWS のロールを引き受ける構成を扱うようになったら'),
    (r'eduPerson|学術', '学術認証連合に参加するようになったら'),
    (r'CDNI|CDN', 'CDN の URI 署名トークンを扱うようになったら'),
    (r'SIP|PASSporT|STIR|電話|発信者', '電話・SIP の発信者認証を扱うようになったら'),
    (r'ACE|IoT|制約デバイス', 'IoT の制約デバイス（ACE-OAuth）を扱うようになったら'),
    (r'3GPP|5G|CAPIF|通信事業者', '通信事業者の API（3GPP）を扱うようになったら'),
    (r'Open Banking|銀行|FAPI|決済|金融', '金融機関の API（Open Banking・FAPI）と接続するようになったら'),
    (r'EAT|端末の証明|アテステーション|attestation', '端末やワークロードの証明（EAT）を認可に使うようになったら'),
    (r'SCIM|プロビジョニング', 'SCIM でのアカウントの自動作成・同期をトークンの処理と結び付けるようになったら'),
    (r'Hasura|Supabase|Firebase|PostgREST', 'そのプラットフォーム（Hasura・Supabase・Firebase など）を採用したら'),
    (r'SAML', 'SAML の IdP を受け入れるようになったら'),
    (r'ログアウト|SET|イベント|CAEP|RISC', 'セキュリティイベント（SET・CAEP・RISC）を送受信するようになったら'),
    (r'DPoP|mTLS|cnf', '送信者制約（DPoP・mTLS）を導入したら'),
    (r'Status List|状態リスト', 'トークンの状態リスト（Status List）で取り消しを配るようになったら'),
]


def domain_revisit(text):
    for pat, rv in DOMAIN:
        if re.search(pat, text):
            return rv
    return None


def main():
    rows = {r['id']: r for r in json.load(open(os.path.join(CAT, 'catalog.json'), encoding='utf-8'))}
    parts = sorted(glob.glob(os.path.join(CAT, 'decisions', 'part*.json')))
    data = {p: json.load(open(p, encoding='utf-8')) for p in parts}
    dec = {d['id']: d for p in parts for d in data[p]}
    import sys
    sys.path.insert(0, HERE)
    import header_rows
    allj = dict(dec)
    for d in header_rows.decisions():
        allj.setdefault(d['id'], d)
    groups = {}
    for i, r in rows.items():
        groups.setdefault(r.get('synonym_group') or '', []).append(i)
    n = {'condition': 0, 'revisit': 0, 'related': 0, 'checks_note': 0}
    left = []
    for i, d in dec.items():
        r = rows.get(i)
        if not r:
            continue
        for c in 'ABC':
            x = d[c]
            j = x['judgement']
            if not x.get('condition') and j in COND:
                x['condition'] = COND[j]
                n['condition'] += 1
            if not x.get('revisit'):
                rv = None
                if j in ('必須（共通基準）', '採用'):
                    rv = REVISIT_ADOPTED.get(r['name'])
                    for pre, t in REVISIT_ADOPTED_PREFIX:
                        if r['name'].startswith(pre):
                            rv = t
                elif j == '対象外':
                    rv = domain_revisit(' '.join([x.get('use_or_loss', ''), r.get('source', ''), r.get('purpose', ''), r.get('category', '')]))
                if rv:
                    x['revisit'] = rv
                    n['revisit'] += 1
                else:
                    left.append((i, c, j, r['name'], x.get('use_or_loss', '')[:50]))
            if j in ('不採用・不要', '不採用・禁止', '対象外') and not x.get('alt') and 'related' not in x:
                g = r.get('synonym_group') or ''
                rel = [k for k in groups.get(g, []) if k != i and (allj.get(k) or {}).get(c, {}).get('judgement') in ADOPT] if g else []
                x['related'] = rel[:3]
                n['related'] += 1 if rel else 0
            if not x.get('checks') and not x.get('checks_note'):
                x['checks_note'] = ('未検証（ケーススタディの実験で直接扱っていない）' if j in ADOPT
                                    else '—（対象外のため検証なし）' if j == '対象外' else '—（採用しないため検証なし）')
                n['checks_note'] += 1
    for p in parts:
        json.dump(data[p], open(p, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print(n)
    print('revisit still empty:', len(left))
    for t in left[:60]:
        print(' ', *t)


if __name__ == '__main__':
    main()

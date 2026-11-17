# -*- coding: utf-8 -*-
"""Elements of the common baseline and of each scenario's emphasis. A configuration is a set of element names.

N  = no element (typical mistakes)
B  = all baseline elements
BE = baseline + the scenario's emphasis elements
Ablation: B minus one baseline element, BE minus one emphasis element.
"""
BASE = {
    'alg': ('アルゴリズムと鍵は受け手が決める', 'alg の許可リスト（RS256）、jku・jwk・x5u・x5c を無視、kid は登録済みの鍵だけ', 'Part 1'),
    'iss': ('発行者の完全一致と鍵の対応', 'iss を許可リストと完全一致、鍵はその発行者に登録されたものだけ', 'Part 1・5'),
    'aud': ('宛先の確認', 'aud に自分が含まれるか', 'Part 1'),
    'exp': ('期限の必須化', 'exp を必須にし、ずれは 30 秒まで', 'Part 1'),
    'typ': ('種類の確認', 'typ（Cognito は token_use）でアクセストークンだけを受ける', 'Part 1'),
    'required': ('必須クレームの欠落は拒否', '組織で必須と定めたクレームが無ければ拒否（fail closed）', 'Part 4'),
    'types': ('型の固定', '必須クレームの型を確認（ID は文字列、配列は配列）', 'Part 4'),
    'immutable_id': ('不変の ID で照合', '利用者のキーは sub・oid+tid・uid。ログイン名やメールを使わない', 'Part 4'),
    'namespace': ('組織の名前空間から読む', '組織のクレームは https://claims.example.com/ の中だけを読む', 'Part 4'),
}
EMPH = {
    'A': {
        'tenant_iss_bind': ('テナントと発行者の照合', 'テナントのクレームが、発行したレルムと一致するか', 'Part 5'),
        'data_tenant_check': ('データ側のテナント照合', 'すべての SQL にテナントの条件（ID 指定・集計も）', 'Part 5・7'),
        'rls_local': ('SET LOCAL と行単位の制御', '取引ごとに文脈を設定し、RLS で絞る', 'Part 7'),
        'per_tenant_keys': ('テナント単位の鍵', '署名鍵をテナントのレルムだけに登録する', 'Part 5（IR 8587 §5.2.1.2）'),
    },
    'B': {
        'normalize_gw': ('入口での正規化', '入口で IdP ごとに検証し内部トークンに交換、サービスは内部トークンだけを読む', 'Part 3・6'),
        'header_strip': ('ヘッダーの除去', 'クライアントが送った x-user-* を大文字小文字・アンダースコア・重複を含めて除去', 'Part 6'),
        'freshness': ('重要な操作の鮮度確認', '経理・管理の操作は属性とセッションを引き直す', 'Part 8'),
        'overage_resolve': ('groups 超過の解決', 'groups が消えたらディレクトリで引く', 'Part 3'),
    },
    'C': {
        'act_chain': ('act の連鎖を正しく読む', '今の行為者（最も外側の act）と呼び出し元を照合して認可', 'Part 10'),
        'aud_exchange': ('宛先に束縛した交換', 'ホップごとに単一の宛先で交換し、受け取ったトークンを渡さない', 'Part 10'),
        'approval_bind': ('承認の束縛', '承認は authorization_details で、金額と相手先を照合', 'Part 10'),
        'short_task': ('タスク単位の短命トークン', '300 秒・タスクの範囲だけ、交換時に取り消しを再確認', 'Part 8・10'),
        'depth_rule': ('深さの組織規則', '委任の連鎖は 3 段まで', 'Part 10'),
    },
}


def configs(scen):
    b = set(BASE)
    out = {'N': set(), 'B': set(b)}
    emph = set(EMPH.get(scen, {}))
    if emph:
        out['BE'] = b | emph
    for e in BASE:
        out['B-' + e] = b - {e}
    for e in emph:
        out['BE-' + e] = (b | emph) - {e}
    if scen == 'A':  # the common pooled mistake: RLS kept, but the context is set per session instead of per transaction
        out['BE~session'] = ((b | emph) - {'rls_local'}) | {'rls_session'}
        # the two data-side elements overlap; remove them together to see what each one was covering
        out['BE-data_tenant_check-rls_local'] = (b | emph) - {'rls_local', 'data_tenant_check'}
        out['BE~session-data_tenant_check'] = ((b | emph) - {'rls_local', 'data_tenant_check'}) | {'rls_session'}
    return out

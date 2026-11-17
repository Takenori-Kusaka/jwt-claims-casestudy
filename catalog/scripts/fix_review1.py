# -*- coding: utf-8 -*-
"""Apply the findings of catalog/reviews/decision-review-2026-11-17.md to the per-case decisions.
Idempotent: every edit sets a field to a fixed value, or appends/prepends a sentence only if it is not there yet.
Edits: catalog/decisions/part*.json (by ID and case), catalog/scripts/header_rows.py (HDR-01, HDR-05) and
catalog/raw/g1_standards.json (pii of the OIDC email_verified row). Afterwards run merge.py, validate.py, build_xlsx.py.
  python catalog/scripts/fix_review1.py"""
import glob
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
CAT = os.path.dirname(HERE)

# ---------------------------------------------------------------- load
FILES = sorted(glob.glob(os.path.join(CAT, 'decisions', 'part*.json')))
DATA = {p: json.load(open(p, encoding='utf-8')) for p in FILES}
DEC = {d['id']: d for p in FILES for d in DATA[p]}
ROWS = {r['id']: r for r in json.load(open(os.path.join(CAT, 'catalog.json'), encoding='utf-8'))}
LOG = []


def cell(i, c):
    return DEC[i][c]


def setf(i, cases, **kw):
    for c in cases:
        x = cell(i, c)
        for k, v in kw.items():
            if x.get(k) != v:
                x[k] = v
                LOG.append((i, c, k))


def append(i, cases, field, text):
    for c in cases:
        x = cell(i, c)
        if text not in x[field]:
            x[field] = (x[field].rstrip() + text) if x[field] else text.lstrip()
            LOG.append((i, c, field))


def prepend(i, cases, field, text):
    for c in cases:
        x = cell(i, c)
        if text not in x[field]:
            x[field] = text + x[field]
            LOG.append((i, c, field))


def drop(i, cases, field, text):
    for c in cases:
        x = cell(i, c)
        if text in x[field]:
            x[field] = x[field].replace(text, '')
            LOG.append((i, c, field))


def C(n):
    return 'CLM-%04d' % n


# ---------------------------------------------------------------- 1・2 DPoP
LABEL = '推奨。ケーススタディの実験では未検証の追加防御。'
B23 = '漏れたトークンの再送（B23 型）の攻撃ケースを足して効果を測ったら見直す。'
for c in 'AC':
    jkt = cell(C(431), c)
    setf(C(133), c, judgement='条件付き採用', condition=jkt['condition'], alt=[], checks=[],
         use_or_loss=LABEL + 'DPoP の証明の iat。受け手は、iat が受け入れる時間の幅（前後数十秒）に入る証明だけを受け、古い証明や先の時刻の証明を拒否する。'
                             '使用済みの jti を覚えておく期間もこの幅で決まる。',
         revisit='cnf.jkt（CLM-0431）の判断（DPoP の対象）を広げる・やめるときに一緒に見直す。' + B23)
    setf(C(179), c, judgement='条件付き採用', condition=jkt['condition'], alt=[], checks=[],
         use_or_loss=LABEL + 'DPoP の証明の jti。受け手は使用済みの jti を（iat の受け入れ幅の間）覚えておき、同じ jti の証明を拒否して、証明の再送を検知する。',
         revisit='cnf.jkt（CLM-0431）の判断（DPoP の対象）を広げる・やめるときに一緒に見直す。' + B23)
for n in (429, 431, 442, 443, 444, 486):
    prepend(C(n), 'AC', 'use_or_loss', LABEL)
for n in (429, 431):
    append(C(n), 'AC', 'revisit', B23)

# ---------------------------------------------------------------- 3 typ
setf(C(198), 'ABC', revisit='クライアント設定 access.token.header.type.rfc9068 を外したら')

# ---------------------------------------------------------------- 4 代替が別の概念を指していた
NOMAIL = 'メールでアカウントを結び付けないので使い道がない。'
for n in (604, 605, 606):
    setf(C(n), 'ABC', judgement='不採用・不要', alt=[])
    prepend(C(n), 'ABC', 'use_or_loss', NOMAIL)
setf(C(782), 'C', judgement='不採用・不要', alt=[], checks=[],
     use_or_loss='操作のリスクを示す文脈クレームで、C はリスクの値で判断しないので使い道がない。リスクの値でツールが自ら判断することはできない。'
                 '支払いの可否は、これとは別に承認の束縛（ORG-08・ORG-10）で確かめる。')
for n in (299, 300, 303, 304, 305, 307, 308):  # CLM-0306 (Apple scopes) is 対象外 in B and stays so
    setf(C(n), 'B', judgement='不採用・不要', alt=[])

# ---------------------------------------------------------------- 5 入口は ID トークンを受けない（B）
IDONLY_MAIL = 'ID トークンのみ。ポータルが表示に使う（CLM-0527 と同じ扱い。アクセストークンには載せない）'
IDONLY_NAME = 'ID トークンのみ。ポータルが表示に使う（CLM-0559 と同じ扱い。アクセストークンには載せない）'
B5 = {
    529: (IDONLY_MAIL, 'Entra の email は、ポータルが ID トークンから読んで画面に表示するだけに使う。入口は ID トークンを受けないので、内部トークンには写さない。可変で正しさも保証されないので照合には使わない。', 'CLM-0527'),
    530: (IDONLY_MAIL, 'Okta の email は、ポータルが ID トークンから読んで画面に表示するだけに使う。入口は ID トークンを受けないので、内部トークンには写さない。一意性に依存しない。', 'CLM-0527'),
    531: (IDONLY_MAIL, 'Cognito の email は、ポータルが ID トークンから読んで画面に表示するだけに使う。本人が編集できることがあるので、照合や認可には使わない（B18 と同じ型）。入口は ID トークンを受けないので、内部トークンには写さない。', 'CLM-0527'),
    534: (IDONLY_MAIL, 'Entra の verified_primary_email は、ポータルが ID トークンから読んで表示用のメールとして画面に出すだけに使う。入口は ID トークンを受けないので、内部トークンには写さない。照合には使わない。', 'CLM-0527'),
    561: (IDONLY_NAME, 'Entra の姓は、ポータルが ID トークンから読んで画面に表示するだけに使う。入口は ID トークンを受けないので、内部トークンにも各サービスにも載せない。', 'CLM-0559'),
    562: (IDONLY_NAME, 'Entra の名は、ポータルが ID トークンから読んで画面に表示するだけに使う。入口は ID トークンを受けないので、内部トークンにも各サービスにも載せない。', 'CLM-0559'),
    565: (IDONLY_NAME, 'Entra の表示名は、ポータルが ID トークンから読んで画面に表示するだけに使う。入口は ID トークンを受けないので、内部トークンにも各サービスにも載せない。', 'CLM-0559'),
    566: (IDONLY_NAME, 'Entra の別名は、ポータルが ID トークンから読んで画面に表示するだけに使う。入口は ID トークンを受けないので、内部トークンにも各サービスにも載せない。', 'CLM-0559'),
}
for n, (cond, use, ref) in B5.items():
    setf(C(n), 'B', judgement='条件付き採用', condition=cond, alt=[], use_or_loss=use,
         revisit='IdP を一本化して、このクレームを出す IdP をやめたら外す。%s の判断を変えたら一緒に見直す。' % ref)
setf(C(229), 'B', condition='ID トークンのみ。ポータル（RP）が max_age を付けてログインを求めたときに、RP が照合する', checks=[],
     use_or_loss='ポータルが ID トークンの auth_time で、ログインが max_age の範囲内かを確かめる。入口は ID トークンを受けないので、内部の auth_time（CLM-0228）はこの値から作らない。',
     revisit='ポータルが max_age を使わなくなったら')
setf(C(118), 'B', judgement='不採用・不要', alt=[],
     use_or_loss='Entra の任意クレームの auth_time で、入口は読まない。内部トークンの auth_time（CLM-0228）は、IdP のアクセストークンの auth_time かイントロスペクションの結果から作る。'
                 '重要な操作の鮮度はイントロスペクションとディレクトリの引き直しで確かめる（B11）。',
     revisit='経理の操作に再認証の時間制限（max_age）を設け、アクセストークンの auth_time もイントロスペクションも使えないと分かったら')

# ---------------------------------------------------------------- 6 G-username
REV_USER = '見直さない（表示が要っても UserInfo か API から取る）'
for d in DEC.values():
    for c in 'ABC':
        if d[c]['revisit'] == 'ログイン名を表示に使う画面ができても UserInfo・API から取る方針を変えるなら':
            setf(d['id'], c, revisit=REV_USER)
ALT_USER = 'アクセストークンには載せない（禁止）。利用者の照合は user_id（ORG-02）、表示は ID トークンか UserInfo の name（CLM-0559）で行う。'
G6 = {
    (589, 'A'): '本人が変えられる短い名前で、一意でないので利用者のキーにも認可にも使えない。',
    (589, 'B'): 'ログイン名は再利用されうるので照合に使わない（B13 の型）。',
    (591, 'A'): 'Entra の preferred_username はログイン名で、可変で再利用されうる。A は Entra ID を使わないので、いまは出ない。',
    (591, 'B'): 'Entra の preferred_username はログイン名で、可変で認可に使えないので照合に使わない（B13 の型）。',
    (592, 'A'): 'Okta のログイン名で、再利用されうる。A は Okta を使わないので、いまは出ない。',
    (592, 'B'): 'Okta のログイン名は再利用されうるので照合に使わない（B13 の型）。',
    (593, 'A'): 'Entra の unique_name（v1.0）はログイン名で、一意とは限らない。A は Entra ID を使わないので、いまは出ない。',
    (593, 'B'): 'Entra の unique_name（v1.0）は一意とは限らないので照合に使わない（B13 の型）。',
}
for (n, c), head in G6.items():
    setf(C(n), c, judgement='不採用・禁止', condition='', alt=[], use_or_loss=head + ALT_USER, revisit=REV_USER)

# ---------------------------------------------------------------- 7 アクセストークンと ID トークンの区別
AT_NO = 'アクセストークン：禁止（載せない）／ID トークン：このケースでは不要。'
G7 = {
    (535, 'B'): '副のメールアドレスを表示する画面がない。',
    (551, 'A'): 'イニシャルを出す画面がない。表示は name で足りる。',
    (551, 'B'): 'イニシャルを出す社内の画面がない。',
    (576, 'A'): '電話番号を載せないので、その検証の有無も使い道がない。',
    (576, 'B'): '電話番号を載せないので、その検証の有無も使い道がない。',
    (578, 'A'): 'SCIM の写真の URI を画面に出す要件がない。写真を画面に出すことはできない。',
    (578, 'B'): '社員の写真は社内ディレクトリの API で配るので、ポータルに SCIM の写真の URI は要らない。',
    (579, 'A'): 'プロフィール画像の URL を画面に出す要件がない。本人が書ける URL で、画面に出すと外部への読み込みで追跡にも使われうる。',
    (579, 'B'): '社員の写真は社内ディレクトリの API で配るので、ポータルにプロフィール画像の URL は要らない。',
    (582, 'A'): 'SCIM のプロフィールページの URI を画面に出す要件がない。',
    (582, 'B'): '社員のページは社内ディレクトリの API で配るので、ポータルに SCIM のプロフィールページの URI は要らない。',
    (583, 'A'): 'プロフィールページの URL を画面に出す要件がない。本人が書ける URL で、画面に出すと外部への読み込みで追跡にも使われうる。',
    (583, 'B'): '社員のページは社内ディレクトリの API で配るので、ポータルにプロフィールページの URL は要らない。',
    (584, 'A'): '敬称を画面に出さない。表示は name で足り、宛名に要るならテナントの DB で持つ。',
    (584, 'B'): '社内の画面は敬称を出さない。',
    (586, 'A'): '肩書（Dr など）を画面に出さない。表示は name で足り、宛名に要るならテナントの DB で持つ。',
    (586, 'B'): '社内の画面は肩書（Dr など）を出さない。',
    (594, 'A'): 'Web ページ・ブログの URL を画面に出す要件がない。本人が書ける URL で、画面に出すと外部への読み込みで追跡にも使われうる。',
    (594, 'B'): '社員のページは社内ディレクトリの API で配るので、ポータルに Web ページ・ブログの URL は要らない。',
    (672, 'A'): 'LDAP の部屋番号で、SaaS の利用者には使い道がない。',
    (672, 'B'): '部屋番号は社員の所在の情報で、認可に使わない。座席表などはディレクトリの API で引く。',
}
for (n, c), reason in G7.items():
    assert cell(C(n), c)['judgement'] == '不採用・不要', (n, c)
    setf(C(n), c, use_or_loss=AT_NO + reason)
C_NOTE = '禁止はエージェントやツールに届くトークンについて。ポータルの ID トークンでは、このケースでは単に不要。'
C_SKIP = {C(n) for n in (441, 449, 528, 538, 588, 607, 609, 610, 618, 783)}  # credentials, grants, or already explicit
for i, r in ROWS.items():
    if i in DEC and i not in C_SKIP and r.get('pii') in ('直接識別できる個人情報', '機微な個人情報') \
            and r['category'] in ('識別子', 'プロフィール・連絡先', '本人確認・保証') and cell(i, 'C')['judgement'] == '不採用・禁止':
        append(i, 'C', 'use_or_loss', C_NOTE)
setf(C(488), 'A', judgement='条件付き採用', condition='ID トークンのみ。ログインの応答を受ける RP（SaaS の Web 画面）が照合する',
     revisit='Web 画面が ID トークンを受けないログイン方式に変わったら外す')
setf(C(488), 'B', judgement='条件付き採用', condition='ID トークンのみ。ログインの応答を受ける RP（社内ポータルなど）が照合する',
     revisit='社内ポータルが ID トークンを受けないログイン方式に変わったら外す')
setf(C(538), 'C', judgement='不採用・不要', alt=[],
     use_or_loss='メールアドレスをエージェント用トークンに載せないので、その検証の有無も要らない。ポータルの ID トークンでも、このケースでは使い道がない。')

# ---------------------------------------------------------------- 8 実験にない記述・役割の違い
drop(C(597), 'C', 'use_or_loss', 'ツールサーバーの身元は mTLS のワークロード ID で確かめている。')
setf('ORG-09', 'C', checks=[],
     use_or_loss='タスク単位の短命トークン（300 秒）にタスクの ID を入れ、トークンと監査ログでタスクを相関させる。タスクの範囲を超える要求（返金など）の拒否と取り消しの反映は、'
                 'scope とタスク単位の短命トークン（short_task、実験 C9・C14）で行い、task_id はその判定には使わない。')
setf('ORG-06', 'A', judgement='条件付き採用', condition='顧客が自分の IdP を持ち込む（BYO IdP）場合',
     revisit='BYO IdP を受けず、テナントの IdP を Keycloak のレルムだけに限ると決めたら外す')
UNTESTED = '{} による鮮度の確認は実験で検証していない（実験 B11・B12 はイントロスペクションとディレクトリの引き直しで確かめた）。'
append(C(206), 'B', 'use_or_loss', UNTESTED.format('acr'))
append(C(228), 'B', 'use_or_loss', UNTESTED.format('auth_time'))
setf(C(228), 'B', condition='経理・管理の操作でだけ読む（入口が IdP のアクセストークンの auth_time か、イントロスペクションの結果から写す）')

# ---------------------------------------------------------------- 9 写し間違い・属性メタデータ
setf(C(595), 'A', condition='ID トークンのみ。Web 画面の時刻表示のタイムゾーンの初期値に使う（認可には使わない）')
for i, r in ROWS.items():
    if i in DEC and 'NIST IR 8112' in r['source']:
        setf(i, 'ABC', judgement='対象外', condition='', alt=[], checks=[], revisit='',
             use_or_loss='NIST IR 8112 の属性メタデータ（%s）。トークンには載せず、台帳（この一覧表）の列として使う。' % r['name'])

# ---------------------------------------------------------------- 9 差し込み文の空白（ラテン文字と和文の境目）
JA = '぀-ゟ゠-ヺー-ヿ一-鿿'
RE_LJ = re.compile(r'([A-Za-z0-9_\)])([%s])' % JA)
RE_JL = re.compile(r'([%s])([A-Za-z0-9_])' % JA)


def spaced(s):
    return RE_JL.sub(r'\1 \2', RE_LJ.sub(r'\1 \2', s))


for d in DEC.values():
    for c in 'ABC':
        for k in ('condition', 'use_or_loss', 'revisit'):
            s = spaced(d[c][k])
            if s != d[c][k]:
                d[c][k] = s
                LOG.append((d['id'], c, k + ' (space)'))

# ---------------------------------------------------------------- write decisions
for p in FILES:
    s = json.dumps(DATA[p], ensure_ascii=False, indent=1)
    if open(p, encoding='utf-8').read() != s:
        open(p, 'w', encoding='utf-8').write(s)

# ---------------------------------------------------------------- header_rows.py (HDR-01 all cases, HDR-05 A・C)
HP = os.path.join(HERE, 'header_rows.py')
h = open(HP, encoding='utf-8').read()
h0 = h
OLD01 = "'受け手はアクセストークンとして at+jwt だけを受け入れる（Cognito は token_use で代用）。ID トークンの流用（G11・B2）を防ぐ。'"
NEW01 = ("'内部トークンは at+jwt だけを受ける。入口は IdP ごとに決めた値で照合する（Entra＝JWT、Okta＝application/okta-internal-at+jwt、Cognito＝token_use、"
         "Keycloak＝クライアント設定 access.token.header.type.rfc9068 を有効にして at+jwt）。ID トークンの流用（G11・B2）を防ぐ。'")
assert OLD01 in h or NEW01 in h
h = h.replace(OLD01, NEW01)
BEGIN, END = '# --- review1 overrides (written by fix_review1.py) ---', '# --- end review1 overrides ---'
HDR05 = ('アクセストークンの検証では無視する（G5）。DPoP の証明では、typ が dpop+jwt であることと一緒に jwk ヘッダーを検証し、その鍵で証明の署名を確かめ、'
         '鍵のサムプリントをアクセストークンの cnf.jkt と照合する。')
block = '\n'.join([
    BEGIN,
    '# per-case overrides of the HDR decisions: {id: {case: {field: value}}}',
    'CASE_OVERRIDE = {',
    "    'HDR-05': {c: {'use_or_loss': %r," % HDR05,
    "                   'revisit': 'DPoP の対象（cnf.jkt の判断）を変えたら一緒に見直す。アクセストークンの検証では見直さない。'} for c in 'AC'},",
    '}',
    END, '', ''])
if BEGIN in h:
    h = re.sub(re.escape(BEGIN) + r'.*?' + re.escape(END) + r'\n\n\n', lambda m: block, h, flags=re.S)
else:
    h = h.replace('\ndef decisions():', '\n' + block + 'def decisions():')
OLDAPP = "out.append({'id': hid, 'guide_part': 'Part 1', 'A': dict(d), 'B': dict(d), 'C': dict(d)})"
NEWAPP = "out.append({'id': hid, 'guide_part': 'Part 1', **{c: dict(d, **CASE_OVERRIDE.get(hid, {}).get(c, {})) for c in 'ABC'}})"
assert OLDAPP in h or NEWAPP in h
h = h.replace(OLDAPP, NEWAPP)
if h != h0:
    open(HP, 'w', encoding='utf-8', newline='').write(h)
    LOG.append(('header_rows.py', '-', 'HDR-01/HDR-05'))

# ---------------------------------------------------------------- raw: pii of the OIDC email_verified row (align with CLM-0604)
RP = os.path.join(CAT, 'raw', 'g1_standards.json')
raw = json.load(open(RP, encoding='utf-8'))
hit = [r for r in raw if r['name'] == 'email_verified' and r['source'].startswith('OpenID Connect Core 1.0')]
assert len(hit) == 1
if hit[0]['pii'] != '非該当':
    hit[0]['pii'] = '非該当'
    open(RP, 'w', encoding='utf-8').write(json.dumps(raw, ensure_ascii=False, indent=1))
    LOG.append(('raw/g1_standards.json', '-', 'email_verified pii'))

print('changed fields:', len(LOG))

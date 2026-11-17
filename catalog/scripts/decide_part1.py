# -*- coding: utf-8 -*-
"""Build catalog/decisions/part1.json (rows of assign1.json)."""
import json, sys

ROOT = 'E:/Github/jwt-claims-casestudy/catalog/'
MUST, USE, COND = '必須（共通基準）', '採用', '条件付き採用'
ALT, NO, BAN, OOS = '不採用・代替あり', '不採用・不要', '不採用・禁止', '対象外'
GW = '入口の正規化でのみ読む（内部トークンには載せない）'
IDT = 'ID トークンのみ（クライアントがログイン時に検証する。API では受けない）'


def d(j, use, cond='', alt=None, rev='', checks=None):
    return {'judgement': j, 'condition': cond, 'alt': alt or [], 'use_or_loss': use, 'revisit': rev, 'checks': checks or []}


def same(x):
    return {'A': x, 'B': x, 'C': x}


D = {}  # id -> (guide_part, {'A':..,'B':..,'C':..})


def put(ids, part, cases):
    for i in ids if isinstance(ids, (list, tuple)) else [ids]:
        D[i] = (part, cases)


# ============================================================ core standard rows (共通の基準)
def core(ids, part, name, useA, useB, useC, chk):
    put(ids, part, {'A': d(MUST, useA, checks=chk['A']), 'B': d(MUST, useB, checks=chk['B']), 'C': d(MUST, useC, checks=chk['C'])})


core(['CLM-0091', 'CLM-0092'], 'Part 1・5', 'iss',
     'テナントのレルムごとの発行者を許可リストと完全一致で照合し、その発行者に登録した鍵だけで検証する。テナントのクレームが発行したレルムと一致するかの照合（tenant_iss_bind）の基準にもなる。',
     '入口で 5 つの IdP の発行者を完全一致で照合し、内部トークンでは入口の発行サービスだけを発行者として受ける。Entra の {tenantid} を何でも受ける実装を防ぐ。',
     '内部のトークン発行サービス（STS）だけを発行者として受け、交換で得たトークンも同じ発行者で照合する。',
     {'A': ['G9', 'G10', 'A8', 'A9', 'A10'], 'B': ['G9', 'G10', 'B10'], 'C': ['G9', 'G10']})
core(['CLM-0029', 'CLM-0030'], 'Part 4', 'sub',
     '利用者の主体を iss と組で特定する（文字列に型を固定）。データ側では組織の user_id（ORG-02）と合わせて請求書の持ち主を照合する。',
     '内部トークンの主体。入口で IdP ごとの不変 ID（Keycloak の sub、Entra の oid+tid、Okta の uid など）から決め、ログイン名は使わない。',
     '委任の主体（代わりに操作される利用者）。交換のたびに引き継ぎ、ツールが差し替えられないことを確かめる。今の行為者は act で表す。',
     {'A': ['G14', 'A3'], 'B': ['G14', 'B13', 'B14'], 'C': ['G14', 'C3', 'C15']})
core(['CLM-0070', 'CLM-0071'], 'Part 1', 'aud',
     'API（saas-api）宛てのトークンだけを受け、ID トークンや別サービス宛てを拒否する。',
     'サービスごとの宛先（orders・invoices など）を確かめ、宛先の差し替えを拒否する。aud のない Cognito のトークンは入口で client_id により確かめてから内部トークンの aud を付ける。',
     'ホップごとに単一の宛先で交換したトークンだけを受け、受け取ったトークンの転送や広い宛先のトークンの再送を拒否する。',
     {'A': ['G8', 'A13'], 'B': ['G8', 'B2', 'B3', 'B16'], 'C': ['G8', 'C2', 'C13']})
core(['CLM-0122', 'CLM-0123'], 'Part 1・8', 'exp',
     '必須にし、時計のずれは 30 秒まで。内部トークンの寿命は 300 秒。',
     '必須にし、ずれは 30 秒まで。exp 前の失効は検出できないので、重要な操作は別に引き直す（鮮度確認）。',
     'タスク単位の短命トークン（300 秒）の期限として必須。委任の取り消しは交換時の再確認で補う。',
     {'A': ['G6', 'G7', 'A14'], 'B': ['G6', 'G7'], 'C': ['G6', 'G7', 'C9']})
core(['CLM-0132', 'CLM-0134'], 'Part 1・8', 'iat',
     '内部トークンの発行時刻として必須。障害調査でトークンの年齢を見る（認証時刻とは扱わない）。',
     '発行時刻として必須。鮮度確認で「トークンが古いか」の目安に使うが、認証時刻（auth_time）の代わりにはしない。',
     '発行時刻として必須。タスクの交換の連鎖でどのトークンがいつ作られたかを監査で追う。',
     {'A': [], 'B': [], 'C': []})
core(['CLM-0178', 'CLM-0180'], 'Part 1・8', 'jti',
     '内部トークンの一意 ID として必須。監査ログはトークン全文ではなく jti で残す。',
     '内部トークンの一意 ID として必須。ログにはトークン全文の代わりに jti を残し、入口で交換した元のトークンとの対応を追う。',
     '交換ごとのトークンの一意 ID として必須。タスクの ID（ORG-09）と並べて、どのホップでどのトークンが使われたかを追う。',
     {'A': [], 'B': [], 'C': []})

# ============================================================ ORG rows
NS_ = '組織の名前空間'
put('ORG-01', 'Part 5', {
    'A': d(MUST, '主体が今回の操作で属するテナント。パスやヘッダーの X-Tenant ではなくこの値だけを使い、発行したレルムと照合して SQL のテナント条件と SET LOCAL に渡す。', checks=['G12', 'G13', 'A5', 'A8', 'A10', 'A11', 'A12']),
    'B': d(MUST, '固定値 corp。欠けたら拒否し、受け手が既定値で補わないことで、将来のテナント追加にも同じ検証が使える。', checks=['G12']),
    'C': d(MUST, '固定値 corp。交換のたびに引き継ぎ、エージェントやツールが変えられないことを確かめる。', checks=['G12'])})
put('ORG-02', 'Part 4', {
    'A': d(MUST, '組織内の利用者の不変 ID。請求書の持ち主（owner）との照合と監査に使い、メールやログイン名では照合しない。', checks=['A3']),
    'B': d(MUST, 'IdP をまたいで同じ人を指す不変 ID。入口で IdP ごとの不変 ID から写し、各業務システムはこの値をキーにする。', checks=['B13', 'B14']),
    'C': d(MUST, '委任の主体（利用者）の不変 ID。交換で差し替えられていないか、データの持ち主と一致するかを確かめる。', checks=['C3', 'C15'])})
put('ORG-03', 'Part 4・5', {
    'A': d(USE, 'テナント内の粗いロール（例 approver・tenant-admin）を組織の語彙で運ぶ。請求書ごとの許可は PDP で都度判定する。'),
    'B': d(USE, '各 IdP の groups・roles を入口で組織の語彙に正規化して運ぶ。欠けたら既定値で補わずに拒否し、クライアントが送ったヘッダーのロールは捨てる。', checks=['B4', 'B5', 'B6', 'B7', 'B8', 'B9', 'B18', 'B19', 'B20', 'B21']),
    'C': d(USE, '委任の主体（利用者）の粗いロールを運ぶ。エージェントに何を許すかは scope と act の行為者で決め、このロールだけでは支払いを許さない。')})
put('ORG-04', 'Part 4・8', {
    'A': d(NO, 'SaaS の顧客テナントの部門構成は扱わないため使い道がない。部門による絞り込みはできないが、必要ならテナント内の PDP で判定する。', rev='顧客テナントから部門単位の利用制限を求められたら'),
    'B': d(USE, '社内文書・経理の画面を部門で絞る。異動で変わるため、経理・管理の重要な操作ではディレクトリから引き直し、トークンの値だけでは判断しない。欠けたら拒否する。', checks=['B11', 'B15']),
    'C': d(NO, 'エージェントの委任は利用者・タスク・承認の単位で絞り、部門は判定に使わない。部門をまたぐ委任の制限はできない。', rev='部門ごとにエージェントの利用を制限する規則ができたら')})
put('ORG-05', 'Part 4', {
    'A': d(NO, '顧客テナントの利用者に社員番号はなく使い道がない。', rev='自社の社員を運用担当として SaaS に入れ、社員番号で監査する必要が出たら'),
    'B': d(COND, '社員番号でキーを引く旧システム（給与明細など）に渡すときだけ、数値でなく文字列で運ぶ。', cond='社員番号をキーにする旧システム宛てのトークンだけに載せる（文字列で、他の宛先には載せない）', rev='旧システムが user_id（ORG-02）で引けるようになったら外す', checks=['B22']),
    'C': d(NO, 'エージェントの委任は user_id で主体を表すので社員番号は要らない。', rev='エージェントが社員番号をキーにする旧システムを呼ぶようになったら')})
put('ORG-06', 'Part 3・6', {
    'A': d(USE, '入口で受け取った元の IdP の種類を監査に残し、テナントが自社の IdP を持ち込んだときの正規化の分岐を追えるようにする。認可には使わない。'),
    'B': d(USE, '5 つの IdP のどれから来た利用者かを監査と障害調査で追う（正規化の誤りの切り分け）。認可には使わない。'),
    'C': d(NO, '内部のトークン交換の連鎖は STS だけが発行し、元の IdP の種類で判断することがない。どの IdP で認証したかを内部トークンから追えなくなるが、交換の監査ログで足りる。', rev='エージェントの利用者が複数の IdP から来るようになったら')})
put('ORG-07', 'Part 11', same(None))
D['ORG-07'] = ('Part 11', {
    'A': d(USE, '名前空間オブジェクトの版。受け手は知っている版だけを読み、tenant_id の形式変更などを安全に出し分ける。'),
    'B': d(USE, '名前空間オブジェクトの版。多くの業務システムが読むため、roles の形式変更などを版で出し分け、契約テストで検出する。'),
    'C': d(USE, '名前空間オブジェクトの版。交換のたびに引き継ぎ、エージェント・ツールが知らない版のトークンを受けないようにする。')})
put('ORG-08', 'Part 10', {
    'A': d(NO, 'SaaS の API は人の承認つきの支払いを扱わないため使い道がない。', rev='SaaS に承認つきの支払い・振込の機能を加えたら'),
    'B': d(NO, '社内システムの支払いは人が自分で操作し、承認の内容をトークンに束縛する必要がない。', rev='経理の支払いを自動化し、承認者と実行者が分かれる流れをトークンで運ぶようになったら'),
    'C': d(USE, '人が承認した支払いの金額・相手先・対象を交換時にトークンへ入れ、支払いの API が要求の内容と照合する（本文に書いた承認 ID は信じない）。', checks=['C5', 'C6', 'C8'])})
put('ORG-09', 'Part 8・10', {
    'A': d(NO, 'エージェントのタスクはなく使い道がない。', rev='SaaS にエージェントによる操作を加えたら'),
    'B': d(NO, 'エージェントのタスクはなく使い道がない。', rev='社内システムにエージェントからの呼び出しを許したら'),
    'C': d(USE, 'タスク単位の短命トークン（300 秒）にタスクの ID を入れ、タスクの範囲を超える要求（返金など）の拒否と、監査ログでの相関に使う。', checks=['C9', 'C14'])})
put('ORG-10', 'Part 10', {
    'A': d(NO, '人の承認を伴う操作をトークンで運ばないため使い道がない。', rev='SaaS に承認つきの操作を加えたら'),
    'B': d(NO, '承認は業務システムの中で完結し、トークンで運ぶ必要がない。', rev='承認と実行を別のシステム・主体が行うようになったら'),
    'C': d(USE, '人の承認の記録の ID。存在する承認かを記録と照合し、内容は ORG-08 と突き合わせる。', checks=['C7', 'C8'])})

# ============================================================ ID トークン（OIDC Core）
def idtok(i, name, part='Part 1'):
    put(i, part, {
        'A': d(COND, f'テナントの利用者のログイン時に、クライアントが ID トークンの {name} を検証する。API はこの ID トークンを受けない。', cond=IDT, rev='クライアントをセッションなしの API 直結に変える、または ID トークンを使わない認証方式に移ったら', checks=['A13']),
        'B': d(COND, f'社員のログイン時に、業務システムのクライアントが ID トークンの {name} を検証する。API や入口はこの ID トークンを受けない。', cond=IDT, rev='IdP を 1 つに統合してクライアントのログインを入口に集約したら', checks=['B2']),
        'C': d(COND, f'利用者がポータルにログインするときに、クライアントが ID トークンの {name} を検証する。エージェントやツールには渡さない。', cond=IDT, rev='利用者のログインを別の方式（例 パスキーだけで IdP を介さない）に変えたら')})


idtok('CLM-0033', 'sub（iss と組で利用者を特定）', 'Part 1・4')
idtok('CLM-0073', 'aud（自分の client_id を含むか）')
idtok('CLM-0093', 'iss（Discovery の issuer と完全一致）')
idtok('CLM-0124', 'exp')
idtok('CLM-0136', 'iat')

# ============================================================ Back-Channel Logout トークン
LOGOUT_LOSS = {
    'A': 'IdP でのログアウトをクライアントのセッションへ即時に伝えられない。テナントの利用者のセッションは寿命（300 秒のトークン・30 分のセッション）で切れる。',
    'B': 'IdP でのログアウトを各業務システムのセッションへ即時に伝えられない。経理・管理の重要な操作はイントロスペクションで失効を確かめて補う。',
    'C': '利用者のログアウトをポータルのセッションへ即時に伝えられない。エージェントへの委任の取り消しは交換時の再確認で反映する。'}
LOGOUT_REV = {'A': 'テナントから即時のシングルログアウトを求められたら', 'B': '重要な操作以外でもログアウトの即時反映が必要になったら', 'C': 'ログアウトと同時にエージェントの委任も止める要件ができたら'}


def logout(i, name):
    put(i, 'Part 8', {k: d(NO, f'ログアウトトークンの {name}。' + LOGOUT_LOSS[k], rev=LOGOUT_REV[k], checks=(['B12'] if k == 'B' else [])) for k in 'ABC'})


for i, n in [('CLM-0034', 'sub'), ('CLM-0074', 'aud'), ('CLM-0094', 'iss'), ('CLM-0125', 'exp'), ('CLM-0137', 'iat'), ('CLM-0181', 'jti')]:
    logout(i, n)

# ============================================================ nbf
put('CLM-0143', 'Part 1', {
    'A': d(COND, '外部（レルム）のトークンに nbf があれば入口で検証する。内部トークンは発行と同時に有効なので載せない。', cond='外部のトークンに入っていれば入口で検証する（内部トークンには載せない）', rev='発行より後に有効になるトークン（予約実行など）を内部で使うようになったら'),
    'B': d(COND, 'Entra などのトークンに nbf があれば入口で検証する（ずれは 30 秒まで）。内部トークンには載せない。', cond='外部のトークンに入っていれば入口で検証する（内部トークンには載せない）', rev='発行より後に有効になるトークン（予約実行など）を内部で使うようになったら'),
    'C': d(COND, '外部のトークンに nbf があれば検証する。タスク単位のトークンは発行と同時に有効なので載せない。', cond='外部のトークンに入っていれば入口で検証する（内部トークンには載せない）', rev='承認後の決まった時刻に実行する予約支払いをトークンで表すようになったら')})

# ============================================================ vendor IdP rows
def vendor(i, part, used_in, use, alt_other, loss_other, rev_other, checks=None, alt_used=None):
    """IdP-specific row: read at the gateway in the cases that connect that IdP, else alt."""
    out = {}
    for k in 'ABC':
        if k in used_in:
            if alt_used:
                out[k] = d(ALT, use[k] if isinstance(use, dict) else use, alt=alt_used, rev=rev_other[k] if isinstance(rev_other, dict) else rev_other, checks=(checks or {}).get(k, []))
            else:
                out[k] = d(COND, use[k] if isinstance(use, dict) else use, cond=GW, rev=used_rev(rev_other), checks=(checks or {}).get(k, []))
        else:
            out[k] = d(ALT, loss_other, alt=alt_other, rev=rev_other[k] if isinstance(rev_other, dict) else rev_other)
    put(i, part, out)


REV_ENTRA = {'A': '顧客テナントが Entra ID を IdP として持ち込み、入口に接続したら（入口の正規化でのみ読む）', 'C': 'エージェントの利用者が Entra ID でログインするようになったら（入口の正規化でのみ読む）'}
REV_OKTA = {'A': '顧客テナントが Okta を持ち込み、入口に接続したら（入口の正規化でのみ読む）', 'C': 'エージェントの利用者が Okta でログインするようになったら（入口の正規化でのみ読む）'}
REV_COG = {'A': '顧客テナントの利用者を Cognito のユーザープールで管理するようになったら（入口の正規化でのみ読む）', 'C': 'エージェントの利用者が Cognito でログインするようになったら（入口の正規化でのみ読む）'}
REV_A0 = {'A': '顧客テナントが Auth0 を持ち込み、入口に接続したら（入口の正規化でのみ読む）', 'C': 'エージェントの利用者が Auth0 でログインするようになったら（入口の正規化でのみ読む）'}

def used_rev(r):
    name = {id(REV_ENTRA): 'Entra ID', id(REV_OKTA): 'Okta', id(REV_COG): 'Cognito', id(REV_A0): 'Auth0'}.get(id(r))
    if name is None:
        return 'IdP を Keycloak から別の製品に移したら、または Keycloak がこのクレームの形式・既定値を変えたら'
    return f'{name} を入口から外したら、または {name} がこのクレームの形式・既定値を変えたら'


# --- Entra (B only)
vendor('CLM-0043', 'Part 3・4', 'B', '入口で Entra の利用者の不変キー（oid+tid）として読み、組織の user_id（ORG-02）に写す。ログイン名（upn）は使わない。',
       ['ORG-02'], 'Entra を接続していないので読まない。接続していれば組織の user_id（ORG-02）が同じ人を指す役を担う。', REV_ENTRA, checks={'B': ['B10']})
vendor('CLM-0098', 'Part 1・3', 'B', '入口で Entra の発行者をテナント ID 入りの値と完全一致で照合し（{tenantid} を何でも受けない）、内部トークンの iss（CLM-0092）は入口の発行サービスに置き換える。',
       ['CLM-0092'], 'Entra を接続していないので読まない。発行者の照合は内部トークンの iss（CLM-0092）で行う。', REV_ENTRA, checks={'B': ['B10']})
vendor('CLM-0077', 'Part 1・3', 'B', '入口で Entra の AT の aud（api://orders など、v1/v2 で形式が揺れる）を確かめ、内部トークンにはサービスごとの aud（CLM-0071）を付け直す。',
       ['CLM-0071'], 'Entra を接続していないので読まない。宛先は内部トークンの aud（CLM-0071）で確かめる。', REV_ENTRA, checks={'B': ['B3']})
vendor('CLM-0129', 'Part 1・8', 'B', '入口で Entra のトークンの期限を確かめる。内部トークンは入口が 300 秒の exp（CLM-0123）で発行し直すので、Entra の長い寿命（CAE で最大 28 時間）は内側に持ち込まない。',
       ['CLM-0123'], 'Entra を接続していないので読まない。期限は内部トークンの exp（CLM-0123）で確かめる。', REV_ENTRA)
vendor('CLM-0141', 'Part 1・8', 'B', '入口で Entra のトークンの時刻の妥当性確認にだけ使う。Entra は「認証の時刻」と説明するので、認証時刻としては扱わず、内部トークンの iat（CLM-0134）は入口が付け直す。',
       ['CLM-0134'], 'Entra を接続していないので読まない。発行時刻は内部トークンの iat（CLM-0134）で表す。', REV_ENTRA)
vendor('CLM-0145', 'Part 1', 'B', '入口で Entra のトークンの nbf を検証する（標準の nbf と同義）。内部トークンには載せない。',
       ['CLM-0143'], 'Entra を接続していないので読まない。他の IdP のトークンの nbf は標準の nbf（CLM-0143）として入口で検証する。', REV_ENTRA)
vendor('CLM-0193', 'Part 3・10', 'B', '入口で Entra のトークンがアプリだけのもの（app）か利用者＋アプリかを判定し、利用者のいないトークンに user_id（ORG-02）を付けないようにする。',
       ['CLM-0030', 'CLM-0405'], 'Entra を接続していないので読まない。利用者かクライアントかは内部トークンの sub（CLM-0030）と client_id（CLM-0405）で区別する。', REV_ENTRA)
vendor('CLM-0196', 'Part 3・9', 'B', '入口で Entra のトークン ID（jti 相当）を監査ログに残し、発行した内部トークンの jti（CLM-0180）と対応づける。トークン全文は残さない。',
       ['CLM-0180'], 'Entra を接続していないので読まない。トークンの追跡は内部トークンの jti（CLM-0180）で行う。', REV_ENTRA)
vendor('CLM-0200', 'Part 3', 'B', '入口で Entra のトークンが v1.0 か v2.0 かを見て、iss・aud の形式の違いに合わせて正規化を分ける。',
       ['ORG-07'], 'Entra を接続していないので読まない。内部トークンの形式の版は名前空間の版（ORG-07）で表す。', REV_ENTRA)
for i, nm, use in [
    ('CLM-0046', 'Entra の sub', 'Entra の sub はアプリごとのペアワイズ値で、同じ人でもアプリが違えば一致しない。入口は oid+tid（CLM-0043）から組織の user_id（ORG-02）を作り、内部トークンの sub（CLM-0030）に入れるので、Entra の sub は読まない。'),
    ('CLM-0041', 'Entra の SAML の objectidentifier', 'SAML のアサーションは入口に接続していない。同じ値は JWT の oid として入口で読み、組織の user_id（ORG-02）に写す。'),
    ('CLM-0044', 'Entra の onprem_sid', 'オンプレミスの SID を内側に持ち込まない。オンプレの AD に依存する旧システムを SID で認可することはできなくなるが、利用者の照合は組織の user_id（ORG-02）で行う。'),
    ('CLM-0111', 'Entra の SAML の identityprovider', 'SAML のアサーションは入口に接続していない。どの IdP から来たかは組織の idp（ORG-06）で表す。')]:
    alt = {'CLM-0046': ['ORG-02', 'CLM-0030'], 'CLM-0041': ['ORG-02'], 'CLM-0044': ['ORG-02'], 'CLM-0111': ['ORG-06']}[i]
    altC = [a for a in alt if a != 'ORG-06'] or ['ORG-02']
    revB = {'CLM-0046': 'Entra のアプリごとの sub をキーにする外部サービスと連携する必要が出たら',
            'CLM-0041': 'Entra を SAML で入口に接続するようになったら（入口の正規化でのみ読む）',
            'CLM-0044': 'SID でしか認可できない旧システムを入口の内側に置く必要が出たら（入口の正規化でのみ読む）',
            'CLM-0111': 'Entra を SAML で入口に接続するようになったら（入口の正規化でのみ読む）'}[i]
    put(i, 'Part 3', {
        'A': d(ALT, f'{nm}は読まない（Entra を接続していない）。利用者・IdP の識別は組織のクレームが担う。', alt=alt, rev=REV_ENTRA['A']),
        'B': d(ALT, use, alt=alt, rev=revB),
        'C': d(ALT, f'{nm}は読まない（Entra を接続していない）。' + ('委任の主体は組織の user_id（ORG-02）で表す。' if i != 'CLM-0111' else 'C では元の IdP を内部トークンで運ばないので、利用者の識別だけを組織の user_id（ORG-02）で表す。'), alt=altC, rev=REV_ENTRA['C'])})
put('CLM-0045', 'Part 3', {k: d(NO, 'Entra の restricted claim set に名前があるだけで意味・発行条件の記載がなく、読む理由がない。失うものはない。', rev='Microsoft が意味を文書化し、利用者の照合に必要になったら') for k in 'ABC'})
put('CLM-0010', 'Part 3', {
    'A': d(NO, 'SSO のヒントで、API の認可にも識別にも使わない（Entra も接続していない）。再ログイン時の入力の手間を省けないだけ。', rev='顧客テナントの Entra を接続し、クライアントの再ログインを滑らかにしたくなったら'),
    'B': d(NO, '再認証時の login_hint の最適値だが、業務システムは IdP のログイン画面に任せており読まない。再ログインで利用者を選び直す手間を省けない。', rev='業務システムのクライアントが Entra への再認証を自分で組み立てるようになったら（ID トークンのみで使う）'),
    'C': d(NO, 'エージェントは利用者の再ログインを組み立てないので使い道がない。', rev='ポータルが Entra でのログインを扱うようになったら')})
put('CLM-0057', 'Part 3・5', {
    'A': d(NO, 'Entra を接続しておらず、ゲストかメンバーかの区別はテナントの所属（ORG-01）とロールで扱う。', rev='顧客テナントの Entra を接続し、ゲスト利用者を区別する必要が出たら'),
    'B': d(NO, '社内システムは社員だけを入れており、ゲストかメンバーかで分ける規則がない。ゲストを入れた場合に入口で弾けなくなる。', rev='取引先などのゲスト利用者を社内システムに入れるようになったら（入口の正規化でのみ読み、ロールに写す）'),
    'C': d(NO, 'エージェントの利用者は社員だけで、ゲストかどうかで分ける規則がない。', rev='ゲスト利用者にもエージェントへの委任を許すようになったら')})
put('CLM-0058', 'Part 3・10', {
    'A': d(NO, 'SaaS にはエージェントの委任がなく、Entra Agent ID も接続していない。', rev='顧客テナントの Entra Agent ID のエージェントが SaaS の API を呼ぶようになったら'),
    'B': d(NO, '社内システムはエージェントやデバイスの主体を受けないので、主体の種類を細かく分ける必要がない。', rev='社内システムに Entra Agent ID のエージェントからの呼び出しを許したら（入口の正規化でのみ読む）'),
    'C': d(ALT, 'Entra Agent ID は使っていない。主体と今の行為者の区別は act（CLM-0369）と client_id（CLM-0405）で表すので、主体の種類を数値で受け取れなくても困らない。', alt=['CLM-0369', 'CLM-0405'], rev='エージェントの ID 基盤を Entra Agent ID に移したら（入口の正規化でのみ読む）')})
put('CLM-0147', 'Part 3・8', {k: d(NO, 'パスワードの期限はトークンの認可に関係せず、2 つの文書で値の説明も食い違う。パスワード期限の警告を API 側で出せなくなるが、IdP の画面に任せる。', rev='業務システムが自分でパスワード期限の警告を出す必要が出たら（ID トークンのみ）' if k == 'B' else 'Entra を接続し、パスワード期限の警告を自前の画面で出す必要が出たら') for k in 'ABC'})
for i, nm in [('CLM-0175', 'aio'), ('CLM-0176', 'rh')]:
    put(i, 'Part 3', {k: d(BAN, f'Entra 内部の不透明な値（{nm}）で、リソースは使ってはならないと明記されている。読んで判断に使うと、意味の保証がない値に依存してしまう。', rev='Microsoft が意味を公開し、使ってよいと文書化したら') for k in 'ABC'})

# --- Keycloak (A, B, C)
vendor('CLM-0047', 'Part 3・4', 'ABC', {
    'A': '入口でテナントのレルムの利用者 ID（UUID）として読み、組織の user_id（ORG-02）と内部トークンの sub に写す。軽量アクセストークンでは落ちるので、欠けたら拒否する。',
    'B': '入口で Keycloak（corp レルム）の利用者の不変キーとして読み、組織の user_id（ORG-02）に写す。preferred_username は使わない。',
    'C': '利用者のログイン（corp レルム）の主体として入口で読み、交換の起点となる内部トークンの sub と user_id（ORG-02）に写す。'},
    None, '', {}, checks={'A': ['A11'], 'B': ['B1'], 'C': ['C1']})
vendor('CLM-0078', 'Part 1・3', 'ABC', {
    'A': '入口でテナントのレルムが出す aud（Audience マッパーで saas-api）を確かめる。軽量アクセストークンでは落ちるので、欠けたら拒否する。',
    'B': '入口で Keycloak の aud（orders など）を確かめ、内部トークンのサービスごとの aud（CLM-0071）に付け直す。',
    'C': '入口で利用者のトークンの aud を確かめる。エージェント・ツール向けの宛先は STS の交換で決め、Keycloak の標準交換で宛先を広げられることには頼らない。'},
    None, '', {}, checks={'A': ['A13'], 'B': ['B3'], 'C': ['C13']})
put('CLM-0083', 'Part 3・6', {
    'A': d(COND, 'テナントのレルムで API（saas-api）を aud に明示するために使う。Keycloak は既定で API を aud に入れないため、これがないと宛先の確認ができない。', cond='Keycloak のクライアント設定でのみ使う（宛先を明示するため。軽量アクセストークンでは Add to lightweight を確認）', rev='Keycloak をやめる、または宛先を resource パラメータで決める方式に変えたら', checks=['A13']),
    'B': d(COND, 'corp レルムで orders・invoices などのサービスを aud に明示するために使う。', cond='Keycloak のクライアント設定でのみ使う（宛先を明示するため）', rev='Keycloak をやめる、または宛先を resource パラメータで決める方式に変えたら', checks=['B1', 'B3']),
    'C': d(COND, 'corp レルムでポータル・mcp-tools などの宛先を明示するために使う。ホップごとの宛先は STS の交換で付け直す。', cond='Keycloak のクライアント設定でのみ使う（宛先を明示するため）', rev='Keycloak の標準トークン交換で act を出せるようになり、STS の代わりに使うなら')})
put('CLM-0052', 'Part 3・4', {
    'A': d(NO, 'ペアワイズの sub にすると同じ利用者がクライアントごとに別の値になり、入口で組織の user_id（ORG-02）に写せない。クライアント間での追跡を防ぐ効果は得られない。', rev='テナントの利用者の値を外部のクライアントに渡し、名寄せを防ぐ必要が出たら'),
    'B': d(NO, '社内システム間で同じ人を指す ID が要るため、ペアワイズは逆効果。外部への名寄せ防止は得られない。', rev='社外の取引先のアプリに Keycloak の ID トークンを渡すようになったら'),
    'C': d(NO, '委任の連鎖で同じ利用者を指し続ける必要があるため使わない。', rev='外部のエージェント事業者に利用者の識別子を渡すようになったら')})
put('CLM-0119', 'Part 8', {
    'A': d(NO, 'テナントの利用者の再認証の新しさで判断する操作がなく、認証時刻は入口で読まない。「最近認証した人だけ」の制限はできない。', rev='テナント管理の操作に再認証の時間制限を設けるなら（入口で読み CLM-0228 に写す）'),
    'B': d(NO, '重要な操作の鮮度はイントロスペクションとディレクトリの引き直しで確かめ、認証時刻では判断しない。「直近に認証したか」による制限はできない。', rev='経理の操作に再認証の時間制限（max_age）を設けるなら（入口で読み CLM-0228 に写す）', checks=['B11', 'B12']),
    'C': d(NO, '支払いは人の承認の記録（ORG-10）で確かめ、利用者の認証時刻では判断しない。', rev='承認の代わりに「直近の再認証」を求める操作を作るなら（入口で読み CLM-0228 に写す）')})
put('CLM-0198', 'Part 1・3', {
    'A': d(NO, '種類はヘッダーの typ（at+jwt）で確かめるので、Keycloak のペイロードの typ は読まない。失うものはない。', rev='Keycloak がヘッダーの typ を at+jwt で出せなくなったら（入口の正規化でのみ読む）', checks=['A13']),
    'B': d(NO, '入口はヘッダーの typ（at+jwt）で ID トークンを拒否するので、ペイロードの typ は読まない。', rev='Keycloak がヘッダーの typ を at+jwt で出せなくなったら（入口の正規化でのみ読む）', checks=['B2']),
    'C': d(NO, 'ヘッダーの typ（at+jwt）で確かめるので読まない。', rev='Keycloak がヘッダーの typ を at+jwt で出せなくなったら（入口の正規化でのみ読む）')})

# --- Auth0 (B)
vendor('CLM-0048', 'Part 3・4', 'B', '入口で Auth0 の user_id（接続名|ID の形）を利用者の不変キーとして読み、組織の user_id（ORG-02）に写す。M2M のトークンでは利用者として扱わない。',
       ['ORG-02'], 'Auth0 を接続していないので読まない。利用者の照合は組織の user_id（ORG-02）で行う。', REV_A0, checks={'B': ['B21']})
vendor('CLM-0079', 'Part 1・3', 'B', '入口で Auth0 の aud（API Identifier。openid 付きなら配列）を確かめ、内部トークンにサービスごとの aud を付け直す。',
       ['CLM-0071'], 'Auth0 を接続していないので読まない。宛先は内部トークンの aud（CLM-0071）で確かめる。', REV_A0, checks={'B': ['B21']})
vendor('CLM-0101', 'Part 1・3', 'B', '入口で Auth0 の発行者を Discovery の値と完全一致で照合する（末尾スラッシュの揺れに注意）。',
       ['CLM-0092'], 'Auth0 を接続していないので読まない。発行者は内部トークンの iss（CLM-0092）で照合する。', REV_A0)
vendor('CLM-0194', 'Part 3・9', 'B', '入口で Auth0（RFC 9068 プロファイル）のトークン ID を監査ログに残し、内部トークンの jti と対応づける。',
       ['CLM-0180'], 'Auth0 を接続していないので読まない。トークンの追跡は内部トークンの jti（CLM-0180）で行う。', REV_A0)
put('CLM-0174', 'Part 3', {
    'A': d(NO, 'Auth0 を接続しておらず、グラント種別で判断する規則もない。', rev=REV_A0['A']),
    'B': d(NO, 'グラント種別では認可せず、利用者かクライアントかは内部トークンの sub と client_id で区別する。どのグラントで取ったかを内側で見分けられないだけ。', rev='password グラントなど特定のグラントを入口で拒否する規則を作るなら（入口の正規化でのみ読む）'),
    'C': d(NO, 'Auth0 を接続しておらず、交換の種類は STS の監査ログで分かる。', rev=REV_A0['C'])})

# --- Okta (B)
vendor('CLM-0051', 'Part 3・4', 'B', '入口で Okta の AT の利用者キーとして uid を読み、組織の user_id（ORG-02）に写す。AT の sub はログイン名になりうるので使わない。',
       ['ORG-02'], 'Okta を接続していないので読まない。利用者の照合は組織の user_id（ORG-02）で行う。', REV_OKTA, checks={'B': ['B13', 'B14']})
vendor('CLM-0080', 'Part 1・3', 'B', '入口で Okta の Custom AS の audience（api://default など）を確かめる。Org AS の AT は自前の API では受けない。',
       ['CLM-0071'], 'Okta を接続していないので読まない。宛先は内部トークンの aud（CLM-0071）で確かめる。', REV_OKTA)
vendor('CLM-0099', 'Part 1・3', 'B', '入口で Okta の Custom AS の発行者を完全一致で照合し、Org AS の発行者と取り違えない。',
       ['CLM-0092'], 'Okta を接続していないので読まない。発行者は内部トークンの iss（CLM-0092）で照合する。', REV_OKTA)
vendor('CLM-0130', 'Part 1・8', 'B', '入口で Okta のトークンの期限を確かめる。内部トークンは 300 秒の exp で発行し直す。',
       ['CLM-0123'], 'Okta を接続していないので読まない。期限は内部トークンの exp（CLM-0123）で確かめる。', REV_OKTA)
vendor('CLM-0195', 'Part 3・9', 'B', '入口で Okta のトークン ID（AT. で始まる）を監査ログに残し、内部トークンの jti と対応づける。',
       ['CLM-0180'], 'Okta を接続していないので読まない。トークンの追跡は内部トークンの jti（CLM-0180）で行う。', REV_OKTA)
put('CLM-0049', 'Part 3・4', {
    'A': d(ALT, 'Okta を接続していないので読まない。利用者の照合は組織の user_id（ORG-02）で行う。', alt=['ORG-02'], rev=REV_OKTA['A']),
    'B': d(ALT, 'Okta の AT の sub はログイン名になりうり、再利用されると前任者のデータに一致する。入口は uid（CLM-0051）から組織の user_id（ORG-02）を作るので、sub は読まない。', alt=['ORG-02', 'CLM-0051'], rev='Okta が AT の sub を不変の ID に固定すると文書で保証したら', checks=['B13']),
    'C': d(ALT, 'Okta を接続していないので読まない。委任の主体は組織の user_id（ORG-02）で表す。', alt=['ORG-02'], rev=REV_OKTA['C'])})
put('CLM-0120', 'Part 8', {
    'A': d(NO, 'Okta を接続しておらず、認証時刻で判断する操作もない。', rev=REV_OKTA['A']),
    'B': d(NO, '重要な操作の鮮度はイントロスペクションとディレクトリの引き直しで確かめ、認証時刻では判断しない。「直近に認証したか」による制限はできない。', rev='経理の操作に再認証の時間制限（max_age）を設けるなら（入口で読み CLM-0228 に写す）', checks=['B11']),
    'C': d(NO, 'Okta を接続しておらず、支払いは人の承認の記録で確かめる。', rev=REV_OKTA['C'])})
put('CLM-0201', 'Part 3', {
    'A': d(NO, 'Okta を接続していない。', rev=REV_OKTA['A']),
    'B': d(NO, 'Okta のトークンの形式の版で正規化を分ける必要は今はない。Okta が形式を変えたときに入口で気づく手がかりが 1 つ減る。', rev='Okta がトークンの版を上げてクレームの形式を変えたら（入口の正規化でのみ読む）'),
    'C': d(NO, 'Okta を接続していない。', rev=REV_OKTA['C'])})
put('CLM-0118', 'Part 8', {
    'A': d(NO, 'Entra を接続しておらず、認証時刻で判断する操作もない。', rev=REV_ENTRA['A']),
    'B': d(NO, 'Entra では既定で出ず、重要な操作の鮮度はイントロスペクションとディレクトリの引き直しで確かめる。「直近に認証したか」による制限はできない。', rev='経理の操作に再認証の時間制限（max_age）を設けるなら（入口で読み CLM-0228 に写す）', checks=['B11']),
    'C': d(NO, 'Entra を接続しておらず、支払いは人の承認の記録で確かめる。', rev=REV_ENTRA['C'])})

# --- Cognito (B)
vendor('CLM-0050', 'Part 3・4', 'B', '入口で Cognito の利用者の一意 ID として読み、組織の user_id（ORG-02）に写す（形式は厳密に検証しない）。username は使わない。',
       ['ORG-02'], 'Cognito を接続していないので読まない。利用者の照合は組織の user_id（ORG-02）で行う。', REV_COG, checks={'B': ['B16']})
vendor('CLM-0081', 'Part 1・3', 'B', 'Cognito の AT には既定で aud がないので、入口は client_id で要求元のアプリを確かめ、内部トークンにサービスごとの aud を付ける。aud があれば併せて確かめる。',
       ['CLM-0071'], 'Cognito を接続していないので読まない。宛先は内部トークンの aud（CLM-0071）で確かめる。', REV_COG, checks={'B': ['B16']})
vendor('CLM-0100', 'Part 1・3', 'B', '入口で Cognito のユーザープールの発行者を完全一致で照合する（original／updated の 2 種のどちらを受けるか決めておく）。',
       ['CLM-0092'], 'Cognito を接続していないので読まない。発行者は内部トークンの iss（CLM-0092）で照合する。', REV_COG)
vendor('CLM-0131', 'Part 1・8', 'B', '入口で Cognito のトークンの期限を確かめる。失効は exp 前に分からないので、重要な操作は別に引き直す。',
       ['CLM-0123'], 'Cognito を接続していないので読まない。期限は内部トークンの exp（CLM-0123）で確かめる。', REV_COG)
put('CLM-0197', 'Part 1・3', {
    'A': d(NO, 'Cognito を接続しておらず、種類はヘッダーの typ（at+jwt）で確かめる。', rev=REV_COG['A']),
    'B': d(COND, 'Cognito のトークンはヘッダーで種類を区別できないので、入口で token_use=access を確かめて ID トークンを拒否する。', cond=GW, rev='Cognito を入口から外す、または Cognito がヘッダーの typ で種類を示すようになったら', checks=['B17']),
    'C': d(NO, 'Cognito を接続しておらず、種類はヘッダーの typ（at+jwt）で確かめる。', rev=REV_COG['C'])})
put('CLM-0202', 'Part 3', {
    'A': d(NO, 'Cognito を接続していない。', rev=REV_COG['A']),
    'B': d(NO, '意味の説明がなく、正規化を分ける根拠にならない。失うものはない。', rev='Cognito が版の意味を文書化し、版でクレームの形式が変わるようになったら'),
    'C': d(NO, 'Cognito を接続していない。', rev=REV_COG['C'])})
put('CLM-0007', 'Part 3', {
    'A': d(ALT, 'Cognito を接続していない。どの IdP から来たかは組織の idp（ORG-06）、利用者は user_id（ORG-02）で表す。', alt=['ORG-02', 'ORG-06'], rev=REV_COG['A']),
    'B': d(ALT, 'Cognito にリンクした外部 IdP の一覧は ID トークンにしか出ず、型も揺れる（primary が文字列）。どの IdP から来たかは組織の idp（ORG-06）、利用者は user_id（ORG-02）で表す。', alt=['ORG-02', 'ORG-06'], rev='Cognito のフェデレーションで外部 IdP ごとに扱いを変える必要が出たら（入口の正規化でのみ読む）'),
    'C': d(ALT, 'Cognito を接続していない。委任の主体は組織の user_id（ORG-02）で表す。', alt=['ORG-02'], rev=REV_COG['C'])})

# --- login names (personal data): never in access tokens
for i, nm in [('CLM-0061', 'Cognito の cognito:username'), ('CLM-0062', 'Entra の upn'), ('CLM-0063', 'Keycloak の upn（MicroProfile）'), ('CLM-0064', 'Cognito の username')]:
    put(i, 'Part 4・9', {
        'A': d(BAN, f'{nm}はログイン名で、直接識別できる個人情報かつ再利用されうる。アクセストークンに載せて照合に使うと別人に一致しうる。表示が必要なら UserInfo から取る。', rev='ログイン名を表示に使う画面ができても UserInfo・API から取る方針を変えるなら'),
        'B': d(BAN, f'{nm}はログイン名で、再利用されると前任者のデータに一致する。入口は不変の ID から組織の user_id（ORG-02）を作り、ログイン名は内部トークンにもログにも載せない。', rev='ログイン名を表示に使う画面ができても UserInfo・API から取る方針を変えるなら', checks=['B13']),
        'C': d(BAN, f'{nm}はログイン名で個人情報。エージェント・ツールへ流れるトークンに載せると、第三者のツールに個人情報が渡る。', rev='ログイン名を表示に使う画面ができても UserInfo・API から取る方針を変えるなら')})
for i, nm in [('CLM-0059', 'LDAP の uid'), ('CLM-0060', 'SCIM の userName')]:
    put(i, 'Part 4・9', {k: d(BAN, f'{nm}はログイン名として使われる個人情報で、改名・再利用がありうる。アクセストークンに載せて照合に使うと別人に一致しうる。' + {'A': '', 'B': '利用者は組織の user_id（ORG-02）で照合する。', 'C': 'エージェント側のツールにも個人情報が渡る。'}[k], rev='ログイン名を表示に使う画面ができても UserInfo・API から取る方針を変えるなら', checks=(['B13'] if k == 'B' else [])) for k in 'ABC'})

# --- SCIM / LDAP identifiers
put('CLM-0028', 'Part 4', {k: d(ALT, 'SCIM のプロビジョニング先が割り当てる ID は、そのサービスの中でしか意味を持たない。組織内で同じ人を指す役は組織の user_id（ORG-02）が担い、必要なら入口で SCIM の id から写す。', alt=['ORG-02'], rev={'A': '顧客テナントから SCIM でプロビジョニングを受けるようになったら（入口の正規化でのみ読む）', 'B': 'SCIM で社員を各業務システムへ配るようになり、その ID で照合する旧システムが残ったら', 'C': 'エージェント事業者へ SCIM で利用者を配るようになったら'}[k]) for k in 'ABC'})
put('CLM-0006', 'Part 4', {k: d(ALT, 'プロビジョニング元の識別子は元のドメインの中でしか意味を持たない。組織内の不変 ID は組織の user_id（ORG-02）で運ぶ。', alt=['ORG-02'], rev={'A': '顧客テナントの人事システムの ID で利用者を引く要件ができたら', 'B': '人事システムの ID でしか引けない旧システムを内部トークンで呼ぶ必要が出たら', 'C': 'エージェントが人事システムの ID で利用者を引くツールを使うようになったら'}[k]) for k in 'ABC'})
put('CLM-0032', 'Part 4', {k: d(ALT, 'LDAP の一意識別子（ビット列）をトークンに入れる理由がない。組織内の不変 ID は組織の user_id（ORG-02）で運ぶ。', alt=['ORG-02'], rev='LDAP の一意識別子でしか利用者を引けない旧システムを内部トークンで呼ぶ必要が出たら') for k in 'ABC'})
for i in ['CLM-0004', 'CLM-0005']:
    src = 'SCIM 拡張' if i == 'CLM-0004' else 'LDAP（inetOrgPerson）'
    put(i, 'Part 4・9', {
        'A': d(NO, f'{src}の社員番号。顧客テナントの利用者に社員番号はなく使い道がない。', rev='自社の社員を運用担当として SaaS に入れ、社員番号で監査する必要が出たら'),
        'B': d(ALT, f'{src}の社員番号をそのまま載せず、入口で組織の employee_id（ORG-05）に文字列として写し、必要な旧システム宛てだけに載せる。', alt=['ORG-05'], rev='旧システムが社員番号を必要としなくなったら（ORG-05 ごと外す）'),
        'C': d(NO, f'{src}の社員番号。委任の主体は user_id で表すので要らない。', rev='エージェントが社員番号をキーにする旧システムを呼ぶようになったら')})
put('CLM-0002', 'Part 8', {
    'A': d(NO, 'トークン内の値は発行時点の写しで、アカウントの無効化をすぐには反映しない。無効化は 300 秒の寿命とテナント側の DB で扱い、トークンでアカウントの状態を示すことはできない。', rev='トークンの寿命を延ばし、無効化をトークンで伝える必要が出たら'),
    'B': d(NO, '発行時点の写しで、無効化の即時反映にならない。退職・停止は重要な操作でのイントロスペクションとディレクトリ参照で確かめる。', rev='重要な操作以外でもアカウントの停止を即時に反映する必要が出たら', checks=['B12']),
    'C': d(NO, '発行時点の写しで、無効化の即時反映にならない。利用者の停止は交換時の再確認で反映する。', rev='交換時の再確認をやめ、トークンだけで判断するようになったら')})

# --- SAML subject identifiers
REV_SAML = {'A': '顧客テナントが SAML の IdP を持ち込み、入口に接続したら（入口の正規化でのみ読む）', 'B': '社内の SAML IdP を入口に接続したら（入口の正規化でのみ読む）', 'C': 'エージェントの利用者が SAML の IdP でログインするようになったら（入口の正規化でのみ読む）'}
put('CLM-0056', 'Part 2・4', {k: d(ALT, 'SAML の全 RP 共通の識別子。SAML は入口に接続しておらず、組織内で同じ人を指す役は組織の user_id（ORG-02）が担う。', alt=['ORG-02'], rev=REV_SAML[k]) for k in 'ABC'})
put('CLM-0015', 'Part 2・4', {k: d(ALT, 'SAML の RP ごとの識別子。SAML は入口に接続しておらず、内部では RP をまたいで同じ人を指す必要があるので組織の user_id（ORG-02）を使う。', alt=['ORG-02'], rev=REV_SAML[k]) for k in 'ABC'})
put('CLM-0192', 'Part 2', same(d(OOS, 'SAML の RP メタデータで要求する識別子の種類で、トークンのクレームではない。')))

# --- eduPerson (academic)
for i in ['CLM-0013', 'CLM-0014', 'CLM-0055', 'CLM-0065', 'CLM-0066']:
    put(i, 'Part 2', same(d(OOS, '学術認証連合（eduPerson）の属性で、3 つのケースの会社は学術連合に参加しない。')))

# --- other platforms acting as login providers
REV_PLAT = lambda p: {'A': f'顧客テナントの利用者が {p} でログインできるようにしたら（入口の正規化でのみ読む）', 'B': f'社内システムのログインに {p} を使うようになったら（入口の正規化でのみ読む）', 'C': f'エージェントの利用者が {p} でログインするようになったら（入口の正規化でのみ読む）'}
for i, p, alt, what in [
    ('CLM-0019', 'Google', ['ORG-02'], 'Google アカウントの不変 ID'),
    ('CLM-0020', 'Sign in with Apple', ['ORG-02'], 'Apple の開発チーム内の利用者 ID'),
    ('CLM-0026', 'Firebase Authentication', ['ORG-02'], 'Firebase の uid'),
    ('CLM-0054', 'Firebase Authentication', ['ORG-02'], 'Firebase の予約名 user_id'),
    ('CLM-0008', 'Firebase Authentication', ['ORG-02', 'ORG-06'], 'Firebase の連携先 ID の一覧'),
    ('CLM-0087', 'Firebase Authentication', ['CLM-0071'], 'Firebase の ID トークンの aud（プロジェクト ID）'),
    ('CLM-0105', 'Firebase Authentication', ['CLM-0092'], 'Firebase の ID トークンの iss'),
    ('CLM-0018', 'Cloudflare Access', ['ORG-02'], 'Cloudflare Access のアプリケーショントークンの利用者 ID'),
    ('CLM-0082', 'Cloudflare Access', ['CLM-0071'], 'Cloudflare Access の AUD タグ'),
    ('CLM-0053', 'Hasura', ['ORG-02'], 'Hasura の権限ルール用のユーザー ID')]:
    altC = alt if 'ORG-06' not in alt else ['ORG-02']
    cover = {'ORG-02': '組織の user_id（ORG-02）', 'CLM-0071': '内部トークンの aud（CLM-0071）', 'CLM-0092': '内部トークンの iss（CLM-0092）'}[alt[0]]
    rev = REV_PLAT(p) if p != 'Hasura' else {'A': 'Hasura を API 層に採り入れたら（入口で内部トークンから作る）', 'B': 'Hasura を API 層に採り入れたら（入口で内部トークンから作る）', 'C': 'Hasura を API 層に採り入れたら（入口で内部トークンから作る）'}
    put(i, 'Part 3', {k: d(ALT, f'{what}は、{p} を使っていないので読まない。同じ役は{cover}が担う。', alt=(altC if k == 'C' else alt), rev=rev[k]) for k in 'ABC'})
put('CLM-0003', 'Part 3', {k: d(NO, {'A': 'SaaS は匿名の利用者を受けないので使い道がない（Supabase も使っていない）。', 'B': '社内システムは匿名の利用者を受けない。', 'C': 'エージェントへの委任は認証した利用者だけに許し、匿名の利用者はいない。'}[k], rev={'A': '試用版などで匿名の利用者を受け入れるようになったら', 'B': '社内の公開ページで匿名の利用者を受け入れるようになったら', 'C': '匿名の利用者にもエージェントを使わせるようになったら'}[k]) for k in 'ABC'})
put('CLM-0027', 'Part 3', {k: d(NO, 'Sign in with Apple のアプリ移管用の識別子で、Apple を使っていないので使い道がない。', rev='Sign in with Apple を採り入れ、アプリを別の開発チームへ移管することになったら') for k in 'ABC'})
put('CLM-0199', 'Part 3', {k: d(NO, 'Cloudflare Access のトークンの種類（app／org）で、Cloudflare Access を使っていない。種類はヘッダーの typ（at+jwt）で確かめる。', rev='社内システムを Cloudflare Access の後ろに置くようになったら（入口の正規化でのみ読む）' if k == 'B' else 'Cloudflare Access を入口に置くようになったら（入口の正規化でのみ読む）') for k in 'ABC'})
put('CLM-0010', 'Part 3', D['CLM-0010'][1])

# --- CI/CD, workload platforms
CI = 'CI/CD のジョブが発行するトークンの属性。本ケーススタディはデプロイ基盤を扱わず（B も業務システムの利用者の認可だけ）、利用者・エージェントの API 認可には使わない。'
for i in ['CLM-0009', 'CLM-0021', 'CLM-0022', 'CLM-0024', 'CLM-0025', 'CLM-0084', 'CLM-0085', 'CLM-0086', 'CLM-0103', 'CLM-0104']:
    put(i, 'Part 2', same(d(OOS, CI)))
WL = 'ワークロード（Kubernetes の ServiceAccount）のトークン。サービス間の呼び出しは入口が発行する内部トークン（client_id・act）で表し、ワークロード ID の基盤は実験の範囲外。'
for i in ['CLM-0023', 'CLM-0150']:
    put(i, 'Part 2', same(d(OOS, WL)))
put('CLM-0069', 'Part 2', same(d(OOS, 'SPIFFE のワークロード ID。人間の利用者を表さず、サービス間の認証は内部トークン（client_id・act）で表すため実験の範囲外。C のツールの身元に使う余地はあるが、今回はクライアント ID で足りている。')))
AWS = 'AWS STS が外向けに発行するワークロードのトークン（GetWebIdentityToken）。3 つのケースは AWS のワークロードから外部 API を呼ばないため範囲外。'
for i in ['CLM-0042', 'CLM-0067', 'CLM-0068', 'CLM-0102', 'CLM-0112', 'CLM-0149']:
    put(i, 'Part 2', same(d(OOS, AWS)))

# --- unrelated domains
for i in ['CLM-0016', 'CLM-0107', 'CLM-0108']:
    put(i, 'Part 2', same(d(OOS, '電話の発信者認証（STIR/PASSporT）専用で、Web・API のトークンでは使わない。')))
put('CLM-0001', 'Part 2', same(d(OOS, '3GPP CAPIF（通信事業者の API 公開）専用で、3 つのケースに関係しない。')))
put('CLM-0152', 'Part 2', same(d(OOS, 'ETSI NFV（ネットワーク機能仮想化）専用で、3 つのケースに関係しない。')))
for i in ['CLM-0121', 'CLM-0146', 'CLM-0153']:
    put(i, 'Part 2', same(d(OOS, 'IoT の制約デバイス向け ACE-OAuth 専用で、時計を持つサーバー間の 3 つのケースには関係しない。')))
for i in ['CLM-0155', 'CLM-0156', 'CLM-0157', 'CLM-0158', 'CLM-0159']:
    put(i, 'Part 2', same(d(OOS, 'CDN 相互接続（CDNI）の URI 署名トークン専用で、利用者の API 認可には使わない。')))
for i in ['CLM-0011', 'CLM-0012', 'CLM-0106', 'CLM-0110', 'CLM-0142', 'CLM-0148']:
    put(i, 'Part 2', {'A': d(OOS, 'UK Open Banking（FAPI 対応の銀行 API）専用で、SaaS の API には関係しない。'),
                      'B': d(OOS, 'UK Open Banking（FAPI 対応の銀行 API）専用で、社内システムには関係しない。'),
                      'C': d(OOS, 'UK Open Banking の銀行 API 専用。C の支払いは社内の支払い API で、銀行と直接つながらないため範囲外。')})
for i in ['CLM-0088', 'CLM-0089', 'CLM-0090'] + ['CLM-%04d' % n for n in range(160, 174)]:
    put(i, 'Part 2', same(d(OOS, 'OpenID Federation のエンティティステートメント・トラストマーク専用で、ID トークン・アクセストークンには入らない。3 つのケースは信頼関係を個別に設定する。')))

# --- Verifiable credentials, SD-JWT, KB-JWT
VC = '検証可能な資格情報（VC）とその提示の語彙で、3 つのケースは VC を発行も受け取りもしない。'
for i in ['CLM-0037', 'CLM-0095', 'CLM-0126', 'CLM-0138', 'CLM-0144', 'CLM-0154', 'CLM-0184', 'CLM-0203', 'CLM-0204', 'CLM-0205', 'CLM-0072', 'CLM-0135']:
    put(i, 'Part 2', same(d(OOS, VC)))

# --- SET (RFC 9493 / SSF)
for i, src in [('CLM-0031', 'RFC 9493 の Subject Identifier'), ('CLM-0035', 'Shared Signals Framework の SET')]:
    put(i, 'Part 8', {
        'A': d(NO, f'{src}は、IdP からのセキュリティイベント（SET）で主体を表すもの。SET を受けていないので、テナントの IdP での失効やアカウント停止を即時に受け取れない。', rev='顧客テナントの IdP から SSF/CAEP でセッション失効を受け取るようにしたら'),
        'B': d(NO, f'{src}は SET 専用。SET を受けていないので、IdP 側の失効を即時に受け取れず、重要な操作のイントロスペクションで補う。', rev='IdP から SSF/CAEP でセッション失効・異動を受け取るようにしたら', checks=['B11', 'B12']),
        'C': d(NO, f'{src}は SET 専用。委任の取り消しは交換時の再確認で反映し、SET は受けない。', rev='利用者の IdP から SSF/CAEP で失効を受け取り、エージェントの委任を即時に止める必要が出たら', checks=['C9'])})

# --- DPoP proof
for i, nm in [('CLM-0133', 'iat'), ('CLM-0179', 'jti')]:
    put(i, 'Part 9・6', {
        'A': d(NO, f'DPoP の証明の {nm}。送信者制約は見送るので使わない。漏れたトークンを別の端末から再送されても、寿命（300 秒）の間は防げない。', rev='トークンが顧客テナントの外（連携先）へ渡るようになったら、または盗用の兆候があったら'),
        'B': d(NO, f'DPoP の証明の {nm}。送信者制約（DPoP・mTLS）は見送るので使わない。漏れたトークンを別の端末から再送されると通る。', rev='トークンが社外・取引先へ渡るようになったら、または盗用の兆候があったら', checks=['B23']),
        'C': d(NO, f'DPoP の証明の {nm}。ホップごとに宛先を束縛した短命トークンで代え、送信者制約は使わない。漏れたトークンは宛先と寿命の範囲で再送されうる。', rev='エージェントやツールを社外の事業者が動かすようになったら、または盗用の兆候があったら')})

# --- Transaction tokens (draft)
TXN_ALT = {'CLM-0038': ['CLM-0030', 'ORG-02'], 'CLM-0075': ['CLM-0071'], 'CLM-0096': ['CLM-0092'], 'CLM-0127': ['CLM-0123'], 'CLM-0139': ['CLM-0134']}
for i, alt in TXN_ALT.items():
    nm = {'CLM-0038': 'sub', 'CLM-0075': 'aud', 'CLM-0096': 'iss', 'CLM-0127': 'exp', 'CLM-0139': 'iat'}[i]
    put(i, 'Part 6・10', {
        'A': d(ALT, f'Transaction Token（草案）の {nm}。内部の呼び出しは入口が発行する内部トークン（RFC 9068 の形）で運ぶので、同じ役は {", ".join(alt)} が担う。', alt=alt, rev='RFC になり、サービス間の呼び出しの連鎖で取引の文脈を運ぶ必要が出たら'),
        'B': d(ALT, f'Transaction Token（草案）の {nm}。業務システム間の呼び出しは内部トークンで運び、同じ役は {", ".join(alt)} が担う。', alt=alt, rev='RFC になり、業務システム間で取引の文脈を運ぶ必要が出たら'),
        'C': d(ALT, f'Transaction Token（草案）の {nm}。ホップごとの交換で作る内部トークンが同じ役を担い、同じ値は {", ".join(alt)} で表す。', alt=alt, rev='RFC になり、エージェントの呼び出しの連鎖を Txn-Token で運ぶ実装が IdP・ライブラリに揃ったら')})

# --- ID-JAG (draft)
JAG = {'CLM-0036': 'aud_sub', 'CLM-0039': 'sub', 'CLM-0040': 'sub_id', 'CLM-0076': 'aud', 'CLM-0097': 'iss', 'CLM-0128': 'exp', 'CLM-0140': 'iat', 'CLM-0182': 'jti'}
for i, nm in JAG.items():
    put(i, 'Part 10', {
        'A': d(NO, f'ID-JAG（草案）の {nm}。別組織の認可サーバーに利用者を引き継ぐ仕組みで、SaaS の API は自前の入口で完結するので使い道がない。', rev='RFC になり、顧客テナントの IdP から SaaS の認可サーバーへ ID-JAG で引き継ぐ要望が出たら'),
        'B': d(NO, f'ID-JAG（草案）の {nm}。社内システムは同じ組織の入口で完結し、別組織の認可サーバーへ引き継がない。', rev='RFC になり、社外の SaaS を社員の SSO のまま呼ぶ必要が出たら'),
        'C': d(NO, f'ID-JAG（草案）の {nm}。エージェントの呼び出し先は社内の API だけで、別組織の認可サーバーへ利用者を引き継がない。外部の SaaS をエージェントから呼ぶことはできない。', rev='RFC になり、エージェントが社外の SaaS の API を利用者の代わりに呼ぶようになったら')})
put('CLM-0109', 'Part 10', {
    'A': d(NO, 'ID-JAG（草案）の resource。宛先は内部トークンの aud で表し、ID-JAG を使わない。', rev='RFC になり、ID-JAG を採り入れたら'),
    'B': d(NO, 'ID-JAG（草案）の resource。宛先は内部トークンの aud で表し、ID-JAG を使わない。', rev='RFC になり、ID-JAG を採り入れたら'),
    'C': d(ALT, 'ID-JAG（草案）の resource。ホップごとの宛先は交換時に決めて内部トークンの aud（CLM-0071）に単一の値で入れるので、同じ役を aud が担う。', alt=['CLM-0071'], rev='RFC になり、エージェントが社外の SaaS を ID-JAG で呼ぶようになったら', checks=['C13'])})

# --- Token Status List (draft)
STATUS = {'A': ('個々のトークンを期限前に無効化する手段がない。内部トークンは 300 秒の寿命で切れるのを待つ。', 'RFC になり、寿命の長いトークンを期限前に無効化する必要が出たら'),
          'B': ('個々のトークンを期限前に無効化できず、重要な操作のイントロスペクションで補う。', 'RFC になり、入口や IdP が Status List に対応したら', ['B12']),
          'C': ('個々のトークンを期限前に無効化できず、タスク単位の短命トークンと交換時の取り消しの再確認で補う。', 'RFC になり、委任の取り消しをホップの途中のトークンにも即時に反映する必要が出たら', ['C9'])}
for i in ['CLM-0017', 'CLM-0151', 'CLM-0185', 'CLM-0186', 'CLM-0187', 'CLM-0188', 'CLM-0189', 'CLM-0190', 'CLM-0191']:
    put(i, 'Part 8', {k: d(NO, 'Token Status List（草案）の要素。' + STATUS[k][0], rev=STATUS[k][1], checks=(STATUS[k][2] if len(STATUS[k]) > 2 else [])) for k in 'ABC'})

# --- JWT introspection response
put('CLM-0177', 'Part 1・8', {
    'A': d(NO, 'イントロスペクションは使わず、自己完結の内部トークンで判断する。応答に署名を求める場面がない。', rev='テナントの連携先へイントロスペクションの結果を中継するようになったら'),
    'B': d(NO, '重要な操作ではイントロスペクションを使うが、入口から認可サーバーへ直接問い合わせるので、署名つきの JWT 応答は要らない。応答の改ざんを受け手が検出できないが、TLS の直接接続で足りる。', rev='イントロスペクションの結果を別のサービスへ中継・保存するようになったら', checks=['B11', 'B12']),
    'C': d(NO, '取り消しの再確認は STS の中で行い、イントロスペクションの JWT 応答を使わない。', rev='ツールが外部の認可サーバーにトークンの状態を問い合わせるようになったら')})

# --- NIST IR 8112 metadata
for i, nm, b in [
    ('CLM-0113', 'Cache Time to Live（キャッシュしてよい期間）', '属性ごとにキャッシュの期間を示せず、部門などの値は一律に「重要な操作で引き直す」規則で扱う。'),
    ('CLM-0114', 'Data Deletion Date（削除すべき日付）', 'トークンに削除期限を持たせず、ログにはトークン全文と個人情報のクレームを残さない規則で代える。'),
    ('CLM-0115', 'Expiration Date（属性値の有効期限）', '属性値ごとの有効期限を示せず、トークン全体の exp と重要な操作での引き直しで扱う。'),
    ('CLM-0116', 'Last Refresh（最後に更新した日時）', '属性値の古さを受け手が判断できず、重要な操作では一律に引き直す。'),
    ('CLM-0117', 'Last Verification（最後に検証した日時）', '属性値がいつ確かめられたかを受け手が判断できず、重要な操作では一律に引き直す。')]:
    put(i, 'Part 8・11', {
        'A': d(NO, f'NIST IR 8112 の属性メタデータ {nm}で、トークンのクレーム名は定義されていない。' + b, rev='テナントごとに属性の鮮度の要件が分かれ、受け手が判断する必要が出たら'),
        'B': d(NO, f'NIST IR 8112 の属性メタデータ {nm}で、クレーム名は定義されていない。' + b, rev='属性ごとに鮮度の要件が分かれ、受け手が属性単位で判断する必要が出たら', checks=(['B11'] if i in ('CLM-0113', 'CLM-0115', 'CLM-0116') else [])),
        'C': d(NO, f'NIST IR 8112 の属性メタデータ {nm}で、クレーム名は定義されていない。' + b.replace('重要な操作では一律に引き直す', '交換時に一律に確かめ直す').replace('重要な操作での引き直し', '交換時の再確認'), rev='エージェントが受け取る属性ごとに鮮度の要件が分かれたら')})

put('CLM-0183', 'Part 11', {k: d(NO, 'SCIM のリソースのメタデータ（作成・更新日時、版）で、トークンに載せる理由がない。属性が最後にいつ変わったかを受け手が知る手段にはならない。', rev='SCIM でプロビジョニングを受け、更新の版で同期の漏れを検出する必要が出たら') for k in 'ABC'})

# ============================================================ write
assign = json.load(open(ROOT + 'decisions/assign1.json', encoding='utf-8'))
missing = [i for i in assign if i not in D]
extra = [i for i in D if i not in assign]
if missing or extra:
    print('missing', missing, 'extra', extra)
    sys.exit(1)
out = []
for i in assign:
    part, cases = D[i]
    out.append({'id': i, 'guide_part': part, 'A': cases['A'], 'B': cases['B'], 'C': cases['C']})
json.dump(out, open(ROOT + 'decisions/part1.json', 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
print('wrote', len(out))

# -*- coding: utf-8 -*-
"""Links used by build_xlsx.py: section anchors for RFCs, Japanese book references (title + chapter/section +
printed pages, linked to the publisher's page), the guide's web slides and the case-study results."""
import re

BOOKS = {
    'oidc': ('『OpenID Connect入門』（技術評論社 2026）', 'https://gihyo.jp/book/2026/978-4-297-15456-1'),
    'kc': ('『実践 Keycloak』（オライリー・ジャパン 2022）', 'https://www.oreilly.co.jp/books/9784814400096/'),
    'di': ('『デジタルアイデンティティのすべて』（オライリー・ジャパン 2024）', 'https://www.oreilly.co.jp/books/9784814400980/'),
    'sa': ('『セキュアAPI』（翔泳社 2026）', 'https://www.shoeisha.co.jp/book/detail/9784798196336'),
}

# synonym group -> list of (book, chapter/section and printed pages). Taken from the guide's book mapping notes
# (jwt-claims-guide/research/notes/10–13). 『デジタルアイデンティティのすべて』 is cited for principles only (考え方).
BOOK_REFS = {
    'G-user-id': [('kc', '2.4 節 p.24・4.5 節 p.54（sub をキーにする）'), ('di', '10.2 節 pp.135–136（不変の識別子、考え方）')],
    'G-subject': [('kc', '2.4 節 p.24'), ('oidc', '4.3 節 p.67')],
    'G-username': [('kc', '2.4 節 p.24（ログイン名をキーにしない）')],
    'G-email': [('kc', '14.4 節 p.293（個人情報は最小限）'), ('di', '4.2.2 節 p.31（最小限の開示、考え方）')],
    'G-name': [('kc', '14.4 節 p.293（個人情報は最小限）'), ('di', '4.2.2 節 p.31（考え方）')],
    'G-audience': [('oidc', '13.8・13.9.6 節 pp.225–229（aud の確認）'), ('kc', '5.5 節 pp.75–83（aud・ロール・スコープで絞る）')],
    'G-issuer': [('oidc', '13.8.1 節 p.227'), ('kc', '4.3 節 pp.45–46（発行者 URL）')],
    'G-exp': [('oidc', '13.9.7 節 p.229（有効期間を短く）'), ('kc', '12.3.1 節 pp.243–244')],
    'G-iat': [('oidc', '4.3 節 p.67')],
    'G-jti': [('oidc', '4.3 節 p.67')],
    'G-nonce': [('oidc', '5.2.6 節・5.6 節 pp.79–80')],
    'G-acr': [('oidc', '4.3 節 p.67'), ('di', '11.4 節 pp.173–179（認証の強さ、考え方）')],
    'G-amr': [('oidc', '4.3 節 p.67'), ('di', '11.4 節 pp.173–179（考え方）')],
    'G-auth-time': [('oidc', '4.3 節 p.67')],
    'G-auth_time': [('oidc', '4.3 節 p.67')],
    'G-session': [('oidc', '7.4 節 p.101（sid）')],
    'G-sid': [('oidc', '7.4 節 p.101（sid）')],
    'G-scope': [('oidc', '5.2.1 節 pp.74–75（scope はクライアントに許す範囲）'), ('kc', '5.5.3 節 pp.81–82（スコープ名の付け方）')],
    'G-roles': [('kc', '8.2 節 pp.145–146・5.5.2 節 pp.77–81'), ('di', '12.2.5 節 p.194（RBAC は ABAC の特別な場合、考え方）'), ('oidc', '4.3 節 NOTE p.68')],
    'G-groups': [('kc', '8.2 節 pp.145–146（ロールはグループに割り当てる）')],
    'G-entitlements': [('kc', '8 章 pp.143–156（認可の戦略）')],
    'G-tenant': [('kc', '1.4.1 節 p.11・4.3 節 pp.45–46（レルム）')],
    'G-organization': [('kc', '1.4.1 節 p.11（レルム）')],
    'G-client-id': [('oidc', '4.2.2 節 表 4.1 p.62')],
    'G-actor': [('di', '18.6.1 節 p.326（委任は個別に取り消せるべき、考え方）')],
    'G-authz-details': [('sa', '7.7 節 pp.219–223')],
    'G-authorization-details': [('sa', '7.7 節 pp.219–223')],
    'G-cnf': [('sa', '7.5 節 pp.212–216'), ('oidc', '13.7 節 NOTE p.225（FAPI 2.0）')],
    'G-jose-header': [('oidc', '4.2.2 節 pp.62–65'), ('kc', '14.5.2 節 p.295')],
    'G-attr-metadata': [('di', '6 章 pp.53–58（属性のライフサイクル、考え方）')],
    'G-attr-schema-metadata': [('di', '6 章 pp.53–58（考え方）')],
    'G-pairwise-id': [('di', '4.2.4 節 pp.33–35（指向性を持つ識別子、考え方）')],
    'G-federation': [('di', '13 章（フェデレーション、考え方）'), ('kc', '10.3 節 pp.195–199')],
    'G-upstream-idp': [('kc', '10.3 節 pp.195–199')],
    'G-namespace-object': [('kc', '5.5.3 節 pp.81–82（名前に接頭辞を付ける）')],
    'G-custom-attr': [('kc', '4.5.2 節 pp.56–57（カスタム属性はマッパーで出す）')],
    'G-department': [('di', '12.6 節 pp.199–200（変わりやすい属性は載せない、考え方）')],
    'G-employee-id': [('di', '10.2 節 pp.135–136（考え方）')],
}

GUIDE = 'https://takenori-kusaka.github.io/jwt-claims-guide/'
RESULTS = 'https://github.com/Takenori-Kusaka/jwt-claims-casestudy/blob/main/results/summary.md'


def book_refs(row):
    refs = BOOK_REFS.get(row.get('synonym_group') or '')
    if not refs:
        return '', ''
    text = '／'.join(BOOKS[b][0] + ' ' + where for b, where in refs)
    return text, BOOKS[refs[0][0]][1]


def source_link(row):
    """URL with a section anchor for RFCs when the citation names a section."""
    url = row.get('url') or ''
    src = row.get('source') or ''
    m = re.search(r'RFC\s?(\d{4,5})\s*§\s*([0-9A-Z][0-9.]*)', src)
    if m and ('rfc-editor.org' in url or 'datatracker' in url or not url):
        return 'https://www.rfc-editor.org/rfc/rfc%s#section-%s' % (m.group(1), m.group(2).rstrip('.'))
    return url

# first slide (the divider) of each Part in the published guide (152 slides, 2026-11-18)
PART_SLIDE = {0: 2, 1: 9, 2: 17, 3: 31, 4: 45, 5: 62, 6: 75, 7: 91, 8: 102, 9: 112, 10: 121, 11: 132, 12: 145}


def guide_link(part_text):
    m = re.search(r'Part\s?(\d+)', part_text or '')
    if not m:
        return GUIDE
    return GUIDE + '#s%d' % PART_SLIDE.get(int(m.group(1)), 1)

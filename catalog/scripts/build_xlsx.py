# -*- coding: utf-8 -*-
"""Build catalog/jwt-claims-catalog.xlsx from catalog/catalog.json and catalog/decisions/part*.json.
  python catalog/scripts/build_xlsx.py"""
import collections
import sys
import glob
import json
import os

from openpyxl import Workbook
from openpyxl.formatting.rule import FormulaRule
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.datavalidation import DataValidation

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import links  # noqa: E402
CAT = os.path.dirname(HERE)
OUT = os.path.join(CAT, 'jwt-claims-catalog.xlsx')
FONT = 'Meiryo'
IDPS = [('Entra', 'Entra ID'), ('Keycloak', 'Keycloak'), ('Auth0', 'Auth0'), ('Okta', 'Okta'), ('Cognito', 'Cognito')]
JUDGE = ['必須（共通基準）', '採用', '条件付き採用', '不採用・代替あり', '不採用・不要', '不採用・禁止', '対象外']
CASES = [('A', 'ケース A：マルチテナント SaaS'), ('B', 'ケース B：社内業務システム'), ('C', 'ケース C：AI エージェントの委任')]
CASE_COLS = [('judgement', '判定'), ('condition', '条件'), ('alt', '代替クレーム（ID）'), ('use_or_loss', '用途／失うこと'), ('revisit', '見直し条件'), ('checks', '検証 ID')]
JFILL = {'必須（共通基準）': '1F6F4A', '採用': '3B8458', '条件付き採用': 'D18A0B', '不採用・代替あり': '4E6A86', '不採用・不要': '8A949C', '不採用・禁止': 'C2413B', '対象外': 'C9CED2'}

HEAD_FILL = PatternFill('solid', fgColor='13324A')
SUB_FILL = PatternFill('solid', fgColor='EDF2F4')
CASE_FILL = {'A': PatternFill('solid', fgColor='0B6E78'), 'B': PatternFill('solid', fgColor='4E6A86'), 'C': PatternFill('solid', fgColor='7A5BA8')}
THIN = Side(style='thin', color='D3DCDF')
BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)


def f(bold=False, color='17202B', size=10, italic=False):
    return Font(name=FONT, bold=bold, color=color, size=size, italic=italic)


def load():
    rows = json.load(open(os.path.join(CAT, 'catalog.json'), encoding='utf-8'))
    dec = {}
    for p in sorted(glob.glob(os.path.join(CAT, 'decisions', 'part*.json'))):
        for d in json.load(open(p, encoding='utf-8')):
            dec[d['id']] = d
    import sys
    sys.path.insert(0, HERE)
    import header_rows
    for d in header_rows.decisions():
        dec.setdefault(d['id'], d)
    return rows, dec


def main_columns():
    cols = [('no', 'No', 6), ('id', 'ID', 11), ('category', '分類', 14), ('name', 'クレーム名', 30), ('purpose', '意味（表すこと／表さないこと）', 46),
            ('value_type', '値の型', 18), ('multiplicity', '値の数', 10), ('token', '載るトークン', 16), ('source_kind', '出典の種別', 18),
            ('source', '出典（節）', 30), ('url', '出典 URL', 30), ('book', '書籍の該当箇所', 34), ('status', '状態', 14), ('change_controller', '変更管理者', 16)]
    cols += [('sup_' + k, 'IdP での扱い：' + lab, 13) for k, lab in IDPS]
    cols += [('writer', '値を書ける主体', 18), ('mutability', '可変性', 14), ('freshness', '鮮度', 18), ('authz_use', '認可に使ってよいか', 16),
             ('pii', '個人情報の区分', 16), ('log_policy', 'ログ方針', 12), ('limit', '上限と超過時の挙動', 22), ('comparison', '比較規則', 14),
             ('uniqueness', '一意の範囲', 12), ('vocabulary', '値の語彙', 16), ('synonym_group', '同義グループ', 16), ('guide_part', 'ガイドの該当 Part', 12)]
    for c, _ in CASES:
        cols += [(c + '.' + k, lab, {'judgement': 15, 'condition': 22, 'alt': 16, 'use_or_loss': 44, 'revisit': 26, 'checks': 10}[k]) for k, lab in CASE_COLS]
    cols += [('notes', '備考', 44), ('checked_on', '確認日', 11), ('verified', '一次資料で確認', 10)]
    return cols


def value(r, d, key, no):
    if key == 'no':
        return no
    if key.startswith('sup_'):
        return (r.get('support') or {}).get(key[4:], '不明')
    if key == 'book':
        return links.book_refs(r)[0]
    if key == 'guide_part':
        return (d or {}).get('guide_part', '')
    if '.' in key and key[0] in 'ABC' and key[1] == '.':
        c, k = key.split('.', 1)
        v = ((d or {}).get(c) or {}).get(k, '')
        return '、'.join(v) if isinstance(v, list) else v
    v = r.get(key, '')
    if isinstance(v, bool):
        return 'はい' if v else 'いいえ'
    if isinstance(v, (list, dict)):
        return json.dumps(v, ensure_ascii=False)
    return v


def sheet_main(wb, rows, dec):
    ws = wb.create_sheet('クレーム一覧')
    cols = main_columns()
    # row 1: group headers, row 2: column headers
    groups = [(1, 14, 'クレームの定義と出典'), (15, 19, 'IdP での扱い（既定でサポートされるか）'), (20, 31, '性質（判断に使う情報）')]
    start = 32
    for c, lab in CASES:
        groups.append((start, start + 5, lab))
        start += 6
    groups.append((start, start + 2, '備考と確認'))
    for a, b, lab in groups:
        ws.merge_cells(start_row=1, start_column=a, end_row=1, end_column=b)
        cell = ws.cell(row=1, column=a, value=lab)
        fill = HEAD_FILL
        for c, l2 in CASES:
            if lab == l2:
                fill = CASE_FILL[c]
        for col in range(a, b + 1):
            ws.cell(row=1, column=col).fill = fill
        cell.font = f(True, 'FFFFFF', 11)
        cell.alignment = Alignment(horizontal='center', vertical='center')
    for i, (key, lab, w) in enumerate(cols, 1):
        cell = ws.cell(row=2, column=i, value=lab)
        cell.font = f(True, 'FFFFFF')
        cell.fill = HEAD_FILL if not (key[:2] in ('A.', 'B.', 'C.')) else CASE_FILL[key[0]]
        cell.alignment = Alignment(wrap_text=True, vertical='center')
        cell.border = BORDER
        ws.column_dimensions[get_column_letter(i)].width = w
    rowno = {r['id']: n + 2 for n, r in enumerate(rows, 1)}
    for n, r in enumerate(rows, 1):
        d = dec.get(r['id'])
        for i, (key, lab, w) in enumerate(cols, 1):
            cell = ws.cell(row=n + 2, column=i, value=value(r, d, key, n))
            cell.font = f()
            cell.alignment = Alignment(wrap_text=True, vertical='top')
            cell.border = BORDER
            link = None
            if key in ('url', 'source'):
                link = links.source_link(r)
            elif key == 'book':
                link = links.book_refs(r)[1] or None
            elif key == 'guide_part' and cell.value:
                link = links.guide_link(str(cell.value))
            elif key.endswith('.checks') and cell.value:
                link = links.RESULTS
            elif key.endswith('.alt') and cell.value:
                first = str(cell.value).split('、')[0]
                if first in rowno:
                    link = "#'クレーム一覧'!D%d" % rowno[first]
            if key == 'name':
                cell.font = f(bold=True)
            if link and str(link).startswith(('http', '#')):
                cell.hyperlink = link
                cell.font = f(color='0B6E78', bold=(key == 'name'))
    last = len(rows) + 2
    ws.freeze_panes = 'E3'
    ws.auto_filter.ref = 'A2:%s%d' % (get_column_letter(len(cols)), last)
    ws.row_dimensions[2].height = 42
    # judgement colours and validation
    dv = DataValidation(type='list', formula1='=入力規則!$A$2:$A$%d' % (len(JUDGE) + 1), allow_blank=True)
    ws.add_data_validation(dv)
    for ci, (key, lab, w) in enumerate(cols, 1):
        if key.endswith('.judgement'):
            L = get_column_letter(ci)
            dv.add('%s3:%s%d' % (L, L, last))
            for j, col in JFILL.items():
                ws.conditional_formatting.add('%s3:%s%d' % (L, L, last), FormulaRule(formula=['%s3="%s"' % (L, j)], fill=PatternFill('solid', fgColor=col), font=Font(name=FONT, color='FFFFFF' if j not in ('対象外',) else '17202B', bold=True)))
    # grey italic for drafts and unverified rows
    st = get_column_letter([k for k, _, _ in cols].index('status') + 1)
    vf = get_column_letter(len(cols))
    ws.conditional_formatting.add('A3:%s%d' % (get_column_letter(len(cols)), last), FormulaRule(formula=['OR(ISNUMBER(SEARCH("草案",$%s3)),$%s3="いいえ")' % (st, vf)], font=Font(name=FONT, color='6B7883', italic=True)))
    return ws, cols


def sheet_long(wb, rows, dec):
    ws = wb.create_sheet('判定（縦長）')
    head = ['ID', 'クレーム名', '出典の種別', 'ケース', '判定', '条件', '代替クレーム（ID）', '用途／失うこと', '見直し条件', '検証 ID']
    widths = [11, 30, 18, 8, 15, 24, 18, 50, 30, 10]
    for i, (h, w) in enumerate(zip(head, widths), 1):
        c = ws.cell(row=1, column=i, value=h)
        c.font = f(True, 'FFFFFF'); c.fill = HEAD_FILL; c.border = BORDER
        ws.column_dimensions[get_column_letter(i)].width = w
    n = 2
    for r in rows:
        d = dec.get(r['id']) or {}
        for c, _ in CASES:
            x = d.get(c) or {}
            vals = [r['id'], r['name'], r['source_kind'], c, x.get('judgement', ''), x.get('condition', ''), '、'.join(x.get('alt', []) or []),
                    x.get('use_or_loss', ''), x.get('revisit', ''), '、'.join(x.get('checks', []) or [])]
            for i, v in enumerate(vals, 1):
                cell = ws.cell(row=n, column=i, value=v)
                cell.font = f(); cell.alignment = Alignment(wrap_text=True, vertical='top'); cell.border = BORDER
            n += 1
    ws.freeze_panes = 'C2'
    ws.auto_filter.ref = 'A1:J%d' % (n - 1)
    for j, col in JFILL.items():
        ws.conditional_formatting.add('E2:E%d' % (n - 1), FormulaRule(formula=['E2="%s"' % j], fill=PatternFill('solid', fgColor=col), font=Font(name=FONT, color='FFFFFF' if j != '対象外' else '17202B', bold=True)))


def sheet_groups(wb, rows, dec):
    ws = wb.create_sheet('同義グループ')
    g = collections.OrderedDict()
    for r in rows:
        g.setdefault(r.get('synonym_group') or '（なし）', []).append(r)
    head = ['同義グループ', '行数', '代表のクレーム名', '含む ID', '含むクレーム名'] + ['IdP：' + lab for _, lab in IDPS] + ['A の採用・必須', 'B の採用・必須', 'C の採用・必須']
    widths = [18, 6, 26, 40, 50, 22, 22, 22, 22, 22, 22, 22, 22]
    for i, (h, w) in enumerate(zip(head, widths), 1):
        c = ws.cell(row=1, column=i, value=h)
        c.font = f(True, 'FFFFFF'); c.fill = HEAD_FILL; c.border = BORDER
        ws.column_dimensions[get_column_letter(i)].width = w
    n = 2
    order = {k: i for i, k in enumerate(['標準（IETF RFC）', '標準（OpenID Foundation 最終版）', '本ケーススタディで定義', '草案（IETF・OIDF）'])}
    for key, rs in sorted(g.items()):
        rep = sorted(rs, key=lambda r: order.get(r['source_kind'], 9))[0]
        sup = []
        for k, _ in IDPS:
            vals = collections.Counter((r.get('support') or {}).get(k, '不明') for r in rs)
            best = [v for v in ['既定', '設定で追加', '独自の名前で', 'フック・式で可'] if any(x.startswith(v) for x in vals)]
            sup.append(best[0] if best else ('不可・未対応' if '不可・未対応' in vals else '不明'))
        adopted = []
        for c, _ in CASES:
            ids = [r['id'] for r in rs if ((dec.get(r['id']) or {}).get(c) or {}).get('judgement') in ('必須（共通基準）', '採用', '条件付き採用')]
            adopted.append('、'.join(ids))
        vals = [key, len(rs), rep['name'], '、'.join(r['id'] for r in rs), '、'.join(sorted(set(r['name'] for r in rs)))] + sup + adopted
        for i, v in enumerate(vals, 1):
            cell = ws.cell(row=n, column=i, value=v)
            cell.font = f(); cell.alignment = Alignment(wrap_text=True, vertical='top'); cell.border = BORDER
        n += 1
    ws.freeze_panes = 'B2'
    ws.auto_filter.ref = 'A1:%s%d' % (get_column_letter(len(head)), n - 1)


def sheet_sources(wb, rows):
    ws = wb.create_sheet('出典')
    src = collections.OrderedDict()
    for r in rows:
        k = (r['source_kind'], (r.get('url') or '').split('#')[0])
        src.setdefault(k, []).append(r)
    head = ['出典の種別', '出典 URL', '行数', '状態（代表）', '変更管理者（代表）', '確認日']
    widths = [22, 70, 6, 16, 22, 11]
    for i, (h, w) in enumerate(zip(head, widths), 1):
        c = ws.cell(row=1, column=i, value=h)
        c.font = f(True, 'FFFFFF'); c.fill = HEAD_FILL; c.border = BORDER
        ws.column_dimensions[get_column_letter(i)].width = w
    n = 2
    for (kind, url), rs in sorted(src.items()):
        vals = [kind, url, len(rs), collections.Counter(r.get('status', '') for r in rs).most_common(1)[0][0],
                collections.Counter(r.get('change_controller', '') for r in rs).most_common(1)[0][0], max(r.get('checked_on', '') for r in rs)]
        for i, v in enumerate(vals, 1):
            cell = ws.cell(row=n, column=i, value=v)
            cell.font = f(); cell.alignment = Alignment(wrap_text=True, vertical='top'); cell.border = BORDER
            if i == 2 and str(v).startswith('http'):
                cell.hyperlink = v; cell.font = f(color='0B6E78')
        n += 1
    ws.auto_filter.ref = 'A1:F%d' % (n - 1)


def sheet_summary(wb, rows, cols):
    ws = wb.create_sheet('集計')
    main = "'クレーム一覧'"
    last = len(rows) + 2
    keys = [k for k, _, _ in cols]
    L = lambda k: get_column_letter(keys.index(k) + 1)
    ws['A1'] = '集計（数式。クレーム一覧を絞り込んでも全体の件数を数える）'
    ws['A1'].font = f(True, size=12)
    ws['A3'] = '判定'; ws['B3'] = 'ケース A'; ws['C3'] = 'ケース B'; ws['D3'] = 'ケース C'
    for i, j in enumerate(JUDGE, 4):
        ws.cell(row=i, column=1, value=j)
        for k, (c, _) in enumerate(CASES, 2):
            col = L(c + '.judgement')
            ws.cell(row=i, column=k, value='=COUNTIF(%s!$%s$3:$%s$%d,$A%d)' % (main, col, col, last, i))
    tot = 4 + len(JUDGE)
    ws.cell(row=tot, column=1, value='合計')
    for k in range(2, 5):
        Lk = get_column_letter(k)
        ws.cell(row=tot, column=k, value='=SUM(%s4:%s%d)' % (Lk, Lk, tot - 1))
    r0 = tot + 2
    ws.cell(row=r0, column=1, value='出典の種別'); ws.cell(row=r0, column=2, value='行数')
    kinds = sorted(set(r['source_kind'] for r in rows))
    for i, kd in enumerate(kinds, r0 + 1):
        ws.cell(row=i, column=1, value=kd)
        ws.cell(row=i, column=2, value='=COUNTIF(%s!$%s$3:$%s$%d,$A%d)' % (main, L('source_kind'), L('source_kind'), last, i))
    r1 = r0 + len(kinds) + 2
    ws.cell(row=r1, column=1, value='IdP での扱い');
    vals = ['既定', '設定で追加', '独自の名前で', 'フック・式で可', '不可・未対応', '対象外', '不明']
    for k, (key, lab) in enumerate(IDPS, 2):
        ws.cell(row=r1, column=k, value=lab)
    for i, v in enumerate(vals, r1 + 1):
        ws.cell(row=i, column=1, value=v)
        for k, (key, lab) in enumerate(IDPS, 2):
            col = L('sup_' + key)
            ws.cell(row=i, column=k, value='=COUNTIF(%s!$%s$3:$%s$%d,$A%d&"*")' % (main, col, col, last, i))
    r2 = r1 + len(vals) + 2
    ws.cell(row=r2, column=1, value='分類'); ws.cell(row=r2, column=2, value='行数')
    cats = list(dict.fromkeys(r['category'] for r in rows))
    for i, cg in enumerate(cats, r2 + 1):
        ws.cell(row=i, column=1, value=cg)
        ws.cell(row=i, column=2, value='=COUNTIF(%s!$%s$3:$%s$%d,$A%d)' % (main, L('category'), L('category'), last, i))
    for row in ws.iter_rows():
        for c in row:
            if c.font is None or not c.font.bold:
                c.font = f(bold=c.row in (3, r0, r1, r2))
    ws.column_dimensions['A'].width = 30
    for k in 'BCDEF':
        ws.column_dimensions[k].width = 14


def sheet_lists(wb):
    ws = wb.create_sheet('入力規則')
    lists = {'判定': JUDGE, 'IdP での扱い': ['既定', '設定で追加', '独自の名前で', 'フック・式で可', '不可・未対応', '対象外（他社の独自クレーム）', '不明'],
             '値を書ける主体': ['発行者（権威ある情報源）', '発行者（取得元から転記）', '本人が編集できる', '呼び出し元・クライアントの申告', '発行者が派生', '不明'],
             '可変性': ['不変', '再割り当てなし', '改名・変更あり', '随時変わる', '不明'], '鮮度': ['発行時点で固定（寿命内は古いまま）', '発行ごとに再計算', '都度照会が必要', '該当なし'],
             '認可に使ってよいか': ['単独で可', 'iss・aud などと組で可', '補助のみ', '不可（表示・監査用）'], '個人情報の区分': ['非該当', '仮名の識別子', '直接識別できる個人情報', '機微な個人情報'],
             'ログ方針': ['平文で可', 'ハッシュ・マスク', '記録しない'], '状態': ['最終', '草案（版番号）', '非推奨', '廃止', 'ベンダー提供中', 'プレビュー', '本ケーススタディで定義']}
    for i, (k, vs) in enumerate(lists.items(), 1):
        c = ws.cell(row=1, column=i, value=k); c.font = f(True, 'FFFFFF'); c.fill = HEAD_FILL
        ws.column_dimensions[get_column_letter(i)].width = 26
        for j, v in enumerate(vs, 2):
            ws.cell(row=j, column=i, value=v).font = f()


def sheet_readme(wb, rows, dec):
    ws = wb.active
    ws.title = '読み方'
    ws.column_dimensions['A'].width = 24
    ws.column_dimensions['B'].width = 120
    lines = [
        ('JWT クレーム一覧（付録）', ''),
        ('この表は何か', 'JWT のクレームを、定義した規格・出典ごとに 1 行ずつ集めた一覧。ガイド「JWT クレーム設計ガイド」とケーススタディの付録。3 つのケース（A マルチテナント SaaS、B 社内業務システム、C AI エージェントの委任）ごとに採否と理由を付けた。'),
        ('行の単位', '同じ名前・同じ意味のクレームでも、定義した出典が違えば別の行にした（例：RFC 9068 の groups、Entra ID の groups、Cognito の cognito:groups）。行数はクレームの数ではない。概念の数は「同義グループ」のシートで数える。'),
        ('用語', '列名と値では「クレーム」を使う。「属性」は、SCIM・eduPerson・inetOrgPerson・NIST のように、クレームの元になるディレクトリの属性を指すときだけ使う。'),
        ('判定の値', '必須（共通基準）／採用／条件付き採用／不採用・代替あり／不採用・不要／不採用・禁止／対象外。不採用は禁止ではない（「不要」と「禁止」を分けた）。'),
        ('理由の書き方', '採用・条件付き採用は「どういう場合に使うか」、不採用は「それで何ができなくなるか」を書いた。不採用・代替ありは、代わりに使うクレームの ID を「代替クレーム（ID）」に書いた。不採用と条件付き採用には「見直し条件」を書いた。'),
        ('IdP での扱い', '既定＝設定なしで出る／設定で追加＝任意クレーム・マッパー・スコープで出す／独自の名前で＝同じ概念を別の名前で出す（備考に名前）／フック・式で可＝Actions・フック・式・マッパーを自分で書けば出せる／不可・未対応／対象外＝他社の独自クレームの行なので該当しない／不明＝文書で確認できなかった。'),
        ('注意 1', 'IdP で「既定」でも、認可に使ってよいとは限らない。「認可に使ってよいか」「値を書ける主体」「可変性」を必ず見る。'),
        ('注意 2', '標準のクレームでも、IdP 間で意味や形が同じとは限らない（例：groups を名前で返すか ID で返すか、sub が利用者かログイン名か）。'),
        ('注意 3', '個人情報のクレームの「採用」は、アクセストークンに載せてよいという意味ではない。「載るトークン」と「個人情報の区分」と条件を並べて読む。'),
        ('注意 4', '判定は、このケーススタディの前提（判定の方針：DECISION_POLICY.md）での結論で、2026-11-17 時点のもの。草案の行と、一次資料で確認できなかった行は灰色の斜体で表示する。'),
        ('筆者の判断', '「個人情報の区分」「ログ方針」「認可に使ってよいか」など、出典に書かれていないことが多い列は、出典の記述をもとに作成者が付けた。'),
        ('出典とリンク', 'RFC・OpenID の仕様・IETF の草案・IANA の登録簿・各社の公式文書・公的機関の文書。「出典（節）」と「出典 URL」から原典に飛べる（RFC は該当の節へ）。「書籍の該当箇所」は日本語の書籍の章・節と印刷ページで、出版社の書籍のページへリンクする。「代替クレーム（ID）」は表の中の該当行へ、「検証 ID」はケーススタディの結果へ、「ガイドの該当 Part」はガイドの Web スライドへリンクする。'),
        ('関連', 'ガイド：https://github.com/Takenori-Kusaka/jwt-claims-guide ／ ケーススタディ：https://github.com/Takenori-Kusaka/jwt-claims-casestudy'),
        ('件数', '%d 行（うち本ケーススタディで定義した組織の独自クレーム %d 行）、同義グループ %d。判定の件数は「集計」のシート。' % (
            len(rows), sum(1 for r in rows if r['source_kind'] == '本ケーススタディで定義'), len(set(r.get('synonym_group') for r in rows)))),
        ('ライセンス', 'CC BY 4.0。本表は生成AI（Claude）を使って作成し、作成者が確認して公開している。'),
    ]
    for i, (a, b) in enumerate(lines, 1):
        ca = ws.cell(row=i, column=1, value=a); cb = ws.cell(row=i, column=2, value=b)
        ca.font = f(True, size=14 if i == 1 else 10); cb.font = f()
        cb.alignment = Alignment(wrap_text=True, vertical='top'); ca.alignment = Alignment(vertical='top')
    leg = len(lines) + 2
    ws.cell(row=leg, column=1, value='判定の色').font = f(True)
    for i, (j, col) in enumerate(JFILL.items(), leg + 1):
        c = ws.cell(row=i, column=1, value=j)
        c.fill = PatternFill('solid', fgColor=col); c.font = Font(name=FONT, bold=True, color='FFFFFF' if j != '対象外' else '17202B')


def sheet_history(wb):
    ws = wb.create_sheet('変更履歴')
    for i, h in enumerate(['日付', '内容'], 1):
        c = ws.cell(row=1, column=i, value=h); c.font = f(True, 'FFFFFF'); c.fill = HEAD_FILL
    ws.cell(row=2, column=1, value='2026-11-17').font = f()
    ws.cell(row=2, column=2, value='初版。IANA の JWT クレーム登録簿の全件、標準の仕様、5 つの IdP、プラットフォーム・業界の属性語彙を収録し、3 ケースの判定を付けた。列の設計は別の担当のレビュー（catalog/reviews）を反映。').font = f()
    ws.column_dimensions['A'].width = 12
    ws.column_dimensions['B'].width = 120


def main():
    rows, dec = load()
    wb = Workbook()
    sheet_readme(wb, rows, dec)
    ws, cols = sheet_main(wb, rows, dec)
    sheet_long(wb, rows, dec)
    sheet_groups(wb, rows, dec)
    sheet_sources(wb, rows)
    sheet_summary(wb, rows, cols)
    sheet_lists(wb)
    sheet_history(wb)
    wb.save(OUT)
    print('wrote', OUT, len(rows), 'rows,', len(dec), 'decided')


if __name__ == '__main__':
    main()

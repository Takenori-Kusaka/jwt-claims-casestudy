# -*- coding: utf-8 -*-
"""Apply the catalogue part of research/reviews/factcheck-2026-11-18.md (section 一覧表への波及, finding 観点2-3).
RFC 9396 §2.2: locations is an array of strings for the location of the resource or RS (typically URIs of the RS);
identifier names a specific resource at the API. Case C therefore puts the approved invoice in identifier (adopted)
and does not use locations (the RS is already the single aud of the exchanged token).
Note: the experiment code (cs/scen_c.py) put the invoice ID in locations; this is stated in the decisions.
Idempotent: every edit sets a field to a fixed value. HDR-01 (typ) is edited in header_rows.py directly.
Afterwards run merge.py, validate.py, build_xlsx.py.
  python catalog/scripts/fix_review2.py"""
import glob
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
CAT = os.path.dirname(HERE)
FILES = sorted(glob.glob(os.path.join(CAT, 'decisions', 'part*.json')))
DATA = {p: json.load(open(p, encoding='utf-8')) for p in FILES}
DEC = {d['id']: d for p in FILES for d in DATA[p]}
LOG = []


def setf(i, cases, **kw):
    for c in cases:
        x = DEC[i][c]
        for k, v in kw.items():
            if x.get(k) != v:
                x[k] = v
                LOG.append((i, c, k))


EXP = '実験のコード（cs/scen_c.py）は請求書の ID を locations に入れて照合した（RFC 9396 §2.2 の用法からのずれ。照合の結果は変わらない）。'

# identifier: the approved invoice (C adopts)
setf('CLM-0259', 'C', judgement='採用', condition='常に（このケースの対象のトークンで使う）', alt=[],
     use_or_loss='支払いの type（ORG-08）で、承認した対象の請求書（例：inv-1）を identifier で指す（RFC 9396 §2.2：API の特定の資源）。'
                 '支払いの受け手は要求の請求書と照合し、別の請求書への支払いを承認の外として拒否する。' + EXP,
     revisit='承認の内容を表す業界標準の type が決まったら、その定義に合わせる',
     checks=['C5', 'C6', 'C7', 'C8'], related=['CLM-0256', 'CLM-0257', 'ORG-08'],
     checks_note='C5〜C8 は請求書・金額・相手先の照合で確かめた（実験では請求書を locations に入れた）')

# locations: the RS (not used in C: the exchanged token already has the single aud invoices)
setf('CLM-0260', 'C', judgement='不採用・不要', condition='該当なし（採用しない）', alt=[],
     use_or_loss='RFC 9396 §2.2 の locations はリソースサーバーの場所（通常は URI）を表す。C では交換で aud を請求書 API 1 つに絞る（aud_exchange）ため使わない。'
                 '1 つの承認を複数のリソースサーバーで使い分けることはできない。' + EXP,
     revisit='1 つの承認を複数のリソースサーバーで使うようになったら（各 RS の URI を locations に入れ、受け手は自分の URI を確かめる）',
     checks=[], related=['CLM-0256', 'CLM-0259'], checks_note='—（採用しないため検証なし）')

# the other element rows point at identifier (the adopted object of the approval) instead of locations
for i in ('CLM-0258', 'CLM-0261', 'CLM-0263'):
    setf(i, 'C', related=['CLM-0256', 'CLM-0257', 'CLM-0259'])

for p in FILES:
    s = json.dumps(DATA[p], ensure_ascii=False, indent=1)
    if open(p, encoding='utf-8').read() != s:
        open(p, 'w', encoding='utf-8').write(s)
print('changed fields:', len(LOG))
for x in LOG:
    print(' ', *x)

# -*- coding: utf-8 -*-
"""Check the per-case decisions across all parts: every row decided once; required fields present;
every alt of 不採用・代替あり points at a row judged 必須/採用/条件付き採用 in the same case.
  python catalog/scripts/validate.py"""
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CAT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import header_rows  # noqa: E402

ADOPT = ('必須（共通基準）', '採用', '条件付き採用')
JUDGE = ADOPT + ('不採用・代替あり', '不採用・不要', '不採用・禁止', '対象外')

rows = json.load(open(os.path.join(CAT, 'catalog.json'), encoding='utf-8'))
ids = [r['id'] for r in rows]
dec = {}
dups = []
for p in sorted(glob.glob(os.path.join(CAT, 'decisions', 'part*.json'))):
    for d in json.load(open(p, encoding='utf-8')):
        if d['id'] in dec:
            dups.append(d['id'])
        dec[d['id']] = d
for d in header_rows.decisions():
    dec.setdefault(d['id'], d)
problems = []
missing = [i for i in ids if i not in dec]
for i in ids:
    d = dec.get(i)
    if not d:
        continue
    for c in 'ABC':
        x = d.get(c) or {}
        j = x.get('judgement')
        if j not in JUDGE:
            problems.append((i, c, 'bad judgement %r' % j))
            continue
        if j == '条件付き採用' and not x.get('condition'):
            problems.append((i, c, 'condition empty'))
        if j != '対象外' and not x.get('use_or_loss'):
            problems.append((i, c, 'use_or_loss empty'))
        if not x.get('revisit'):
            problems.append((i, c, 'revisit empty'))
        if j == '不採用・代替あり':
            if not x.get('alt'):
                problems.append((i, c, 'alt empty'))
            for a in x.get('alt') or []:
                t = (dec.get(a) or {}).get(c, {}).get('judgement')
                if a not in ids:
                    problems.append((i, c, 'alt %s not in catalogue' % a))
                elif t not in ADOPT:
                    problems.append((i, c, 'alt %s is %s in case %s' % (a, t, c)))
print('rows', len(ids), 'decided', len([i for i in ids if i in dec]), 'missing', len(missing), 'dups', len(dups))
print('problems', len(problems))
for p in problems[:80]:
    print(' ', *p)
json.dump({'missing': missing, 'dups': dups, 'problems': problems}, open(os.path.join(CAT, 'decisions', 'validation.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)

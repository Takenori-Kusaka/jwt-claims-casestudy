# -*- coding: utf-8 -*-
"""Changing a shared claim: how many consumers break (guide Part 4 型, Part 11 変更の手順・契約テスト).

Nine consumers, written against the CURRENT token shape, each in the style of a common stack. Ten changes are applied by the
issuer. For each change we count consumers that crash, consumers that silently decide wrongly, consumers whose declared contract
(path + type of what they read) would flag the change in CI, and consumers that still fail when they all use the organisation's
common parser instead of reading raw claims.
"""
import json
import math

from .jwtlib import NS

CURRENT = {'sub': 'sato', 'user_id': 'u-1001', 'roles': 'approver viewer', 'employee_id': '9007199254740993', 'tenant': 't1'}
REQ = {'need_role': 'approver', 'admin': False, 'ip': '203.0.113.7', 'tenant': 't1'}
EXPECTED = {'allow': True, 'employee': '9007199254740993', 'tenant': 't1', 'user': 'u-1001'}

CHANGES = {
    'roles: 空白区切り → 配列': ({'roles': ['approver', 'viewer']}, None),
    'roles: 空白区切り → カンマ区切り': ({'roles': 'approver,viewer'}, None),
    'employee_id: 文字列 → 2^53 超の数値': ({'employee_id': 9007199254740993}, None),
    'tenant: 大文字に変わる（T1）': ({'tenant': 'T1'}, None),
    'roles: 組織の URL 名前空間へ移す': ({'roles': None, NS: {'roles': ['approver', 'viewer']}}, None),
    'roles: 名前を role に変える': ({'roles': None, 'role': 'approver viewer'}, None),
    'mfa: 無い（=false）から null に': ({'mfa': None}, {'admin': True, 'expect_allow': False}),
    'mfa: 真偽値を文字列 "false" に': ({'mfa': 'false'}, {'admin': True, 'expect_allow': False}),
    '制限のクレーム ip_allow を追加': ({'ip_allow': ['198.51.100.0/24']}, {'expect_allow': False}),
    'sub: ログイン名 → 不変の UUID（user_id は残す）': ({'sub': '4f6e2c1a-0000-4000-8000-000000000001'}, None),
}


def token(change):
    c = dict(CURRENT)
    for k, v in change.items():
        if v is None:
            c.pop(k, None)
        else:
            c[k] = v
    if 'mfa' in change and change['mfa'] is None:
        c['mfa'] = None
    return json.dumps(c)  # consumers receive the JSON text, as on the wire


# ------------------------------------------------------------------ consumers (written for CURRENT)
def py_service(raw, req):
    c = json.loads(raw)
    if req['admin'] and not c.get('mfa'):
        return {'allow': False}
    return {'allow': req['need_role'] in c['roles'].split(), 'employee': c['employee_id'], 'tenant': c['tenant'], 'user': c['user_id']}


def js_service(raw, req):  # JSON.parse: every number is an IEEE double; `if (c.mfa === false) deny`
    c = json.loads(raw, parse_int=lambda s: str(int(float(s))), parse_float=float)
    if req['admin'] and c.get('mfa', False) is False:
        return {'allow': False}
    return {'allow': req['need_role'] in c['roles'].split(' '), 'employee': str(c['employee_id']), 'tenant': c['tenant'], 'user': c['user_id']}


def go_strict(raw, req):  # struct { Roles string; EmployeeID string; Tenant string; MFA *bool }
    c = json.loads(raw)
    for k in ('roles', 'employee_id', 'tenant', 'user_id'):
        if not isinstance(c.get(k), str):
            raise TypeError(f'json: cannot unmarshal {k}')
    if 'mfa' in c and c['mfa'] is not None and not isinstance(c['mfa'], bool):
        raise TypeError('json: cannot unmarshal mfa')
    if req['admin'] and not c.get('mfa'):
        return {'allow': False}
    return {'allow': req['need_role'] in c['roles'].split(), 'employee': c['employee_id'], 'tenant': c['tenant'], 'user': c['user_id']}


def envoy_header(raw, req):  # jwt_authn claim_to_headers with claim_name 'roles' (dots separate nesting levels)
    c = json.loads(raw)
    hdr = c.get('roles')
    hdr = ','.join(hdr) if isinstance(hdr, list) else hdr
    roles = set((hdr or '').replace(' ', ',').split(','))  # the upstream treats a missing header as "no roles"
    return {'allow': req['need_role'] in roles, 'employee': str(c.get('employee_id')), 'tenant': c.get('tenant'), 'user': c.get('user_id')}


def cel_rule(raw, req):  # 'approver' in claims.roles ; claims.?mfa.orValue(true)
    c = json.loads(raw)
    if req['admin'] and not (c.get('mfa') if 'mfa' in c else True):
        return {'allow': False}
    r = c.get('roles', '')
    return {'allow': req['need_role'] in r, 'employee': str(c.get('employee_id')), 'tenant': c.get('tenant'), 'user': c.get('user_id')}


def sql_rls(raw, req):  # USING (tenant_id = current_setting('request.jwt.claims')::json ->> 'tenant')  — case-sensitive text
    c = json.loads(raw)
    t = c.get('tenant')
    rows_tenant = 't1'
    return {'allow': t == rows_tenant and req['need_role'] in (' '.join(c['roles']) if isinstance(c.get('roles'), list) else c.get('roles', '')).split(),
            'employee': str(c.get('employee_id')), 'tenant': t, 'user': c.get('user_id')}


def k8s_mapping(raw, req):  # claimMappings: username: claims.sub ; groups: claims.roles.split(' ')  (CEL, errors on a list)
    c = json.loads(raw)
    if not isinstance(c.get('roles'), str):
        raise TypeError('CEL: no such overload split(list)')
    return {'allow': req['need_role'] in c['roles'].split(' '), 'employee': c['employee_id'], 'tenant': c['tenant'], 'user': c['user_id']}


def java_lenient(raw, req):  # Jackson with coercion: numbers become strings; arrays of strings are not coerced to a String
    c = json.loads(raw)
    if isinstance(c.get('roles'), list):
        raise TypeError('MismatchedInputException roles')
    emp = c['employee_id']
    emp = str(emp) if not isinstance(emp, float) else repr(emp)
    return {'allow': req['need_role'] in (c.get('roles') or '').split(), 'employee': emp, 'tenant': c['tenant'], 'user': c['user_id']}


def legacy_login(raw, req):  # keys its own records by sub (the login name)
    c = json.loads(raw)
    db = {'sato': 'u-1001'}
    return {'allow': req['need_role'] in c['roles'].split(), 'employee': c['employee_id'], 'tenant': c['tenant'], 'user': db[c['sub']]}


CONSUMERS = {'Python': py_service, 'JavaScript（数値は double）': js_service, 'Go（厳密な型）': go_strict, 'Envoy（claim_name でヘッダーへ）': envoy_header,
             'CEL の規則': cel_rule, 'SQL の RLS（JSON の文字列比較）': sql_rls, 'Kubernetes の claimMappings': k8s_mapping,
             'Java（寛容な変換）': java_lenient, 'sub をキーにする旧システム': legacy_login}
CONTRACTS = {  # what each consumer declares it reads: path -> accepted JSON types
    'Python': {'roles': str, 'employee_id': str, 'tenant': str, 'user_id': str, 'mfa': (bool, type(None))},
    'JavaScript（数値は double）': {'roles': str, 'employee_id': str, 'tenant': str, 'user_id': str, 'mfa': bool},
    'Go（厳密な型）': {'roles': str, 'employee_id': str, 'tenant': str, 'user_id': str, 'mfa': bool},
    'Envoy（claim_name でヘッダーへ）': {'roles': (str, list)},
    'CEL の規則': {'roles': (str, list), 'mfa': bool},
    'SQL の RLS（JSON の文字列比較）': {'tenant': str, 'roles': (str, list)},
    'Kubernetes の claimMappings': {'roles': str, 'sub': str},
    'Java（寛容な変換）': {'roles': str, 'employee_id': (str, int), 'tenant': str},
    'sub をキーにする旧システム': {'sub': str, 'roles': str},
}
CATALOG_VALUES = {'tenant': {'t1', 't2'}, 'sub_format': 'login'}  # the catalogue also records allowed values / formats


def contract_flags(name, change, newtok):
    """A contract test in CI: the consumer's declared paths/types against the new token, plus catalogue value checks."""
    c = json.loads(newtok)
    for path, typ in CONTRACTS[name].items():
        if path == 'mfa' and 'mfa' not in c:
            continue
        if path not in c or not isinstance(c[path], typ) or isinstance(c[path], bool) and typ in (str, (str, int)):
            return True
        if path == 'employee_id' and isinstance(c[path], int) and abs(c[path]) > 2 ** 53:
            return True
    if 'tenant' in CONTRACTS[name] and c.get('tenant') not in CATALOG_VALUES['tenant']:
        return True
    if 'sub' in CONTRACTS[name] and c.get('sub') != CURRENT['sub'] and 'sub' in change:
        return True
    return False


def common_parser(raw, req):
    """The organisation's parser: every published shape (catalogue versions), strict types, unknown restricting claims fail closed."""
    c = json.loads(raw, parse_int=str)
    roles = (c.get(NS) or {}).get('roles', c.get('roles', c.get('role')))
    if roles is None:
        raise ValueError('roles missing')
    roles = set(roles) if isinstance(roles, list) else set(roles.replace(',', ' ').split())
    mfa = c.get('mfa')
    if mfa not in (None, True, False):
        raise ValueError('mfa must be a JSON boolean')
    if req['admin'] and mfa is not True:
        return {'allow': False}
    if 'ip_allow' in c:  # registered in the catalogue as a restricting claim: enforce it
        if not req['ip'].startswith('198.51.100.'):
            return {'allow': False}
    tenant = c['tenant'].lower() if c['tenant'].lower() in CATALOG_VALUES['tenant'] else c['tenant']  # catalogue: tenant ids are lower-case
    return {'allow': req['need_role'] in roles, 'employee': str(c['employee_id']), 'tenant': tenant, 'user': c['user_id']}


def judge(fn, raw, req, expect_allow, before=None):
    """'ok' when the consumer decides as intended. For changes that only re-encode an existing meaning (mfa null / "false"),
    the intended decision is the consumer's own decision on the current token, so that consumers that never checked mfa are not
    counted as broken by the change."""
    try:
        out = fn(raw, req)
    except Exception:  # noqa: BLE001
        return 'crash'
    want = before if before is not None else expect_allow
    if out.get('allow') != want:
        return 'wrong'
    if not want:
        return 'ok'
    for k in ('employee', 'tenant', 'user'):
        if out.get(k) != EXPECTED[k]:
            return 'wrong'
    return 'ok'


def run():
    base_req = dict(REQ)
    assert all(judge(fn, token({}), base_req, True) == 'ok' for fn in CONSUMERS.values()), 'consumers must work on the current token'
    out = {}
    for name, (ch, opt) in CHANGES.items():
        req = dict(base_req)
        expect = True
        if opt:
            req['admin'] = opt.get('admin', False)
            expect = opt.get('expect_allow', True)
        raw = token(ch)
        reencode = 'mfa' in ch  # same meaning, new encoding: compare with each consumer's decision on the current token
        res = {}
        for k, fn in CONSUMERS.items():
            before = fn(token({}), req).get('allow') if reencode else None
            res[k] = judge(fn, raw, req, expect, before)
        flagged = [k for k in CONSUMERS if contract_flags(k, ch, raw)]
        bad = [k for k, v in res.items() if v != 'ok']
        out[name] = {'consumers': len(CONSUMERS), 'crash': [k for k, v in res.items() if v == 'crash'], 'silently_wrong': [k for k, v in res.items() if v == 'wrong'],
                     'broken': len(bad), 'caught_by_contract_tests': len([k for k in bad if k in flagged]),
                     'broken_but_not_caught': [k for k in bad if k not in flagged],
                     'common_parser': judge(common_parser, raw, req, expect)}
    return out


_ = math

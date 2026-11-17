# -*- coding: utf-8 -*-
"""How many consumers break when a shared claim changes (guide Part 4 型, Part 11 変更の手順・契約テスト).

Six consumers read the same 'roles' information the way different stacks commonly do. Three changes are applied to the issuer.
Without a common parser each consumer reads the raw claim; with the organisation's common parser (schema-aware) every consumer
gets the same normalised value, and a contract test (declared path + type per consumer) flags the change before release.
"""
from .jwtlib import NS

OLD = {'roles': 'approver viewer'}  # space-delimited string, top level
CHANGES = {
    'string→array': {'roles': ['approver', 'viewer']},
    'top level→namespace object': {NS: {'roles': ['approver', 'viewer']}},
    'rename roles→role': {'role': 'approver viewer'},
}


def c_split(c):  # JS style: claims.roles.split(' ')
    return set(c['roles'].split(' '))


def c_list(c):  # Python style written for the string: re.split(r'\s+', claims['roles'])
    import re
    return set(re.split(r'\s+', c['roles']))


def c_header(c):  # gateway copies to a header: ','.join(...) if list else value
    v = c['roles']
    return set((','.join(v) if isinstance(v, list) else v).replace(' ', ',').split(','))


def c_contains(c):  # policy expression: 'approver' in claims.roles (substring on strings, membership on lists)
    return {'approver'} if 'approver' in c.get('roles', '') else set()


def c_strict(c):  # typed struct: Roles string `json:"roles"`
    if not isinstance(c.get('roles'), str):
        raise TypeError('roles is not a string')
    return set(c['roles'].split())


def c_optional(c):  # treats a missing claim as "no roles" (silent)
    v = c.get('roles') or ''
    return set(v.split()) if isinstance(v, str) else set(v)


CONSUMERS = {'split': c_split, 'list': c_list, 'header': c_header, 'contains': c_contains, 'strict': c_strict, 'optional': c_optional}
CONTRACT = {'split': ('roles', str), 'list': ('roles', str), 'header': ('roles', (str, list)), 'contains': ('roles', (str, list)),
            'strict': ('roles', str), 'optional': ('roles', (str, list))}


def common_parser(c):
    """The organisation's parser: knows every published shape of the claim (台帳のスキーマ版)."""
    v = (c.get(NS) or {}).get('roles', c.get('roles', c.get('role')))
    if v is None:
        raise ValueError('required claim roles missing')
    return set(v.split()) if isinstance(v, str) else set(v)


def decision(fn, c):
    try:
        return 'approver' in fn(c)
    except Exception:  # noqa: BLE001
        return 'error'


def run():
    expected = True  # the user is an approver in every version
    out = {}
    for name, new in CHANGES.items():
        broken = [k for k, fn in CONSUMERS.items() if decision(fn, new) != expected]
        silent = [k for k in broken if decision(CONSUMERS[k], new) is False]
        flagged = [k for k, (path, typ) in CONTRACT.items() if not isinstance(new.get(path), typ)]
        with_parser = [k for k in CONSUMERS if decision(common_parser, new) != expected]
        out[name] = {'consumers': len(CONSUMERS), 'broken_without_parser': len(broken), 'silently_wrong': len(silent), 'broken_list': broken,
                     'caught_by_contract_tests_before_release': len(flagged), 'broken_with_common_parser': len(with_parser)}
    assert all(decision(fn, OLD) == expected for fn in CONSUMERS.values())
    return out

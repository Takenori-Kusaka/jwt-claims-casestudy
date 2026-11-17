# -*- coding: utf-8 -*-
"""Measurements of real Keycloak 26.8 behaviour that the guide relies on."""
import time

import jwt
import requests

from . import infra
from .jwtlib import NS, size


def dec(t):
    return jwt.decode(t, options={'verify_signature': False})


def uid(realm, username):
    return infra.admin('GET', f'{realm}/users', params={'username': username, 'exact': 'true'})[0]['id']


def full_scope():
    """Full Scope Allowed on vs off: which realm roles reach a token issued to a client that does not need them."""
    out = {}
    for cid in ('fs-on', 'fs-off'):
        c = dec(infra.token('t1', cid, 'alice')['access_token'])
        out[cid] = {'realm_roles': sorted(c.get('realm_access', {}).get('roles', [])), 'tenant_admin_leaks': 'tenant-admin' in c.get('realm_access', {}).get('roles', [])}
    return out


def lightweight():
    full = dec(infra.token('t1', 'saas-web', 'alice')['access_token'])
    light = dec(infra.token('t1', 'saas-light', 'alice')['access_token'])
    return {'full_claims': sorted(full), 'light_claims': sorted(light), 'missing_in_light': sorted(set(full) - set(light)),
            'tenant_in_light': NS in light, 'aud_in_light': 'aud' in light, 'sub_in_light': 'sub' in light}


def unmanaged_attribute():
    """Unmanaged attributes: stored or dropped depending on the realm's user-profile policy."""
    out = {}
    prof = infra.admin('GET', 't2/users/profile')
    for policy in ('ENABLED', None):
        p = dict(prof)
        if policy:
            p['unmanagedAttributePolicy'] = policy
        else:
            p.pop('unmanagedAttributePolicy', None)
        infra.admin('PUT', 't2/users/profile', json=p)
        u = uid('t2', 'bob')
        full = infra.admin('GET', f't2/users/{u}')
        full.setdefault('attributes', {})['clearance'] = ['secret']
        err = None
        try:
            infra.admin('PUT', f't2/users/{u}', json=full)
        except requests.HTTPError as e:
            err = e.response.status_code
        after = infra.admin('GET', f't2/users/{u}').get('attributes', {})
        out[policy or 'DISABLED(default)'] = {'stored': 'clearance' in after, 'http_error': err}
        full = infra.admin('GET', f't2/users/{u}')
        full.get('attributes', {}).pop('clearance', None)
        try:
            infra.admin('PUT', f't2/users/{u}', json=full)
        except requests.HTTPError:
            pass
    prof['unmanagedAttributePolicy'] = 'ENABLED'
    infra.admin('PUT', 't2/users/profile', json=prof)
    return out


def organizations():
    try:
        r = infra.admin('GET', 't1')
        r['organizationsEnabled'] = True
        infra.admin('PUT', 't1', json=r)
        orgs = infra.admin('GET', 't1/organizations', params={'search': 'acme'})
        if not orgs:
            infra.admin('POST', 't1/organizations', json={'name': 'acme', 'alias': 'acme', 'domains': [{'name': 'acme.example.com'}]})
            orgs = infra.admin('GET', 't1/organizations', params={'search': 'acme'})
        oid = orgs[0]['id']
        h = {'Authorization': 'Bearer ' + infra.admin_token(), 'Content-Type': 'application/json'}
        requests.post(f'{infra.KC}/admin/realms/t1/organizations/{oid}/members', headers=h, data=f'"{uid("t1", "alice")}"', timeout=10)
        tok = infra.token('t1', 'saas-web', 'alice', 'openid organization')['access_token']
        c = dec(tok)
        return {'organization_claim': c.get('organization'), 'type': type(c.get('organization')).__name__}
    except Exception as e:  # noqa: BLE001
        return {'error': str(e)[:200]}


def groups_size():
    """Token size against group count: full token with a group-membership mapper vs lightweight token."""
    out = {}
    have = {g['name']: g['id'] for g in infra.admin('GET', 't1/groups', params={'max': 1000})}
    u = uid('t1', 'alice')
    added = 0
    for n in (0, 10, 50, 100, 200):
        while added < n:
            name = f'grp-{added:03d}-' + 'x' * 16
            if name not in have:
                infra.admin('POST', 't1/groups', json={'name': name})
                have = {g['name']: g['id'] for g in infra.admin('GET', 't1/groups', params={'max': 1000})}
            infra.admin('PUT', f't1/users/{u}/groups/{have[name]}')
            added += 1
        out[n] = {'full_bytes': size(infra.token('t1', 'fs-on', 'alice')['access_token']), 'light_bytes': size(infra.token('t1', 'grp-light', 'alice')['access_token'])}
    for name, gid in have.items():
        if name.startswith('grp-'):
            requests.delete(f'{infra.KC}/admin/realms/t1/users/{u}/groups/{gid}', headers={'Authorization': 'Bearer ' + infra.admin_token()}, timeout=10)
    return out


def refresh_reevaluation():
    """Does a refresh pick up a changed attribute / a newly granted role? Does a new login?"""
    infra.set_attr('corp', 'carol', 'department', 'sales')
    if not any(r['name'] == 'auditor' for r in infra.admin('GET', 'corp/roles')):
        infra.admin('POST', 'corp/roles', json={'name': 'auditor'})
    u = uid('corp', 'carol')
    role = infra.admin('GET', 'corp/roles/auditor')
    requests.delete(f'{infra.KC}/admin/realms/corp/users/{u}/role-mappings/realm', headers={'Authorization': 'Bearer ' + infra.admin_token()}, json=[role], timeout=10)
    t = infra.token('corp', 'portal', 'carol', 'openid aud-orders')
    before = dec(t['access_token'])
    infra.set_attr('corp', 'carol', 'department', 'finance')
    infra.admin('POST', f'corp/users/{u}/role-mappings/realm', json=[role])
    r = requests.post(f'{infra.KC}/realms/corp/protocol/openid-connect/token', data={'grant_type': 'refresh_token', 'client_id': 'portal',
                                                                                     'client_secret': 'portal-secret', 'refresh_token': t['refresh_token']}, timeout=10).json()
    after_refresh = dec(r['access_token'])
    relogin = dec(infra.token('corp', 'portal', 'carol', 'openid aud-orders')['access_token'])
    g = lambda c: {'department': (c.get(NS) or {}).get('department'), 'auditor': 'auditor' in c.get('realm_access', {}).get('roles', [])}  # noqa: E731
    out = {'issued': g(before), 'after_refresh': g(after_refresh), 'after_relogin': g(relogin), 'refresh_token_rotated': r.get('refresh_token') != t['refresh_token']}
    infra.set_attr('corp', 'carol', 'department', 'sales')
    requests.delete(f'{infra.KC}/admin/realms/corp/users/{u}/role-mappings/realm', headers={'Authorization': 'Bearer ' + infra.admin_token()}, json=[role], timeout=10)
    return out


def logout_introspection(reps=20):
    """Time from the logout call returning to introspection reporting active=false, and the JWT's own remaining validity."""
    res = []
    for _ in range(reps):
        t = infra.token('corp', 'portal', 'dave', 'openid aud-orders')
        assert infra.introspect('corp', 'orders', t['access_token'])['active']
        infra.logout_user('corp', 'dave')
        t0 = time.perf_counter()
        n = 0
        while infra.introspect('corp', 'orders', t['access_token'])['active']:
            n += 1
            if n > 50:
                break
        res.append({'ms_until_inactive': (time.perf_counter() - t0) * 1000, 'polls_still_active': n,
                    'jwt_seconds_left': dec(t['access_token'])['exp'] - int(time.time())})
    t = infra.token('corp', 'portal', 'dave', 'openid aud-orders')['access_token']
    who = {c: infra.introspect('corp', c, t).get('active') for c in ('orders', 'portal', 'mcp-tools')}
    return {'reps': reps, 'introspection_active_by_client': who, 'all_inactive_on_first_check': all(r['polls_still_active'] == 0 for r in res),
            'ms_until_inactive_max': max(r['ms_until_inactive'] for r in res), 'jwt_seconds_left_min': min(r['jwt_seconds_left'] for r in res)}


def run():
    out = {}
    for name, fn in (('full_scope', full_scope), ('lightweight', lightweight), ('unmanaged_attribute', unmanaged_attribute),
                     ('organizations', organizations), ('groups_size', groups_size), ('refresh_reevaluation', refresh_reevaluation),
                     ('logout_introspection', logout_introspection)):
        try:
            out[name] = fn()
        except Exception as e:  # noqa: BLE001
            out[name] = {'error': f'{type(e).__name__}: {str(e)[:300]}'}
    return out

# -*- coding: utf-8 -*-
"""Containers (Keycloak 26.8.0 dev mode + Postgres 16) in the Ubuntu-24.04 WSL distro, realm import, admin helpers."""
import json
import os
import subprocess
import time

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KC_IMAGE = 'quay.io/keycloak/keycloak:26.8.0'
PG_IMAGE = 'postgres:16-alpine'
KC = 'http://localhost:18080'
PG_DSN = 'host=localhost port=15432 user=app password=app dbname=saas'
NS = 'https://claims.example.com/'
NS_KC = 'https://claims\\.example\\.com/'  # Keycloak treats '.' as nesting: escape the dots of the namespace URI


def wsl(cmd, check=True):
    r = subprocess.run(['wsl', '-d', 'Ubuntu-24.04', '--', 'bash', '-lc', cmd], capture_output=True, text=True, encoding='utf-8', errors='replace',
                       env=dict(os.environ, MSYS_NO_PATHCONV='1'))
    if check and r.returncode != 0:
        raise RuntimeError(f'wsl failed: {cmd}\n{r.stdout}\n{r.stderr}')
    return r.stdout


def wsl_path(p):
    d, rest = p[0].lower(), p[2:].replace('\\', '/')
    return f'/mnt/{d}{rest}'


# ---------------------------------------------------------------- realm import
def _mapper(name, kind, cfg):
    base = {'access.token.claim': 'true', 'id.token.claim': 'false', 'userinfo.token.claim': 'false', 'introspection.token.claim': 'true'}
    base.update(cfg)
    return {'name': name, 'protocol': 'openid-connect', 'protocolMapper': kind, 'consentRequired': False, 'config': base}


def hard(name, claim, value, jtype='String'):
    return _mapper(name, 'oidc-hardcoded-claim-mapper', {'claim.name': claim, 'claim.value': value, 'jsonType.label': jtype})


def attr(name, user_attr, claim, jtype='String'):
    return _mapper(name, 'oidc-usermodel-attribute-mapper', {'user.attribute': user_attr, 'claim.name': claim, 'jsonType.label': jtype})


def aud(name, client):
    return _mapper(name, 'oidc-audience-mapper', {'included.client.audience': client})


USER_PROFILE = {'unmanagedAttributePolicy': 'ENABLED', 'attributes': [
    {'name': 'username', 'displayName': 'username', 'permissions': {'view': ['admin', 'user'], 'edit': ['admin']}, 'multivalued': False},
    {'name': 'email', 'displayName': 'email', 'permissions': {'view': ['admin', 'user'], 'edit': ['admin']}, 'multivalued': False},
    {'name': 'firstName', 'displayName': 'first', 'permissions': {'view': ['admin', 'user'], 'edit': ['admin']}, 'multivalued': False},
    {'name': 'lastName', 'displayName': 'last', 'permissions': {'view': ['admin', 'user'], 'edit': ['admin']}, 'multivalued': False}]}


def user(name, roles=(), attrs=None):
    return {'username': name, 'enabled': True, 'email': f'{name}@example.com', 'emailVerified': True, 'firstName': name, 'lastName': 'Test',
            'credentials': [{'type': 'password', 'value': 'Passw0rd!', 'temporary': False}], 'realmRoles': list(roles) + ['default-roles-' + 'X'],
            'attributes': attrs or {}}


def client(cid, mappers=(), direct=True, exchange=False, default_scopes=None, optional_scopes=None, service=False):
    c = {'clientId': cid, 'enabled': True, 'publicClient': False, 'secret': f'{cid}-secret', 'standardFlowEnabled': False,
         'directAccessGrantsEnabled': direct, 'serviceAccountsEnabled': service, 'protocol': 'openid-connect', 'fullScopeAllowed': True,
         'attributes': {'access.token.header.type.rfc9068': 'true', 'standard.token.exchange.enabled': 'true' if exchange else 'false'},
         'protocolMappers': list(mappers)}
    if default_scopes is not None:
        c['defaultClientScopes'] = default_scopes
    if optional_scopes is not None:
        c['optionalClientScopes'] = optional_scopes
    return c


def scope(name, mappers):
    return {'name': name, 'protocol': 'openid-connect', 'attributes': {'include.in.token.scope': 'true', 'display.on.consent.screen': 'false'},
            'protocolMappers': mappers}


BASE_SCOPES = ['basic', 'roles', 'profile', 'email', 'acr', 'web-origins']


def realm(name, clients, users, scopes=(), roles=()):
    for u in users:
        u['realmRoles'] = [r if r != 'default-roles-X' else f'default-roles-{name}' for r in u['realmRoles']]
    return {'realm': name, 'enabled': True, 'accessTokenLifespan': 300, 'ssoSessionIdleTimeout': 1800, 'revokeRefreshToken': True,
            'roles': {'realm': [{'name': r} for r in roles]}, 'clients': clients, 'users': users,
            'components': {'org.keycloak.userprofile.UserProfileProvider': [
                {'providerId': 'declarative-user-profile', 'subComponents': {}, 'config': {'kc.user.profile.config': [json.dumps(USER_PROFILE)]}}]}}


def tenant_realm(t, rogue=False):
    ns = [hard('tenant', NS_KC + '.tenant_id', t), aud('aud-saas-api', 'saas-api')]
    clients = [client('saas-web', ns), client('saas-api', direct=False)]
    if rogue:  # a tenant administrator controls mappers inside its own realm and can claim another tenant
        clients.append(client('rogue-web', [hard('tenant', NS_KC + '.tenant_id', 't1'), aud('aud-saas-api', 'saas-api')]))
    users = [user('alice' if t == 't1' else 'bob', roles=['approver'])]
    return realm(t, clients, users, roles=['approver'])


def corp_realm():
    dept = attr('department', 'department', NS_KC + '.department')
    tenant = hard('tenant', NS_KC + '.tenant_id', 'corp')
    scopes = [scope('aud-orders', [aud('aud-orders', 'orders')]), scope('aud-invoices', [aud('aud-invoices', 'invoices')]),
              scope('aud-mcp', [aud('aud-mcp', 'mcp-tools')])]
    clients = [client('portal', [dept, tenant], exchange=False), client('orders', direct=False), client('invoices', direct=False),
               client('mcp-tools', [dept, tenant], exchange=True, service=True)]
    users = [user('carol', roles=['approver'], attrs={'department': ['sales']}), user('dave', attrs={'department': ['finance']})]
    return realm('corp', clients, users, scopes=scopes, roles=['approver'])


CORP_SCOPES = {'aud-orders': 'orders', 'aud-invoices': 'invoices', 'aud-mcp': 'mcp-tools'}
CORP_OPTIONAL = {'portal': ['aud-orders', 'aud-invoices', 'aud-mcp'], 'mcp-tools': ['aud-invoices', 'aud-orders']}


def setup_scopes():
    """Audience scopes are created after import: a clientScopes list in the import file replaces the built-in scopes (basic, roles…)."""
    have = {c['name']: c['id'] for c in admin('GET', 'corp/client-scopes')}
    for name, target in CORP_SCOPES.items():
        if name not in have:
            admin('POST', 'corp/client-scopes', json=scope(name, [aud(name, target)]))
    have = {c['name']: c['id'] for c in admin('GET', 'corp/client-scopes')}
    clients = {c['clientId']: c['id'] for c in admin('GET', 'corp/clients')}
    for cid, names in CORP_OPTIONAL.items():
        for n in names:
            admin('PUT', f"corp/clients/{clients[cid]}/optional-client-scopes/{have[n]}")


def write_realms():
    d = os.path.join(ROOT, 'kc', 'import')
    os.makedirs(d, exist_ok=True)
    for r in (tenant_realm('t1'), tenant_realm('t2', rogue=True), corp_realm()):
        json.dump(r, open(os.path.join(d, r['realm'] + '.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    return d


# ---------------------------------------------------------------- containers
def up():
    d = write_realms()
    down()
    wsl(f"docker run -d --name cs-kc -p 18080:8080 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin "
        f"-e JAVA_OPTS_KC_HEAP='-Xms256m -Xmx640m' -v {wsl_path(d)}:/opt/keycloak/data/import:ro {KC_IMAGE} start-dev --import-realm "
        f"--features=token-exchange-standard:v2 >/dev/null")
    wsl(f"docker run -d --name cs-pg -p 15432:5432 -e POSTGRES_USER=app -e POSTGRES_PASSWORD=app -e POSTGRES_DB=saas {PG_IMAGE} >/dev/null")
    t0 = time.time()
    while time.time() - t0 < 240:
        try:
            if requests.get(f'{KC}/realms/corp/.well-known/openid-configuration', timeout=3).ok:
                break
        except requests.RequestException:
            pass
        time.sleep(3)
    else:
        raise RuntimeError('keycloak did not start:\n' + wsl('docker logs --tail 40 cs-kc', check=False))
    setup_scopes()
    return time.time() - t0


def down():
    wsl('docker rm -f cs-kc cs-pg >/dev/null 2>&1', check=False)


def mem():
    return wsl("docker stats --no-stream --format '{{.Name}} {{.MemUsage}}'", check=False).strip()


# ---------------------------------------------------------------- Keycloak helpers
def token(realm_, client_id, username, scope_='openid', password='Passw0rd!'):
    r = requests.post(f'{KC}/realms/{realm_}/protocol/openid-connect/token', data={
        'grant_type': 'password', 'client_id': client_id, 'client_secret': f'{client_id}-secret', 'username': username, 'password': password,
        'scope': scope_}, timeout=10)
    r.raise_for_status()
    return r.json()


def exchange(realm_, client_id, subject_token, audience=None, scope_=None):
    data = {'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange', 'client_id': client_id, 'client_secret': f'{client_id}-secret',
            'subject_token': subject_token, 'subject_token_type': 'urn:ietf:params:oauth:token-type:access_token',
            'requested_token_type': 'urn:ietf:params:oauth:token-type:access_token'}
    if audience:
        data['audience'] = audience
    if scope_:
        data['scope'] = scope_
    r = requests.post(f'{KC}/realms/{realm_}/protocol/openid-connect/token', data=data, timeout=10)
    return r.status_code, r.json()


def introspect(realm_, client_id, tok):
    r = requests.post(f'{KC}/realms/{realm_}/protocol/openid-connect/token/introspect',
                      data={'token': tok, 'client_id': client_id, 'client_secret': f'{client_id}-secret'}, timeout=10)
    r.raise_for_status()
    return r.json()


def jwks(realm_):
    return requests.get(f'{KC}/realms/{realm_}/protocol/openid-connect/certs', timeout=10).json()


def admin_token():
    r = requests.post(f'{KC}/realms/master/protocol/openid-connect/token', data={'grant_type': 'password', 'client_id': 'admin-cli',
                                                                                 'username': 'admin', 'password': 'admin'}, timeout=10)
    r.raise_for_status()
    return r.json()['access_token']


def admin(method, path, **kw):
    h = {'Authorization': 'Bearer ' + admin_token()}
    r = requests.request(method, f'{KC}/admin/realms/{path}', headers=h, timeout=10, **kw)
    r.raise_for_status()
    return r.json() if r.content else None


def set_attr(realm_, username, key, value):
    u = admin('GET', f'{realm_}/users', params={'username': username, 'exact': 'true'})[0]
    full = admin('GET', f"{realm_}/users/{u['id']}")
    full.setdefault('attributes', {})[key] = [value]
    admin('PUT', f"{realm_}/users/{u['id']}", json=full)
    return u['id']


def logout_user(realm_, username):
    u = admin('GET', f'{realm_}/users', params={'username': username, 'exact': 'true'})[0]
    admin('POST', f"{realm_}/users/{u['id']}/logout")

# -*- coding: utf-8 -*-
"""Scenario C: an AI agent acting for a user through MCP-style tool servers to an upstream invoices API.

Tokens come from the internal token service (mock) so that time can be advanced. Callers are identified by a workload identity
(e.g. mTLS); 'caller' below is that identity.
"""
import statistics
import time

from . import infra
from .common import Case
from .jwtlib import CLOCK, NS, STS, Reject
from .verify import Verifier

T0 = 1_800_000_000
INVOICES = {'inv-1': {'owner': 'u1', 'amount': 120000, 'creditor': 'B-019'}, 'inv-2': {'owner': 'u2', 'amount': 50000, 'creditor': 'B-020'}}
APPROVALS = {'ap-311': {'owner': 'u1', 'invoice': 'inv-1', 'amount': 120000, 'creditor': 'B-019'}}
ACTOR_POLICY = {'tool:invoice-mcp': {'read', 'pay', 'refund'}, 'agent:expense': {'read', 'pay', 'refund'}, 'agent:viewer': {'read'},
                'console:admin': {'read', 'pay', 'refund'}, 'portal': {'read', 'pay', 'refund'}}
SCOPE_OF = {'read': 'invoices.read', 'pay': 'invoices.pay', 'refund': 'invoices.refund'}
REVOKED = set()
MAX_DEPTH = 3
BROAD_SCOPE = 'invoices.read invoices.pay invoices.refund'


def chain(*actors):
    """act chain with the CURRENT actor outermost; actors are given oldest first."""
    act = None
    for a in actors:
        act = {'sub': a, **({'act': act} if act else {})}
    return act


def depth(act):
    d = 0
    while act:
        d, act = d + 1, act.get('act')
    return d


def innermost(act):
    while act and act.get('act'):
        act = act['act']
    return act['sub'] if act else None


class TokenService:
    def __init__(self, f):
        self.f = f

    def life(self):
        return 300 if 'short_task' in self.f else 3600

    def delegate(self, user, agent, resource='mcp-a', scope=BROAD_SCOPE, task_scope='invoices.read invoices.pay'):
        """User → agent consent. With resource binding the token is for one MCP server; without it the AS falls back to every
        audience the client may use."""
        if 'short_task' in self.f and (user, agent) in REVOKED:
            raise Reject('delegation revoked')
        aud = [resource] if 'aud_exchange' in self.f else ['mcp-a', 'mcp-b', 'invoices']
        sc = task_scope if 'short_task' in self.f else scope
        return STS.mint({'sub': user, 'aud': aud, 'client_id': agent, 'act': {'sub': agent}, 'scope': sc, NS: {'tenant_id': 'corp', 'user_id': user}},
                        lifetime=self.life())

    def exchange(self, subject_token, actor, aud, approval=None, scope=None, requested_subject=None):
        c = Verifier({'alg', 'iss', 'exp', 'typ'}, {STS.iss: [STS]}, clock=CLOCK).verify(subject_token)
        if 'short_task' in self.f and (c['sub'], c['act']['sub']) in REVOKED:
            raise Reject('delegation revoked (checked at exchange)')
        act = {'sub': actor, 'act': c['act']}
        if 'depth_rule' in self.f and depth(act) > MAX_DEPTH:
            raise Reject('delegation chain too deep (organisation rule)')
        granted = set(c.get('scope', '').split())
        want = set((scope or c.get('scope', '')).split())
        sc = ' '.join(sorted(want & granted)) if 'short_task' in self.f else ' '.join(sorted(want))  # without the task limit the tool gets what it asks for
        claims = {'sub': c['sub'], 'aud': [aud], 'client_id': actor, 'act': act, 'scope': sc, NS: c[NS]}
        if requested_subject and 'aud_exchange' not in self.f:
            claims['sub'] = requested_subject
        if approval and 'approval_bind' in self.f:
            rec = APPROVALS.get(approval)
            if not rec or rec['owner'] != c['sub']:
                raise Reject('no approval record')
            claims['authorization_details'] = [{'type': 'https://claims.example.com/rar/payment', 'actions': ['pay'], 'locations': [rec['invoice']],
                                                'instructedAmount': {'currency': 'JPY', 'amount': str(rec['amount'])}, 'creditorAccount': rec['creditor']}]
        return STS.mint(claims, lifetime=300 if 'short_task' in self.f else 3600)


class Resource:
    """The upstream invoices API (audience 'invoices') or an MCP server ('mcp-a')."""

    def __init__(self, f, audience='invoices'):
        self.f, self.audience = f, audience
        self.v = Verifier(f, {STS.iss: [STS]}, audience=audience, typ=('at+jwt',), required={'sub': str}, clock=CLOCK)

    def check(self, token, caller, action):
        c = self.v.verify(token)
        f = self.f
        aud = c.get('aud')
        if 'aud_exchange' in f and isinstance(aud, list) and len(aud) != 1:
            raise Reject('token bound to more than one audience')
        if 'depth_rule' in f and depth(c.get('act')) > MAX_DEPTH:
            raise Reject('delegation chain too deep')
        if c.get('scope') == 'invoices.read.all':
            if action != 'read':
                raise Reject('service identity may only read')
            return c
        if SCOPE_OF[action] not in c.get('scope', '').split():
            raise Reject('scope')
        if 'act_chain' in f:
            actor = (c.get('act') or {}).get('sub') or c.get('client_id')
            if actor != caller:
                raise Reject('the caller is not the current actor')
        else:
            actor = innermost(c.get('act'))  # mistake: the oldest actor is read as the one acting now
        if actor and action not in ACTOR_POLICY.get(actor, set()):
            raise Reject('actor may not ' + action)
        return c

    def read(self, token, caller, inv):
        c = self.check(token, caller, 'read')
        if c.get('scope') != 'invoices.read.all' and INVOICES[inv]['owner'] != c['sub']:
            raise Reject('not the owner')
        return INVOICES[inv]

    def pay(self, token, caller, inv, amount, creditor, body_approval=None, action='pay'):
        c = self.check(token, caller, action)
        if INVOICES[inv]['owner'] != c['sub']:
            raise Reject('not the owner')
        if action == 'refund':
            return True
        if 'approval_bind' not in self.f:
            if not body_approval:
                raise Reject('approval id required')
            return True  # the approval id in the request body is trusted as is
        ad = [d for d in c.get('authorization_details', []) if d.get('type') == 'https://claims.example.com/rar/payment']
        if not any(inv in d.get('locations', []) and d['instructedAmount']['amount'] == str(amount) and d.get('creditorAccount') == creditor for d in ad):
            raise Reject('payment not covered by the approved authorization_details')
        return True


class Tool:
    """The MCP tool server (workload identity tool:invoice-mcp)."""
    ID = 'tool:invoice-mcp'

    def __init__(self, f):
        self.f, self.sts, self.up = f, TokenService(f), Resource(f)

    def token_for_upstream(self, user_token, approval=None, scope=None, requested_subject=None):
        if 'aud_exchange' in self.f:
            return self.sts.exchange(user_token, self.ID, 'invoices', approval, scope, requested_subject)
        return user_token  # passthrough

    def read(self, user_token, inv, requested_subject=None):
        if 'aud_exchange' in self.f:
            return self.up.read(self.token_for_upstream(user_token, requested_subject=requested_subject), self.ID, inv)
        svc = STS.mint({'sub': self.ID, 'aud': 'invoices', 'client_id': self.ID, 'scope': 'invoices.read.all'}, lifetime=3600)
        return self.up.read(svc, self.ID, inv)  # without exchange the tool reads with its own broad identity

    def pay(self, user_token, inv, amount, creditor, approval=None, action='pay', scope=None):
        tok = self.token_for_upstream(user_token, approval, scope)
        return self.up.pay(tok, self.ID, inv, amount, creditor, body_approval=approval, action=action)


def cases():
    def reset():
        CLOCK.t = T0
        REVOKED.clear()

    def d(f, **kw):
        reset()
        return TokenService(f).delegate('u1', 'agent:expense', **kw)

    def wrong_actor(f):
        reset()
        tok = STS.mint({'sub': 'u1', 'aud': ['invoices'], 'client_id': 'agent:viewer', 'act': chain('console:admin', 'agent:viewer'), 'scope': BROAD_SCOPE,
                        NS: {'tenant_id': 'corp', 'user_id': 'u1'}, 'authorization_details': [
                            {'type': 'https://claims.example.com/rar/payment', 'actions': ['pay'], 'locations': ['inv-1'],
                             'instructedAmount': {'currency': 'JPY', 'amount': '120000'}, 'creditorAccount': 'B-019'}]})
        return Resource(f).pay(tok, 'agent:viewer', 'inv-1', 120000, 'B-019', body_approval='ap-311')

    def revoked(f):
        reset()
        tok = TokenService(f).delegate('u1', 'agent:expense')
        CLOCK.advance(60)
        REVOKED.add(('u1', 'agent:expense'))
        CLOCK.advance(480)  # nine minutes after issuance the agent continues
        try:
            return Tool(f).read(tok, 'inv-1') if 'aud_exchange' in f else Resource(f).read(tok, 'agent:expense', 'inv-1')
        finally:
            reset()

    def deep(f, n):
        reset()
        for i in range(n):
            ACTOR_POLICY.setdefault(f'agent:hop{i}', {'read'})
        tok = STS.mint({'sub': 'u1', 'aud': ['invoices'], 'client_id': Tool.ID, 'act': chain(*[f'agent:hop{i}' for i in range(n - 1)], Tool.ID),
                        'scope': 'invoices.read', NS: {'tenant_id': 'corp', 'user_id': 'u1'}})
        return Resource(f).read(tok, Tool.ID, 'inv-1')

    def impersonate(f):  # the agent got hold of the user's own session token (client portal, no act) and pays with it
        reset()
        tok = STS.mint({'sub': 'u1', 'aud': ['invoices'], 'client_id': 'portal', 'scope': BROAD_SCOPE, NS: {'tenant_id': 'corp', 'user_id': 'u1'}})
        return Resource(f).pay(tok, 'agent:expense', 'inv-1', 120000, 'B-019', body_approval='ap-311')

    def unbound(f):  # a malicious MCP server B replays the token it received against MCP server A
        tok = d(f, resource='mcp-b')
        return Resource(f, audience='mcp-a').read(tok, 'agent:expense', 'inv-1') if 'aud_exchange' not in f else \
            Resource(f, audience='mcp-a').read(tok, 'agent:expense', 'inv-1')

    def broader(f):  # the task was 'read and pay'; the tool asks for a refund scope
        tok = d(f)
        return Tool(f).pay(tok, 'inv-1', 0, 'B-019', action='refund', scope='invoices.refund')

    return [
        Case('C1', 'legit', '委任', 'Part 10 エージェントの ID', '利用者 u1 の代わりにエージェントが、ツール経由で自分の請求書を読む', lambda f: Tool(f).read(d(f), 'inv-1')),
        Case('C2', 'attack', 'パススルー', 'Part 10 MCP の認可', 'ツールが受け取ったトークンを、そのまま上流に渡して読む', lambda f: Resource(f).read(d(f), Tool.ID, 'inv-1')),
        Case('C3', 'attack', '代理の混乱', 'Part 5 代理の混乱', 'u1 に委任されたエージェントが、ツールに u2 の請求書を読ませる', lambda f: Tool(f).read(d(f), 'inv-2')),
        Case('C4', 'attack', 'act の読み違い', 'Part 10 4 つの問い', '過去の行為者（管理コンソール）の権限で、読み取り専用のエージェントが支払う', wrong_actor),
        Case('C5', 'attack', '承認の照合（金額）', 'Part 10 人の承認の証拠', '120,000 円の承認で、990,000 円を支払う',
             lambda f: Tool(f).pay(d(f), 'inv-1', 990000, 'B-019', approval='ap-311')),
        Case('C6', 'attack', '承認の照合（相手先）', 'Part 10 人の承認の証拠', '承認の金額のまま、振込先を別の口座に変える',
             lambda f: Tool(f).pay(d(f), 'inv-1', 120000, 'X-666', approval='ap-311')),
        Case('C7', 'attack', '承認の偽造', 'Part 10 人の承認の証拠', '存在しない承認 ID を本文に書いて支払う', lambda f: Tool(f).pay(d(f), 'inv-1', 120000, 'B-019', approval='ap-999')),
        Case('C8', 'legit', '承認', 'Part 10 人の承認の証拠', '承認どおり 120,000 円を B-019 に支払う', lambda f: Tool(f).pay(d(f), 'inv-1', 120000, 'B-019', approval='ap-311')),
        Case('C9', 'attack', '委任の取り消し', 'Part 8・10', '利用者が委任を取り消した後（発行から 9 分）に、エージェントが読む', revoked),
        Case('C10', 'attack', '委任の深さ', 'Part 10 委任の連鎖と深さ', '5 段の委任の連鎖で読む', lambda f: deep(f, 5)),
        Case('C11', 'legit', '委任の深さ', 'Part 10 委任の連鎖と深さ', '2 段の委任の連鎖で読む', lambda f: deep(f, 2)),
        Case('C12', 'attack', 'なりすまし', 'Part 10 エージェントの ID', 'エージェントが利用者自身のトークン（act なし）を借りて支払う', impersonate),
        Case('C13', 'attack', 'resource の欠落', 'Part 10 MCP の認可', 'resource を付けずに得た広い宛先のトークンを、悪意ある MCP サーバー B が A に再送する', unbound),
        Case('C14', 'attack', '範囲の拡大', 'Part 10 ツールごとのスコープ', '読む・払うだけのタスクで、ツールが返金の範囲を求めて返金する', broader),
        Case('C15', 'attack', 'sub の差し替え', 'Part 10 4 つの問い', 'ツールが交換で sub を u2 に差し替えて u2 の請求書を読む', lambda f: Tool(f).read(d(f), 'inv-2', requested_subject='u2')),
    ]


def keycloak_exchange(reps=200):
    """Keycloak 26.8 standard token exchange V2: latency, act claim, and whether the audience/scope can be widened."""
    import jwt
    sub = infra.token('corp', 'portal', 'carol', 'openid aud-mcp')['access_token']
    lat = []
    st, j = 0, {}
    for _ in range(reps):
        t = time.perf_counter()
        st, j = infra.exchange('corp', 'mcp-tools', sub, audience='invoices', scope_='aud-invoices')
        lat.append((time.perf_counter() - t) * 1000)
    c = jwt.decode(j['access_token'], options={'verify_signature': False}) if st == 200 else {}
    probes = {}
    for name, kw in {'narrow_to_invoices': dict(audience='invoices', scope_='aud-invoices'), 'audience_not_in_scope': dict(audience='invoices'),
                     'audience_not_configured': dict(audience='orders-admin'), 'scope_not_granted': dict(scope_='aud-orders'),
                     'no_audience_no_scope': {}}.items():
        s_, j_ = infra.exchange('corp', 'mcp-tools', sub, **kw)
        cc = jwt.decode(j_['access_token'], options={'verify_signature': False}) if s_ == 200 else {}
        probes[name] = {'status': s_, 'aud': cc.get('aud'), 'scope': cc.get('scope'), 'error': j_.get('error_description') if s_ != 200 else None}
    lat.sort()
    return {'reps': reps, 'status': st, 'ms_p50': statistics.median(lat), 'ms_p95': lat[int(len(lat) * 0.95)], 'aud': c.get('aud'), 'azp': c.get('azp'),
            'has_act': 'act' in c, 'subject_aud': jwt.decode(sub, options={'verify_signature': False}).get('aud'), 'probes': probes}


def sts_exchange_cost(reps=2000):
    s = TokenService({'alg', 'iss', 'exp', 'typ', 'aud_exchange', 'short_task', 'depth_rule', 'approval_bind'})
    lat = []
    for _ in range(reps):
        CLOCK.t = T0
        t = time.perf_counter()
        u = s.delegate('u1', 'agent:expense')
        s.exchange(u, Tool.ID, 'invoices')
        lat.append((time.perf_counter() - t) * 1e6)
    lat.sort()
    return {'reps': reps, 'per_task_two_hops_us_p50': statistics.median(lat), 'p95': lat[int(len(lat) * 0.95)]}


def run():
    return cases(), {'keycloak_exchange': keycloak_exchange(), 'sts_exchange': sts_exchange_cost()}

# -*- coding: utf-8 -*-
"""Scenario C: an AI agent acting for a user through an MCP-style tool server to an upstream invoices API.

Tokens come from the internal STS (mock) so that the clock can be advanced for the revocation window.
N  : the tool server passes the user's token through, or uses its own broad service token; the upstream accepts any token from
     the issuer (no aud), authorises by sub only, reads the innermost act as "the actor", takes approvals from the request body;
     delegation tokens live one hour; no depth limit
B  : common baseline at the upstream (iss, aud, typ, exp, required claims, fail closed); the tool server uses its own service
     token (passthrough is rejected by aud); act is ignored; approvals from the request body; one-hour tokens
BE : baseline + emphasis "delegation": the tool server exchanges the user's token per hop (RFC 8693 act chain, aud=invoices);
     the upstream authorises the user (sub) AND the current actor (outermost act); approvals are carried as authorization_details
     issued by the STS from an approval record; per-task tokens of 300 s; the STS re-checks revocation at every exchange;
     delegation depth limited to 3 by an organisation rule
"""
import statistics
import time

from . import infra
from .common import Case
from .jwtlib import CLOCK, NS, STS, Baseline, Reject, naive_verify

INVOICES = {'inv-1': {'owner': 'u1', 'amount': 120000}, 'inv-2': {'owner': 'u2', 'amount': 50000}}
APPROVALS = {'ap-311': {'owner': 'u1', 'invoice': 'inv-1', 'amount': 120000}}
ACTOR_POLICY = {'tool:invoice-mcp': {'read', 'pay'}, 'agent:expense': {'read', 'pay'}, 'agent:viewer': {'read'}, 'console:admin': {'read', 'pay', 'refund'}}
REVOKED = set()  # (user, agent) pairs whose delegation the user revoked
MAX_DEPTH = 3


def chain(*actors):
    """act chain with the CURRENT actor outermost (RFC 8693 §4.1)."""
    act = None
    for a in actors:  # actors given oldest first
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


class STSService:
    def __init__(self, cfg):
        self.cfg = cfg
        self.life = 300 if cfg == 'BE' else 3600

    def delegate(self, user, agent, aud='mcp'):
        """User → agent: token for the MCP server with act = agent."""
        if self.cfg == 'BE' and (user, agent) in REVOKED:
            raise Reject('delegation revoked')
        return STS.mint({'sub': user, 'aud': aud, 'client_id': agent, 'act': {'sub': agent}, NS: {'tenant_id': 'corp', 'user_id': user}}, lifetime=self.life)

    def exchange(self, subject_token, actor, aud, approval=None):
        """Tool server → upstream: RFC 8693-style exchange; act gets the tool on the outside."""
        c = Baseline([STS], 'mcp', clock=CLOCK).verify(subject_token)
        agent = c['act']['sub']
        if (c['sub'], agent) in REVOKED:
            raise Reject('delegation revoked')
        act = {'sub': actor, 'act': c['act']}
        if depth(act) > MAX_DEPTH:
            raise Reject('delegation chain too deep (organisation rule)')
        claims = {'sub': c['sub'], 'aud': aud, 'client_id': actor, 'act': act, NS: c[NS]}
        if approval:
            rec = APPROVALS.get(approval)
            if not rec or rec['owner'] != c['sub']:
                raise Reject('no approval record')
            claims['authorization_details'] = [{'type': 'https://claims.example.com/rar/payment', 'actions': ['pay'],
                                                'locations': [rec['invoice']], 'instructedAmount': {'currency': 'JPY', 'amount': str(rec['amount'])}}]
        return STS.mint(claims, lifetime=300)


class Upstream:
    def __init__(self, cfg):
        self.cfg = cfg
        self.base = Baseline([STS], 'invoices', typ=('at+jwt',), required={'sub': str}, clock=CLOCK)

    def claims(self, token):
        if self.cfg == 'N':
            c = naive_verify(token, {STS.kid: STS.pub_pem})
            if c.get('exp', 0) <= CLOCK.now():
                pass  # N does not check exp
            return c
        return self.base.verify(token)

    def actor(self, c):
        if self.cfg == 'N':
            return innermost(c.get('act')) or c.get('sub')  # reads the oldest actor as if it were acting now
        if self.cfg == 'B':
            return None  # act ignored
        return (c.get('act') or {}).get('sub')

    def allowed(self, c, action):
        if c.get('scope') == 'invoices.read.all' and action == 'read':
            return True  # the tool server's own service identity
        a = self.actor(c)
        if self.cfg == 'BE' and depth(c.get('act')) > MAX_DEPTH:
            return False
        if a and action not in ACTOR_POLICY.get(a, set()):
            return False
        return True

    def read(self, token, inv):
        c = self.claims(token)
        if not self.allowed(c, 'read'):
            raise Reject('actor may not read')
        if c.get('scope') != 'invoices.read.all' and INVOICES[inv]['owner'] != c['sub']:
            raise Reject('not the owner')
        return INVOICES[inv]

    def pay(self, token, inv, amount, body_approval=None):
        c = self.claims(token)
        if not self.allowed(c, 'pay'):
            raise Reject('actor may not pay')
        if INVOICES[inv]['owner'] != c['sub']:
            raise Reject('not the owner')
        if self.cfg in ('N', 'B'):
            if not body_approval:
                raise Reject('approval id required')
            return True  # the approval id in the body is trusted as is
        ad = [d for d in c.get('authorization_details', []) if d.get('type') == 'https://claims.example.com/rar/payment']
        if not any(inv in d.get('locations', []) and d['instructedAmount']['amount'] == str(amount) for d in ad):
            raise Reject('payment not covered by the approved authorization_details')
        return True


SERVICE_TOKEN = None


def service_token():
    return STS.mint({'sub': 'tool:invoice-mcp', 'aud': 'invoices', 'client_id': 'tool:invoice-mcp', 'scope': 'invoices.read.all'}, lifetime=3600)


class Tool:
    def __init__(self, cfg):
        self.cfg, self.sts, self.up = cfg, STSService(cfg), Upstream(cfg)

    def upstream_token(self, user_token, approval=None):
        if self.cfg == 'BE':
            return self.sts.exchange(user_token, 'tool:invoice-mcp', 'invoices', approval)
        return service_token()  # N and B: the tool's own broad identity

    def read(self, user_token, inv):
        return self.up.read(self.upstream_token(user_token), inv)

    def pay(self, user_token, inv, amount, approval=None):
        if self.cfg == 'BE':
            return self.up.pay(self.upstream_token(user_token, approval), inv, amount)
        return self.up.pay(user_token, inv, amount, body_approval=approval)  # N/B pass the user's token for payments


def cases():
    tools = {cfg: Tool(cfg) for cfg in ('N', 'B', 'BE')}

    def deleg(cfg, user='u1'):
        return tools[cfg].sts.delegate(user, 'agent:expense')

    def deleg_invoices(cfg):  # a delegated token usable at the upstream directly (for the pay path of N/B)
        return STS.mint({'sub': 'u1', 'aud': 'invoices', 'client_id': 'agent:expense', 'act': {'sub': 'agent:expense'},
                         NS: {'tenant_id': 'corp', 'user_id': 'u1'}}, lifetime=tools[cfg].sts.life)

    def pay_with(cfg, amount, approval):
        tok = deleg(cfg) if cfg == 'BE' else deleg_invoices(cfg)
        return tools[cfg].pay(tok, 'inv-1', amount, approval)

    def wrong_actor(cfg):
        # issued legitimately: the admin console handed the task to a read-only viewer agent; the viewer is acting now
        tok = STS.mint({'sub': 'u1', 'aud': 'invoices', 'client_id': 'agent:viewer', 'act': chain('console:admin', 'agent:viewer'),
                        NS: {'tenant_id': 'corp', 'user_id': 'u1'}, 'authorization_details': [
                            {'type': 'https://claims.example.com/rar/payment', 'actions': ['pay'], 'locations': ['inv-1'],
                             'instructedAmount': {'currency': 'JPY', 'amount': '120000'}}]})
        return tools[cfg].up.pay(tok, 'inv-1', 120000, body_approval='ap-311')

    def revoked(cfg):
        CLOCK.t = 1_800_000_000
        REVOKED.discard(('u1', 'agent:expense'))
        tok = deleg(cfg)
        CLOCK.advance(60)
        REVOKED.add(('u1', 'agent:expense'))  # the user withdraws the delegation
        CLOCK.advance(540)  # ten minutes after issuance the agent tries again
        try:
            if cfg == 'BE':
                return tools[cfg].read(tok, 'inv-1')
            return tools[cfg].up.read(deleg_invoices_at(cfg, tok), 'inv-1')
        finally:
            REVOKED.discard(('u1', 'agent:expense'))
            CLOCK.t = 1_800_000_000

    def deleg_invoices_at(cfg, tok):  # N/B: the agent reuses the one-hour delegation token directly at the upstream
        return STS.mint({'sub': 'u1', 'aud': 'invoices', 'client_id': 'agent:expense', 'act': {'sub': 'agent:expense'},
                         NS: {'tenant_id': 'corp', 'user_id': 'u1'}}, lifetime=3600, now=1_800_000_000)

    def deep(cfg, n):
        act = chain(*[f'agent:hop{i}' for i in range(n - 1)], 'tool:invoice-mcp')
        for a in [f'agent:hop{i}' for i in range(n - 1)]:
            ACTOR_POLICY.setdefault(a, {'read'})
        tok = STS.mint({'sub': 'u1', 'aud': 'invoices', 'client_id': 'tool:invoice-mcp', 'act': act, NS: {'tenant_id': 'corp', 'user_id': 'u1'}})
        return tools[cfg].up.read(tok, 'inv-1')

    return [
        Case('C1', 'legit', '委任', 'Part 10 エージェントの ID', '利用者 u1 の代わりにエージェントが、自分の請求書を読む', lambda cfg: tools[cfg].read(deleg(cfg), 'inv-1')),
        Case('C2', 'attack', 'パススルー', 'Part 10 MCP の認可', 'ツールサーバーが受け取った MCP 宛てのトークンを、そのまま上流に渡す',
             lambda cfg: tools[cfg].up.read(deleg(cfg), 'inv-1')),
        Case('C3', 'attack', '代理の混乱', 'Part 5 代理の混乱', 'u1 に委任されたエージェントが、ツールに u2 の請求書を読ませる',
             lambda cfg: tools[cfg].read(deleg(cfg), 'inv-2')),
        Case('C4', 'attack', 'act の読み違い', 'Part 10 4 つの問い', '過去の行為者（管理コンソール）の権限で、読み取り専用のエージェントが支払う（過去の act を今の行為者と読む）', wrong_actor),
        Case('C5', 'attack', '承認の照合', 'Part 10 人の承認の証拠', '120,000 円の承認で、990,000 円を支払う', lambda cfg: pay_with(cfg, 990000, 'ap-311')),
        Case('C6', 'attack', '承認の偽造', 'Part 10 人の承認の証拠', '存在しない承認 ID を本文に書いて支払う', lambda cfg: pay_with(cfg, 120000, 'ap-999')),
        Case('C7', 'legit', '承認', 'Part 10 人の承認の証拠', '承認どおり 120,000 円を支払う', lambda cfg: pay_with(cfg, 120000, 'ap-311')),
        Case('C8', 'attack', '委任の取り消し', 'Part 10 ツールごとのスコープ', '利用者が委任を取り消した 9 分後に、エージェントが読む', revoked),
        Case('C9', 'attack', '委任の深さ', 'Part 10 委任の連鎖と深さ', '5 段の委任の連鎖で読む', lambda cfg: deep(cfg, 5)),
        Case('C10', 'legit', '委任の深さ', 'Part 10 委任の連鎖と深さ', '2 段の委任の連鎖で読む', lambda cfg: deep(cfg, 2)),
    ]


def keycloak_exchange(reps=20):
    """Keycloak 26.8 standard token exchange V2: latency, and whether an act claim is produced."""
    import jwt
    sub = infra.token('corp', 'portal', 'carol', 'openid aud-mcp')['access_token']
    lat, out = [], None
    for _ in range(reps):
        t = time.perf_counter()
        st, j = infra.exchange('corp', 'mcp-tools', sub, audience='invoices', scope_='aud-invoices')
        lat.append((time.perf_counter() - t) * 1000)
        out = j
    c = jwt.decode(out['access_token'], options={'verify_signature': False}) if st == 200 else {}
    return {'status': st, 'ms_p50': statistics.median(lat), 'aud': c.get('aud'), 'azp': c.get('azp'), 'has_act': 'act' in c}


def sts_exchange_cost(reps=500):
    s = STSService('BE')
    lat = []
    for _ in range(reps):
        t = time.perf_counter()
        u = s.delegate('u1', 'agent:expense')
        s.exchange(u, 'tool:invoice-mcp', 'invoices')
        lat.append((time.perf_counter() - t) * 1e6)
    lat.sort()
    return {'per_task_two_hops_us_p50': statistics.median(lat), 'p95': lat[int(len(lat) * 0.95)],
            'revocation_window_s': {'N_B_lifetime_3600': {'max': 3600}, 'BE_per_task_300_and_recheck': {'max': 300, 'at_next_exchange': 0}}}


def run():
    return cases(), {'keycloak_exchange': keycloak_exchange(), 'sts_exchange': sts_exchange_cost()}

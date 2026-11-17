# -*- coding: utf-8 -*-
"""Access-token lifetime trade-off (guide Part 8): stale window vs authorisation-server load, simulated with a fixed seed.

Traffic model: 1,000 active users for one hour, each sending requests as a Poisson process at 2 requests/min; 5 % of requests
are critical (payments, admin). One attribute change per user at a uniformly random time. Strategies:
  self   : self-contained tokens only (the change is seen when the token is renewed at expiry)
  crit   : introspection / lookup for critical requests only
  always : introspection on every request
Stale window = time from the change until the first request that is evaluated with fresh information (critical requests only,
for 'crit'; any request for the others); a request evaluated with stale data in that window counts as a stale decision.
"""
import random
import statistics

USERS, HOURS, RATE_PER_MIN, CRIT = 1000, 1, 2.0, 0.05
LIFETIMES_MIN = (1, 5, 15, 60)


def simulate(lifetime_min, strategy, seed=20261117):
    rnd = random.Random(seed)
    L = lifetime_min * 60
    T = HOURS * 3600
    as_calls = 0
    stale_crit, stale_any, windows = 0, 0, []
    for _ in range(USERS):
        t, reqs = 0.0, []
        while True:
            t += rnd.expovariate(RATE_PER_MIN / 60)
            if t > T:
                break
            reqs.append((t, rnd.random() < CRIT))
        change = rnd.uniform(0, T)
        offset = rnd.uniform(0, L)  # tokens are renewed every L seconds, at a user-specific phase
        renewals = int(T // L) + 1
        as_calls += renewals
        next_renew = offset + ((change - offset) // L + 1) * L if change >= offset else offset
        seen = None
        for (rt, crit) in reqs:
            fresh = strategy == 'always' or (strategy == 'crit' and crit) or rt >= next_renew
            if strategy == 'always' or (strategy == 'crit' and crit):
                as_calls += 1
            if rt >= change:
                if fresh and seen is None:
                    seen = rt
                if not fresh:
                    stale_any += 1
                    stale_crit += crit
        windows.append((seen - change) if seen is not None else (T - change))
    return {'stale_window_s_mean': statistics.mean(windows), 'stale_window_s_p95': sorted(windows)[int(len(windows) * 0.95)],
            'stale_decisions_after_change': stale_any, 'stale_critical_decisions': stale_crit, 'as_calls_per_hour': as_calls}


def run():
    return {f'{L}min/{s}': simulate(L, s) for L in LIFETIMES_MIN for s in ('self', 'crit', 'always')} | {
        'model': {'users': USERS, 'hours': HOURS, 'requests_per_min_per_user': RATE_PER_MIN, 'critical_share': CRIT, 'seed': 20261117}}

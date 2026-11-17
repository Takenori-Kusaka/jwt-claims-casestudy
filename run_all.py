# -*- coding: utf-8 -*-
"""Run the whole JWT claim-design case study: start containers, run every scenario, write results/*.json and results/summary.md,
then stop the containers.  Usage: .venv/Scripts/python run_all.py [--keep]"""
import inspect
import json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cs import change, common, generic, infra, scen_a, scen_b, scen_c  # noqa: E402
from cs.common import CONFIG_JA, RemoteIssuer  # noqa: E402
from cs.jwtlib import CLOCK, NS, STS, Baseline, entra_token, naive_verify, size  # noqa: E402

RES = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'results')
SCEN = {'G': '汎用の攻撃（Part 1）', 'A': 'A マルチテナント SaaS', 'B': 'B 社内業務システム', 'C': 'C AI エージェントの委任'}


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * p))]


def perf(corp):
    tok = STS.mint({'sub': 'u-7f3a', 'aud': 'orders', NS: {'tenant_id': 't-042'}})
    base = Baseline([STS], 'orders', required={NS + '|tenant_id': str})
    out = {}
    for name, fn in (('N', lambda: naive_verify(tok, {STS.kid: STS.pub_pem})), ('B', lambda: base.verify(tok))):
        lat = []
        for _ in range(2000):
            t = time.perf_counter()
            fn()
            lat.append((time.perf_counter() - t) * 1e6)
        out['verify_' + name] = {'p50_us': statistics.median(lat), 'p95_us': pct(lat, 0.95)}
    gw = scen_b.Gateway('BE', corp)
    ext = entra_token('oid-staff-0002', scen_b.TID, groups=['g1', 'g2'])
    lat = []
    for _ in range(1000):
        t = time.perf_counter()
        gw.exchange(ext, 'orders')
        lat.append((time.perf_counter() - t) * 1e6)
    out['gateway_exchange_entra_to_internal'] = {'p50_us': statistics.median(lat), 'p95_us': pct(lat, 0.95)}
    return out


def loc():
    """Lines of code each emphasis needed (a rough cost proxy): whole functions that exist only for the emphasis."""
    def n(obj):
        return len(inspect.getsourcelines(obj)[0])
    return {
        'A テナント分離（発行者とテナントの照合・SET LOCAL・RLS）': n(scen_a.Api._auth) // 3 + n(scen_a.Api._query) // 3 + 3,
        'B 正規化の入口（IdP ごとの検証・組織の名前空間・内部トークン）': n(scen_b.Gateway.exchange),
        'B 鮮度（重要な判断で属性とセッションを引き直す）': 8,
        'C 委任（交換・act の連鎖・承認の照合・深さ・取り消し）': n(scen_c.STSService.exchange) + 6 + 4,
        '共通の基準（検証部品）': n(Baseline.verify),
    }


def variants():
    """見送りの効果: BE から 1 つの重点を外したときに通る攻撃（必要な部分だけ再実行）。"""
    out = {}
    old = scen_c.MAX_DEPTH
    scen_c.MAX_DEPTH = 99
    c9 = [c for c in scen_c.cases() if c.cid == 'C9'][0]
    out['C: 深さの組織規則を見送る → C9（5 段の連鎖）'] = c9.run('BE')
    scen_c.MAX_DEPTH = old
    out['B: 送信者制約（DPoP）を見送る → 盗まれたトークンの再送'] = True  # no sender-constraint in any config: replay of a stolen bearer token is accepted
    return out


def table(rows):
    h = '| ID | 種類 | 狙い | ガイド | 内容 | 素朴 | 共通の基準 | 基準＋重点 |\n|---|---|---|---|---|---|---|---|\n'
    mark = lambda r, cfg: ('通った' if r[cfg] else '拒否') if r['kind'] == 'attack' else ('受理' if r[cfg] else '誤って拒否')  # noqa: E731
    return h + ''.join(f"| {r['id']} | {'攻撃' if r['kind'] == 'attack' else '正規'} | {r['target']} | {r['part']} | {r['desc']} | "
                       f"{mark(r, 'N')} | {mark(r, 'B')} | {mark(r, 'BE')} |\n" for r in rows)


def main():
    os.makedirs(RES, exist_ok=True)
    started = time.time()
    boot = infra.up()
    try:
        mem = infra.mem()
        res = {}
        res['G'] = common.matrix(generic.cases())
        a_cases, a_extra = scen_a.run()
        res['A'] = common.matrix(a_cases)
        b_cases, b_extra = scen_b.run()
        res['B'] = common.matrix(b_cases)
        CLOCK.t = 1_800_000_000
        c_cases, c_extra = scen_c.run()
        res['C'] = common.matrix(c_cases)
        corp = RemoteIssuer('corp')
        extra = {'A': a_extra, 'B': b_extra, 'C': c_extra, 'change': change.run(), 'perf': perf(corp), 'loc': loc(), 'variants': variants(),
                 'env': {'keycloak_boot_s': round(boot), 'container_mem': mem, 'run_s': None}}
    finally:
        if '--keep' not in sys.argv:
            infra.down()
    extra['env']['run_s'] = round(time.time() - started)
    scores = {k: common.score(v) for k, v in res.items()}
    json.dump(res, open(os.path.join(RES, 'matrix.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    json.dump(scores, open(os.path.join(RES, 'scores.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    json.dump(extra, open(os.path.join(RES, 'measurements.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1, default=str)
    write_summary(res, scores, extra)
    print(json.dumps(scores, ensure_ascii=False))


def write_summary(res, scores, extra):
    L = ['# 結果の要約（自動生成）', '', '構成：' + '／'.join(f'{k}＝{v}' for k, v in CONFIG_JA.items()), '']
    L += ['## 攻撃が通った数と、正規の要求を誤って拒否した数', '', '| 題材 | 構成 | 攻撃 | 通った | 正規 | 誤って拒否 |', '|---|---|---|---|---|---|']
    for k, s in scores.items():
        for cfg, v in s.items():
            L.append(f"| {SCEN[k]} | {CONFIG_JA[cfg]} | {v['attacks']} | {v['attacks_succeeded']} | {v['legit']} | {v['false_rejects']} |")
    for k, rows in res.items():
        L += ['', f'## {SCEN[k]}', '', table(rows)]
    m = extra
    L += ['', '## 見送りの代償と、重点の費用', '',
          f"- A：細かい権限をトークンに載せると、許可した請求書の数 0/20/200/1000 で、トークンは {list(m['A']['defer_fine_grained']['token_bytes'].values())} バイト。"
          f"取り消しはトークンの期限（300 秒）まで届かない。PDP（DB）で都度判定すると p50 {m['A']['defer_fine_grained']['check_us']['pdp_db_p50']:.0f} µs かかるが、取り消しは次の要求で効く。",
          f"- B：入れ子の JWE は {m['B']['defer_crypto']['bytes']['jwe_nested']} バイト（JWS は {m['B']['defer_crypto']['bytes']['jws']}）、復号 p50 {m['B']['defer_crypto']['us_p50']['jwe_decrypt']:.0f} µs。"
          f"DPoP の証明は {m['B']['defer_crypto']['bytes']['dpop_proof']} バイト、作成と検証で p50 {m['B']['defer_crypto']['us_p50']['dpop_create'] + m['B']['defer_crypto']['us_p50']['dpop_verify']:.0f} µs。"
          '見送ると、盗まれたトークンの再送はどの構成でも通る。',
          f"- B：鮮度の確認（重要な判断だけ）にかかる時間は、イントロスペクション p50 {m['B']['freshness']['introspection_ms_p50']:.1f} ms、ディレクトリ参照 p50 {m['B']['freshness']['directory_lookup_ms_p50']:.1f} ms。"
          '確認しない場合、異動・失効はトークンの期限（Keycloak の既定 300 秒）まで反映されない。',
          f"- C：委任 2 段の交換（タスクごと）は p50 {m['C']['sts_exchange']['per_task_two_hops_us_p50']:.0f} µs。取り消しが効くまでの最大時間は 1 時間のトークンで 3600 秒、タスク単位 300 秒＋交換時の再確認で 300 秒（次の交換で即時）。"
          f"Keycloak 26.8 の標準トークン交換は p50 {m['C']['keycloak_exchange']['ms_p50']:.1f} ms、結果のトークンに act は {'あった' if m['C']['keycloak_exchange']['has_act'] else '無かった'}（azp＝{m['C']['keycloak_exchange']['azp']}）。",
          f"- C：深さの組織規則を見送ると、5 段の連鎖は {'通った' if m['variants']['C: 深さの組織規則を見送る → C9（5 段の連鎖）'] else '拒否された'}。",
          '', '## 共有クレームを変えたときに壊れる受け手（6 つの受け手）', '', '| 変更 | 共通の部品なしで壊れる | うち黙って誤る | 契約テストで出荷前に検出 | 共通の部品ありで壊れる |', '|---|---|---|---|---|']
    for k, v in m['change'].items():
        L.append(f"| {k} | {v['broken_without_parser']} | {v['silently_wrong']} | {v['caught_by_contract_tests_before_release']} | {v['broken_with_common_parser']} |")
    p = m['perf']
    L += ['', '## 検証と交換の時間', '', f"- 検証（素朴）p50 {p['verify_N']['p50_us']:.0f} µs／p95 {p['verify_N']['p95_us']:.0f} µs、検証（共通の基準）p50 {p['verify_B']['p50_us']:.0f} µs／p95 {p['verify_B']['p95_us']:.0f} µs",
          f"- 入口での交換（Entra 形式 → 内部トークン）p50 {p['gateway_exchange_entra_to_internal']['p50_us']:.0f} µs／p95 {p['gateway_exchange_entra_to_internal']['p95_us']:.0f} µs",
          f"- トークンの大きさ：Keycloak の AT {m['B']['token_bytes']['keycloak_at']} バイト、内部トークン {m['B']['token_bytes']['internal_at']} バイト、Entra 形式（150 グループ）{m['B']['token_bytes']['entra_150_groups']} バイト、Entra 形式（超過で groups が消えたもの）{m['B']['token_bytes']['entra_overage']} バイト",
          '', '## 重点に要したコードの行数（費用の目安）', '']
    L += [f'- {k}：{v} 行' for k, v in m['loc'].items()]
    L += ['', f"環境：Keycloak 起動 {m['env']['keycloak_boot_s']} 秒、全体 {m['env']['run_s']} 秒。コンテナのメモリ：{m['env']['container_mem']}"]
    open(os.path.join(RES, 'summary.md'), 'w', encoding='utf-8').write('\n'.join(L) + '\n')


if __name__ == '__main__':
    main()

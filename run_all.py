# -*- coding: utf-8 -*-
"""Run the whole JWT claim-design case study: start containers, run every scenario with every configuration and ablation,
measure Keycloak behaviour, simulate lifetimes, run the claim-change experiment, write results/ and stop the containers.
Usage: .venv/Scripts/python run_all.py [--keep]"""
import json
import os
import platform
import statistics
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import jwt  # noqa: E402

from cs import change, common, flags, generic, infra, kcmeasure, lifetime, scen_a, scen_b, scen_c  # noqa: E402
from cs.common import RemoteIssuer  # noqa: E402
from cs.jwtlib import CLOCK, NS, STS, entra_token, size  # noqa: E402
from cs.verify import Verifier  # noqa: E402

RES = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'results')
SCEN = {'G': '汎用の攻撃（Part 1）', 'A': 'A マルチテナント SaaS', 'B': 'B 社内業務システム', 'C': 'C AI エージェントの委任'}
REPS = 5000


def q(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * p))]


def timing(fn, reps=REPS):
    for _ in range(200):
        fn()
    lat = []
    for _ in range(reps):
        t = time.perf_counter()
        fn()
        lat.append((time.perf_counter() - t) * 1e6)
    return {'reps': reps, 'p50_us': statistics.median(lat), 'p95_us': q(lat, 0.95), 'p99_us': q(lat, 0.99)}


def perf(corp):
    tok = STS.mint({'sub': 'u-7f3a', 'aud': 'orders', NS: {'tenant_id': 't-042'}}, lifetime=10 ** 9)
    req = {'sub': str, NS + '|tenant_id': str}
    vn = Verifier(set(), {STS.iss: [STS]}, audience='orders', required=req, clock=CLOCK)
    vb = Verifier(set(flags.BASE), {STS.iss: [STS]}, audience='orders', required=req, clock=CLOCK)
    env = scen_b.Env(corp)
    gw = scen_b.Gateway(set(flags.BASE) | {'normalize_gw'}, env)
    ext = entra_token('oid-staff-0002', scen_b.TID, groups=['g1', 'g2'], iss=scen_b.ENTRA_ISS, lifetime=10 ** 9) if False else \
        entra_token('oid-staff-0002', scen_b.TID, groups=['g1', 'g2'], iss=scen_b.ENTRA_ISS)
    return {'verify_naive': timing(lambda: vn.verify(tok)), 'verify_baseline': timing(lambda: vb.verify(tok)),
            'gateway_exchange_entra_to_internal': timing(lambda: gw.forward(ext, [], 'orders'), reps=2000)}


def env_info():
    try:
        cpu = subprocess.run(['powershell', '-NoProfile', '-Command', '(Get-CimInstance Win32_Processor).Name'], capture_output=True, text=True).stdout.strip()
    except Exception:  # noqa: BLE001
        cpu = platform.processor()
    return {'cpu': cpu, 'os': platform.platform(), 'python': sys.version.split()[0], 'pyjwt': jwt.__version__, 'keycloak': infra.KC_IMAGE, 'postgres': infra.PG_IMAGE}


def run_scenario(key, cases):
    cfgs = flags.configs(key)
    rows = common.matrix(cases, cfgs)
    out = {'configs': {k: sorted(v) for k, v in cfgs.items()}, 'rows': rows, 'scores': common.score(rows, list(cfgs)),
           'ablation_B': common.ablation(rows, 'B', 'B'), 'blockers_B': common.blockers(rows, 'B', 'B')}
    if 'BE' in cfgs:
        out['ablation_BE'] = common.ablation(rows, 'BE', 'BE')
        out['blockers_BE'] = common.blockers(rows, 'BE', 'BE')
    return out


def main():
    os.makedirs(RES, exist_ok=True)
    started = time.time()
    boot = infra.up()
    res, extra = {}, {}
    try:
        mem = infra.mem()
        res['G'] = run_scenario('G', generic.cases())
        a_cases, extra['A'] = scen_a.run()
        res['A'] = run_scenario('A', a_cases)
        b_cases, extra['B'] = scen_b.run()
        res['B'] = run_scenario('B', b_cases)
        CLOCK.t = scen_c.T0
        c_cases, extra['C'] = scen_c.run()
        res['C'] = run_scenario('C', c_cases)
        extra['keycloak'] = kcmeasure.run()
        corp = RemoteIssuer('corp')
        extra['perf'] = perf(corp)
        extra['env'] = env_info() | {'keycloak_boot_s': round(boot), 'container_mem': mem}
    finally:
        if '--keep' not in sys.argv:
            infra.down()
    extra['change'] = change.run()
    extra['lifetime'] = lifetime.run()
    extra['env']['run_s'] = round(time.time() - started)
    json.dump(res, open(os.path.join(RES, 'matrix.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    json.dump(extra, open(os.path.join(RES, 'measurements.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1, default=str)
    json.dump({k: v['scores'] for k, v in res.items()}, open(os.path.join(RES, 'scores.json'), 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    write_summary(res, extra)
    print(json.dumps({k: {c: v['scores'][c] for c in ('N', 'B', 'BE') if c in v['scores']} for k, v in res.items()}, ensure_ascii=False))


def mark(r, c):
    if r['kind'] == 'attack':
        return '**通る**' if r[c] else '拒否'
    return '受理' if r[c] else '**誤拒否**'


def write_summary(res, x):
    L = ['# 結果の要約（自動生成）', '', '構成：N＝素朴（よくある誤り）／B＝共通の基準／BE＝共通の基準＋その題材の重点。'
         '除去実験：B から基準の要素を 1 つ、BE から重点の要素を 1 つずつ外して、どの攻撃が再び通るかを見る。', '']
    L += ['## 要素', '', '| 区分 | 要素 | 中身 | ガイド |', '|---|---|---|---|']
    for k, (ja, d, part) in flags.BASE.items():
        L.append(f'| 共通の基準 | {ja}（{k}） | {d} | {part} |')
    for s, es in flags.EMPH.items():
        for k, (ja, d, part) in es.items():
            L.append(f'| 重点 {s} | {ja}（{k}） | {d} | {part} |')
    L += ['', '## 攻撃が通った数と、正規の要求が正しく処理されなかった数', '', '| 題材 | N 通った | B 通った | BE 通った | 攻撃 | N 誤拒否 | B 誤拒否 | BE 誤拒否 | 正規 |', '|---|---|---|---|---|---|---|---|---|']
    for k, v in res.items():
        s = v['scores']
        be = s.get('BE', s['B'])
        L.append(f"| {SCEN[k]} | {s['N']['attacks_succeeded']} | {s['B']['attacks_succeeded']} | {be['attacks_succeeded'] if 'BE' in s else '—'} | {s['N']['attacks']} | "
                 f"{s['N']['false_rejects']} | {s['B']['false_rejects']} | {be['false_rejects'] if 'BE' in s else '—'} | {s['N']['legit']} |")
    for k, v in res.items():
        L += ['', f'## {SCEN[k]}', '', '| ID | 種類 | 狙い | ガイド | 内容 | N | B | BE |', '|---|---|---|---|---|---|---|---|']
        for r in v['rows']:
            L.append(f"| {r['id']} | {'攻撃' if r['kind'] == 'attack' else '正規'} | {r['target']} | {r['part']} | {r['desc']} | {mark(r, 'N')} | {mark(r, 'B')} | "
                     f"{mark(r, 'BE') if 'BE' in r else '—'} |")
        for full, key in (('B', 'ablation_B'), ('BE', 'ablation_BE')):
            if key not in v:
                continue
            names = flags.BASE if full == 'B' else flags.EMPH[k]
            L += ['', f'### 除去実験：{full} から 1 つ外すと', '', '| 外した要素 | 再び通る攻撃 | 新たに拒否される正規の要求 | 外すと通る正規の要求（要素の誤拒否の代償） |', '|---|---|---|---|']
            for e, a in v[key].items():
                L.append(f"| {names[e][0]} | {'、'.join(a['reopened']) or '—'} | {'、'.join(a['newly_rejected_legit']) or '—'} | {'、'.join(a['legit_only_without']) or '—'} |")
            multi = [c for c, es in v['blockers_' + full].items() if not es]
            if multi:
                L.append(f"\n{full} で防げている攻撃のうち、1 つ外しても防げたまま（複数の要素が重ねて防いでいる）：{'、'.join(multi)}")
        if k == 'A':
            r = {row['id']: row for row in v['rows']}
            L.append('\n接続プールの補足：' + '、'.join(f"{c}＝{'通る' if r['A7'][c] else '拒否'}" for c in ('BE~session', 'BE-data_tenant_check-rls_local', 'BE~session-data_tenant_check')))
    a, b, c, kc = x['A'], x['B'], x['C'], x['keycloak']
    L += ['', '## 見送りの代償と重点の費用', '',
          f"- A 細かい権限をトークンに：許可した請求書 0/20/200/1000 件で {list(a['defer_fine_grained']['token_bytes'].values())} バイト。PDP（DB）の判定 p50 {a['defer_fine_grained']['check_us']['pdp_db_p50']:.0f} µs／p95 {a['defer_fine_grained']['check_us']['pdp_db_p95']:.0f} µs。",
          f"- B JWE（入れ子）{b['defer_crypto']['bytes']['jwe_nested']} バイト（JWS {b['defer_crypto']['bytes']['jws']}）、暗号化 p50 {b['defer_crypto']['us']['jwe_encrypt']['p50']:.0f} µs、復号 p50 {b['defer_crypto']['us']['jwe_decrypt']['p50']:.0f} µs。"
          f"DPoP の証明 {b['defer_crypto']['bytes']['dpop_proof']} バイト、作成 p50 {b['defer_crypto']['us']['dpop_create']['p50']:.0f} µs・検証 p50 {b['defer_crypto']['us']['dpop_verify']['p50']:.0f} µs（{b['defer_crypto']['reps']} 回）。",
          f"- B 鮮度の確認：イントロスペクション p50 {b['freshness']['introspection_ms']['p50']:.1f} ms／p95 {b['freshness']['introspection_ms']['p95']:.1f} ms、ディレクトリ参照 p50 {b['freshness']['directory_lookup_ms']['p50']:.1f} ms（管理用トークンの取得を含む）。",
          f"- C タスクごとの 2 段の交換 p50 {c['sts_exchange']['per_task_two_hops_us_p50']:.0f} µs／p95 {c['sts_exchange']['p95']:.0f} µs。Keycloak の標準トークン交換 p50 {c['keycloak_exchange']['ms_p50']:.1f} ms／p95 {c['keycloak_exchange']['ms_p95']:.1f} ms（{c['keycloak_exchange']['reps']} 回）、act は {'あり' if c['keycloak_exchange']['has_act'] else 'なし'}。",
          '', '## Keycloak 26.8 の実際の挙動', '']
    L.append(f"- Full Scope Allowed：オンのクライアントに tenant-admin が漏れる＝{kc['full_scope']['fs-on']['tenant_admin_leaks']}、オフ＝{kc['full_scope']['fs-off']['tenant_admin_leaks']}（オフでは realm_access 自体が空：{kc['full_scope']['fs-off']['realm_roles']}）")
    lw = kc['lightweight']
    L.append(f"- 軽量アクセストークン：落ちるクレーム＝{'、'.join(lw['missing_in_light'])}（sub・aud・組織の名前空間も落ちる）")
    L.append(f"- 定義していない利用者属性：{json.dumps(kc['unmanaged_attribute'], ensure_ascii=False)}")
    L.append(f"- Organizations のクレーム：{json.dumps(kc['organizations'], ensure_ascii=False)}")
    L.append('- グループ数とトークンの大きさ（全量／軽量）：' + '、'.join(f"{n} 個＝{v['full_bytes']}/{v['light_bytes']} B" for n, v in kc['groups_size'].items()))
    L.append(f"- リフレッシュでの再評価：{json.dumps(kc['refresh_reevaluation'], ensure_ascii=False)}")
    L.append(f"- ログアウト → イントロスペクション：{json.dumps(kc['logout_introspection'], ensure_ascii=False)}")
    L.append(f"- 標準トークン交換の絞り込み・拡大の試験：{json.dumps(c['keycloak_exchange']['probes'], ensure_ascii=False)}")
    L += ['', '## 寿命の試算（1,000 人・1 時間・1 人 2 件／分・重要 5%）', '', '| 寿命 | 方式 | 変更後に古い情報で判断した件数 | うち重要な操作 | 古さの平均（秒） | p95（秒） | 認可サーバーへの呼び出し／時 |', '|---|---|---|---|---|---|---|']
    for k_, v_ in x['lifetime'].items():
        if k_ == 'model':
            continue
        lt, st = k_.split('/')
        ja = {'self': '自己完結のみ', 'crit': '重要な操作だけ問い合わせ', 'always': '毎回問い合わせ'}[st]
        L.append(f"| {lt} | {ja} | {v_['stale_decisions_after_change']} | {v_['stale_critical_decisions']} | {v_['stale_window_s_mean']:.0f} | "
                 f"{v_['stale_window_s_p95']:.0f} | {v_['as_calls_per_hour']} |")
    L += ['', '## 共有クレームを変えたとき（9 つの受け手）', '', '| 変更 | 壊れた | うち黙って誤る | 契約テストで出荷前に検出 | 検出できない受け手 | 共通の部品 |', '|---|---|---|---|---|---|']
    for k_, v_ in x['change'].items():
        L.append(f"| {k_} | {v_['broken']} | {len(v_['silently_wrong'])} | {v_['caught_by_contract_tests']} | {'、'.join(v_['broken_but_not_caught']) or '—'} | "
                 f"{'正しく処理' if v_['common_parser'] == 'ok' else '拒否（fail closed）' if v_['common_parser'] == 'crash' else '誤り'} |")
    p = x['perf']
    L += ['', '## 時間（検証は ' + str(p['verify_naive']['reps']) + ' 回、入口での交換は ' + str(p['gateway_exchange_entra_to_internal']['reps']) + ' 回）', '',
          f"- 検証（素朴）p50 {p['verify_naive']['p50_us']:.1f} µs／p95 {p['verify_naive']['p95_us']:.1f} µs、検証（共通の基準）p50 {p['verify_baseline']['p50_us']:.1f} µs／p95 {p['verify_baseline']['p95_us']:.1f} µs",
          f"- 入口での交換（Entra 形式 → 内部トークン）p50 {p['gateway_exchange_entra_to_internal']['p50_us']:.0f} µs／p95 {p['gateway_exchange_entra_to_internal']['p95_us']:.0f} µs",
          f"- トークンの大きさ：Keycloak の AT {b['token_bytes']['keycloak_at']} B、内部トークン {b['token_bytes']['internal_at']} B、Entra 形式 150 グループ {b['token_bytes']['entra_150_groups']} B、超過で groups が消えたもの {b['token_bytes']['entra_overage']} B",
          '', '## 環境', '', '```', json.dumps(x['env'], ensure_ascii=False, indent=1), '```']
    open(os.path.join(RES, 'summary.md'), 'w', encoding='utf-8').write('\n'.join(L) + '\n')


if __name__ == '__main__':
    main()

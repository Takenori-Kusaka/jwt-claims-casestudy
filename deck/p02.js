// Chapter 2: scenario A, multi-tenant SaaS
module.exports = (L) => {
  const { C } = L;
  const M = L.mk;
  L.section('2 題材 A マルチテナント SaaS');
  L.divider('CHAPTER 2', '題材 A マルチテナント SaaS', 'テナントの境界を、トークン・発行者・鍵・データの 4 か所で守る',
    ['基準だけでは、どの攻撃が通るか', '4 つの重点は、それぞれ何を止めるか', '接続プールで、何がテナントを漏らすか', '細かい権限をトークンに載せない代償は何か'],
    '第 2 章は題材 A、マルチテナント SaaS です。テナントごとに Keycloak のレルムを分け、API は Postgres の行単位の制御でデータを絞ります。共通の基準だけでは 10 件中 5 件の攻撃が通り、正規の集計の要求も誤ります。重点の 4 要素、テナントと発行者の照合、データ側のテナント照合、SET LOCAL と行単位の制御、テナント単位の鍵を足すと、すべて止まります。最後に、細かい権限をトークンに載せないという見送りの代償を測ります。');

  {
    const s = L.content('題材 A の構成：テナントごとのレルムと、Postgres の RLS', {
      lead: 't1・t2 の 2 つのレルム（実機）が発行し、API は 1 本のプールした接続で Postgres（RLS）を読む',
      stages: [3],
      notes: '題材 A の構成です。Keycloak の実機に、テナント t1 と t2 のレルムを作りました。t1 には利用者 alice、t2 には bob がいます。t1 には、通常のクライアントのほか、軽量アクセストークンのクライアント、マッパーの設定誤りでテナントが配列になるクライアントもあります。t2 には、t2 の管理者が自分のレルムのマッパーで tenant_id を t1 にしてしまうクライアント rogue-web を置きました。さらに、t2 の連携先に渡した署名鍵で作ったトークンも攻撃に使います。API は saas-api 宛てのアクセストークンを受け、組織の名前空間の tenant_id でテナントを決めます。データベースへの接続は、構成ごとに 1 本をプールして使い回します。Postgres の請求書の表には RLS を設定し、取引ごとに app.tenant を設定します。アクセストークンの寿命は 300 秒です。右は重点の 4 要素です。',
      refs: { res: 'results/summary.md §A マルチテナント SaaS', code: 'cs/scen_a.py Api・cases()／kc/import/t1.json・t2.json（accessTokenLifespan 300）', guide: 'ガイド Part 5（マルチテナント）・Part 7（データ層）' },
    });
    L.box(s, [{ text: 'Keycloak レルム t1', options: { bold: true, fontSize: 14, breakLine: true } }, { text: 'alice／通常・軽量 AT・配列のクライアント', options: { fontSize: 11 } }], { x: 0.6, y: 1.95, w: 3.2, h: 0.95, fill: C.accent1 });
    L.box(s, [{ text: 'Keycloak レルム t2', options: { bold: true, fontSize: 14, breakLine: true } }, { text: 'bob／rogue-web（tenant_id=t1 を出す）', options: { fontSize: 11 } }], { x: 0.6, y: 3.05, w: 3.2, h: 0.95, fill: C.accent5 });
    L.box(s, [{ text: 't2 の連携先', options: { bold: true, fontSize: 14, breakLine: true } }, { text: '渡した署名鍵で自分で発行', options: { fontSize: 11 } }], { x: 0.6, y: 4.15, w: 3.2, h: 0.95, fill: C.accent3 });
    L.arrow(s, 3.85, 3.52, 0.6, 'r');
    s.addShape(L.SH.LINE, { x: 3.85, y: 2.42, w: 0.6, h: 0.95, line: { color: L.MUTED, width: 1.75, endArrowType: 'triangle' } });
    s.addShape(L.SH.LINE, { x: 3.85, y: 3.67, w: 0.6, h: 0.95, flipV: true, line: { color: L.MUTED, width: 1.75, endArrowType: 'triangle' } });
    L.box(s, [{ text: 'API（saas-api）', options: { bold: true, fontSize: 14, breakLine: true } }, { text: '基準の検証・名前空間の tenant_id', options: { fontSize: 11 } }], { x: 4.5, y: 3.0, w: 2.4, h: 1.05, fill: C.accent4 });
    L.arrow(s, 6.95, 3.52, 0.45, 'r');
    L.box(s, [{ text: 'Postgres 16', options: { bold: true, fontSize: 14, breakLine: true } }, { text: '請求書の表・RLS', options: { fontSize: 11 } }], { x: 7.45, y: 3.0, w: 1.6, h: 1.05, fill: C.text2 });
    L.T(s, '1 本のプールした接続', { x: 6.6, y: 4.15, w: 2.4, h: 0.3, fontSize: 10.5, color: L.MUTED, margin: 0, align: 'center' });
    const em = [['tenant_iss_bind', 'テナントのクレームが、発行したレルムと一致するか'], ['per_tenant_keys', '署名鍵をテナントのレルムだけに登録する'], ['data_tenant_check', 'すべての SQL にテナントの条件（ID 指定・集計も）'], ['rls_local', '取引ごとに SET LOCAL で文脈を設定し、RLS で絞る']];
    L.T(s, '重点の 4 要素', { x: 9.35, y: 1.95, w: 3.35, h: 0.35, fontSize: 14, bold: true, color: C.accent2, margin: 0 });
    em.forEach((e, i) => L.box(s, [{ text: e[0], options: { bold: true, fontSize: 12, breakLine: true } }, { text: e[1], options: { fontSize: 10.5 } }], { x: 9.35, y: 2.35 + i * 0.95, w: 3.35, h: 0.85, fill: C.background2, color: C.text1, lineColor: L.BORDER, bold: false, align: 'left' }));
    L.note(s, 'tip', 'アクセストークンの寿命は 300 秒（レルムの設定）', { x: 0.6, y: 5.45, w: 8.45, h: 0.6, size: 12.5, label: '' });
  }

  {
    const s = L.content('題材 A の結果：基準（B）で 10 件中 5 件が残り、重点を足すと 0 件', {
      lead: '基準で残るのは BOLA・接続プール・他テナントのマッパー・連携先の鍵（2 件）。正規の集計（A4）も基準では誤る',
      stages: [3],
      notes: '題材 A の 14 件の結果です。素朴（N）では攻撃 10 件中 9 件が通りました。基準（B）では 5 件が残ります。残るのは、t2 の請求書の ID を直接指定する BOLA（オブジェクト単位の認可の欠落）の A6、接続プールの文脈の残りの A7、t2 の管理者が自分のレルムのマッパーで tenant_id を t1 にする A8、t2 の連携先に渡した鍵で t1 のトークンを作る A9 と、iss を t2 のままテナントだけ t1 を名乗る A10 です。どれもトークンの署名は正しく、期限内で、宛先も合っているため、受け入れの検証では止まりません。A8 は実際の Keycloak で起きることで、レルムの管理者は自分のレルムのマッパーで任意の値を出せます。正規の A4 は、集計の API が素朴と基準では他テナントの行まで返したため、正しく処理されなかったと数えています。基準＋重点（BE）ではすべての攻撃が拒否され、正規の 4 件も正しく処理されました。A12 の配列のテナントは素朴でも拒否されています。',
      refs: { res: 'results/summary.md §A の表／results/scores.json 題材 A（素朴 9・基準 5・基準＋重点 0）', code: 'cs/scen_a.py cases()', guide: 'ガイド Part 5（BOLA・マルチテナント）・Part 7（接続プール）' },
    });
    const rows = [
      ['A1', '正規：t1 の利用者が自テナントの請求書を一覧', '受理', '受理', '受理'],
      ['A2', '正規：t2 の利用者が自テナントの請求書を一覧', '受理', '受理', '受理'],
      ['A3', '正規：t1 の利用者が自分の請求書を ID で読む', '受理', '受理', '受理'],
      ['A4', '正規：t1 の利用者が集計 API で自テナントだけを得る', '誤処理', '誤処理', '受理'],
      ['A5', 't2 のトークンで、パスとヘッダー X-Tenant を t1 にする', '通る', '拒否', '拒否'],
      ['A6', 't1 の利用者が t2 の請求書の ID を直接指定（BOLA）', '通る', '通る', '拒否'],
      ['A7', 't2 の文脈が残った接続で、条件を忘れた集計 API を t1 が呼ぶ', '通る', '通る', '拒否'],
      ['A8', 't2 の管理者がマッパーで tenant_id=t1 を出させる（実機）', '通る', '通る', '拒否'],
      ['A9', 't2 の連携先の鍵で、iss=t1・tenant=t1 のトークンを作る', '通る', '通る', '拒否'],
      ['A10', '同じ鍵で、iss=t2 のまま tenant=t1 を名乗る', '通る', '通る', '拒否'],
      ['A11', '軽量 AT で tenant が落ち、X-Tenant: t2 で既定を上書き', '通る', '拒否', '拒否'],
      ['A12', 'マッパーの誤りで tenant が配列 ["t1","t2"]', '拒否', '拒否', '拒否'],
      ['A13', 'ログインで得た ID トークンを API に送る', '通る', '拒否', '拒否'],
      ['A14', '期限切れのトークン（発行から 400 秒後）', '通る', '拒否', '拒否']];
    L.table(s, [['ID', '内容', '素朴（N）', '基準（B）', '基準＋重点（BE）']].concat(rows.map((r) => [r[0], r[1], M(r[2]), M(r[3]), M(r[4])])),
      { x: 0.6, y: 1.9, w: 12.1, colW: [0.75, 7.55, 1.1, 1.1, 1.6], fontSize: 10.5, rowH: 0.29 });
  }

  {
    const s = L.content('題材 A の重点：照合と鍵は単独で効き、データ側は重ねがけ', {
      lead: '基準＋重点（BE）から tenant_iss_bind を外すと A8・A10、per_tenant_keys を外すと A9 が再び通る',
      stages: [3],
      notes: '基準＋重点（BE）から重点の要素を 1 つずつ外した結果です。テナントと発行者の照合を外すと、A8 と A10 が再び通ります。どちらも、トークンのテナントのクレームと、そのトークンを発行したレルムが食い違う攻撃です。テナント単位の鍵を外すと、t2 の連携先に渡した鍵で iss を t1 と書いたトークンが t1 の鍵として受け入れられ、A9 が通ります。NIST IR 8587 の鍵のスコープの考え方です。一方、データ側のテナント照合と SET LOCAL と行単位の制御は、どちらか 1 つを外しても何も再び通りません。片方がもう片方を覆っているからで、重ねがけです。両方を外すと何が起きるかは次のスライドで見ます。BE で防げている攻撃のうち、A5・A6・A7・A11〜A14 の 7 件は、重点を 1 つ外しても防げたままでした。',
      refs: { res: 'results/summary.md §A 除去実験：BE から 1 つ外すと', code: 'cs/scen_a.py Api._auth()（tenant_iss_bind）・Api.__init__（per_tenant_keys）・get()・report()', guide: 'ガイド Part 5（IR 8587 §5.2.1.2 の鍵のスコープ）・Part 7' },
    });
    L.table(s, [['重点の要素', '中身', 'BE から外すと再び通る'],
      ['tenant_iss_bind', 'テナントのクレームが、発行したレルムと一致するか', { text: 'A8、A10', options: { bold: true, color: C.accent3 } }],
      ['per_tenant_keys', '署名鍵をテナントのレルムだけに登録する', { text: 'A9', options: { bold: true, color: C.accent3 } }],
      ['data_tenant_check', 'すべての SQL にテナントの条件（ID 指定・集計も）', '—（rls_local と重ねて防御）'],
      ['rls_local', '取引ごとに SET LOCAL で文脈を設定し、RLS で絞る', '—（data_tenant_check と重ねて防御）']],
    { x: 0.6, y: 1.95, w: 12.1, colW: [2.3, 5.9, 3.9], fontSize: 12.5, rowH: 0.52 });
    L.card(s, { x: 0.6, y: 4.75, w: 5.9, h: 1.7, icon: 'MdVpnKey', color: C.accent3, title: 'A8 は実機の Keycloak で起きる', titleSize: 14, body: ['t2 の管理者は、自分のレルムのマッパーで任意の tenant_id を出せる。署名は正しいので、基準の 9 要素では止まらない'], bodySize: 12 });
    L.note(s, 'leader', '重ねがけは、片方の書き忘れに備える保険。BE で防げている 7 件（A5〜A7・A11〜A14）は、1 つ外しても防げたまま', { x: 6.8, y: 4.75, w: 5.9, h: 1.7, size: 12.5 });
  }

  {
    const s = L.content('接続プール：接続単位の文脈と、条件の書き忘れが重なると漏れる', {
      lead: 'SET LOCAL（取引単位）か SQL のテナント条件のどちらかがあれば A7 は止まる。両方なければ通る',
      stages: [3],
      notes: '接続プールの攻撃 A7 を、構成を変えて確かめた結果です。A7 は、直前に t2 の要求を処理した接続を、t1 の要求が使い回す場面です。集計の API はテナントの条件を書き忘れています。BE では、取引ごとに SET LOCAL で文脈を設定し、SQL にもテナントの条件があるので、拒否されます。文脈を接続単位で設定する、よくある誤りの構成 BE~session でも、SQL のテナント条件があるので拒否されます。しかし、接続単位の設定のままテナント条件を外すと、前の要求の t2 の文脈が残った接続で、t1 の利用者が t2 の行を読めてしまいます。RLS もテナント条件も無い構成、BE − data_tenant_check − rls_local でも通ります。この構成では A7 のほかに、BOLA の A6 も通り、正規の集計 A4 も他テナントの行を返して誤処理になりました。RLS を入れていても、文脈の設定の仕方を誤ると守れない、というのがこの実験の要点です。',
      refs: { res: 'results/summary.md §A 接続プールの補足', code: 'cs/flags.py（BE~session ほか 3 構成）／cs/scen_a.py Api._run()', guide: 'ガイド Part 7（接続プール・SET LOCAL）' },
    });
    L.table(s, [['構成', '文脈の設定', 'SQL のテナント条件', 'A7', 'ほかの影響'],
      ['BE', 'SET LOCAL（取引単位）＋ RLS', 'あり', M('拒否'), '—'],
      ['BE~session', '接続単位（よくある誤り）＋ RLS', 'あり', M('拒否'), '—'],
      ['BE − data_tenant_check − rls_local', 'なし（RLS なし）', 'なし', M('通る'), { text: 'A6 も通る。正規の A4 を誤処理', options: { bold: true, color: C.accent3 } }],
      ['BE~session − data_tenant_check', '接続単位 ＋ RLS', 'なし', M('通る'), '—']],
    { x: 0.6, y: 1.95, w: 12.1, colW: [3.8, 3.2, 1.9, 0.9, 2.3], fontSize: 12, rowH: 0.52 });
    L.flow(s, [{ t: 't2 の要求', d: '接続に app.tenant=t2 を設定', fill: C.accent5 }, { t: '同じ接続を再利用', d: '文脈が残ったまま', fill: C.accent2 }, { t: 't1 の集計 API', d: 'テナント条件を書き忘れ', fill: C.accent3 }, { t: 't2 の行が返る', d: 'RLS は残った t2 で絞る', fill: C.text2 }], { x: 0.6, y: 4.75, w: 12.1, h: 0.95, tSize: 13.5, dSize: 11 });
    L.T(s, 'RLS を入れても、文脈を接続単位で設定すると守れない。SET LOCAL を共通の部品にする', { x: 0.6, y: 5.9, w: 12.1, h: 0.4, fontSize: 13, bold: true, color: C.accent3, margin: 0 });
  }

  {
    const s = L.content('題材 A の見送り：請求書ごとの許可は載せず、PDP で判定する', {
      lead: '許可した請求書が 1,000 件でトークンは 6,563 バイト。PDP（DB）の判定は p50 548 µs',
      stages: [3],
      notes: '題材 A で見送ったのは、請求書ごとの細かい許可をトークンに載せることです。許可した請求書の ID をトークンに入れると、0 件で 634 バイト、20 件で 707 バイト、200 件で 1,629 バイト、1,000 件で 6,563 バイトになりました。判定の時間は、トークンの中を見るだけなら p50 0.1 マイクロ秒ですが、PDP としてデータベースを引いても p50 548 マイクロ秒、p95 693 マイクロ秒で、2,000 回の測定です。取り消しの反映は、トークンに載せると寿命の 300 秒の間は古いままで、最大 300 秒、平均 150 秒です。これは寿命の設定からの計算で、PDP なら即時です。見送りで失うのは、トークン単独で請求書ごとの許可を判定できないことです。見直し条件は、付録の一覧表の authorization_details の行に書いたとおり、連携先に特定の請求書だけを一時的に渡す共有を、トークンで表す必要が出たときです。',
      refs: { res: 'results/measurements.json A.defer_fine_grained／catalog/jwt-claims-catalog.xlsx CLM-0256（A）', code: 'cs/scen_a.py defer_fine_grained()（2,000 回）', guide: 'ガイド Part 4・5（変わりやすい権限は PDP で）' },
    });
    L.bar(s, { x: 0.6, y: 1.9, w: 6.6, h: 4.1, labels: ['0 件', '20 件', '200 件', '1,000 件'], values: [634, 707, 1629, 6563], title: 'トークンの大きさ（バイト）：許可した請求書の件数ごと', fmt: '#,##0', colors: [L.HEX.accent2] });
    L.card(s, { x: 7.5, y: 1.9, w: 5.2, h: 1.12, color: C.accent1, title: '判定の時間（2,000 回）', titleSize: 13, titleH: 0.34, pad: 0.08, body: ['トークン内 p50 0.1 µs／PDP（DB）p50 548 µs・p95 693 µs'], bodySize: 11 });
    L.card(s, { x: 7.5, y: 3.04, w: 5.2, h: 1.12, color: C.accent5, title: '取り消しの反映', titleSize: 13, titleH: 0.34, pad: 0.08, body: ['載せると寿命 300 秒の間は古い（最大 300・平均 150 秒、設定からの計算）。PDP は即時'], bodySize: 11 });
    L.card(s, { x: 7.5, y: 4.18, w: 5.2, h: 1.12, color: C.accent3, title: '失うこと', titleSize: 13, titleH: 0.34, pad: 0.08, body: ['トークン単独では請求書ごとの許可を判定できない（毎回 PDP を引く）'], bodySize: 11 });
    L.card(s, { x: 7.5, y: 5.32, w: 5.2, h: 1.12, color: C.accent2, title: '見直し条件', titleSize: 13, titleH: 0.34, pad: 0.08, body: ['連携先に特定の請求書だけを一時的に渡す共有を、トークンで表す必要が出たら'], bodySize: 11 });
  }
};

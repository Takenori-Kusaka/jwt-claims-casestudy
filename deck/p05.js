// Chapter 5: measurements (Keycloak 26.8 behaviour, token size, lifetime simulation, costs, shared-claim changes)
module.exports = (L) => {
  const { C, HEX } = L;
  L.section('5 測定');
  L.divider('CHAPTER 5', '測定：Keycloak 26.8・寿命・大きさ・変更', '文書だけでは分からない製品の挙動と、トレードオフを数字で示す',
    ['Keycloak の交換・イントロスペクション・リフレッシュは実際どう動くか', 'グループの数で、トークンはどこまで大きくなるか', '寿命と問い合わせの方式で、古い判断はどれだけ残るか', '共有クレームを変えると、何が壊れ、何が見つかるか'],
    '第 5 章は測定です。前半は Keycloak 26.8.0 の実機で、標準トークン交換、イントロスペクション、リフレッシュ、軽量アクセストークン、Full Scope Allowed、定義していない利用者属性、Organizations、グループ数とトークンの大きさを測りました。後半は、アクセストークンの寿命と問い合わせの方式の試算、時間と大きさの一覧、共有クレームを変えたときに 9 つの受け手がどうなるかの実験です。');

  {
    const s = L.content('Keycloak 26.8 の標準交換：元のトークンに無い宛先へ広げられる', {
      lead: 'optional scope の aud-orders を求めると、元に無い orders 宛てが 200 で出た',
      stages: [6],
      notes: 'Keycloak 26.8 の標準トークン交換を、クライアント mcp-tools から試した結果です。交換に使った元のトークンは、利用者 carol が portal でログインして得たもので、宛先は mcp-tools と account です。audience に invoices、scope に aud-invoices を指定すると、200 で invoices 宛てのトークンが出ました。絞り込みは期待どおりです。audience だけを指定すると「Requested audience not available: invoices」の 400、設定に無い audience では「Audience not found」の 400 でした。注目は 4 行目で、mcp-tools に optional scope として割り当てた aud-orders だけを scope に指定すると、200 で orders と account 宛てのトークンが出ました。元のトークンの宛先に orders は無かったので、交換で宛先が広がったことになります。何も指定しないと account 宛てです。200 回の交換の時間は p50 9.7 ミリ秒、p95 31.3 ミリ秒で、交換結果に act のクレームはありませんでした。この挙動は Keycloak の文書にも書かれていて、既定では交換で元に無いスコープと宛先を要求できます。audience パラメータは宛先を絞るだけで足さず、宛先を足すのは scope です。絞り込みだけを許すには、client policy の executor downscope-assertion-grant-enforcer をクライアントに適用します。交換は元のトークンの宛先に縛られないので、この executor で交換を絞り込みだけに限り、受け手では aud を 1 つに限るのが安全です。',
      refs: { res: 'measurements.json C.keycloak_exchange／Keycloak 文書（Token exchange・downscoping）', code: 'cs/scen_c.py keycloak_exchange()／cs/infra.py CORP_OPTIONAL', guide: 'ガイド Part 10（トークン交換）・Part 3（Keycloak）' },
    });
    L.table(s, [['試験', '要求', '結果', '交換後の aud', '交換後の scope'],
      ['narrow_to_invoices', 'audience=invoices・scope=aud-invoices', '200', 'invoices', 'aud-invoices email profile'],
      ['audience_not_in_scope', 'audience=invoices だけ', '400 Requested audience not available', '—', '—'],
      ['audience_not_configured', 'audience=orders-admin（設定に無い）', '400 Audience not found', '—', '—'],
      [{ text: 'scope_not_granted', options: { color: C.accent3 } }, 'scope=aud-orders だけ（optional scope）', { text: '200', options: { bold: true, color: C.accent3 } }, { text: 'orders・account', options: { bold: true, color: C.accent3 } }, 'aud-orders email profile'],
      ['no_audience_no_scope', '指定なし', '200', 'account', 'email profile']],
    { x: 0.6, y: 1.95, w: 12.1, colW: [2.5, 3.4, 2.6, 1.6, 2.0], fontSize: 11.5, rowH: 0.5 });
    L.T(s, '元のトークン（portal でログイン、scope aud-mcp）の aud：mcp-tools・account。交換 200 回：p50 9.7 ms／p95 31.3 ms。交換結果に act は無い', { x: 0.6, y: 5.05, w: 12.1, h: 0.4, fontSize: 12, color: L.MUTED, margin: 0 });
    L.note(s, 'leader', '交換は元のトークンの宛先に縛られない。downscope-assertion-grant-enforcer で絞り込みだけに限り、受け手で aud を 1 つに限る（題材 C の aud_exchange）', { x: 0.6, y: 5.55, w: 12.1, h: 0.85, size: 13 });
  }

  {
    const s = L.content('Keycloak 26.8 のイントロスペクションは、宛先のクライアントだけ', {
      lead: 'active=true は aud の orders だけ。発行した portal でも false（3 クライアントで各 1 回）',
      stages: [6],
      notes: 'Keycloak のイントロスペクションとリフレッシュの挙動です。portal で発行した orders 宛てのトークンを、3 つのクライアントの資格情報で 1 回ずつイントロスペクションすると、active が true になるのは aud に含まれる orders だけで、トークンを発行した portal や mcp-tools では false でした。これは Keycloak の文書に書かれた仕様で、互換のためのクライアント設定で無効にもできます。イントロスペクションで鮮度を確かめる受け手は、自分がトークンの aud に入っている必要があります。ログアウトの後は、20 回の試行すべてで最初の確認から inactive になり、かかったのは最大 26.8 ミリ秒でした。JWT そのものには少なくとも 299 秒の寿命が残っていました。リフレッシュでは、利用者の部署を sales から finance に変え、auditor のロールを足してからリフレッシュすると、新しいアクセストークンに両方が反映されました。再ログインでも同じです。このレルムは Revoke Refresh Token を有効にしていて（既定は無効）、リフレッシュトークンは入れ替わりました。ここから、属性の古さの上限はアクセストークンの寿命、このレルムでは 300 秒だと推論できます。これは設定値からの推論で、古さそのものは測っていません。',
      refs: { res: 'measurements.json keycloak（logout・refresh）／Keycloak 文書（aud 確認）', code: 'cs/kcmeasure.py／kc/import/corp.json（revokeRefreshToken・寿命 300）', guide: 'ガイド Part 3（Keycloak）・Part 8（リフレッシュ・失効）' },
    });
    const cw = 3.83, y = 1.95, h = 3.2;
    L.card(s, { x: 0.6, y, w: cw, h, icon: 'MdManageSearch', color: C.accent1, title: 'イントロスペクション', titleSize: 15, body: ['orders（aud）：true', 'portal（発行したクライアント）：false', 'mcp-tools：false', '問い合わせる受け手を aud に入れる'], bodySize: 12.5 });
    L.card(s, { x: 4.73, y, w: cw, h, icon: 'MdLogout', color: C.accent3, title: 'ログアウトの後', titleSize: 15, body: ['20 回すべて、最初の確認で inactive', '最大 26.8 ms', 'JWT 自体は 299 秒以上有効のまま'], bodySize: 12.5 });
    L.card(s, { x: 8.87, y, w: cw, h, icon: 'MdRefresh', color: C.accent4, title: 'リフレッシュ', titleSize: 15, body: ['発行時：department=sales・auditor なし', 'リフレッシュ後：finance・auditor あり', '再ログインも同じ', 'RT は入れ替わった（Revoke Refresh Token を有効にしたレルム）'], bodySize: 12.5 });
    L.note(s, 'tip', 'リフレッシュで属性とロールは再評価される。古さの上限はアクセストークンの寿命（このレルムは 300 秒。設定値からの推論）', { x: 0.6, y: 5.4, w: 12.1, h: 0.75, size: 13 });
  }

  {
    const s = L.content('Keycloak 26.8 の軽量 AT は sub・aud・組織のクレームも落とす', {
      lead: '通常 20 個のクレームが、軽量では 8 個。設定 1 つでテナントの境界の根拠が消える（A11）',
      stages: [6],
      notes: 'Keycloak の既定と設定による違いです。軽量アクセストークンを有効にしたクライアントでは、通常 20 個あったクレームが 8 個になりました。落ちたのは、acr、aud、email、email_verified、family_name、given_name、組織の名前空間、name、preferred_username、realm_access、resource_access、sub の 12 個です。sub と aud と組織のテナントまで落ちるので、必須のクレームが欠けたら拒否する基準が無いと、A11 のようにヘッダーのテナントで補ってしまいます。Full Scope Allowed をオンにしたクライアントには、必要のない tenant-admin のロールが漏れ、オフにすると realm_access 自体が空になりました。なお、Full Scope Allowed の設定は非推奨で、将来削除される予定です。定義していない利用者属性は、ユーザープロファイルの設定が ENABLED なら保存され、既定の無効では保存されず、HTTP のエラーも返りませんでした。黙って消えます。Organizations を有効にすると、organization のクレームは、既定の ["acme"] という配列でした。マッパーの設定によってはオブジェクトの形にもなるので、設定を変えたら型の固定も見直します。',
      refs: { res: 'measurements.json keycloak.lightweight ほか／Keycloak 管理ガイド', code: 'cs/kcmeasure.py／kc/import/t1.json（saas-light・fs-on・fs-off）', guide: 'ガイド Part 3（Keycloak）・Part 4（型・必須）' },
    });
    L.table(s, [['項目', '測った結果', '設計への意味'],
      ['軽量アクセストークン', '20 → 8 クレーム。落ちた 12：acr・aud・email・email_verified・family_name・given_name・組織の名前空間・name・preferred_username・realm_access・resource_access・sub', '必須のクレームが欠けたら拒否する（required）'],
      ['Full Scope Allowed', 'オン：要らない tenant-admin が漏れる／オフ：realm_access が空', 'オフにし、要るロールだけ割り当てる（この設定は非推奨で、将来削除予定）'],
      ['定義していない利用者属性', 'ENABLED：保存される／既定（無効）：保存されず、HTTP エラーも無い', '黙って消える。属性はユーザープロファイルで定義する'],
      ['Organizations', 'organization クレームは既定で配列 ["acme"]（マッパーの設定でオブジェクトにもなる）', '型を固定する（types）。マッパーの設定を変えたら型も見直す']],
    { x: 0.6, y: 1.95, w: 12.1, colW: [2.4, 5.9, 3.8], fontSize: 11.5, rowH: 0.7 });
  }

  {
    const s = L.content('グループをトークンに載せると、200 個で 8,609 バイトになる', {
      lead: 'Keycloak：グループ 0 個 1,394 B → 200 個 8,609 B。軽量アクセストークンは 759 B のまま',
      stages: [6],
      notes: 'グループの数とトークンの大きさです。Keycloak でグループのマッパーを付けたクライアントでは、グループ 0 個で 1,394 バイト、10 個で 1,769 バイト、50 個で 3,209 バイト、100 個で 5,009 バイト、200 個で 8,609 バイトになりました。グループ名は 24 文字です。軽量アクセストークンは、グループの数にかかわらず 759 バイトでした。参考に、題材 B の測定では、Entra 形式で 150 グループのトークンが 8,650 バイト、上限を超えて groups が消えたトークンが 1,042 バイトでした。内部トークンは 967 バイト、Keycloak のアクセストークンは 1,423 バイトです。HTTP のヘッダーの大きさには上限があるので、groups をそのまま載せる設計は、組織が大きくなると破綻します。付録の一覧表では、組織のロールのクレームの見直し条件を、ロールの数がトークンの上限に近づいたら PDP で都度引く方式に移す、としています。',
      refs: { res: 'measurements.json keycloak.groups_size・B.token_bytes／一覧表 ORG-03', code: 'cs/kcmeasure.py groups_size()／cs/scen_b.py run()', guide: 'ガイド Part 3（Entra の groups 超過）・Part 4' },
    });
    L.bar(s, { x: 0.6, y: 1.9, w: 7.4, h: 4.3, labels: ['0 個', '10 個', '50 個', '100 個', '200 個'], series: [{ name: '全量（グループのマッパーあり）', labels: ['0 個', '10 個', '50 個', '100 個', '200 個'], values: [1394, 1769, 3209, 5009, 8609] }, { name: '軽量アクセストークン', labels: ['0 個', '10 個', '50 個', '100 個', '200 個'], values: [759, 759, 759, 759, 759] }], colors: [HEX.accent1, HEX.accent5], legend: true, fmt: '#,##0', title: 'トークンの大きさ（バイト）：グループの数ごと' });
    L.table(s, [['ほかの大きさ', 'バイト'],
      ['Keycloak のアクセストークン', '1,423'],
      ['内部トークン（題材 B）', '967'],
      ['Entra 形式・150 グループ', '8,650'],
      ['Entra 形式・超過で groups が消えた', '1,042']],
    { x: 8.3, y: 1.95, w: 4.4, colW: [3.2, 1.2], fontSize: 12, rowH: 0.46 });
    L.note(s, 'tip', 'ロールの数がトークンの上限に近づいたら、PDP で都度引く方式に移す（一覧表 ORG-03 の見直し条件）', { x: 8.3, y: 4.6, w: 4.4, h: 1.6, size: 12.5, label: '' });
  }

  {
    const s = L.content('寿命の試算：寿命が長いほど、古い情報での判断が増える', {
      lead: '1,000 人・1 時間・1 人 2 件／分・重要な操作 5%・属性は 1 人 1 回変わる・乱数の種 20261117',
      stages: [6],
      notes: 'アクセストークンの寿命と、問い合わせの方式の試算です。1,000 人の利用者が 1 時間、1 人あたり 1 分に 2 件の要求を送り、そのうち 5% が支払いや管理などの重要な操作で、各利用者の属性が 1 時間に 1 回変わる、というモデルです。乱数の種は 20261117 に固定しています。方式は 3 つで、自己完結のトークンだけ、重要な操作だけ問い合わせる、毎回問い合わせる、です。自己完結だけでは、寿命 1 分で属性の変更後に古い情報で判断した件数が 984 件、うち重要な操作が 55 件、60 分では 40,883 件、うち重要 2,096 件になります。重要な操作だけ問い合わせると、重要な操作の古い判断はどの寿命でも 0 になります。毎回問い合わせると古い判断は 0 ですが、認可サーバーへの呼び出しは 1 時間に 12 万から 18 万回になります。古さの列は、変更から最初に新しい情報で判断されるまでの秒数です。',
      refs: { res: 'results/summary.md §寿命の試算／results/measurements.json lifetime', code: 'cs/lifetime.py simulate()（seed=20261117）', guide: 'ガイド Part 8（寿命と失効）' },
    });
    const R = [['1 分', '自己完結のみ', '984', '55', '59', '122', '61,000'], ['', '重要な操作だけ問い合わせ', '929', '0', '56', '122', '67,109'], ['', '毎回問い合わせ', '0', '0', '30', '91', '181,249'],
      ['5 分', '自己完結のみ', '4,950', '258', '177', '313', '13,000'], ['', '重要な操作だけ問い合わせ', '4,692', '0', '149', '302', '19,109'], ['', '毎回問い合わせ', '0', '0', '30', '91', '133,249'],
      ['15 分', '自己完結のみ', '14,358', '777', '452', '872', '5,000'], ['', '重要な操作だけ問い合わせ', '13,581', '0', '284', '747', '11,109'], ['', '毎回問い合わせ', '0', '0', '30', '91', '125,249'],
      ['60 分', '自己完結のみ', '40,883', '2,096', '1,231', '2,861', '2,000'], ['', '重要な操作だけ問い合わせ', '38,787', '0', '430', '1,267', '8,109'], ['', '毎回問い合わせ', '0', '0', '30', '91', '122,249']];
    const rows = R.map((r) => r.map((c, i) => (i === 3 && c !== '0') ? { text: c, options: { bold: true, color: C.accent3, align: 'right' } } : (i >= 2 ? { text: c, options: { align: 'right' } } : c)));
    L.table(s, [['寿命', '方式', '古い判断', 'うち重要', '古さ平均（秒）', 'p95（秒）', '認可サーバーへの呼び出し／時']].concat(rows),
      { x: 0.6, y: 1.9, w: 12.1, colW: [0.9, 3.0, 1.4, 1.2, 1.6, 1.3, 2.7], fontSize: 10.5, rowH: 0.32 });
  }

  {
    const s = L.content('重要な操作だけ問い合わせると、重要な古い判断は 0（モデル上）', {
      lead: '毎回問い合わせに比べた呼び出しは、寿命 1 分で 37%、5 分で 14%、15 分で 8.9%、60 分で 6.6%',
      stages: [6],
      notes: '前のスライドの試算から、重要な操作だけ問い合わせる方式を、毎回問い合わせる方式と比べました。重要な操作の古い判断は、どの寿命でも 0 です。認可サーバーへの呼び出しは、毎回問い合わせる場合に比べて、寿命 1 分で 37%、5 分で 14%、15 分で 8.9%、60 分で 6.6% でした。寿命を延ばすほど呼び出しは減りますが、重要でない操作の古い判断は増え、15 分で 13,581 件、60 分で 38,787 件残ります。題材 B の freshness は、この「重要な操作だけ問い合わせる」方式に当たります。比は 1 つの数字で言わず、寿命ごとの値で伝えてください。この試算はモデルで、利用者の行動や変更の頻度が違えば値も変わります。重要な操作の 0 も、モデルの定義によるものです。重要な操作では毎回問い合わせて最新の値で判断する、と置いているので、定義上 0 になります。問い合わせの遅延や、問い合わせ先の情報そのものの遅れは含みません。',
      refs: { res: 'results/measurements.json lifetime（as_calls_per_hour・stale_critical_decisions）', code: 'cs/lifetime.py', guide: 'ガイド Part 8（寿命の間のクレーム）' },
    });
    const labels = ['1 分', '5 分', '15 分', '60 分'];
    L.bar(s, { x: 0.6, y: 1.9, w: 7.6, h: 4.4, series: [{ name: '自己完結のみ', labels, values: [61000, 13000, 5000, 2000] }, { name: '重要な操作だけ問い合わせ', labels, values: [67109, 19109, 11109, 8109] }, { name: '毎回問い合わせ', labels, values: [181249, 133249, 125249, 122249] }], colors: [HEX.accent5, HEX.accent1, HEX.accent3], legend: true, fmt: '#,##0', showValue: false, title: '認可サーバーへの呼び出し／時（寿命ごと。値は前の表）' });
    L.table(s, [['寿命', '重要だけ÷毎回', '重要でない古い判断'],
      ['1 分', '37%', '929'], ['5 分', '14%', '4,692'], ['15 分', '8.9%', '13,581'], ['60 分', '6.6%', '38,787']],
    { x: 8.5, y: 1.95, w: 4.2, colW: [1.0, 1.5, 1.7], fontSize: 12, rowH: 0.46 });
    L.note(s, 'leader', '重要な操作だけ問い合わせる（題材 B の freshness）。比は 1 つの数字でなく、寿命ごとの値で伝える', { x: 8.5, y: 4.6, w: 4.2, h: 1.7, size: 12.5 });
  }

  {
    const s = L.content('費用の一覧：基準の検証はほぼ無料。重い費用は外部への問い合わせ', {
      lead: '時間は p50／p95、回数を併記。同じ PC（Ryzen 7 3700X・Python 3.14.6・PyJWT 2.10.1）での値',
      stages: [6],
      notes: 'この実験で測った時間の一覧です。検証は 5,000 回で、素朴な検証が p50 82.3、p95 138.2 マイクロ秒、共通の基準が p50 84.2、p95 108.4 マイクロ秒で、基準の費用はほとんどありません。入口での Entra 形式から内部トークンへの交換は p50 682、p95 1,027 マイクロ秒、JWE の暗号化と復号、DPoP の証明の作成と検証、PDP の判定、題材 C のタスクごとの 2 段の発行は、いずれも 2,000 回の測定で、1 ミリ秒前後かそれ以下です。桁が変わるのは、ネットワーク越しに Keycloak を呼ぶもので、標準トークン交換が p50 9.7 ミリ秒、イントロスペクションが p50 8.9 ミリ秒、ディレクトリの参照が p50 50.7 ミリ秒、いずれも 200 回です。1 台の PC の値なので、絶対値より比で読んでください。',
      refs: { res: 'results/measurements.json perf（reps）・B.defer_crypto・B.freshness・A・C', code: 'cs/scen_a.py・scen_b.py・scen_c.py の測定関数', guide: 'ガイド Part 6・8・9' },
    });
    const r = (a, b, c, d) => [a, { text: b, options: { align: 'right' } }, { text: c, options: { align: 'right' } }, { text: d, options: { align: 'right' } }];
    L.table(s, [['測定', 'p50', 'p95', '回数'],
      r('検証（素朴）', '82.3 µs', '138.2 µs', '5,000'),
      r('検証（共通の基準）', '84.2 µs', '108.4 µs', '5,000'),
      r('入口の交換（Entra 形式 → 内部トークン）', '682 µs', '1,027 µs', '2,000'),
      r('JWE の暗号化／復号', '142／628 µs', '202／899 µs', '2,000'),
      r('DPoP の証明の作成／検証', '99／97 µs', '153／142 µs', '2,000'),
      r('PDP（DB）の判定', '548 µs', '693 µs', '2,000'),
      r('題材 C のタスクごとの 2 段の発行', '1,182 µs', '1,548 µs', '2,000'),
      r('Keycloak の標準トークン交換', '9.7 ms', '31.3 ms', '200'),
      r('イントロスペクション（Keycloak）', '8.9 ms', '31.8 ms', '200'),
      r('ディレクトリ参照（管理用トークンの取得を含む）', '50.7 ms', '75.6 ms', '200')],
    { x: 0.6, y: 1.9, w: 12.1, colW: [6.1, 2.2, 2.2, 1.6], fontSize: 11.5, rowH: 0.38 });
  }

  {
    const s = L.content('共有クレームの変更：10 の変更のうち 8 つで黙って誤る', {
      lead: '9 つの受け手（Python・JS・Go・Envoy・CEL・SQL の RLS・K8s・Java・旧システム）× 10 の変更',
      stages: [6],
      notes: '共有クレームを発行側で変えたとき、今の形を前提に書かれた 9 つの受け手がどうなるかの実験です。受け手は、Python、JavaScript、Go、Envoy、CEL の規則、SQL の RLS、Kubernetes の claimMappings、Java、sub をキーにする旧システムで、それぞれよくある書き方を再現しています。壊れたは、例外で落ちたか黙って誤ったかの合計です。黙って誤る受け手が出なかったのは、roles を配列にする変更と、sub を不変の UUID にする変更の 2 つだけで、残りの 8 つでは、どれかの受け手がエラーを出さずに誤った判断をしました。tenant を大文字にする変更と、制限のクレーム ip_allow を足す変更は、9 つすべてが黙って誤りました。契約テストは、受け手が読む経路と型を宣言し、出荷前に検査するものです。右端の共通の部品は、受け手が生のクレームを読まずに組織の共通の部品で読む場合で、10 の変更のうち 9 つを正しく処理し、mfa を文字列にする変更は拒否、つまり fail closed しました。',
      refs: { res: 'results/summary.md §共有クレームを変えたとき／results/measurements.json change', code: 'cs/change.py', guide: 'ガイド Part 4（型）・Part 11（契約テスト・変更の手順）' },
    });
    const n = (v, warn) => ({ text: v, options: Object.assign({ align: 'center' }, warn && v !== '0' ? { bold: true, color: C.accent3 } : {}) });
    const R = [['roles：空白区切り → 配列', '6', '0', '6', '正しく処理'], ['roles：空白区切り → カンマ区切り', '7', '7', '0', '正しく処理'], ['employee_id：文字列 → 2^53 超の数値', '5', '4', '3', '正しく処理'],
      ['tenant：大文字に変わる（T1）', '9', '9', '5', '正しく処理'], ['roles：組織の URL 名前空間へ移す', '9', '4', '9', '正しく処理'], ['roles：名前を role に変える', '9', '4', '9', '正しく処理'],
      ['mfa：無い（=false）から null に', '2', '2', '2', '正しく処理'], ['mfa：真偽値を文字列 "false" に', '3', '2', '3', '拒否（fail closed）'], ['制限のクレーム ip_allow を追加', '9', '9', '0', '正しく処理'],
      ['sub：ログイン名 → 不変の UUID（user_id は残す）', '1', '0', '1', '正しく処理']];
    L.table(s, [['変更', '壊れた', 'うち黙って誤る', '契約テストで検出', '共通の部品']].concat(R.map((r) => [r[0], n(r[1]), n(r[2], true), n(r[3]), r[4]])),
      { x: 0.6, y: 1.95, w: 12.1, colW: [5.0, 1.3, 1.9, 1.9, 2.0], fontSize: 11.5, rowH: 0.39 });
  }

  {
    const s = L.content('契約テストは万能ではない。共通の部品は 10 の変更を受け止めた', {
      lead: '契約テストで全部は見つからない変更が 4 つ。共通の部品は 9 つを正しく処理し、1 つは拒否（fail closed）した',
      stages: [6],
      notes: '前のスライドの表から、契約テストの限界と共通の部品の効果を取り出しました。壊れた受け手を契約テストが全部は見つけられなかった変更は 4 つです。roles をカンマ区切りにする変更は 7 つが壊れて検出 0、制限のクレーム ip_allow の追加は 9 つが壊れて検出 0 でした。どちらも、受け手が読む経路と型は変わらず、意味だけが変わるため、型の契約では見つかりません。tenant を大文字にする変更は 9 つが壊れ、検出は 5 つです。employee_id を 2 の 53 乗を超える数値にする変更は 5 つが壊れ、契約テストが見つけたのは 3 つだけで、Kubernetes の claimMappings と sub をキーにする旧システムは見逃されました。「契約テストで検出できる」と言うときは、何件中何件かを添えてください。一方、組織の共通の部品で読ませた場合は、10 の変更のうち 9 つを正しく処理し、mfa を文字列の "false" にする変更は拒否して止まりました。誤って許可するのではなく拒否する、fail closed の振る舞いです。',
      refs: { res: 'measurements.json change／summary.md §共有クレームを変えたとき', code: 'cs/change.py', guide: 'ガイド Part 11（契約テスト・変更の手順）' },
    });
    L.card(s, { x: 0.6, y: 1.95, w: 3.85, h: 3.15, icon: 'MdWarning', color: C.accent3, title: 'employee_id を数値に', titleSize: 15, body: ['壊れた 5 つのうち、契約テストが見つけたのは 3 つ', '見逃し：Kubernetes の claimMappings、sub をキーにする旧システム'], bodySize: 12.5 });
    L.card(s, { x: 4.73, y: 1.95, w: 3.85, h: 3.15, icon: 'MdVisibilityOff', color: C.accent2, title: '形は同じで意味が変わる', titleSize: 15, body: ['カンマ区切り：7 つ壊れ、検出 0', 'ip_allow の追加：9 つ壊れ、検出 0', 'tenant の大文字：9 つ壊れ、検出 5'], bodySize: 12.5 });
    L.card(s, { x: 8.87, y: 1.95, w: 3.83, h: 3.15, icon: 'MdShield', color: C.accent4, title: '共通の部品で読む', titleSize: 15, body: ['10 の変更のうち 9 つを正しく処理', 'mfa の文字列化は拒否（fail closed）', '誤って許可した変更は 0'], bodySize: 12.5 });
    L.note(s, 'leader', '共有クレームの変更は、契約テスト＋共通の部品＋変更の手順の 3 つで守る。「検出できる」は何件中何件かを添えて言う', { x: 0.6, y: 5.35, w: 12.1, h: 0.85, size: 13 });
  }
};

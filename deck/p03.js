// Chapter 3: scenario B, internal business systems behind a gateway
module.exports = (L) => {
  const { C } = L;
  const M = L.mk;
  L.section('3 題材 B 社内業務システム');
  L.divider('CHAPTER 3', '題材 B 社内業務システム', '5 つの IdP のトークンを入口で内部トークンに正規化する。厳しい基準は正規の要求も止める',
    ['入口の正規化は、何を解決するか', 'IdP ごとの癖は、どこで事故になるか', '厳しい基準が止めた 2 件の正規の要求を、どう通すか', '盗まれたトークンの再送を、なぜ見送るか'],
    '第 3 章は題材 B、社内業務システムです。社員は Keycloak、Entra ID、Okta、Cognito、Auth0 のどれかでログインし、入口のゲートウェイを通って社内のサービスを呼びます。Keycloak は実機、ほかの 4 社は公式文書の形の模擬です。共通の基準で 18 件中 11 件が止まりますが、ヘッダーの偽装と属性の鮮度の攻撃は残り、さらに正規の要求が 2 件拒否されます。重点を足すと攻撃は 1 件まで減り、誤拒否は 0 になります。残る 1 件、盗まれたトークンの再送は意図した見送りです。');

  {
    const s = L.content('題材 B の構成：入口で IdP ごとに検証し、内部トークンに交換する', {
      lead: 'サービスは内部トークンだけを読む。旧来の入口は Keycloak のロールをヘッダー X-User-Role に写していた',
      stages: [4],
      notes: '題材 B の構成です。左が 5 つの IdP で、Keycloak の corp レルムは実機、Entra ID・Okta・Cognito・Auth0 は模擬です。Okta は、自社 API 向けのカスタム認可サーバー（default）の AT を模擬しました。基準＋重点（BE）の構成では、入口のゲートウェイが IdP ごとに決めた発行者・種類・宛先・必須クレームで検証し、組織の名前空間に正規化した内部トークンに交換します。サービスは内部トークンだけを受け、外部の IdP のトークンは受けません。ヘッダーの除去では、クライアントが送った x-user- で始まるヘッダーを、大文字小文字、アンダースコア、重複を含めて捨てます。Entra ID の groups が上限を超えて消えたときは、重点の overage_resolve として、入口がディレクトリを引いて解決します。比較の相手の旧来の構成では、入口は Keycloak 向けに作られていて、ロールをヘッダー X-User-Role に写し、サービスはそのヘッダーを信じます。さらにサービスのフレームワークは、ヘッダー名を小文字にし、アンダースコアをハイフンに変え、重複した値をカンマでつなぎます。入口での交換は p50 682 マイクロ秒、p95 1,027 マイクロ秒、2,000 回の測定です。内部トークンは 967 バイトで、Keycloak のアクセストークンの 1,423 バイトより小さくなりました。',
      refs: { res: 'results/summary.md §B・§時間／measurements.json perf・B.token_bytes', code: 'cs/scen_b.py Gateway・Service・Env.normalize()／kc/import/corp.json', guide: 'ガイド Part 3（IdP の実際）・Part 6（流れ）' },
    });
    const idps = [['Keycloak corp', '実機', C.accent1], ['Entra ID', '模擬', C.accent5], ['Okta', '模擬', C.accent5], ['Cognito', '模擬', C.accent5], ['Auth0', '模擬', C.accent5]];
    idps.forEach((d, i) => L.box(s, [{ text: d[0], options: { bold: true, fontSize: 13, breakLine: true } }, { text: d[1], options: { fontSize: 10.5 } }], { x: 0.6, y: 1.95 + i * 0.78, w: 2.3, h: 0.66, fill: d[2] }));
    L.arrow(s, 2.95, 3.85, 0.55, 'r');
    L.card(s, { x: 3.6, y: 1.95, w: 4.1, h: 3.8, icon: 'MdRouter', color: C.accent2, fill: 'FBF3E4', title: '入口（ゲートウェイ）', titleSize: 15, body: ['normalize_gw：IdP ごとの iss・typ・aud・必須を検証し、内部トークン（at+jwt）に交換', 'header_strip：x-user-* を大文字小文字・アンダースコア・重複を含めて除去', 'overage_resolve：groups が消えたらディレクトリで引く', '交換 p50 682 µs・p95 1,027 µs（2,000 回）'], bodySize: 11.5 });
    L.arrow(s, 7.75, 3.85, 0.55, 'r');
    L.card(s, { x: 8.4, y: 1.95, w: 4.3, h: 2.2, icon: 'MdDns', color: C.accent4, title: '社内のサービス', titleSize: 15, body: ['内部トークンだけを受ける', 'freshness：経理・管理の操作は属性とセッションを引き直す'], bodySize: 12 });
    L.note(s, 'warn', 'フレームワークはヘッダー名を小文字にし、_ を - に変え、重複を「,」で連結する（CVE-2026-26308 の型）', { x: 8.4, y: 4.3, w: 4.3, h: 1.45, size: 12, label: '' });
    L.T(s, '内部トークン 967 B（Keycloak の AT 1,423 B）', { x: 3.6, y: 5.9, w: 9.1, h: 0.35, fontSize: 12, color: L.MUTED, margin: 0 });
  }

  {
    const s = L.content('IdP ごとの癖：同じ情報が、IdP ごとに違う場所と形で来る', {
      lead: '入口の正規化で IdP ごとに読み分け、内部トークンでは組織の名前空間に揃える。右端は、その癖を突くケース',
      stages: [4],
      notes: 'IdP ごとの違いです。種類の値は、Keycloak が at+jwt ですが、これは既定ではなく、クライアント設定 access.token.header.type.rfc9068 を有効にした結果です。Auth0 の at+jwt は RFC 9068 プロファイルを選んだ場合で、既定の Auth0 プロファイルでは JWT です。模擬は RFC 9068 プロファイルを選んだ形です。Entra ID は JWT です。Okta は、自社 API 向けのカスタム認可サーバーの AT を模擬しました。Okta の文書「Validate Access Tokens」によると、org 認可サーバーの AT は Okta 以外が検証すべきではありません。模擬で使った typ の値 application/okta-internal-at+jwt は、公式文書では確かめられていません。Cognito は typ ではなく token_use で見分けます。不変の ID は、Entra ID が oid と tid の組、Okta が uid、ほかは sub です。Okta のアクセストークンの sub はログイン名で、再利用されると別人と一致します。Entra ID は、グループが上限を超えると groups が消えて _claim_names に置き換わります。模擬の上限は 200 で、ケースでは 250 グループを使いました。Entra のマルチテナントの発行者を {tenantid} のまま何でも受ける実装は、別の顧客テナントのトークンを通します。Okta のインラインフックは 3 秒で打ち切られ、クレームが欠けたまま発行されます。Cognito のアクセストークンは、resource を指定しない、つまりリソースバインディングを使わない既定では aud が無く、client_id で宛先を表します。模擬はこの既定の形です。custom: で始まる属性は本人が書き換えられ、発行前のフックで groups が消えることがあります。Auth0 は、名前空間の無い予約名 roles のクレームを黙って外します。これらはすべて模擬の上の再現で、各社の公式文書の形に基づいています。表のロールの列は、ロールやグループを運ぶクレームの場所です。',
      refs: { res: 'summary.md §B／Okta Validate Access Tokens・Auth0 AT Profiles・Cognito 文書', code: 'cs/scen_b.py Env.verifier()／cs/jwtlib.py／kc corp.json（rfc9068）／HDR-01', guide: 'ガイド Part 3（Entra ID・Keycloak・Okta・Cognito・Auth0）' },
    });
    L.table(s, [['IdP', '種類（typ）', '不変の ID', 'ロール', '癖（ケース）'],
      ['Keycloak（実機）', 'at+jwt（クライアント設定 rfc9068）', 'sub', 'realm_access.roles', '軽量 AT で sub・aud・組織のクレームが落ちる（A11）'],
      ['Entra ID（模擬）', 'JWT', 'oid＋tid', 'groups', '上限超過で groups が消える（B8・B9）。{tenantid} を何でも受けると別の顧客テナント（B10）'],
      ['Okta（模擬）', 'カスタム認可サーバーの AT。typ は application/okta-internal-at+jwt（文書で未確認）', 'uid', 'groups', 'sub はログイン名で再利用される（B13）。インラインフックが 3 秒で打ち切られる（B15）'],
      ['Cognito（模擬）', 'token_use=access', 'sub', 'cognito:groups', '既定（resource なし）では AT に aud が無く client_id（B16）。custom: は本人が書ける（B18）。フックで groups が消える（B19）'],
      ['Auth0（模擬）', 'at+jwt（RFC 9068 プロファイル選択時）', 'sub', '組織の名前空間', '名前空間の無い予約名 roles を黙って外す（B20）']],
    { x: 0.6, y: 1.95, w: 12.1, colW: [1.65, 2.75, 0.95, 1.65, 5.1], fontSize: 10.5, rowH: 0.62 });
    L.note(s, 'tip', '内側のサービスに IdP ごとの読み分けを持たせない。癖は入口の 1 か所で吸収する', { x: 0.6, y: 5.95, w: 12.1, h: 0.55, size: 12.5, label: '' });
  }

  {
    const s = L.content('題材 B の結果：基準（B）で 18 件中 7 件が残り、重点で 1 件まで減る', {
      lead: '素朴（N）では 18 件すべて通る。基準で 11 件止まり、重点でさらに 6 件。残る 1 件は意図した見送り',
      stages: [4],
      notes: '題材 B の 23 件を、どこで止まったかでまとめました。素朴（N）では攻撃 18 件がすべて通ります。共通の基準で止まるのは 11 件で、ID トークンの流用、宛先の差し替え、groups の超過で消えた一般社員の管理操作、別の顧客テナントのトークン、Okta のログイン名の再利用、フックの打ち切りで欠けたクレーム、Cognito の ID トークン、本人が書ける custom 属性、フックで消えた groups、Auth0 が黙って外したクレーム、2 の 53 乗を超える数値の社員番号です。基準ではトークンしか見ないので、ヘッダーの偽装 4 件と、異動とログアウトの 2 件は残ります。これらは重点で止まります。基準＋重点（BE）でも通るのは、盗まれたトークンの再送 B23 だけです。正規の要求は 5 件で、B1・B14・B21 は常に受理されますが、B9 と B16 は基準で拒否されます。これが次の次のスライドの話題です。',
      refs: { res: 'results/summary.md §B の表／results/scores.json 題材 B（素朴 18・基準 7・基準＋重点 1）', code: 'cs/scen_b.py cases()', guide: 'ガイド Part 3・4・6・8' },
    });
    L.card(s, { x: 0.6, y: 1.95, w: 4.6, h: 4.5, icon: 'MdVerified', color: C.accent1, title: '基準で止まる　11 件', titleSize: 15, body: ['B2 ID トークン／B3 宛先の差し替え', 'B8 groups が消えた一般社員', 'B10 別の顧客テナントの Entra', 'B13 Okta のログイン名の再利用', 'B15 フックの打ち切りで部署が欠ける', 'B17 Cognito の ID トークン', 'B18 本人が書ける custom:role', 'B19 フックで消えた groups', 'B20 Auth0 が黙って外した roles', 'B22 2^53 超の数値の社員番号'], bodySize: 11.5 });
    L.card(s, { x: 5.4, y: 1.95, w: 3.6, h: 2.65, icon: 'MdAddModerator', color: C.accent4, title: '重点で止まる　6 件', titleSize: 15, body: ['B4〜B6 ヘッダーの偽装（X-User-Role・アンダースコア・重複）', 'B7 入口の迂回', 'B11 異動後の古い属性', 'B12 ログアウト後のトークン'], bodySize: 11.5 });
    L.card(s, { x: 5.4, y: 4.75, w: 3.6, h: 1.7, icon: 'MdReplay', color: C.accent3, title: '基準＋重点でも通る　1 件', titleSize: 15, body: ['B23 盗まれたトークンの再送（意図した見送り）'], bodySize: 11.5 });
    L.card(s, { x: 9.2, y: 1.95, w: 3.5, h: 4.5, icon: 'MdPersonOutline', color: C.accent2, title: '正規の要求　5 件', titleSize: 15, body: ['B1・B14・B21：3 つの構成すべてで受理', 'B9 Entra の groups 超過の管理者：基準（B）で誤拒否 → BE で受理', 'B16 既定の形で aud の無い Cognito の AT：基準（B）で誤拒否 → BE で受理'], bodySize: 11.5 });
  }

  {
    const s = L.content('ヘッダーの偽装：除去と正規化は重ねがけ', {
      lead: 'B4〜B7 は基準では止まらない。入口の迂回（B7）は正規化でしか止まらない',
      stages: [4],
      notes: 'ヘッダーの偽装の 4 件です。B4 はクライアントが X-User-Role: admins を付けて送るもの、B5 はアンダースコア版の X_User_Role で、フレームワークがアンダースコアをハイフンに変えるため通ります。CVE-2025-64484 の型です。B6 は小文字の x-user-role を足して重複させ、フレームワークが値をカンマでつなぐことを利用します。CVE-2026-26308 の型です。B7 は、入口を通らずにサービスへ直接、正しいトークンと偽のヘッダーを送るものです。トークン自体は正しいので、基準の 9 要素では 4 件とも止まりません。基準＋重点（BE）ではすべて拒否されます。BE からヘッダーの除去だけを外しても、どれも再び通りません。サービスが内部トークンだけを受け、ヘッダーを読まなくなるからです。入口での正規化を外すと、B7 が再び通り、正規の Cognito の B16 も拒否されます。入口を迂回されたときに守るのは、サービス側の「内部トークンだけを受ける」規則です。',
      refs: { res: 'results/summary.md §B の表・§B 除去実験：BE から 1 つ外すと', code: 'cs/scen_b.py Gateway.forward()（header_strip）・Service.org()・headers_seen()', guide: 'ガイド Part 6（ヘッダーへの転記・検証の分担）' },
    });
    L.table(s, [['ケース', '手口', '基準（B）', '基準＋重点（BE）', 'BE から外すと'],
      ['B4', 'クライアントが X-User-Role: admins を付ける', M('通る'), M('拒否'), '重ねて防御'],
      ['B5', 'アンダースコア版 X_User_Role（CVE-2025-64484 の型）', M('通る'), M('拒否'), '重ねて防御'],
      ['B6', '小文字の x-user-role を足して重複させ、値を連結（CVE-2026-26308 の型）', M('通る'), M('拒否'), '重ねて防御'],
      ['B7', '入口を通らず、サービスに直接、正しいトークンと偽のヘッダー', M('通る'), M('拒否'), { text: 'normalize_gw を外すと通る', options: { bold: true, color: C.accent3 } }]],
    { x: 0.6, y: 1.95, w: 12.1, colW: [0.9, 5.5, 1.1, 1.7, 2.9], fontSize: 12, rowH: 0.55 });
    L.note(s, 'leader', 'ヘッダーの除去は入口にしか置けない。入口を迂回されたときの最後の砦は、サービスが「内部トークンだけを受ける」こと', { x: 0.6, y: 4.95, w: 12.1, h: 0.85, size: 13.5 });
  }

  {
    const s = L.content('厳しい基準の誤拒否 2 件は、基準を緩めず入口で直す', {
      lead: 'B9（Entra の groups 超過の管理者）と B16（既定の形の Cognito の AT）。重点を足すと誤拒否は 0',
      stages: [4],
      notes: '共通の基準を厳しくしたことで、正規の要求が 2 件拒否されました。B9 は、250 のグループに属して groups が消えた Entra ID の管理者が、管理操作を呼ぶものです。groups が無いので必須のロールが欠け、required が拒否します。required を外せば B9 は通りますが、同じ形の一般社員 B8 と、フックの打ち切りでクレームが欠けた B15 が再び通ります。重点の overage_resolve は、groups が消えて _claim_names があるときにディレクトリで引き直すもので、これで B9 は受理されます。BE からこれを外すと B9 は再び拒否されます。B16 は、リソースバインディングを使わない既定の形で aud が無い Cognito のアクセストークンです。模擬はこの既定の形です。aud の確認が拒否します。aud を外せば通りますが、宛先の差し替え B3 が再び通ります。重点の入口での正規化は、Cognito だけは client_id を照合し、内部トークンにはサービスの aud を入れます。誤拒否が出たときに基準の要素を外すと、別の攻撃が通ります。直すのは、その IdP の形を入口で正規化することです。',
      refs: { res: 'results/summary.md §B 除去実験（B から・BE から 1 つ外すと）', code: 'cs/scen_b.py Env.normalize()（overage_resolve）・Gateway.forward()（Cognito の client_id）', guide: 'ガイド Part 3（Entra ID の groups 超過・Cognito）' },
    });
    const col = (x, t, rows) => {
      L.T(s, t, { x, y: 1.95, w: 5.9, h: 0.45, fontSize: 16, bold: true, color: C.accent2, margin: 0, valign: 'middle' });
      rows.forEach((r, i) => L.card(s, { x, y: 2.5 + i * 1.25, w: 5.9, h: 1.12, title: r[0], titleSize: 12.5, titleH: 0.3, pad: 0.1, titleColor: r[2], body: [r[1]], bodySize: 12, fill: i === 2 ? 'E6F2EA' : undefined }));
    };
    col(0.6, 'B9　Entra の groups 超過の管理者', [['原因', '250 グループで groups が消え、必須のロールが欠ける → required が拒否', C.accent3], ['基準を緩めると', 'required を外すと B9 は通るが、B8（一般社員）と B15（フックの打ち切り）が再び通る', C.accent2], ['重点で通す', 'overage_resolve：groups が消えたらディレクトリで引く。BE から外すと B9 は再び拒否', C.accent4]]);
    col(6.8, 'B16　aud の無い Cognito の AT（既定の形）', [['原因', '既定（resource なし）の Cognito の AT は aud が無く client_id で宛先を表す → aud の確認が拒否', C.accent3], ['基準を緩めると', 'aud を外すと B16 は通るが、B3（宛先の差し替え）が再び通る', C.accent2], ['重点で通す', 'normalize_gw：入口で Cognito だけ client_id を照合し、内部トークンに aud を入れる', C.accent4]]);
  }

  {
    const s = L.content('属性の鮮度：重要な操作だけ引き直せば、異動とログアウトがすぐ効く', {
      lead: 'freshness を外すと、B11（異動後の古い属性）と B12（ログアウト後のトークン）が再び通る',
      stages: [4],
      notes: '属性の鮮度の 2 件です。B11 は、経理の finance から営業の sales に異動した直後に、異動前に発行されたトークンで経理台帳を読むものです。B12 は、ログアウトでセッションが失効した後に、残ったトークンで経理台帳を読むものです。どちらもトークンは正しく期限内なので、基準では止まりません。重点の freshness は、経理と管理の重要な操作だけ、Keycloak の管理 API で今の属性とセッションを引き直します。費用は、freshness の実装そのものではなく、それに近い操作を測ったもので、イントロスペクションが p50 8.9 ミリ秒、p95 31.8 ミリ秒、ディレクトリの参照が p50 50.7 ミリ秒、p95 75.6 ミリ秒で、どちらも 200 回の測定、ディレクトリの参照には毎回の管理用トークンの取得が含まれます。Keycloak の実機では、ログアウトした後のイントロスペクションは 20 回すべてで最初の確認から inactive になり、かかったのは最大 26.8 ミリ秒でした。イントロスペクションが aud に含まれるクライアントにだけ active を返すのは、Keycloak の文書に書かれた仕様で、互換のためのクライアント設定で無効にもできます。一方、JWT そのものは少なくとも 299 秒の寿命が残っていました。自己完結のトークンだけでは、ログアウトしても寿命まで使えます。',
      refs: { res: 'measurements.json B.freshness・logout_introspection／Keycloak 文書（aud 確認）', code: 'cs/scen_b.py Service.fresh()・freshness_cost()／cs/kcmeasure.py logout_introspection()', guide: 'ガイド Part 8（寿命の間のクレーム・失効の伝播）' },
    });
    L.card(s, { x: 0.6, y: 1.95, w: 5.9, h: 1.35, icon: 'MdSwapHoriz', color: C.accent3, title: 'B11 異動後の古い属性', titleSize: 14, titleH: 0.45, body: ['finance から sales に異動した直後、古いトークンで経理台帳を読む'], bodySize: 12 });
    L.card(s, { x: 0.6, y: 3.45, w: 5.9, h: 1.35, icon: 'MdLogout', color: C.accent3, title: 'B12 ログアウト後のトークン', titleSize: 14, titleH: 0.45, body: ['セッション失効後に、残ったトークンで経理台帳を読む'], bodySize: 12 });
    L.table(s, [['近い操作の費用（200 回。freshness そのものではない）', 'p50', 'p95'],
      ['イントロスペクション', '8.9 ms', '31.8 ms'],
      ['ディレクトリ参照（管理用トークンの取得を含む）', '50.7 ms', '75.6 ms']],
    { x: 6.8, y: 1.95, w: 5.9, colW: [3.7, 1.1, 1.1], fontSize: 12, rowH: 0.5 });
    L.card(s, { x: 6.8, y: 3.7, w: 5.9, h: 1.1, title: 'Keycloak の実機：ログアウトの後', titleSize: 13.5, titleH: 0.32, pad: 0.1, body: ['イントロスペクションは 20 回すべて最初の確認で inactive（最大 26.8 ms）。JWT は 299 秒以上残る'], bodySize: 12 });
    L.note(s, 'tip', '自己完結のトークンだけでは、ログアウトしても寿命まで使える。重要な操作だけ問い合わせる（寿命の試算は第 5 章）', { x: 0.6, y: 5.1, w: 12.1, h: 0.75, size: 13 });
  }

  {
    const s = L.content('題材 B の見送り：盗まれたトークンの再送は基準＋重点（BE）でも通る', {
      lead: '送信者制約（DPoP・mTLS）と JWE は入れない。費用は小さいが、クライアントの鍵管理の手間を避けた',
      stages: [4, 7],
      notes: '題材 B で意図して見送ったのは、送信者制約と暗号化です。B23 は、漏れたトークンを別の端末からそのまま再送する攻撃で、素朴でも基準でも基準＋重点でも通ります。DPoP や mTLS でトークンを鍵に束縛していないので、トークンを持つ者は誰でも使えます。これが見送りの代償です。費用はどうか。2,000 回の測定で、署名だけの JWS は 670 バイト、検証 p50 83.0 マイクロ秒です。入れ子の JWE は 1,345 バイトで、暗号化 p50 142 マイクロ秒、復号 p50 628 マイクロ秒。DPoP の証明は 498 バイトで、作成 p50 99 マイクロ秒、検証 p50 97 マイクロ秒です。計算の費用は小さく、見送りの理由はクライアントの鍵管理の手間です。見直し条件は、トークンが社外や取引先へ渡るようになったとき、または盗用の兆候が見えたときです。注意が 1 つあります。この実験で測ったのは送信者制約の費用だけで、DPoP を入れれば B23 が止まることは測っていません。',
      refs: { res: 'measurements.json B.defer_crypto／summary.md §見送りの代償／一覧表 CLM-0431（B）', code: 'cs/scen_b.py defer_crypto()・B23／catalog/DECISION_POLICY.md §ケースごとの重点', guide: 'ガイド Part 2（cnf）・Part 8（送信者制約）・Part 9（JWE）・Part 6' },
    });
    L.table(s, [['項目（2,000 回）', '大きさ', '時間 p50'],
      ['JWS（いまの形）', '670 B', '検証 83.0 µs'],
      ['JWE（入れ子）', '1,345 B', '暗号化 142 µs／復号 628 µs'],
      ['DPoP の証明', '498 B', '作成 99 µs／検証 97 µs']],
    { x: 0.6, y: 1.95, w: 6.4, colW: [2.2, 1.3, 2.9], fontSize: 12.5, rowH: 0.52 });
    L.card(s, { x: 7.3, y: 1.95, w: 5.4, h: 1.55, icon: 'MdRemoveCircleOutline', color: C.accent3, title: '失うこと', titleSize: 14, titleH: 0.45, body: ['トークンを持つ者は誰でも使える（B23）。中継者から中身を隠せない'], bodySize: 12 });
    L.card(s, { x: 7.3, y: 3.65, w: 5.4, h: 1.55, icon: 'MdUpdate', color: C.accent2, title: '見直し条件', titleSize: 14, titleH: 0.45, body: ['トークンが社外・取引先へ渡るようになったとき、または盗用の兆候が見えたとき'], bodySize: 12 });
    L.note(s, 'warn', '測ったのは送信者制約の費用だけ。DPoP で B23 が止まることは、この実験では測っていない（未検証）', { x: 0.6, y: 5.45, w: 12.1, h: 0.75, size: 13.5 });
  }
};

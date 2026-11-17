// Title and chapter 0 (premises): why a case study, how it was measured, the environment and the cases
module.exports = (L) => {
  const { pres, C, SH } = L;

  L.section('はじめに');
  {
    const s = pres.addSlide({ masterName: 'TITLE', sectionTitle: 'はじめに' });
    L.T(s, 'JWT CLAIM DESIGN CASE STUDY', { x: 0.8, y: 1.2, w: 11, h: 0.5, fontSize: 18, bold: true, color: C.accent2, charSpacing: 6, margin: 0 });
    L.T(s, 'JWT クレーム設計ケーススタディ', { x: 0.8, y: 1.8, w: 12.0, h: 1.0, fontSize: 40, bold: true, color: C.background1, margin: 0 });
    L.T(s, '銀の弾丸はない。共通の基準・題材ごとの重点・意図した見送りを、攻撃と除去実験で測る', { x: 0.8, y: 2.85, w: 11.8, h: 0.6, fontSize: 21, color: C.background2, margin: 0 });
    const seg = [['共通の基準', '9 要素（全題材で同じ）', C.accent1], ['＋ 重点', '題材ごとに 4〜5 要素', C.accent2], ['＋ 見送り', '失うことと見直し条件を書いて残す', C.accent3]];
    seg.forEach(([t, d, col], i) => {
      s.addText([{ text: t, options: { bold: true, fontSize: 15, color: C.background1, breakLine: true } }, { text: d, options: { fontSize: 12, color: C.background1 } }],
        { shape: SH.ROUNDED_RECTANGLE, rectRadius: 0.08, x: 0.8 + i * 3.95, y: 3.95, w: 3.7, h: 0.95, fill: { color: col }, line: { color: col }, align: 'center', valign: 'middle', margin: 0.05 });
    });
    L.T(s, '対象：「JWT クレーム設計ガイド」を読んだ（これから読む）新任のテックリーダー', { x: 0.8, y: 5.35, w: 11.8, h: 0.4, fontSize: 15, color: C.background2, margin: 0 });
    L.T(s, '実機：Keycloak 26.8.0・Postgres 16（RLS）／模擬：Entra ID・Okta・Cognito・Auth0（2026-11 の公式文書の形）／67 ケース', { x: 0.8, y: 5.8, w: 11.8, h: 0.4, fontSize: 13, color: 'A9BCC2', margin: 0 });
    s.addNotes('本資料は、「JWT クレーム設計ガイド」の対になるケーススタディです。ガイドが原則と根拠を示したのに対し、ここでは「どれを必須にし、どこに重点を置き、何を見送るか」を、実際に攻撃と正規の要求を流して測った数字で示します。結論の型は、銀の弾丸はない、というものです。どの組織でも外せない共通の基準が 9 つの要素、題材ごとに足す重点が題材 A で 4、題材 B で 4、題材 C で 5 の要素、そして意図して入れない見送りです。比べる構成は、素朴（N）、基準（B）、基準＋重点（BE）と呼び、題材は題材 A・題材 B・題材 C と書き分けます。見送りには、何を失うかと、何が起きたら見直すかを書いて残します。実機で動かしたのは OSS の Keycloak 26.8.0 と Postgres 16 だけで、Entra ID・Okta・Cognito・Auth0 は 2026 年 11 月時点の公式文書にある形を再現した模擬です。各社の製品そのもので測ったわけではない点に注意してください。ケースは攻撃と正規の要求を合わせて 67 件、付録の一覧表の判定は 2026 年 11 月 17 日時点のものです。');
  }

  {
    const s = L.content('この資料の位置づけ：ガイドは原則、ケーススタディは判断の数字', {
      lead: 'ガイド（152 枚）で示した原則のうち、どれを必須にし、何を見送るかを、測った数字で示す',
      stages: [0],
      notes: 'この資料は 3 つの成果物の 1 つです。ガイドは前提編で、標準のクレーム、IdP の実際、設計原則、流れ、期限、AI エージェント、ガバナンスを、仕様・公的な指針・書籍を根拠に解説した 152 枚の資料です。このケーススタディは、ガイドの原則を実装し、攻撃と正規の要求を流して、どの要素が何を防ぐかを測ったものです。付録の一覧表は、805 行のクレームそれぞれについて、3 つの題材での判定と理由を書いたものです。この資料では、比べる構成を素朴（N、要素なし）、基準（B、共通の基準の 9 要素）、基準＋重点（BE、基準に題材の重点を足したもの）と呼び、題材は題材 A・題材 B・題材 C と書きます。各スライドの右上の表示は、この資料の流れのどこにいるかを示します。前提、構成、汎用の攻撃、題材 A・B・C、測定、判断の順です。スライドの下の行は根拠で、結果のファイル、実装のファイル、ガイドの該当 Part の 3 種類を色で分けています。数字はすべて結果のファイルから取っています。用語をまとめておきます。AT はアクセストークン、PDP は許可するかを判断する場所（ポリシー判断点）、BOLA はオブジェクト単位の認可の欠落、MCP は AI エージェントがツールを呼ぶための Model Context Protocol、act は委任で今の行為者を表すクレーム（RFC 8693）、RAR は authorization_details で細かい権限を表す仕組み（RFC 9396）、cnf.jkt はトークンを DPoP の鍵に結び付けるクレーム、ID-JAG は IdP が発行する委任の草案のトークン、p50・p95 は測った時間の中央値と 95 パーセンタイルです。ほかの用語は、ガイドの S7（用語）を見てください。',
      refs: { res: 'README.md（冒頭・付録）', code: 'run_all.py（全題材と測定を 1 本で実行）', guide: 'ガイド Part 12 S149（重点と見送り）・S7（用語）' },
    });
    const cw = 3.83, y = 1.95, h = 2.45;
    L.card(s, { x: 0.6, y, w: cw, h, icon: 'MdMenuBook', color: C.accent5, title: 'ガイド（前提編）', body: ['原則・仕様・IdP の実際', '仕様・公的な指針・書籍が根拠', '152 枚（Web 版あり）'], bodySize: 13 });
    L.card(s, { x: 4.73, y, w: cw, h, icon: 'MdScience', color: C.accent1, title: 'ケーススタディ（本資料）', body: ['67 ケース（攻撃＋正規の要求）', '素朴・基準・基準＋重点と除去実験', 'Keycloak の実機の測定・試算'], bodySize: 13 });
    L.card(s, { x: 8.87, y, w: cw, h, icon: 'MdTableChart', color: C.accent2, title: '付録の一覧表（xlsx）', body: ['805 行のクレーム', '題材 A・B・C ごとの判定と理由', '見直し条件と検証 ID'], bodySize: 13 });
    L.T(s, '凡例', { x: 0.6, y: 4.6, w: 1.0, h: 0.35, fontSize: 14, bold: true, margin: 0 });
    s.addText('題材 B', { shape: SH.ROUNDED_RECTANGLE, rectRadius: 0.14, x: 0.6, y: 5.05, w: 0.86, h: 0.28, fill: { color: C.accent1 }, line: { color: C.accent1 }, fontSize: 10, bold: true, color: C.background1, align: 'center', valign: 'middle', margin: 0 });
    L.T(s, '右上の表示：前提・構成・汎用・題材 A〜C・測定・判断のどこの話か', { x: 1.6, y: 4.97, w: 5.2, h: 0.45, fontSize: 13, margin: 0, valign: 'middle' });
    const legend = [['結果', C.accent1, 'results/・catalog/ の結果のファイル（節）'], ['実装', C.accent4, 'cs/・kc/・catalog/scripts の実装'], ['ガイド', C.accent2, 'ガイドの該当 Part']];
    legend.forEach(([t, col, d], i) => {
      L.T(s, [{ text: t + '  ', options: { bold: true, color: col } }, { text: d, options: { color: C.text1 } }], { x: 7.0, y: 4.65 + i * 0.42, w: 5.7, h: 0.38, fontSize: 13, margin: 0, valign: 'middle' });
    });
    L.T(s, 'スライド下の行：そのスライドの根拠（3 種類）。本文は要点、ノート欄は詳しい説明', { x: 0.6, y: 5.75, w: 12.1, h: 0.4, fontSize: 12, color: L.MUTED, margin: 0, valign: 'middle' });
  }

  {
    const s = L.content('結論：基準では攻撃が残る。重点で、見送りの 1 件まで減る', {
      lead: '基準（B）では題材 A 5 件・題材 B 7 件・題材 C 12 件が通る。基準＋重点（BE）では見送りの 1 件だけ',
      stages: [0, 1],
      notes: '最初に結論の数字を示します。素朴（N）は要素を何も入れない実装で、よくある誤りを再現したものです。基準（B）は共通の基準の 9 要素、基準＋重点（BE）は基準に題材ごとの重点を足したものです。汎用の攻撃は 14 件中 13 件が素朴で通り、基準で 0 件になります。ところが、題材の攻撃では、基準だけでは題材 A で 10 件中 5 件、題材 B で 18 件中 7 件、題材 C では 12 件すべてが通ります。基準＋重点では、題材 A と題材 C が 0 件、題材 B が 1 件です。題材 B の 1 件は、盗まれたトークンの再送で、送信者制約を意図して見送った代償です。残るのはこの 1 件だけで、ほかに見送りの代償で通った攻撃はありません。もう 1 つ大事なのが右の列で、正規の要求が正しく処理されなかった数です。題材 A では集計の正規の要求が素朴と基準で他テナントの行を返し、題材 B では基準を厳しくしたことで正規の要求が 2 件拒否されました。どちらも基準＋重点で 0 になります。攻撃だけを数えると、厳しすぎる基準の副作用を見逃します。',
      refs: { res: 'results/summary.md §攻撃が通った数と、正規の要求が正しく処理されなかった数／results/scores.json', code: 'cs/flags.py（N・B・BE の定義）', guide: 'ガイド Part 1・4（基準）、Part 5〜10（重点）' },
    });
    const M = L.mk;
    L.table(s, [['題材', '攻撃', '素朴（N）\n通った', '基準（B）\n通った', '基準＋重点\n（BE）通った', '正規', '素朴（N）\n誤処理', '基準（B）\n誤処理', '基準＋重点\n（BE）誤処理'],
      ['汎用の攻撃（Part 1）', '14', M('13'), M('0'), M('—'), '1', M('0'), M('0'), M('—')],
      ['題材 A マルチテナント SaaS', '10', M('9'), M('5'), M('0'), '4', M('1'), M('1'), M('0')],
      ['題材 B 社内業務システム', '18', M('18'), M('7'), M('1'), '5', M('0'), M('2'), M('0')],
      ['題材 C AI エージェントの委任', '12', M('12'), M('12'), M('0'), '3', M('0'), M('0'), M('0')]],
    { x: 0.6, y: 1.95, w: 12.1, colW: [2.9, 0.8, 1.3, 1.3, 1.4, 0.8, 1.2, 1.2, 1.2], fontSize: 12.5, rowH: 0.5 });
    L.note(s, 'leader', '基準は全題材で同じ、重点は題材で選ぶ。題材 B の残り 1 件（盗まれたトークンの再送 B23）は、見直し条件を付けた意図的な見送り', { x: 0.6, y: 4.75, w: 12.1, h: 0.8, size: 13.5 });
    L.T(s, '誤処理＝正規の要求が拒否された、または他テナントの行が混ざった（A4）。「—」は汎用の攻撃に重点が無いため', { x: 0.6, y: 5.75, w: 12.1, h: 0.4, fontSize: 12, color: L.MUTED, margin: 0 });
  }

  {
    const s = L.content('測り方：構成を要素の集合にし、1 つずつ外して何が再び通るかを見る', {
      lead: '素朴（N）・基準（B）・基準＋重点（BE）を比べ、除去実験で各要素が何を防ぐかを確かめる。誤拒否も数える',
      stages: [1],
      notes: '測り方です。構成は要素の集合として表します。素朴（N）は要素なし、基準（B）は共通の基準の 9 要素、基準＋重点（BE）は基準に題材の重点を足したものです。除去実験では、基準（B）から基準の要素を 1 つずつ外した 9 通りと、基準＋重点（BE）から重点の要素を 1 つずつ外した構成を流し、どの攻撃が再び通るか、どの正規の要求が新たに拒否されるかを記録します。これが、その要素が何を防いでいるかの証拠になります。題材 A では、接続プールの誤りを見るために、文脈を接続単位で設定する構成など 3 つを足しています。各題材には攻撃だけでなく正規の要求も混ぜてあり、正規の要求が拒否されたら失敗として数えます。判定に LLM は使わず、同じ手順で何度流しても同じ結果になります。期限切れや取り消し後の時刻は仮想の時計で進め、寿命の試算は乱数の種を 20261117 に固定しています。',
      refs: { res: 'README.md §構成と要素', code: 'cs/flags.py configs()／cs/jwtlib.py（仮想の時計）／cs/lifetime.py（seed=20261117）', guide: 'ガイド Part 1・4〜10（各要素の根拠）' },
    });
    L.flow(s, [{ t: '素朴（N）', d: '要素なし（よくある誤り）', fill: C.accent3 }, { t: '基準（B）', d: '共通の基準 9 要素', fill: C.accent1 }, { t: '基準＋重点（BE）', d: '基準 ＋ 題材の重点', fill: C.accent4 }], { x: 0.6, y: 1.95, w: 7.2, h: 1.15 });
    L.card(s, { x: 8.1, y: 1.95, w: 4.6, h: 2.5, icon: 'MdContentCut', color: C.accent2, title: '除去実験', titleSize: 15, body: ['基準（B）から要素を 1 つ外す（9 通り）', '基準＋重点（BE）から重点を 1 つ外す（題材 A 4・題材 B 4・題材 C 5 通り）', '題材 A は接続プールの 3 構成を追加'], bodySize: 12.5 });
    const rules = [['MdRule', '決定的', 'LLM を使わない。何度流しても同じ判定'], ['MdSchedule', '仮想の時計', '期限切れ・取り消し後の時刻を進める'], ['MdCasino', '乱数の種を固定', '寿命の試算は seed 20261117']];
    rules.forEach((r, i) => L.card(s, { x: 0.6 + i * 2.45, y: 3.3, w: 2.3, h: 1.15, title: r[1], titleSize: 13.5, titleH: 0.36, pad: 0.1, body: [r[2]], bodySize: 11 }));
    L.note(s, 'warn', '正規の要求が拒否されるのも失敗（誤拒否）。攻撃だけを数えると、厳しすぎる基準の副作用を見逃す', { x: 0.6, y: 4.75, w: 12.1, h: 0.8, size: 13.5 });
  }

  {
    const s = L.content('環境：Keycloak と Postgres は実機、商用 IdP は模擬', {
      lead: '実機は OSS の 2 つだけ。Entra ID・Okta・Cognito・Auth0 は 2026-11 の公式文書の形の模擬',
      stages: [0],
      notes: '環境です。実機はコンテナで動かした Keycloak 26.8.0 と Postgres 16 です。Keycloak には、題材 A のテナントごとのレルム t1 と t2、題材 B と題材 C の社内のレルム corp を作りました。Postgres では行単位の制御、RLS を使っています。Entra ID、Okta、Cognito、Auth0 は、2026 年 11 月時点の公式文書にある形、たとえばトークンの種類の値、不変の ID のクレーム名、グループの超過、フックの挙動などを再現した模擬です。ただし Okta の typ に使った値は、公式文書では確かめられていない模擬の値です（第 3 章）。実際のサービスの挙動のすべてではないので、「各社の製品で測った」とは言えません。題材 B と題材 C の内部トークンは、時刻を進めるために、組織の内部のトークン発行サービスの模擬が発行します。測定の PC は AMD Ryzen 7 3700X、Windows 11、Python 3.14.6、PyJWT 2.10.1 です。Keycloak の起動は 32 秒、メモリは Keycloak が 773.7 MiB、Postgres が 30.81 MiB、全体の実行は 157 秒でした。',
      refs: { res: 'results/measurements.json §env／README.md §注意', code: 'run_all.py／cs/infra.py／kc/import/t1.json・t2.json・corp.json', guide: 'ガイド Part 3（IdP の実際）' },
    });
    L.table(s, [['対象', '扱い', '使った題材'],
      ['Keycloak 26.8.0', '実機（コンテナ）。レルム t1・t2・corp', '題材 A・B・C、Keycloak の測定'],
      ['Postgres 16（alpine）', '実機（コンテナ）。行単位の制御（RLS）', '題材 A'],
      ['Entra ID・Okta・Cognito・Auth0', '模擬（2026-11 の公式文書の形）', '題材 B'],
      ['内部のトークン発行サービス', '模擬（仮想の時計で時刻を進める）', '題材 B の内部トークン、題材 C']],
    { x: 0.6, y: 1.95, w: 7.6, colW: [2.5, 3.0, 2.1], fontSize: 12, rowH: 0.55 });
    L.card(s, { x: 8.5, y: 1.95, w: 4.2, h: 2.75, icon: 'MdComputer', color: C.accent5, title: '測定の環境', titleSize: 15, body: ['AMD Ryzen 7 3700X・Windows 11', 'Python 3.14.6・PyJWT 2.10.1', 'Keycloak の起動 32 秒', 'メモリ：Keycloak 773.7 MiB・Postgres 30.81 MiB', '全体の実行 157 秒'], bodySize: 12 });
    L.note(s, 'warn', '模擬の IdP は実際のサービスの挙動のすべてではない。「各社の製品で測った」とは言えない', { x: 0.6, y: 5.0, w: 12.1, h: 0.75, size: 13.5 });
  }

  {
    const s = L.content('題材：67 ケース＝攻撃 54 件＋正規の要求 13 件', {
      lead: '件数は攻撃と正規の要求の合計。「通った」は攻撃の数、「誤拒否・誤処理」は正規の要求の数で数える',
      stages: [0],
      notes: '題材は 4 つで、ケースは合わせて 67 件です。67 件は攻撃だけの数ではなく、攻撃 54 件と正規の要求 13 件の合計です。汎用の攻撃は 15 件で、攻撃 14 件と正規 1 件、ガイドの Part 1 の攻撃の型を中心にしています。題材 A のマルチテナント SaaS は 14 件で、攻撃 10 件と正規 4 件、Keycloak の 2 つのレルムと Postgres の RLS を使います。題材 B の社内業務システムは 23 件で、攻撃 18 件と正規 5 件、Keycloak の corp と商用 4 社の模擬を入口でまとめます。題材 C の AI エージェントの委任は 15 件で、攻撃 12 件と正規 3 件です。以降のスライドで「何件中何件通った」と言うときは攻撃の数、「誤拒否」は正規の要求の数です。題材 A の誤処理には、正規の集計の要求が他テナントの行を返した誤りも含みます。各ケースの狙いとガイドの Part は、results/summary.md の表にあります。',
      refs: { res: 'results/matrix.json／results/scores.json（attacks・legit）／README.md §題材', code: 'cs/generic.py・scen_a.py・scen_b.py・scen_c.py の cases()', guide: 'ガイド Part 1・3・5〜10' },
    });
    const cards = [
      ['MdBugReport', C.accent5, '汎用の攻撃　15 件', '攻撃 14・正規 1', ['alg none・HS256・kid・jku・jwk', 'exp・aud・iss・typ', '必須の欠落・型の揺れ']],
      ['MdApartment', C.accent1, '題材 A マルチテナント SaaS　14 件', '攻撃 10・正規 4', ['テナントの出どころ・BOLA', '接続プール・他テナントのマッパー', '連携先の鍵・軽量 AT']],
      ['MdBusiness', C.accent4, '題材 B 社内業務システム　23 件', '攻撃 18・正規 5', ['ID トークン・宛先・ヘッダーの偽装', 'groups 超過・異動・ログアウト', 'IdP ごとの癖・盗まれたトークン']],
      ['MdSmartToy', C.accent6, '題材 C AI エージェントの委任　15 件', '攻撃 12・正規 3', ['パススルー・代理の混乱', 'act の読み違い・承認の照合', '取り消し・深さ・範囲の拡大']]];
    cards.forEach((c, i) => {
      const x = 0.6 + i * 3.06;
      L.card(s, { x, y: 1.95, w: 2.86, h: 3.3, color: c[1], title: c[2], titleSize: 14, titleH: 0.6, body: [{ text: c[3], options: { bold: true, color: c[1], breakLine: true, paraSpaceAfter: 6 } }].concat(L.runs(c[4], { space: 4 })), bodySize: 12 });
    });
    L.note(s, 'tip', '合計 67 件＝攻撃 54 件＋正規の要求 13 件。題材 A の誤処理には、正規の集計が他テナントの行を返した誤り（A4）を含む', { x: 0.6, y: 5.45, w: 12.1, h: 0.75, size: 13 });
  }
};

# JWT クレーム設計ケーススタディ（実験基盤）

「JWT クレーム設計ガイド」の対になる実測です。どの組織でも外せない**共通の基準**が何を防ぎ、題材ごとの**重点**が何を足し、**見送り**が何を残すかを、攻撃と正規の要求、要素を 1 つずつ外す**除去実験**、大きさ、遅延、反映までの時間、変更で壊れる受け手の数で測ります。LLM は使わず、同じ手順で何度でも同じ判定になります（時刻は仮想の時計で進めます。試算は乱数の種を固定）。

## 構成と要素

構成は「要素の集合」です。N は要素なし（よくある誤り）、B は共通の基準の 9 要素、BE は B に題材の重点を足したものです。除去実験では、B から基準の要素を 1 つ、BE から重点の要素を 1 つずつ外し、どの攻撃が再び通るか、どの正規の要求が拒否されるかを記録します。

| 区分 | 要素 | 中身 |
| --- | --- | --- |
| 共通の基準 | alg | alg の許可リスト（RS256）。jku・jwk・x5u・x5c を無視し、kid は登録済みの鍵だけ |
| | iss | iss を許可リストと完全一致。鍵はその発行者に登録されたものだけ（Storm-0558 の教訓） |
| | aud | aud に自分が含まれるか |
| | exp | exp を必須にし、ずれは 30 秒まで |
| | typ | typ（Cognito は token_use）でアクセストークンだけを受ける |
| | required | 組織で必須と定めたクレームが無ければ拒否（fail closed） |
| | types | 必須クレームの型を確認（ID は文字列、配列は配列） |
| | immutable_id | 利用者のキーは sub・oid+tid・uid。ログイン名やメールを使わない |
| | namespace | 組織のクレームは `https://claims.example.com/` の中だけを読む |
| 重点 A | tenant_iss_bind／data_tenant_check／rls_local／per_tenant_keys | テナントと発行者の照合、すべての SQL にテナント条件、SET LOCAL と RLS、テナント単位の鍵 |
| 重点 B | normalize_gw／header_strip／freshness／overage_resolve | 入口での正規化（内部トークン）、x-user-* の変種と重複の除去、重要な操作の鮮度確認、groups 超過の解決 |
| 重点 C | act_chain／aud_exchange／approval_bind／short_task／depth_rule | 今の行為者と呼び出し元の照合、単一の宛先への交換、承認（金額と相手先）の束縛、タスク単位 300 秒と取り消しの再確認、深さ 3 の規則 |

## 題材（全 72 ケース）

- **汎用の攻撃（Part 1、15 件）**：alg none、RS256→HS256、kid 注入、jku、jwk、exp なし、期限切れ、宛先違い、別の発行者、別の発行者の鍵で iss を偽る（Storm-0558 の型）、typ、必須クレームの欠落、型の揺れ、数値の sub。
- **A マルチテナント SaaS（14 件、Keycloak のレルム t1・t2 と Postgres の RLS）**：テナントの出どころ、BOLA、接続プールの文脈の残り、他テナントの管理者のマッパー、連携先に渡した鍵、軽量アクセストークンで落ちるテナント、配列になったテナント、ID トークン、期限切れ。
- **B 社内業務システム（23 件、Keycloak corp と Entra ID・Okta・Cognito・Auth0 の形の模擬）**：ID トークン、宛先の差し替え、ヘッダーの偽装（アンダースコア版・重複・入口の迂回）、groups 超過、別の顧客テナントの Entra トークン、異動後の古い属性、ログアウト後のトークン、Okta のログイン名の再利用とフックの打ち切り、Cognito の aud なし・ID トークン・本人が書ける custom 属性・フックで消えた groups、Auth0 の予約名の黙った削除、2^53 を超える数値の ID、盗まれたトークンの再送。
- **C AI エージェントの委任（15 件）**：パススルー、代理の混乱、act の読み違い、承認の金額・相手先・偽造、取り消し後の利用、委任の深さ、利用者のトークンの借用、resource の欠落、範囲の拡大、sub の差し替え。

各ケースの狙いとガイドの Part は [results/summary.md](results/summary.md) の表にあります。

## そのほかの測定

- **Keycloak 26.8 の実際の挙動**：Full Scope Allowed のオン・オフ、軽量アクセストークンで落ちるクレーム、定義していない利用者属性、Organizations のクレーム、グループ数とトークンの大きさ、リフレッシュ・再ログインでの再評価、ログアウト後のイントロスペクション、標準トークン交換での宛先と範囲の絞り込み・拡大。
- **寿命の試算**：アクセストークンの寿命 1・5・15・60 分 × 3 方式（自己完結のみ／重要な操作だけ問い合わせ／毎回問い合わせ）で、古い情報での判断の件数と認可サーバーへの呼び出し数。
- **共有クレームの変更**：9 つの受け手（Python、JavaScript、Go、Envoy、CEL、SQL の RLS、Kubernetes の claimMappings、Java、sub をキーにする旧システム）× 10 の変更で、壊れる・黙って誤る・契約テストで検出・共通の部品で吸収できるかを数える。
- **時間**：検証と交換は 5,000 回、暗号化・DPoP は 2,000 回、Keycloak の交換は 200 回の p50・p95。環境（CPU、Python、PyJWT、Keycloak）は結果に記録。

## 実行

前提：Windows から WSL（Ubuntu-24.04）の Docker が使えること。Keycloak 26.8.0 と Postgres 16 のイメージを使います（メモリは約 0.8 GB）。

```bash
python -m venv .venv && .venv/Scripts/python -m pip install "pyjwt[crypto]==2.10.1" jwcrypto "psycopg[binary]" requests
.venv/Scripts/python run_all.py        # コンテナを起動 → 全題材と除去実験 → 測定 → results/ に書き出し → コンテナを停止
```

結果：`results/matrix.json`（構成・除去実験 × ケース）、`results/scores.json`、`results/measurements.json`、`results/summary.md`。

## 注意

- 鍵（`keys/`、リポジトリには含めない）、パスワード、クライアントシークレットはすべて試験用です。
- 要素を外した構成は、過去にライブラリやアプリが実際にしていた誤りを手で再現したものです。現在の PyJWT 2.10 は数値の sub などいくつかを自分で拒否します（G14）。
- 模擬の IdP は、2026 年 11 月時点の公式文書にある形を再現したもので、実際のサービスの挙動のすべてではありません。

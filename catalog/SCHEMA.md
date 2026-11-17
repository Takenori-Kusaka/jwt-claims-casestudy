# Claim catalogue row schema (JSON array of objects, UTF-8)

Each row = one claim name AS DEFINED BY ONE SOURCE. If the same or a similar claim is defined by two sources (e.g. `groups` in RFC 9068/RFC 7643 and `groups` in Entra ID and `cognito:groups`), make separate rows.

Fields (all strings unless noted; Japanese for prose, claim names verbatim):
- name: exact claim name as it appears in the token (e.g. "sub", "cognito:groups", "https://aws.amazon.com/tags", "kubernetes.io/serviceaccount" for nested give the path with "." e.g. "kubernetes.io.serviceaccount.uid")
- category (column name in the sheet: 分類): one of 識別子 / 発行者・宛先 / 時刻・寿命 / トークン種別・メタ / 認証の強さ・セッション / 権限・認可 / 組織・テナント / 委任・行為者 / クライアント・ワークロード / 鍵・送信者制約 / 監査・相関・イベント / 同意・目的・取引 / プロフィール・連絡先 / 本人確認・保証 / 端末・ネットワーク・場所 / 開示・暗号・検証補助 / CI・ワークロード属性 / その他
- purpose: 1–2 sentences in Japanese: what it says and what it does NOT mean
- source_kind: one of 標準（IETF RFC） / 標準（OpenID Foundation 最終版） / 草案（IETF・OIDF） / IANA 登録（その他の標準化団体） / 公的機関・研究 / ベンダー独自 / プラットフォーム独自 / 業界の属性語彙
- source: short citation with section, e.g. "RFC 7519 §4.1.2", "OpenID Connect Core 1.0 §5.1", "Microsoft Entra ID access token reference", "IANA JWT Claims registry (registered by RFC 8417)"
- url: primary-source URL you actually opened
- value_type: JSON type and format, e.g. "string (StringOrURI)", "array of string", "object", "number (NumericDate)", "boolean", "string (space-delimited)"
- token: where it appears: ID / AT / 両方 / ログアウトトークン / SET / DPoP 証明 / Txn-Token / 証明書・VC / その他 (say which)
- support: object with keys Entra, Keycloak, Auth0, Okta, Cognito; each value one of
  "既定"（default, no config）, "設定で追加"（optional claim / mapper / scope needed）, "独自の名前で"（the IdP has the concept but under its own claim name — say which in notes）, "フック・式で可"（only via Actions/hooks/expressions/mappers you write）, "不可・未対応", "不明"
  Fill this only from documentation you checked (research notes E:\Github\jwt-claims-guide\research\notes\02_idp-claims.md and the vendors' docs). Use "不明" rather than guessing.
- is_custom: "独自（どの標準にもない）" / "標準" / "標準だが値の語彙は独自"
- notes: Japanese; pitfalls, status (final/draft, date), deprecations, size limits, writer (who can set it)
- verified: true/false — whether you opened the primary source for this row

Rules: facts only from primary sources you opened (or the research notes in E:\Github\jwt-claims-guide\research\notes\, which cite sources). Never invent claims. Mark drafts as drafts with draft number. As of 2026-11-17.

## Additional fields (added after the column review, 2026-11-17)
- status: 最終 / 草案（版番号） / 非推奨 / 廃止 / ベンダー提供中 / プレビュー
- change_controller: IESG / OpenID Foundation / IANA登録者名 / ベンダー名 / OASIS / REFEDS など
- writer: who determines the value — 発行者（権威ある情報源） / 発行者（取得元から転記） / 本人が編集できる / 呼び出し元・クライアントの申告 / 発行者が派生 / 不明
- mutability: 不変 / 再割り当てなし / 改名・変更あり / 随時変わる / 不明
- freshness: 発行時点で固定（寿命内は古いまま） / 発行ごとに再計算 / 都度照会が必要 / 該当なし
- authz_use: 単独で可 / iss・aud などと組で可 / 補助のみ / 不可（表示・監査用）  — guidance from the sources, not an adoption decision
- pii: 非該当 / 仮名の識別子 / 直接識別できる個人情報 / 機微な個人情報
- log_policy: 平文で可 / ハッシュ・マスク / 記録しない
- multiplicity: 単一 / 配列 / 単一または配列（揺れあり）
- limit: size/count limit and over-limit behaviour if documented (e.g. "200 件超で欠落し _claim_names に置換"), else 記載なし
- comparison: 大小区別の完全一致 / 大小区別なし / 正規化が必要 / 該当なし
- uniqueness: なし / 発行者内で一意 / 全体で一意 / 該当なし
- vocabulary: 標準で列挙（列挙先） / 発行者ごと / 自由な文字列 / URI
- synonym_group: a short key that groups the same concept across sources, e.g. "G-groups", "G-tenant", "G-user-id", "G-roles", "G-scope", "G-actor"
- checked_on: date you opened the source (2026-11-17)
Fill each from the source when stated; otherwise use 不明 / 記載なし. Do not guess.
